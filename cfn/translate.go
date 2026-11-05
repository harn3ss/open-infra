// Resource translation for the CFN engine (Phase 2, stateful create).
//
// A translator turns one CloudFormation resource's Properties into a concrete open-infra
// manifest. This is where the cardinal rule bites hardest: at CREATE fidelity, a kind-level
// "supported" mapping is not enough — every PROPERTY must either translate faithfully, be a
// provably-inert value we may ignore with a loud caveat, or block the whole deploy. An
// ignored behavior-bearing property is a silent partial apply, which is exactly what this
// engine must never do.
//
// The honest consequence: the set of types with a create translator is much smaller than the
// plan-level mapping table, and each translator is strict. A type that maps at plan time but
// has no translator here is refused at deploy time — plan-supported is not create-faithful.
package cfn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/policyengine"
)

// Manifest is a concrete open-infra resource to apply.
type Manifest struct {
	APIVersion string
	Kind       string
	Name       string
	Spec       map[string]any
	Caveats    []string // declared, non-silent losses (e.g. a KMS key policy that has no equivalent)
	// Extra holds companion manifests a single CFN resource expands into — e.g. an IAM Role's inline
	// Policies become companion kind: Policy objects. They are applied right AFTER this manifest, in
	// order, and inherit its DeletionPolicy unless they set their own (DeletionPolicy, below). Most
	// translators leave this nil.
	Extra []*Manifest
	// DeletionPolicy, when non-empty, OVERRIDES the parent resource's DeletionPolicy for this manifest
	// (Delete | Retain | Snapshot). Used for a SHARED companion that must outlive the stack that first
	// created it — e.g. the per-namespace default EncryptionKey, which other stacks' disks also key
	// on, so it is Retain and a stack destroy/update/rollback must not delete it. Empty = inherit.
	DeletionPolicy string
	// Shared marks a companion several stacks apply on purpose under one fixed name (the per-namespace
	// default EncryptionKey). It is not refused for belonging to another stack (applyOwned).
	Shared bool
	// Requires names objects outside the stack this resource depends on for its meaning (e.g. a
	// SecurityGroup a parameter names). Deploy refuses to apply it while one does not exist.
	Requires []Requirement
	// Protected (RDS DeletionProtection) makes a stack delete, or an update that removes the resource,
	// refuse while it is set.
	Protected bool
	// Annotations are set on the applied object (AWSViewAnnotation: the AWS-side properties the kind does
	// not model, for the aws-shim's EC2 API). nil = none.
	Annotations map[string]string
}

// Requirement is an object outside the stack that must exist before a resource is applied.
type Requirement struct {
	APIVersion, Kind, Name string
	Why                    string // what the resource uses it for, for the refusal message
}

// translator produces a Manifest from a resource's already-resolved Properties, or a set of
// blocking findings. props values have been run through the resolver, so intrinsics are
// evaluated; a value that could not be resolved to something concrete (a cross-resource
// attribute, an unsupported intrinsic) still carries a placeholder marker and must block.
//
// ctx gives cross-resource access for the rare type that COLLATES several CloudFormation
// resources into one open-infra kind (an ECS Service reads its referenced TaskDefinition). Most
// translators ignore it. A translator may return a nil Manifest with no findings to mean "this
// resource is a no-op" — it composes into another kind, or has no standalone form (an ECS
// Cluster, or a TaskDefinition on its own).
type translator func(logicalID string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding)

// stackCtx lets a collating translator reach the rest of the stack: resolve another resource's
// properties (given a `!Ref` to it) and read a resource's raw (pre-resolution) properties, which
// is where a `{Ref: X}` target's logical id is still visible.
type stackCtx struct {
	template *Template
	resolver *resolver
	caps     Capabilities      // deploy-environment facts (zero = fail-closed); same value at plan and deploy
	namer    *physNamer        // each in-stack resource's Kubernetes name (naming.go); nil = bare logical ids
	svcIDs   map[string]string // ids this operation chose for service-backed resources (service.go)
	// signalURL builds a WaitConditionHandle's Ref (signals.go); nil = a placeholder URL (plan, the CLI).
	signalURL func(stackName, handleID string) string
}

// refTarget returns the logical id a raw property references, if it is a bare `{Ref: X}`.
func refTarget(rawProp any) (string, bool) {
	m, ok := rawProp.(map[string]any)
	if !ok {
		return "", false
	}
	id, ok := m["Ref"].(string)
	return id, ok
}

// resolveProps resolves resource `id`'s properties through the same resolver the loop uses.
func (c *stackCtx) resolveProps(id string) (map[string]any, bool) {
	res, ok := c.template.Resources[id]
	if !ok {
		return nil, false
	}
	c.resolver.where = "Resource " + id
	p, _ := c.resolver.resolve(res.Properties).(map[string]any)
	return p, true
}

// rawProps returns resource `id`'s raw (unresolved) properties — where `!Ref` targets are still
// `{Ref: X}` and can be followed to a logical id.
func (c *stackCtx) rawProps(id string) (map[string]any, bool) {
	res, ok := c.template.Resources[id]
	if !ok {
		return nil, false
	}
	return res.Properties, true
}

// included reports whether a resource is active given its Condition: true when it has none, or its
// named condition evaluated true. A conditioned-OFF resource must provision nothing and must not be
// collated into another kind — otherwise a rule the template gates off would be deployed anyway.
func (c *stackCtx) included(res Resource) bool {
	if res.Condition == "" {
		return true
	}
	if c == nil || c.resolver == nil {
		return true
	}
	return c.resolver.conds[res.Condition]
}

// resolveVal resolves a single raw property value through the stack resolver, turning a {Ref: Param}
// into the parameter's value and leaving an unresolvable intrinsic as a placeholder concrete() refuses.
// It is for reading a scalar out of an otherwise-raw rule (where the raw form is kept only to follow a
// SG !Ref to its logical id). A nil ctx/resolver returns the value unchanged (concrete() still guards it).
func (c *stackCtx) resolveVal(v any) any {
	if c == nil || c.resolver == nil {
		return v
	}
	return c.resolver.resolve(v)
}

// translators is the create-fidelity registry. A CFN type is create-provisionable only if it
// appears here AND its translator accepts every property. Grow it the gated way.
var translators = map[string]translator{
	"AWS::KMS::Key":                         translateKMSKey,
	"AWS::KMS::Alias":                       translateKMSAlias,
	"AWS::SQS::QueuePolicy":                 translateSQSQueuePolicy,
	"AWS::SNS::TopicPolicy":                 translateSNSTopicPolicy,
	"AWS::Lambda::Function":                 translateLambdaFunction,
	"AWS::StepFunctions::StateMachine":      translateStateMachine,
	"AWS::EC2::Volume":                      translateVolume,
	"AWS::EC2::VPCEndpoint":                 translateEC2VPCEndpoint,
	"AWS::EC2::Instance":                    translateEC2Instance,
	"AWS::EC2::VPC":                         translateEC2VPC,
	"AWS::EC2::Subnet":                      translateEC2Subnet,
	"AWS::EC2::SecurityGroup":               translateEC2SecurityGroup,
	"AWS::EC2::SecurityGroupIngress":        translateEC2SecurityGroupRule,
	"AWS::EC2::SecurityGroupEgress":         translateEC2SecurityGroupRule,
	"AWS::EC2::EIP":                         translateEC2EIP,
	"AWS::EC2::EIPAssociation":              translateEC2EIPAssociation,
	"AWS::EC2::InternetGateway":             translateEC2ImplicitGateway,
	"AWS::EC2::VPCGatewayAttachment":        translateEC2ImplicitGateway,
	"AWS::EC2::SubnetNetworkAclAssociation": translateEC2ImplicitGateway,
	"AWS::EC2::SubnetRouteTableAssociation": translateEC2ImplicitGateway,
	"AWS::EC2::RouteTable":                  translateEC2RouteTable,
	"AWS::EC2::Route":                       translateEC2Route,
	"AWS::DynamoDB::Table":                  translateDynamoDBTable,
	"AWS::IAM::User":                        translateIAMUser,
	"AWS::IAM::Role":                        translateIAMRole,
	"AWS::IAM::InstanceProfile":             translateIAMInstanceProfile,
	"AWS::IAM::Policy":                      translateIAMPolicy,
	"AWS::IAM::ManagedPolicy":               translateManagedPolicy,
	"AWS::SSM::Parameter":                   translateSSMParameter,
	"AWS::Cognito::UserPool":                translateCognitoUserPool,
	"AWS::Cognito::UserPoolClient":          translateCognitoUserPoolClient,
	"AWS::ECS::Service":                     translateECSService,
	"AWS::ECS::TaskDefinition":              translateECSTaskDefinition,
	"AWS::ECS::Cluster":                     translateECSCluster,
	"AWS::RDS::DBInstance":                  translateRDSDBInstance,
	"AWS::S3::Bucket":                       translateS3Bucket,
	"AWS::S3::BucketPolicy":                 translateS3BucketPolicy,
	"AWS::SQS::Queue":                       translateSQSQueue,
	"AWS::SNS::Topic":                       translateSNSTopic,
	"AWS::SNS::Subscription":                translateSNSSubscription,
	"AWS::AppSync::GraphQLApi":              translateAppSyncGraphQLApi,
	"AWS::AppSync::GraphQLSchema":           translateAppSyncChild,
	"AWS::AppSync::DataSource":              translateAppSyncChild,
	"AWS::AppSync::Resolver":                translateAppSyncChild,
	"AWS::AppSync::FunctionConfiguration":   translateAppSyncChild,
	// API Gateway REST v1: the whole API collates into one sentinel on its RestApi (#295); every other
	// AWS::ApiGateway::* type composes into it (translateAPIGatewayChild → nil, or blocks a dangling one).
	"AWS::ApiGateway::RestApi":          translateAPIGatewayRestAPI,
	"AWS::ApiGateway::Resource":         translateAPIGatewayChild,
	"AWS::ApiGateway::Method":           translateAPIGatewayChild,
	"AWS::ApiGateway::Model":            translateAPIGatewayChild,
	"AWS::ApiGateway::RequestValidator": translateAPIGatewayChild,
	"AWS::ApiGateway::Authorizer":       translateAPIGatewayChild,
	"AWS::ApiGateway::Deployment":       translateAPIGatewayChild,
	"AWS::ApiGateway::Stage":            translateAPIGatewayChild,
	"AWS::ApiGateway::ApiKey":           translateAPIGatewayChild,
	"AWS::ApiGateway::UsagePlan":        translateAPIGatewayChild,
	"AWS::ApiGateway::UsagePlanKey":     translateAPIGatewayChild,
	// CloudFront (narrow static-site subset, translate_cloudfront.go): the Distribution becomes a kind:
	// StaticSite; its access identities / policies / certificate compose into it.
	"AWS::CloudFront::Distribution":                   translateCloudFrontDistribution,
	"AWS::CloudFront::OriginAccessControl":            translateCloudFrontChild,
	"AWS::CloudFront::CloudFrontOriginAccessIdentity": translateCloudFrontChild,
	"AWS::CloudFront::ResponseHeadersPolicy":          translateCloudFrontChild,
	"AWS::CloudFront::CachePolicy":                    translateCloudFrontChild,
	"AWS::CloudFront::OriginRequestPolicy":            translateCloudFrontChild,
	"AWS::CertificateManager::Certificate":            translateACMCertificate,
	// A nested stack: a stack of its own, created by the front door's NestedStacks driver (nested_stacks.go).
	"AWS::CloudFormation::Stack": translateNestedStack,
}

// hasTranslator reports whether a type can be created (not merely planned).
// translatorFor returns the translator for a CFN type, routing any custom resource
// (AWS::CloudFormation::CustomResource or Custom::*) to translateCustomResource (#269), since those
// aren't exact keys in the registry. Returns nil when the type is not create-provisionable.
func translatorFor(cfnType string) translator {
	if t, ok := translators[cfnType]; ok {
		return t
	}
	if isCustomResourceType(cfnType) {
		return translateCustomResource
	}
	return nil
}

// isCustomResourceType reports whether a CFN type is a Lambda-backed custom resource.
func isCustomResourceType(cfnType string) bool {
	return cfnType == "AWS::CloudFormation::CustomResource" || strings.HasPrefix(cfnType, "Custom::")
}

func hasTranslator(cfnType string) bool { return translatorFor(cfnType) != nil }

// A custom resource does not translate to a k8s object — it translates to this sentinel manifest, which
// the deploy loop recognizes (never applies as an object) and turns into a synchronous Function invoke.
const (
	customResourceAPIVersion = "cfn.openinfra.dev/v1"
	customResourceKind       = "CustomResourceInvoke"
)

// translateCustomResource handles a Lambda-backed custom resource (#269). Fail-closed: ServiceToken must
// !Ref/!GetAtt an in-stack AWS::Lambda::Function — an out-of-stack / AWS-ARN ServiceToken has no invoke
// target on open-infra. The sentinel manifest carries the backing Function name, the CFN resource type,
// and the (resolved) ResourceProperties the handler receives.
func translateCustomResource(logicalID string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	fin := func(msg string) []Finding { return []Finding{{"Resource " + logicalID, msg}} }
	if ctx == nil {
		return nil, fin("a custom resource needs stack context to resolve its ServiceToken")
	}
	raw, ok := ctx.rawProps(logicalID)
	if !ok {
		return nil, fin("custom resource has no properties")
	}
	stRaw, hasST := raw["ServiceToken"]
	if !hasST {
		return nil, fin("a custom resource requires a ServiceToken")
	}
	fnID, ok := getAttTarget(stRaw)
	if !ok || !ctx.isType(fnID, "AWS::Lambda::Function") {
		return nil, fin("ServiceToken must !Ref or !GetAtt an in-stack AWS::Lambda::Function — an out-of-stack or AWS-ARN ServiceToken has no invoke target on open-infra (author the handler as a kind: Function in this stack)")
	}
	// ResourceProperties = the resolved properties minus ServiceToken (what AWS passes to the handler).
	rp := map[string]any{}
	for k, v := range props {
		if k == "ServiceToken" {
			continue
		}
		rp[k] = v
	}
	return &Manifest{
		APIVersion: customResourceAPIVersion,
		Kind:       customResourceKind,
		Name:       ctx.name(logicalID),
		Spec: map[string]any{
			"function":     ctx.functionName(fnID),
			"resourceType": ctx.template.Resources[logicalID].Type,
			"properties":   rp,
		},
	}, nil
}

// ---- AWS::KMS::Key -> kind: EncryptionKey ----
//
// Faithful: Description, EnableKeyRotation (-> rotationDays), KeySpec (-> keyType).
// Declared caveat: KeyPolicy (Vault-managed key; access is governed by open-infra IAM, not a
// per-key policy). Anything else blocks.
func translateKMSKey(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"Description": true, "EnableKeyRotation": true, "KeySpec": true, "KeyPolicy": true, "Enabled": true, "Tags": true}
	served := ctx.servedBy(id) // the key is also a key in the KMS API's store (service.go)
	if served {
		known["KeyUsage"], known["PendingWindowInDays"], known["MultiRegion"] = true, true, true
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	f = append(f, shapeFindings(id, props, nil, nil, []string{"KeySpec"})...)

	spec := map[string]any{}
	if d, ok := concrete(props["Description"]); ok && d != "" {
		spec["description"] = d
	}
	rot, ff := boolProp(id, props, "EnableKeyRotation", false)
	f = append(f, ff...)
	if rot {
		spec["rotationDays"] = 365 // AWS annual rotation
	}
	// A disabled key cannot be used on AWS; a kind: EncryptionKey is always usable, so creating one would
	// grant what the template withheld.
	enabled, ff := boolProp(id, props, "Enabled", true)
	f = append(f, ff...)
	if !enabled {
		f = append(f, Finding{"Resource " + id, "Enabled: false (a disabled key) has no open-infra form — a kind: EncryptionKey is always usable; refusing rather than creating a usable key"})
	}
	if ks, ok := concrete(props["KeySpec"]); ok && ks != "" {
		switch ks {
		case "SYMMETRIC_DEFAULT":
			spec["keyType"] = "aes256-gcm96"
		case "RSA_4096":
			spec["keyType"] = "rsa-4096"
		default:
			f = append(f, Finding{"Resource " + id, "KMS KeySpec " + ks + " has no open-infra Vault Transit equivalent"})
		}
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: ctx.name(id), Spec: spec}
	if served {
		comp, cf := kmsKeyCompanion(id, props, ctx)
		f = append(f, cf...)
		if comp != nil {
			m.Extra = append(m.Extra, comp)
		}
		if _, ok := props["KeyPolicy"]; ok {
			m.Caveats = append(m.Caveats, "KMS KeyPolicy governs the key in the KMS API (as that front door enforces key policies); the volume-encryption key under it is governed by open-infra IAM")
		}
		return m, f
	}
	if _, ok := props["KeyPolicy"]; ok {
		m.Caveats = append(m.Caveats, "KMS KeyPolicy dropped — the key is Vault-managed; access is governed by open-infra IAM, not a per-key policy")
	}
	return m, f
}

// ---- AWS::Lambda::Function -> kind: Function ----
//
// open-infra Functions are CONTAINER images, so only a PackageType: Image Lambda translates
// faithfully. A zip/Runtime Lambda has no image to run and is refused.
// Faithful: Code.ImageUri (-> image), Environment.Variables (-> env), MemorySize (-> memory),
// Timeout (-> timeout). Declared caveat: Role (Functions connect via secrets/env, not an
// assumed IAM role). Zip packaging, VpcConfig, Layers, and the rest block.
//
// The Function is also the ANCHOR of the SNS-subscription collation (#113): it scans the stack for
// lambda SNS subscriptions (a standalone AWS::SNS::Subscription, or an inline Subscription on a topic)
// whose Endpoint resolves to THIS Function and whose topic is an in-stack AWS::SNS::Topic, and adds
// each subscribed topic's stream name to spec.queues — so the Function consumes the topic's JetStream
// stream directly (open-infra's "subscribe a consumer to the topic" mechanism, in place of SNS's
// push delivery). The subscription resource itself is then a no-op.
func translateLambdaFunction(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"Code": true, "PackageType": true, "Environment": true, "MemorySize": true,
		"Timeout": true, "Role": true, "FunctionName": true, "Description": true,
		"Architectures": true, "Tags": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	pkg, _ := concrete(props["PackageType"])
	if pkg != "Image" {
		f = append(f, Finding{"Resource " + id, "only a PackageType: Image Lambda maps to a Function; a zip/Runtime Lambda has no container image to run"})
	}
	spec := map[string]any{}
	code, _ := props["Code"].(map[string]any)
	if img, ok := concrete(code["ImageUri"]); ok && img != "" {
		spec["image"] = img
	} else {
		f = append(f, Finding{"Resource " + id, "Lambda Code.ImageUri is required and must be a concrete image reference"})
	}
	if mem, ok := props["MemorySize"]; ok {
		spec["memory"] = fmt.Sprintf("%dMi", toInt(mem))
	}
	if to, ok := props["Timeout"]; ok {
		spec["timeout"] = toInt(to)
	}
	if env := lambdaEnv(id, code, props, &f); len(env) > 0 {
		spec["env"] = env
	}
	// #113: fold every lambda SNS subscription targeting this Function into spec.queues.
	if ctx != nil {
		if qs := ctx.snsQueuesForFunction(id); len(qs) > 0 {
			spec["queues"] = qs
		}
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Function", Name: lambdaKindName(id, props, ctx), Spec: spec}
	if fn, ok := concrete(props["FunctionName"]); ok && fn != "" && fn != m.Name {
		m.Caveats = append(m.Caveats, fmt.Sprintf("FunctionName %q is not a valid open-infra Function name (lowercase letters, digits and hyphens, at most 63) — the Function is named %q, and Ref / Arn resolve to that name", fn, m.Name))
	}
	if _, ok := props["Role"]; ok {
		m.Caveats = append(m.Caveats, "Lambda Role dropped — open-infra Functions connect via injected secrets/env, they do not assume an IAM role")
	}
	if a, ok := props["Architectures"]; ok {
		if l, _ := a.([]any); len(l) != 1 || fmt.Sprint(l[0]) != "x86_64" {
			m.Caveats = append(m.Caveats, fmt.Sprintf("Architectures %v is not honored — the Function runs on the cluster's node architecture, so its image must support it", a))
		}
	}
	return m, f
}

// ---- AWS::StepFunctions::StateMachine -> kind: StateMachine ----
//
// open-infra's StateMachine runs the SAME Amazon States Language document you'd pass to
// aws_sfn_state_machine.definition — so the definition maps byte-for-byte. The one boundary is
// the Task "Resource" field: open-infra Tasks reference a Function as "function:<name>", whereas
// AWS uses a Lambda ARN. A definition carrying an AWS ARN (or an unresolved cross-resource ref
// to a sibling Lambda's Arn) is REFUSED rather than deployed-and-silently-broken — it would
// create a state machine that looks fine and fails at execution, the worst shape.
// Faithful: DefinitionString / Definition (-> definition), STANDARD type.
// Declared caveats: RoleArn, StateMachineName, Tags, Logging/Tracing (open-infra has its own).
func translateStateMachine(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"DefinitionString": true, "Definition": true, "RoleArn": true, "StateMachineName": true,
		"StateMachineType": true, "LoggingConfiguration": true, "TracingConfiguration": true,
		"Tags": true, "DefinitionS3Location": true, "DefinitionSubstitutions": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	f = append(f, shapeFindings(id, props, nil, nil, []string{"StateMachineType"})...)

	if _, ok := props["DefinitionS3Location"]; ok {
		f = append(f, Finding{"Resource " + id, "DefinitionS3Location is not translatable — the ASL must be inline (DefinitionString/Definition), not fetched from S3"})
	}
	if _, ok := props["DefinitionSubstitutions"]; ok {
		f = append(f, Finding{"Resource " + id, "DefinitionSubstitutions is not applied — provide a fully-resolved ASL definition rather than one with ${} substitutions"})
	}
	if t, ok := concrete(props["StateMachineType"]); ok && t != "" && t != "STANDARD" {
		f = append(f, Finding{"Resource " + id, "StateMachineType " + t + " is not supported — open-infra runs STANDARD-semantics workflows (EXPRESS has different execution/history semantics)"})
	}

	// Exactly one definition, as on AWS: with both, one would be silently ignored.
	if _, s := props["DefinitionString"]; s {
		if _, d := props["Definition"]; d {
			f = append(f, Finding{"Resource " + id, "both DefinitionString and Definition are set — set exactly one"})
		}
	}
	// Resolve the ASL definition from DefinitionString (a string) or Definition (an object).
	var def string
	if ds, ok := props["DefinitionString"]; ok {
		s, cok := concrete(ds)
		if !cok {
			f = append(f, Finding{"Resource " + id, "the ASL definition references cross-resource values with no open-infra equivalent (e.g. a sibling Lambda's ARN) — remap Task Resources to \"function:<name>\" and inline the definition"})
		}
		def = s
	} else if d, ok := props["Definition"].(map[string]any); ok {
		b, err := json.Marshal(d)
		if err != nil {
			f = append(f, Finding{"Resource " + id, "Definition object is not serializable to ASL JSON"})
		} else {
			def = string(b)
		}
	} else {
		f = append(f, Finding{"Resource " + id, "a state machine requires an inline ASL definition (DefinitionString or Definition)"})
	}

	// The fidelity boundary: an AWS ARN in the definition can't run on open-infra.
	if def != "" && strings.Contains(def, "arn:aws:") {
		f = append(f, Finding{"Resource " + id, "the ASL Task \"Resource\" fields are AWS ARNs (arn:aws:…) — open-infra Tasks reference a Function as \"function:<name>\"; remap them before deploying (refusing rather than deploying a workflow that fails at execution)"})
	}

	spec := map[string]any{}
	if def != "" {
		spec["definition"] = def
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "StateMachine", Name: ctx.name(id), Spec: spec}
	if n, ok := concrete(props["StateMachineName"]); ok && n != "" && n != m.Name {
		m.Caveats = append(m.Caveats, fmt.Sprintf("StateMachineName %q is not used — the state machine is kind: StateMachine %q", n, m.Name))
	}
	if _, ok := props["RoleArn"]; ok {
		m.Caveats = append(m.Caveats, "RoleArn dropped — the open-infra StateMachine controller invokes Functions directly, it does not assume an IAM role")
	}
	if _, ok := props["LoggingConfiguration"]; ok {
		m.Caveats = append(m.Caveats, "LoggingConfiguration dropped — execution logging is via open-infra's own observability (Loki), not per-machine config")
	}
	if _, ok := props["TracingConfiguration"]; ok {
		m.Caveats = append(m.Caveats, "TracingConfiguration dropped — tracing is via open-infra's OTel/Tempo pipeline")
	}
	return m, f
}

// ---- AWS::EC2::Volume -> kind: Volume ----
//
// A Longhorn block volume. Size maps directly; MultiAttach maps to shared (RWX). Encryption maps:
// Encrypted -> a LUKS volume (longhorn-encrypted) keyed by a customer kind: EncryptionKey, which
// KmsKeyId must reference (an in-stack AWS::KMS::Key). AWS's storage-class/perf knobs (VolumeType,
// Iops, Throughput) and AvailabilityZone have no open-infra counterpart (one flat cluster) and are
// inert caveats. Restoring from an AWS SnapshotId is behavior-bearing with no faithful form and blocks.
func translateVolume(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"Size": true, "AvailabilityZone": true, "VolumeType": true, "Iops": true,
		"Throughput": true, "Encrypted": true, "KmsKeyId": true, "SnapshotId": true,
		"MultiAttachEnabled": true, "Tags": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	spec := map[string]any{}
	if sz, ok := props["Size"]; ok {
		spec["size"] = fmt.Sprintf("%dGi", toInt(sz))
	} else {
		f = append(f, Finding{"Resource " + id, "Size is required to create a Volume"})
	}
	multi, ff := boolProp(id, props, "MultiAttachEnabled", false)
	f = append(f, ff...)
	if multi {
		spec["shared"] = true
	}
	// Encryption: open-infra encrypts with a CUSTOMER key (kind: EncryptionKey / Vault Transit). A
	// KmsKeyId that !Refs an in-stack AWS::KMS::Key maps to that key. A KmsKeyId that does NOT map (an
	// ARN/alias to an out-of-stack or AWS-managed key) still refuses — we can't fabricate a specific
	// external key. But Encrypted with NO KmsKeyId uses the per-namespace default key (below), the way
	// AWS uses the account-default aws/ebs key.
	encrypted, ff := boolProp(id, props, "Encrypted", false) // CloudFormation accepts true or "true"
	f = append(f, ff...)
	_, hasKms := props["KmsKeyId"]
	needDefaultKey := false
	if encrypted || hasKms {
		spec["encrypted"] = true
		var kid string
		if ctx != nil {
			if raw, ok := ctx.rawProps(id); ok {
				if t, ok := getAttTarget(raw["KmsKeyId"]); ok {
					if k, in := ctx.template.Resources[t]; in && k.Type == "AWS::KMS::Key" {
						kid = t
					}
				}
			}
		}
		switch {
		case kid != "":
			spec["encryptionKey"] = ctx.name(kid)
		case hasKms:
			f = append(f, Finding{"Resource " + id, "KmsKeyId must reference an in-stack AWS::KMS::Key — open-infra keys volumes with a customer kind: EncryptionKey (via that KMS key); an ARN/alias to an out-of-stack or AWS-managed key has no mappable equivalent. Omit KmsKeyId to use the per-namespace default key."})
		default:
			// #347 Phase 1.7 (#344 4.2): Encrypted with NO KmsKeyId — AWS keys it with the account-default
			// aws/ebs key; open-infra keys it with the stack's default kind: EncryptionKey, created on
			// first use (emitted as a companion below).
			spec["encryptionKey"] = ctx.defaultEBSKey().Name
			needDefaultKey = true
		}
	}
	if _, ok := props["SnapshotId"]; ok {
		f = append(f, Finding{"Resource " + id, "SnapshotId is not translatable — an AWS EBS snapshot id has no open-infra VolumeSnapshot equivalent to restore from"})
	}

	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Volume", Name: ctx.name(id), Spec: spec}
	if needDefaultKey {
		k := ctx.defaultEBSKey()
		m.Extra = append(m.Extra, k)
		m.Caveats = append(m.Caveats, "Encrypted with no KmsKeyId — keyed by the stack's default kind: EncryptionKey \""+k.Name+"\" (the open-infra analog of AWS's account-default aws/ebs key), created on first use")
	}
	// #114 (Part 2, disproven): VolumeType/Iops/Throughput INTENT does not map to a Longhorn setting.
	// Longhorn is replica-based distributed storage; it provisions durability (replica count), not
	// IOPS. Mapping an AWS IOPS number onto a Longhorn knob and calling it equivalent would fabricate
	// a performance contract the substrate can't hold — forbidden by the honesty rail. So it stays
	// explicitly unmapped: Size and Encrypted map faithfully; the perf/AZ knobs are inert caveats.
	for _, p := range []string{"AvailabilityZone", "VolumeType", "Iops", "Throughput"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — Longhorn provides replica-based durability, not provisioned IOPS / EBS volume-types; the perf number stays unmapped (mapping it would imply a guarantee the substrate can't hold). AZ has no equivalent on one flat cluster.")
		}
	}
	return m, f
}

// defaultEBSKeyName is the default kind: EncryptionKey's name stem. An Encrypted EBS disk with NO
// KmsKeyId is keyed by its stack's default key — the open-infra analog of AWS's account-default aws/ebs
// key (#347 Phase 1.7 / #344 4.2), created on first use (emitted as a companion).
//
// The key is the stack's own (<stack>-ebs-default), not one key for every stack in the namespace: every
// caller's stacks share the CloudFormation namespace, so a shared key would let one caller's crypto-erase
// (kind: Destruction of the key) erase every other caller's default-encrypted disks. A stack created
// while the key was shared keeps using the shared "ebs-default" (its disks are keyed by it).
const defaultEBSKeyName = "ebs-default"

// defaultEBSEncryptionKey is the shared companion kind: EncryptionKey that stacks created before per-stack
// default keys use. Annual rotation, mirroring AWS default-key behavior.
func defaultEBSEncryptionKey() *Manifest {
	return &Manifest{
		APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: defaultEBSKeyName,
		Spec: map[string]any{
			"description":  "default data-disk encryption key — open-infra analog of AWS aws/ebs; created on first use for an Encrypted volume/disk with no KmsKeyId",
			"rotationDays": 365,
		},
		// SHARED, namespace-scoped singleton: other stacks' disks in the same namespace key on this
		// same object. Retain so a stack destroy/update/rollback never deletes a key a sibling still
		// uses (it is create-if-absent on next use). Deleting the kind: EncryptionKey wouldn't erase
		// the Vault transit key anyway (that is the separate kind: Destruction path) — it would just
		// strand every disk that references it until re-created. #347 review item 3.
		DeletionPolicy: "Retain",
		Shared:         true,
	}
}

// defaultSecurityGroup is the stack's default kind: SecurityGroup — the open-infra analog of a VPC's default
// group, which an instance that names no group gets: inbound (TCP and UDP, every port) only from the group's
// own members, and all outbound (no egress rules). Every such instance of the stack shares it.
func (c *stackCtx) defaultSecurityGroup() *Manifest {
	name := "vpc-default"
	if c != nil && c.namer != nil {
		name = stackQualifiedName(c.namer.stack, name)
	}
	self := []any{map[string]any{"securityGroup": name}}
	return &Manifest{
		APIVersion: "openinfra.dev/v1", Kind: "SecurityGroup", Name: name,
		Spec: map[string]any{"ingress": []any{
			map[string]any{"protocol": "TCP", "from": self, "description": "the default group: its own members"},
			map[string]any{"protocol": "UDP", "from": self, "description": "the default group: its own members"},
		}},
		Shared: true,
	}
}

// defaultEBSKey is the default kind: EncryptionKey an Encrypted-without-KmsKeyId disk of this stack is
// keyed by: the stack's own key, or the shared one for a stack that already uses it. The stack's own key
// is deleted with the stack unless a disk resource of the stack is retained (it keys that disk).
func (c *stackCtx) defaultEBSKey() *Manifest {
	if c == nil || c.namer == nil || c.namer.legacyDefaultKey {
		return defaultEBSEncryptionKey()
	}
	policy := "Delete"
	for id, r := range c.template.Resources {
		if (r.Type == "AWS::EC2::Volume" || r.Type == "AWS::EC2::Instance") && c.included(r) &&
			(isRetain(StackResource{DeletionPolicy: r.DeletionPolicy}) || strings.EqualFold(r.DeletionPolicy, "Snapshot")) {
			policy = "Retain"
		}
		// A volume kept past its instance (DeleteOnTermination: false) is keyed by it too.
		if r.Type == "AWS::EC2::Instance" && c.included(r) && c.keepsDefaultKeyedVolume(id) {
			policy = "Retain"
		}
	}
	return &Manifest{
		// Named around a key an earlier stack of this name retained (for a disk it kept): that key keys
		// the kept disk, and this stack's own key is a new one.
		APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: c.namer.fresh("\x00"+defaultEBSKeyName, stackQualifiedName(c.namer.stack, defaultEBSKeyName), maxPhysNameLen),
		Spec: map[string]any{
			"description":  "the stack's default data-disk encryption key — open-infra analog of AWS aws/ebs; created on first use for an Encrypted volume/disk with no KmsKeyId",
			"rotationDays": 365,
		},
		DeletionPolicy: policy,
	}
}

// ebsEncryptionKey resolves an encrypted EBS block's KmsKeyId — which must !Ref an in-stack
// AWS::KMS::Key — to that key's kind: EncryptionKey name. ok=false means a KmsKeyId was given but does
// not map to an in-stack key. The no-KmsKeyId default-key case is handled by the caller (it needs no
// stack resolution), the way AWS uses the account-default aws/ebs key (#347 Phase 1.7).
// awsDataDeviceRE is an AWS data-volume device name the guest can be given as an alias (/dev/sdf,
// /dev/xvdf, /dev/sdba): the kind: VirtualMachine deviceName pattern.
var awsDataDeviceRE = regexp.MustCompile(`^/dev/(sd|xvd)[a-z]{1,2}$`)

func ebsEncryptionKey(rawEbs any, ctx *stackCtx) (string, bool) {
	ebs, _ := rawEbs.(map[string]any)
	if ebs == nil || ctx == nil {
		return "", false
	}
	if t, ok := getAttTarget(ebs["KmsKeyId"]); ok {
		if k, in := ctx.template.Resources[t]; in && k.Type == "AWS::KMS::Key" {
			return ctx.name(t), true
		}
	}
	return "", false
}

// ---- AWS::EC2::Instance -> kind: VirtualMachine ----
//
// Translated the way CloudFormation does, with ONE honest substitution (#115): the ImageId names an
// open-infra catalog OS in place of the AMI, because a raw ami- id is an opaque, region/time-specific
// pointer into Amazon's private catalog that cannot be decoded. A well-known public image
// SSM-parameter path (which carries a human-readable OS) IS recognized and mapped; a raw ami- id, or
// an OS not in the catalog, refuses with a message that names what IS available. InstanceType maps to
// a CPU/memory shape (same discipline as RDS #114). Network fields (subnet/security-groups) are the
// deferred half and surface a SECURITY caveat, not a silent drop.

// ec2InstanceTypes maps common EC2 instance types to a VirtualMachine CPU/memory shape: the type's
// published vCPU/RAM. Burst credits (t-family) are not modelled — a burstable type gets its full vCPU.
// A type not listed surfaces a caveat and the VM uses its default shape (never a guess).
var ec2InstanceTypes = map[string]struct {
	cpu int
	mem string
}{
	// burstable (t2 / t3 / t3a)
	"t3.nano": {2, "512Mi"}, "t3a.nano": {2, "512Mi"},
	"t2.micro": {1, "1Gi"}, "t3.micro": {2, "1Gi"}, "t3a.micro": {2, "1Gi"},
	"t2.small": {1, "2Gi"}, "t3.small": {2, "2Gi"}, "t3a.small": {2, "2Gi"},
	"t2.medium": {2, "4Gi"}, "t3.medium": {2, "4Gi"}, "t3a.medium": {2, "4Gi"},
	"t2.large": {2, "8Gi"}, "t3.large": {2, "8Gi"}, "t3a.large": {2, "8Gi"},
	"t2.xlarge": {4, "16Gi"}, "t3.xlarge": {4, "16Gi"}, "t3a.xlarge": {4, "16Gi"},
	"t2.2xlarge": {8, "32Gi"}, "t3.2xlarge": {8, "32Gi"}, "t3a.2xlarge": {8, "32Gi"},
	// general purpose (m5 / m6i / m6a)
	"m5.large": {2, "8Gi"}, "m6i.large": {2, "8Gi"}, "m6a.large": {2, "8Gi"},
	"m5.xlarge": {4, "16Gi"}, "m6i.xlarge": {4, "16Gi"}, "m6a.xlarge": {4, "16Gi"},
	"m5.2xlarge": {8, "32Gi"}, "m6i.2xlarge": {8, "32Gi"}, "m6a.2xlarge": {8, "32Gi"},
	"m5.4xlarge": {16, "64Gi"}, "m6i.4xlarge": {16, "64Gi"}, "m6a.4xlarge": {16, "64Gi"},
	// compute optimized (c5 / c6i) — 2 GiB/vCPU
	"c5.large": {2, "4Gi"}, "c6i.large": {2, "4Gi"},
	"c5.xlarge": {4, "8Gi"}, "c6i.xlarge": {4, "8Gi"},
	"c5.2xlarge": {8, "16Gi"}, "c6i.2xlarge": {8, "16Gi"},
	"c5.4xlarge": {16, "32Gi"}, "c6i.4xlarge": {16, "32Gi"},
	// memory optimized (r5 / r6i) — 8 GiB/vCPU
	"r5.large": {2, "16Gi"}, "r6i.large": {2, "16Gi"},
	"r5.xlarge": {4, "32Gi"}, "r6i.xlarge": {4, "32Gi"},
	"r5.2xlarge": {8, "64Gi"}, "r6i.2xlarge": {8, "64Gi"},
}

// ec2CatalogOSes MUST stay in sync with vm-xrd.yaml's os enum and vm-composition.yaml's $catalog
// (the XRD comment warns these three must match).
var ec2CatalogOSes = []string{
	"ubuntu-24.04", "ubuntu-22.04", "fedora-40", "debian-12", "centos-stream-9",
	"windows-server-2019", "windows-server-2022", "windows-server-2025",
}

// ssmImagePaths recognizes well-known PUBLIC image SSM-parameter path fragments (the resolved
// ImageId value in sophisticated templates) and maps them to a catalog OS. A raw ami- id stays
// opaque; the SSM path carries a human-readable OS, so it can translate rather than refuse (#115).
var ssmImagePaths = []struct{ frag, os string }{
	{"ubuntu/server/24.04", "ubuntu-24.04"},
	{"ubuntu/server/22.04", "ubuntu-22.04"},
	{"debian/release/12", "debian-12"},
	{"debian/release/bookworm", "debian-12"},
	{"fedora", "fedora-40"},
	{"centos-stream-9", "centos-stream-9"},
	{"windows_server-2019", "windows-server-2019"},
	{"windows_server-2022", "windows-server-2022"},
	{"windows_server-2025", "windows-server-2025"},
}

// resolveEC2Image maps a template ImageId to a catalog OS. It accepts a catalog OS name directly, or
// a recognizable public image SSM-parameter path. Returns (os, "") on success, or ("", reason) where
// reason is "ami" (opaque raw id) or "unknown" (no catalog/SSM match).
func resolveEC2Image(imageID string) (os, reason string) {
	v := strings.TrimSpace(imageID)
	lc := strings.ToLower(v)
	for _, c := range ec2CatalogOSes {
		if lc == c {
			return c, ""
		}
	}
	if strings.HasPrefix(lc, "ami-") {
		if c := catalogOSForImageID(lc); c != "" {
			return c, "" // a catalog OS's own image id (ec2 describe-images; the guest's ami-id)
		}
		return "", "ami"
	}
	for _, p := range ssmImagePaths {
		if strings.Contains(lc, p.frag) {
			return p.os, ""
		}
	}
	return "", "unknown"
}

// resolveSubnetRef maps an AWS subnet reference to an open-infra kind: Subnet name (#120). Like an
// AMI, a raw subnet- id is opaque and refuses; a !Ref to an in-stack AWS::EC2::Subnet uses that
// resource's name (AWS::EC2::Subnet translation, Phase 3, provisions the matching kind: Subnet); a
// plain string is taken as a kind: Subnet name (substitution). Returns (name, reason) where reason is
// "raw" (opaque id), "unresolved" (an intrinsic we can't resolve), or "" on success.
func resolveSubnetRef(id, prop string, props map[string]any, ctx *stackCtx) (string, string) {
	if ctx != nil {
		if raw, ok := ctx.rawProps(id); ok {
			if t, ok := refTarget(raw[prop]); ok {
				if r, in := ctx.template.Resources[t]; in && r.Type == "AWS::EC2::Subnet" {
					return ctx.name(t), ""
				}
			}
		}
	}
	if v, ok := concrete(props[prop]); ok && v != "" {
		if strings.HasPrefix(strings.ToLower(v), "subnet-") {
			return "", "raw"
		}
		return v, ""
	}
	return "", "unresolved"
}

// listEntries returns the entries of a list-valued property. A literal list is returned as written (raw,
// so an in-stack !Ref in it can still be followed); a list-level Fn::If is followed to the branch its
// condition picks, still raw; anything else (a !Ref to a List or CommaDelimitedList parameter,
// Fn::Split, Fn::ImportValue) is resolved to its values. Unset or AWS::NoValue is an empty list.
// ok=false means the property is set but is not a list: callers refuse it rather than read it as empty.
func listEntries(raw any, ctx *stackCtx) (entries []any, ok bool) {
	switch v := raw.(type) {
	case nil:
		return nil, true
	case []any:
		return v, true
	case map[string]any:
		if len(v) == 1 {
			if args, isIf := v["Fn::If"].([]any); isIf && len(args) == 3 && ctx != nil && ctx.resolver != nil {
				if ctx.resolver.conds[fmt.Sprint(args[0])] {
					return listEntries(args[1], ctx)
				}
				return listEntries(args[2], ctx)
			}
			if ref, isRef := v["Ref"].(string); isRef && ref == "AWS::NoValue" {
				return nil, true
			}
		}
	}
	if ctx == nil {
		return nil, false
	}
	switch l := ctx.resolveVal(raw).(type) {
	case nil:
		return nil, true
	case []any:
		return l, true
	case []string: // Fn::Split
		out := make([]any, 0, len(l))
		for _, s := range l {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, true
	case string:
		// A List<…> / CommaDelimitedList parameter's Ref resolves to its comma-separated value.
		if p, isRef := refTarget(raw); isRef && isListParam(ctx.template, p) {
			var out []any
			for _, s := range strings.Split(l, ",") {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
			return out, true
		}
	}
	return nil, false
}

// isListParam reports whether template parameter name is list-typed (its Ref is a list on AWS).
func isListParam(t *Template, name string) bool {
	if t == nil {
		return false
	}
	p, ok := t.Parameters[name]
	if !ok {
		return false
	}
	return p.Type == "CommaDelimitedList" || strings.HasPrefix(p.Type, "List<") ||
		strings.Contains(p.Type, "<List<")
}

// sgRefName resolves ONE security-group reference (a RAW, pre-resolution value) to a kind:
// SecurityGroup name: a {Ref: X} / {Fn::GetAtt: [X, GroupId]} to an in-stack AWS::EC2::SecurityGroup
// → its kind name (AWS::EC2::SecurityGroup translates to a matching kind: SecurityGroup); a plain string
// name → itself (substitution); a raw sg- id → ("", raw=true) so the caller can refuse it like an
// AMI/subnet id. A {Ref} to something that is not an in-stack SG → ("", false): skipped, not fatal.
func sgRefName(rawVal any, ctx *stackCtx) (name string, raw bool) {
	if t, ok := getAttTarget(rawVal); ok { // handles {Ref: X} and {Fn::GetAtt: [X, GroupId]}
		if ctx != nil {
			if r, in := ctx.template.Resources[t]; in && r.Type == "AWS::EC2::SecurityGroup" {
				return ctx.name(t), false
			}
		}
		return "", false
	}
	if s, ok := concrete(rawVal); ok && s != "" {
		if strings.HasPrefix(strings.ToLower(s), "sg-") {
			return "", true
		}
		return s, false
	}
	return "", false
}

// resolveSGList resolves a list-valued security-group property (SecurityGroupIds, SecurityGroups, or a
// NetworkInterface GroupSet) from a raw property list to kind: SecurityGroup names. A raw sg- id in
// the list is a blocking Finding (opaque, like an AMI); in-stack !Refs and plain names map. An entry
// that is not a direct in-stack SG !Ref is RESOLVED — a parameter (or Fn::ImportValue) whose value names
// a kind: SecurityGroup (the cross-stack case, as an SG rule's SourceSecurityGroupId does), or an
// intrinsic (!If) wrapping an in-stack SG reference; AWS::NoValue drops it. An entry that still names no
// SecurityGroup REFUSES: silently launching the VM without a firewall attachment the template declared
// is fail-open.
func resolveSGList(id, label string, rawList any, ctx *stackCtx) (names []string, findings []Finding) {
	list, ok := listEntries(rawList, ctx)
	if !ok {
		return nil, []Finding{{"Resource " + id,
			label + " does not resolve to a list of security groups — refusing rather than launching the VM without the firewall attachment it declares"}}
	}
	for _, entry := range list {
		n, isRaw := sgRefName(entry, ctx)
		if n == "" && !isRaw && ctx != nil {
			rv := ctx.resolveVal(entry)
			if rv == nil {
				continue // AWS::NoValue (e.g. via Fn::If) removes the entry
			}
			if t, ok := placeholderTarget(rv); ok && ctx.isType(t, "AWS::EC2::SecurityGroup") {
				n = ctx.name(t)
			} else {
				n, isRaw = sgRefName(rv, ctx)
			}
		}
		if isRaw {
			findings = append(findings, Finding{"Resource " + id,
				label + " contains a raw AWS security-group id (opaque) — reference an in-stack AWS::EC2::SecurityGroup or name a kind: SecurityGroup"})
			continue
		}
		if n == "" {
			findings = append(findings, Finding{"Resource " + id,
				label + " contains an entry that resolves to no kind: SecurityGroup (it must !Ref an in-stack AWS::EC2::SecurityGroup, or be a parameter/import naming one) — refusing rather than launching the VM without that firewall attachment"})
			continue
		}
		names = append(names, n)
	}
	return names, findings
}

func translateEC2Instance(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"ImageId": true, "InstanceType": true, "KeyName": true, "UserData": true,
		"BlockDeviceMappings": true, "SecurityGroupIds": true, "SecurityGroups": true,
		"SubnetId": true, "NetworkInterfaces": true, "Tags": true, "AvailabilityZone": true,
		"Monitoring": true, "EbsOptimized": true, "IamInstanceProfile": true,
		"PrivateIpAddress": true, "SourceDestCheck": true, "DisableApiTermination": true,
		"MetadataOptions": true,
	}
	var f []Finding
	var cav []string
	vmNeedDefaultKey := false // #347 Phase 1.7: an encrypted data disk with no KmsKeyId used the default key
	var keptVols []*Manifest  // data volumes that outlive the instance (DeleteOnTermination: false)
	var keptAttach []any      // ... and their spec.volumes entries
	f = append(f, blockUnknownProps(id, props, known)...)
	f = append(f, shapeFindings(id, props, []string{"BlockDeviceMappings"}, []string{"MetadataOptions"}, []string{"InstanceType"})...)

	spec := map[string]any{}

	// --- ImageId -> a catalog OS (the honest substitution) ---
	if imageID, ok := concrete(props["ImageId"]); ok && imageID != "" {
		switch os, reason := resolveEC2Image(imageID); {
		case os != "":
			spec["os"] = os
		case reason == "ami":
			f = append(f, Finding{"Resource " + id, "ImageId " + imageID + " is a raw AMI id — an opaque, region/time-specific pointer into Amazon's catalog that open-infra cannot decode. Name a catalog OS instead: " + strings.Join(ec2CatalogOSes, ", ")})
		default:
			f = append(f, Finding{"Resource " + id, "ImageId " + imageID + " matches no catalog OS or recognized public image SSM-parameter path. Available catalog OSes: " + strings.Join(ec2CatalogOSes, ", ")})
		}
	} else if _, present := props["ImageId"]; present {
		f = append(f, Finding{"Resource " + id, "ImageId could not be resolved (an unresolvable intrinsic) — name a catalog OS literally: " + strings.Join(ec2CatalogOSes, ", ")})
	} else {
		f = append(f, Finding{"Resource " + id, "ImageId is required — name an open-infra catalog OS in place of the AMI: " + strings.Join(ec2CatalogOSes, ", ")})
	}

	// --- InstanceType -> CPU/memory shape ---
	if it, ok := concrete(props["InstanceType"]); ok && it != "" {
		if shape, in := ec2InstanceTypes[strings.ToLower(it)]; in {
			spec["cpu"] = shape.cpu
			spec["memory"] = shape.mem
		} else {
			f = append(f, Finding{"Resource " + id, "InstanceType " + it + " is not in the mapping table — the VM uses its default shape (2 vCPU / 2Gi); map a known type or set cpu/memory natively"})
		}
	}

	// --- KeyName: the key pair's public key, from the environment's key pairs (ec2 import-key-pair) ---
	if _, ok := props["KeyName"]; ok {
		f, cav = ec2KeyName(id, props, ctx, spec, f, cav)
	}

	// --- UserData -> cloud-init (#! script form; a #cloud-config isn't merged) ---
	if ud, ok := concrete(props["UserData"]); ok && ud != "" {
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ud)); err == nil {
			s := strings.TrimSpace(string(dec))
			switch {
			case strings.HasPrefix(s, "#cloud-config"):
				cav = append(cav, "UserData is a #cloud-config document — open-infra can't safely merge it with the base VM cloud-init; it was NOT applied. Supply a #! script (run at first boot) or configure the VM natively")
			case strings.HasPrefix(s, "#!"):
				spec["userData"] = s
			default:
				spec["userData"] = "#!/bin/sh\n" + s
			}
		} else {
			f = append(f, Finding{"Resource " + id, "UserData is not valid base64 — CloudFormation UserData must be base64-encoded"})
		}
	} else if _, present := props["UserData"]; present {
		raw, _ := ctx.rawProps(id)
		if eip := ctx.unknownEIPAddressIn(raw["UserData"]); eip != "" {
			if ctx.resolver != nil && ctx.resolver.addressOf != nil {
				// The create or update could not get the address: never boot the instance without the
				// script that embeds it.
				f = append(f, Finding{"Resource " + id, "UserData embeds Elastic IP " + eip + "'s address, which is not known when this instance is created: the address is assigned when the EIP's allocation is created, and an update can embed it only once the stack holds the allocation (add the EIP in one update, and embed it in the next)"})
			} else {
				// A plan or change set: the create fills the address in (the EIP's allocation is created first).
				cav = append(cav, "UserData embeds Elastic IP "+eip+"'s address: the EIP is allocated before this instance is created, and the address is filled in then, as on AWS")
			}
		} else {
			cav = append(cav, "UserData could not be statically resolved (Fn::Sub/Fn::Base64 over references) — it was NOT applied; provide literal user data or configure the VM natively")
		}
	}

	// --- BlockDeviceMappings: root device size -> diskSize; extra EBS devices -> spec.dataDisks ---
	// As on AWS, a mapping overrides the ROOT volume only when its DeviceName is the image's root device
	// (/dev/sda1, /dev/xvda, …); any other DeviceName (/dev/sdf, /dev/xvdb, …) attaches an additional
	// volume, whatever its position in the list. The root mapping sets diskSize. Every other
	// EBS device becomes a boot-time data disk (spec.dataDisks), named from its DeviceName so it is
	// recognizable. An Encrypted data device maps to a LUKS (longhorn-encrypted) disk keyed by a
	// customer kind: EncryptionKey — KmsKeyId must reference an in-stack AWS::KMS::Key (same contract as
	// EC2::Volume); Encrypted without a mappable key REFUSES rather than silently dropping the guarantee.
	if bdms, ok := props["BlockDeviceMappings"].([]any); ok {
		// Raw BlockDeviceMappings so an Ebs.KmsKeyId !Ref can be followed to an in-stack KMS key.
		var rawBDMs []any
		if ctx != nil {
			if rp, ok := ctx.rawProps(id); ok {
				rawBDMs, _ = rp["BlockDeviceMappings"].([]any)
			}
		}
		rootDevNames := ec2RootDeviceNames
		// The root index is the mapping that names the root device; with none, every mapping is a data disk
		// and the root keeps the image's default size.
		rootIdx := -1
		for i, raw := range bdms {
			bdm, _ := raw.(map[string]any)
			if dn, _ := concrete(bdm["DeviceName"]); rootDevNames[dn] {
				rootIdx = i
				break
			}
		}
		var dataDisks []map[string]any
		mappedExtraDevName := false
		for i, raw := range bdms {
			bdm, _ := raw.(map[string]any)
			if bdm == nil {
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("BlockDeviceMappings[%d] does not resolve to a mapping — refusing rather than launching the VM without the disk it declares", i)})
				continue
			}
			f = append(f, blockUnknownProps(fmt.Sprintf("%s.BlockDeviceMappings[%d]", id, i), bdm, bdmKnown)...)
			if bdm["Ebs"] != nil && (bdm["NoDevice"] != nil || bdm["VirtualName"] != nil) {
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("BlockDeviceMappings[%d] names an EBS volume and also NoDevice or VirtualName (an instance store) — one mapping is one of them; refusing rather than guessing which", i)})
				continue
			}
			ebs, _ := bdm["Ebs"].(map[string]any)
			if ebs == nil {
				cav = append(cav, "a BlockDeviceMapping without an Ebs block was dropped (ephemeral/NoDevice has no open-infra equivalent)")
				continue
			}
			f = append(f, blockUnknownProps(fmt.Sprintf("%s.BlockDeviceMappings[%d].Ebs", id, i), ebs, ebsKnown)...)
			ebsBool := func(k string) bool {
				v, present := ebs[k]
				if !present || v == nil {
					return false
				}
				b, ok := cfnBoolValue(v)
				if !ok {
					f = append(f, Finding{"Resource " + id, fmt.Sprintf("BlockDeviceMappings[%d].Ebs.%s must be true or false (got %v)", i, k, v)})
				}
				return b
			}
			if _, has := ebs["SnapshotId"]; has {
				// A volume restored from an EBS snapshot: open-infra has no snapshot to restore from, and a
				// blank disk in its place would silently lose the data.
				f = append(f, Finding{"Resource " + id, "a BlockDeviceMapping's Ebs.SnapshotId does not map — open-infra cannot restore an EBS snapshot, and a blank disk in its place would lose its data"})
				continue
			}
			if i == rootIdx {
				// An Encrypted root -> spec.rootDisk: LUKS on longhorn-encrypted, keyed by a customer kind:
				// EncryptionKey exactly like an encrypted data disk (KmsKeyId must !Ref an in-stack
				// AWS::KMS::Key; none = the stack's default key, the aws/ebs analog). Never an unencrypted root.
				if enc, kms := ebsBool("Encrypted"), ebs["KmsKeyId"] != nil; enc || kms {
					key := ""
					if kms {
						var rawEbs any
						if i < len(rawBDMs) {
							if rb, _ := rawBDMs[i].(map[string]any); rb != nil {
								rawEbs = rb["Ebs"]
							}
						}
						k, ok := ebsEncryptionKey(rawEbs, ctx)
						if !ok {
							f = append(f, Finding{"Resource " + id, "the encrypted root BlockDeviceMapping's KmsKeyId must reference an in-stack AWS::KMS::Key — open-infra keys a VM's root disk with a customer kind: EncryptionKey (LUKS on longhorn-encrypted); an ARN/alias to an out-of-stack or AWS-managed key has no mappable equivalent. Omit KmsKeyId to use the stack's default key. Refusing rather than booting from an unencrypted root"})
							continue
						}
						key = k
					} else {
						key = ctx.defaultEBSKey().Name
						vmNeedDefaultKey = true
					}
					spec["rootDisk"] = map[string]any{"encrypted": true, "encryptionKey": key}
					cav = append(cav, "root disk: encrypted at rest with LUKS on longhorn-encrypted, keyed by kind: EncryptionKey "+key+" (destroying the key crypto-erases the disk). The OS image is copied onto it before first boot, so the instance starts a few minutes later than an unencrypted one, and the disk is RWO, so the VM does not live-migrate")
				}
				if vs, has := ebs["VolumeSize"]; has {
					spec["diskSize"] = fmt.Sprintf("%dGi", toInt(vs))
				}
				for _, p := range []string{"VolumeType", "Iops", "Throughput"} {
					if _, ok := ebs[p]; ok {
						cav = append(cav, "root disk: "+p+" dropped — a VM root disk is a StorageClass PVC, not provisioned-IOPS EBS")
					}
				}
				if _, ok := ebs["DeleteOnTermination"]; ok && !ebsBool("DeleteOnTermination") {
					cav = append(cav, "root disk: DeleteOnTermination=false does NOT map — the root disk is deleted with the VM")
				}
				continue
			}
			// A non-root EBS device -> a data disk. An Encrypted device -> a LUKS data disk keyed by a
			// customer kind: EncryptionKey (KmsKeyId must !Ref an in-stack AWS::KMS::Key).
			enc := ebsBool("Encrypted")
			_, hasKms := ebs["KmsKeyId"]
			var encKey string
			if enc || hasKms {
				if hasKms {
					var rawEbs any
					if i < len(rawBDMs) {
						if rb, _ := rawBDMs[i].(map[string]any); rb != nil {
							rawEbs = rb["Ebs"]
						}
					}
					k, ok := ebsEncryptionKey(rawEbs, ctx)
					if !ok {
						f = append(f, Finding{"Resource " + id, "an encrypted data BlockDeviceMapping's KmsKeyId must reference an in-stack AWS::KMS::Key — open-infra keys a VM data disk with a customer kind: EncryptionKey (LUKS on longhorn-encrypted); an ARN/alias to an out-of-stack or AWS-managed key has no mappable equivalent. Omit KmsKeyId to use the per-namespace default key. NB an encrypted data disk is RWO, so on a highAvailability VM it pins live migration."})
						continue
					}
					encKey = k
				} else {
					// #347 Phase 1.7 (#344 4.2): Encrypted with NO KmsKeyId — the AWS account-default
					// aws/ebs key; open-infra keys it with the stack's default kind: EncryptionKey,
					// created on first use (companion emitted after the manifest is built).
					encKey = ctx.defaultEBSKey().Name
					vmNeedDefaultKey = true
				}
			}
			vs, has := ebs["VolumeSize"]
			if !has {
				f = append(f, Finding{"Resource " + id, "a data BlockDeviceMapping has no VolumeSize — a blank data disk needs an explicit size (a SnapshotId-only device has no open-infra source to restore from)"})
				continue
			}
			disk := map[string]any{"size": fmt.Sprintf("%dGi", toInt(vs))}
			if dn, _ := concrete(bdm["DeviceName"]); dn != "" {
				if nm := k8sName(strings.TrimPrefix(dn, "/dev/")); nm != "" {
					disk["name"] = nm
				}
				if awsDataDeviceRE.MatchString(dn) {
					disk["deviceName"] = dn
				}
			}
			if encKey != "" {
				disk["encrypted"] = true
				disk["encryptionKey"] = encKey
			}
			mappedExtraDevName = true
			// DeleteOnTermination: false -> the volume outlives the instance, as on AWS: a kind: Volume of
			// its own, attached to the VM (spec.volumes) and retained when the instance goes (a stack delete,
			// a rolled-back create, an update that removes the instance), then no longer the stack's. An
			// instance a stack already created with it as a data disk keeps that disk (re-deriving it
			// would replace the disk and lose its data).
			if _, ok := ebs["DeleteOnTermination"]; ok && !ebsBool("DeleteOnTermination") {
				nm, _ := disk["name"].(string)
				if nm == "" {
					nm = fmt.Sprintf("disk%d", i)
				}
				if !ctx.recordedDataDisk(id, nm) {
					kv := ctx.keptVolume(id, nm, disk)
					keptVols = append(keptVols, kv)
					att := map[string]any{"name": kv.Name}
					if dn, ok := disk["deviceName"]; ok {
						att["deviceName"] = dn
					}
					keptAttach = append(keptAttach, att)
					cav = append(cav, "data disk "+nm+": DeleteOnTermination=false — it is kind: Volume "+kv.Name+", attached to the VM and kept when the instance goes (a stack delete, a rolled-back create, an update that removes the instance), as AWS keeps the volume; it is then no longer part of the stack. It is attached after the instance's other data disks, so its Nitro name (/dev/nvme<n>n1) follows theirs")
					for _, p := range []string{"VolumeType", "Iops", "Throughput"} {
						if _, ok := ebs[p]; ok {
							cav = append(cav, "data disk "+nm+": "+p+" dropped — a volume is a StorageClass PVC (Longhorn), not provisioned-IOPS EBS")
						}
					}
					continue
				}
			}
			dataDisks = append(dataDisks, disk)
			// Perf/lifecycle knobs with no honest VM-disk equivalent (same as EC2::Volume).
			for _, p := range []string{"VolumeType", "Iops", "Throughput"} {
				if _, ok := ebs[p]; ok {
					cav = append(cav, "data disk "+fmt.Sprint(disk["name"])+": "+p+" dropped — a VM data disk is a StorageClass PVC (Longhorn/local-path), not provisioned-IOPS EBS")
				}
			}
			if _, ok := ebs["DeleteOnTermination"]; ok && !ebsBool("DeleteOnTermination") {
				cav = append(cav, "data disk "+fmt.Sprint(disk["name"])+": DeleteOnTermination=false does NOT map for this instance — the stack created it with the disk sharing the VM's lifecycle (it is deleted with the VM), and it keeps that disk rather than replace it")
			}
		}
		if len(dataDisks) > 0 {
			spec["dataDisks"] = dataDisks
		}
		if mappedExtraDevName {
			cav = append(cav, "DEVICE NAMES: the disks are virtio devices (/dev/vd*); the guest gets the AWS names as udev aliases of the right disk — the Nitro names (/dev/nvme0n1 the root, /dev/nvme1n1… the data disks in mapping order, then attached volumes, with their partitions) and each mapping's DeviceName with its sd/xvd twin (/dev/sdf and /dev/xvdf) — so a UserData script that formats/mounts by those paths runs unchanged. Tools that read the kernel name (lsblk, /proc/mounts) show /dev/vd*.")
		}
	}

	// SubnetId -> place the VM in a kind: Subnet with real OVN isolation (#120). A raw subnet- id is
	// opaque (refuse with help); a plain kind: Subnet name, or a !Ref to an in-stack AWS::EC2::Subnet, maps.
	if _, present := props["SubnetId"]; present {
		switch name, reason := resolveSubnetRef(id, "SubnetId", props, ctx); {
		case name != "":
			spec["subnet"] = name
		case reason == "raw":
			f = append(f, Finding{"Resource " + id, "SubnetId is a raw AWS subnet id (opaque, like an AMI) — name an open-infra kind: Subnet in its place, or reference an in-stack AWS::EC2::Subnet"})
		default:
			cav = append(cav, "SubnetId could not be resolved to a kind: Subnet — set the VM's subnet natively to place it in one")
		}
	}

	// --- Network wiring: security-group attachment, subnet placement, public reachability ---
	// Attach security groups to the VM and honor the primary NetworkInterface (DeviceIndex 0), rather
	// than dropping them as a security caveat. SG !Refs resolve to kind: SecurityGroup names
	// (spec.securityGroups); the NIC's SubnetId places the VM the same way a top-level SubnetId does;
	// AssociatePublicIpAddress maps to expose — a LAN-reachable IP, the nearest open-infra analog of
	// an auto-assigned public IP. A raw sg-/subnet- id in any of these is refused (opaque), like an AMI.
	var sgNames []string
	{
		// Prefer the RAW properties (so an in-stack {Ref: SG} / {Fn::GetAtt} is still visible); fall
		// back to the resolved props when there is no stack context (unit calls), where a concrete
		// name or an opaque sg- id is still actionable.
		var rawP map[string]any
		if ctx != nil {
			rawP, _ = ctx.rawProps(id)
		}
		listFor := func(prop string) any {
			if rawP != nil {
				return rawP[prop]
			}
			return props[prop]
		}
		n, ff := resolveSGList(id, "SecurityGroupIds", listFor("SecurityGroupIds"), ctx)
		sgNames, f = append(sgNames, n...), append(f, ff...)
		n, ff = resolveSGList(id, "SecurityGroups", listFor("SecurityGroups"), ctx)
		sgNames, f = append(sgNames, n...), append(f, ff...)
		nis, ok := listEntries(listFor("NetworkInterfaces"), ctx)
		if !ok {
			f = append(f, Finding{"Resource " + id, "NetworkInterfaces does not resolve to a list — refusing rather than launching the VM without the interface (and its security groups) it declares"})
		}
		nis, ff = nicEntries(id, nis, ctx)
		f = append(f, ff...)
		if len(nis) > 0 {
			{
				ni0 := primaryNIC(nis)
				if ni0 != nil {
					if sref, present := ni0["SubnetId"]; present {
						if t, ok := getAttTarget(sref); ok && ctx != nil {
							if r, in := ctx.template.Resources[t]; in && r.Type == "AWS::EC2::Subnet" {
								spec["subnet"] = ctx.name(t)
							}
						} else if s, ok := concrete(sref); ok && s != "" {
							if strings.HasPrefix(strings.ToLower(s), "subnet-") {
								f = append(f, Finding{"Resource " + id, "NetworkInterfaces[0].SubnetId is a raw AWS subnet id (opaque) — name a kind: Subnet or reference an in-stack AWS::EC2::Subnet"})
							} else {
								spec["subnet"] = s
							}
						}
					}
					n, ff := resolveSGList(id, "NetworkInterfaces[0].GroupSet", ni0["GroupSet"], ctx)
					sgNames, f = append(sgNames, n...), append(f, ff...)
					if raw, has := ni0["AssociatePublicIpAddress"]; has {
						pub, ok := cfnBoolValue(ctx.resolveVal(raw))
						switch {
						case !ok:
							f = append(f, Finding{"Resource " + id, fmt.Sprintf("NetworkInterfaces[0].AssociatePublicIpAddress must be true or false (got %v)", ctx.resolveVal(raw))})
						case pub:
							spec["expose"] = true
						}
					}
					for _, p := range []string{"PrivateIpAddress", "PrivateIpAddresses", "SecondaryPrivateIpAddressCount", "Ipv6AddressCount", "Ipv6Addresses"} {
						if _, has := ni0[p]; has {
							cav = append(cav, "NetworkInterfaces[0]."+p+" dropped — the VM's address comes from its subnet's IP pool (IPv6 is not provisioned)")
						}
					}
					if dot, has := ni0["DeleteOnTermination"]; has && isExplicitFalse(ctx.resolveVal(dot)) {
						cav = append(cav, "NetworkInterfaces[0].DeleteOnTermination=false does not map — the VM's interface is deleted with the VM")
					}
				}
				if len(nis) > 1 {
					cav = append(cav, "only the primary NetworkInterface (DeviceIndex 0) is mapped; additional interfaces were dropped")
				}
			}
		}
	}
	var requires []Requirement
	if len(sgNames) > 0 {
		spec["securityGroups"] = dedupStrings(sgNames)
		// A group named from outside the stack (a parameter or a literal name) must exist: a VM that
		// names a missing group gets no firewall from it.
		for _, n := range dedupStrings(sgNames) {
			if !ctx.isInStackName(n, "AWS::EC2::SecurityGroup") {
				requires = append(requires, Requirement{APIVersion: "openinfra.dev/v1", Kind: "SecurityGroup", Name: n, Why: "a security group this instance attaches"})
			}
		}
	}
	// #347 1.6: an in-stack AWS::EC2::EIP associated with this instance folds onto the VM's LAN IP
	// (spec.expose + spec.ports derived from its SecurityGroups) — translate_ec2eip.go.
	cav = append(cav, eipExposeVM(id, spec, ctx)...)
	if eip, ok := spec["elasticIp"].(map[string]any); ok {
		if alloc, _ := eip["allocationId"].(string); alloc != "" && !ctx.inStackAllocation(alloc) {
			// Another stack's allocation must exist (an AWS account's allocation ids have the same shape).
			requires = append(requires, Requirement{APIVersion: ServiceAPIVersion, Kind: KindEC2Address, Name: alloc,
				Why: "the Elastic IP allocation this instance's EIPAssociation names (another stack's AWS::EC2::EIP)"})
		}
	}
	cav = append(cav, instanceDNSNameCaveats(id, spec, ctx)...)
	// On AWS an instance with no security group gets the VPC default group, which admits inbound only from
	// its own members and all outbound. A VM with none here has no firewall, so a published one gets the
	// stack's default group (defaultSecurityGroup) instead — never every port open to the LAN.
	var defaultSG *Manifest
	if exp, _ := spec["expose"].(bool); exp && len(sgNames) == 0 {
		defaultSG = ctx.defaultSecurityGroup()
		spec["securityGroups"] = []string{defaultSG.Name}
		cav = append(cav, "the instance attaches no SecurityGroup, so it gets the stack's default kind: SecurityGroup \""+defaultSG.Name+"\" — as a VPC's default group, it admits inbound only from its own members (so nothing on the LAN reaches the instance's published address) and all outbound")
	}

	// IamInstanceProfile -> spec.instanceRole: follow the profile to its in-stack AWS::IAM::Role and
	// bind the VM to that kind: Role (the guest gets its credentials from instance metadata, no static
	// keys). An out-of-stack profile/arn can't be resolved to a kind: Role here — caveat, don't guess.
	if _, present := props["IamInstanceProfile"]; present {
		if role, ok := resolveInstanceRole(id, ctx); ok {
			spec["instanceRole"] = role
		} else {
			cav = append(cav, "IamInstanceProfile could not be resolved to an in-stack AWS::IAM::Role — set spec.instanceRole to the kind: Role the VM should assume (it must trust the vm principal)")
		}
	}

	// MetadataOptions -> spec.metadataOptions: the in-guest instance metadata service (169.254.169.254).
	if raw, present := props["MetadataOptions"]; present {
		mo, ff, cc := ec2MetadataOptions(id, raw)
		f, cav = append(f, ff...), append(cav, cc...)
		if len(mo) > 0 {
			spec["metadataOptions"] = mo
		}
		if vmOS, _ := spec["os"].(string); strings.HasPrefix(vmOS, "windows-") {
			cav = append(cav, "MetadataOptions has no effect on a Windows guest — open-infra serves instance metadata to Linux guests only")
		}
	}

	// The volumes the instance launched with and keeps (DeleteOnTermination: false) come first, then the
	// ones VolumeAttachments attach.
	vols, vcav, vreq := ctx.attachedVolumes(id)
	if all := append(keptAttach, vols...); len(all) > 0 {
		spec["volumes"] = all
		cav = append(cav, vcav...)
		requires = append(requires, vreq...)
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "VirtualMachine", Name: ctx.name(id), Spec: spec, Requires: requires}
	if defaultSG != nil {
		m.Extra = append(m.Extra, defaultSG)
	}
	if vmNeedDefaultKey {
		k := ctx.defaultEBSKey()
		m.Extra = append(m.Extra, k)
		cav = append(cav, "an encrypted data disk has no KmsKeyId — keyed by the stack's default kind: EncryptionKey \""+k.Name+"\" (open-infra analog of AWS's account-default aws/ebs key), created on first use")
	}
	// After the key that encrypts them: a kept volume is Ready only once its encrypted disk is bound.
	m.Extra = append(m.Extra, keptVols...)

	for _, p := range []string{"AvailabilityZone", "Monitoring", "EbsOptimized", "PrivateIpAddress", "SourceDestCheck", "DisableApiTermination"} {
		if _, ok := props[p]; ok {
			cav = append(cav, p+" dropped — no open-infra equivalent")
		}
	}
	cav = append(cav, awsViewCaveats(props, "Tags")...)
	m.Caveats = cav
	return m, f
}

// ec2MetadataOptions maps an AWS::EC2::Instance MetadataOptions block onto spec.metadataOptions, the
// settings of the in-guest instance metadata service. HttpTokens, HttpPutResponseHopLimit and
// HttpEndpoint map 1:1 (same names, same values, same hop-limit semantics). HttpProtocolIpv6 (the
// fd00:ec2::254 endpoint) and InstanceMetadataTags (tags under /latest/meta-data/tags/instance) are not
// served: enabling them is a caveat, not a refusal — the IPv4 endpoint still answers every other path.
// A value outside the AWS enum/range refuses rather than being guessed.
func ec2MetadataOptions(id string, raw any) (map[string]any, []Finding, []string) {
	mo, ok := raw.(map[string]any)
	if !ok {
		return nil, []Finding{{"Resource " + id, "MetadataOptions could not be resolved to an object — set spec.metadataOptions natively"}}, nil
	}
	f := blockUnknownProps(id+".MetadataOptions", mo, map[string]bool{
		"HttpEndpoint": true, "HttpTokens": true, "HttpPutResponseHopLimit": true,
		"HttpProtocolIpv6": true, "InstanceMetadataTags": true,
	})
	var cav []string
	out := map[string]any{}
	enum := func(prop string, allowed ...string) string {
		v, present := mo[prop]
		if !present {
			return ""
		}
		if s, ok := concrete(v); ok {
			for _, a := range allowed {
				if s == a {
					return s
				}
			}
		}
		f = append(f, Finding{"Resource " + id, fmt.Sprintf("MetadataOptions.%s must be one of %s (got %v)", prop, strings.Join(allowed, "|"), v)})
		return ""
	}
	if s := enum("HttpTokens", "optional", "required"); s != "" {
		out["httpTokens"] = s
	}
	if s := enum("HttpEndpoint", "enabled", "disabled"); s != "" {
		out["httpEndpoint"] = s
	}
	if v, present := mo["HttpPutResponseHopLimit"]; present {
		if n := toInt(v); n >= 1 && n <= 64 {
			out["httpPutResponseHopLimit"] = n
		} else {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("MetadataOptions.HttpPutResponseHopLimit must be an integer 1..64 (got %v)", v)})
		}
	}
	if enum("HttpProtocolIpv6", "enabled", "disabled") == "enabled" {
		cav = append(cav, "MetadataOptions.HttpProtocolIpv6=enabled: instance metadata is served on IPv4 (169.254.169.254) only — the IPv6 endpoint fd00:ec2::254 is not served")
	}
	if enum("InstanceMetadataTags", "enabled", "disabled") == "enabled" {
		cav = append(cav, "MetadataOptions.InstanceMetadataTags=enabled: instance tags are not served under /latest/meta-data/tags/instance")
	}
	return out, f, cav
}

// bdmKnown and ebsKnown are the BlockDeviceMapping and Ebs properties the instance translator reads or
// reports. Anything else in either block refuses.
var (
	bdmKnown = map[string]bool{"DeviceName": true, "Ebs": true, "NoDevice": true, "VirtualName": true}
	ebsKnown = map[string]bool{
		"DeleteOnTermination": true, "Encrypted": true, "Iops": true, "KmsKeyId": true,
		"SnapshotId": true, "Throughput": true, "VolumeSize": true, "VolumeType": true,
	}
)

// nicKnown are the NetworkInterface properties the instance translator reads (SubnetId, GroupSet,
// AssociatePublicIpAddress, DeviceIndex) or reports as dropped. Anything else refuses.
var nicKnown = map[string]bool{
	"DeviceIndex": true, "SubnetId": true, "GroupSet": true, "AssociatePublicIpAddress": true,
	"DeleteOnTermination": true, "Description": true, "PrivateIpAddress": true, "PrivateIpAddresses": true,
	"SecondaryPrivateIpAddressCount": true, "Ipv6AddressCount": true, "Ipv6Addresses": true,
	"NetworkInterfaceId": true,
}

// nicEntries resolves each NetworkInterfaces entry (raw, so a GroupSet !Ref is still visible) to an
// interface object. An entry-level Fn::If takes the branch its condition picks; AWS::NoValue removes the
// entry. An entry that is not an interface object, or that attaches an existing interface by
// NetworkInterfaceId (whose security groups are not in the template), refuses: reading it as an
// interface with no GroupSet would launch the VM with no firewall the template asked for.
func nicEntries(id string, nis []any, ctx *stackCtx) ([]any, []Finding) {
	var out []any
	var f []Finding
	for i, e := range nis {
		for depth := 0; depth < 8; depth++ {
			m, ok := e.(map[string]any)
			if !ok || len(m) != 1 {
				break
			}
			if args, isIf := m["Fn::If"].([]any); isIf && len(args) == 3 && ctx != nil && ctx.resolver != nil {
				if ctx.resolver.conds[fmt.Sprint(args[0])] {
					e = args[1]
				} else {
					e = args[2]
				}
				continue
			}
			if ref, isRef := m["Ref"].(string); isRef && ref == "AWS::NoValue" {
				e = nil
			}
			break
		}
		if e == nil {
			continue
		}
		ni, ok := e.(map[string]any)
		if ok && len(ni) == 1 {
			for k := range ni {
				ok = k != "Ref" && !strings.HasPrefix(k, "Fn::")
			}
		}
		if !ok {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("NetworkInterfaces[%d] does not resolve to an interface — refusing rather than launching the VM without the interface (and its security groups) it declares", i)})
			continue
		}
		where := fmt.Sprintf("%s.NetworkInterfaces[%d]", id, i)
		f = append(f, blockUnknownProps(where, ni, nicKnown)...)
		if _, has := ni["NetworkInterfaceId"]; has {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("NetworkInterfaces[%d].NetworkInterfaceId attaches an existing network interface, whose subnet and security groups are not in the template — open-infra cannot attach it; declare the interface with SubnetId and GroupSet instead", i)})
		}
		out = append(out, ni)
	}
	return out, f
}

// primaryNIC returns the NetworkInterface with DeviceIndex 0 (the primary), or the first entry when
// no DeviceIndex is set. DeviceIndex may be an int, a float (JSON), or a string.
func primaryNIC(nis []any) map[string]any {
	var first map[string]any
	for i, raw := range nis {
		ni, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if i == 0 {
			first = ni
		}
		switch di := ni["DeviceIndex"].(type) {
		case string:
			if di == "0" {
				return ni
			}
		case float64:
			if di == 0 {
				return ni
			}
		case int:
			if di == 0 {
				return ni
			}
		}
	}
	return first
}

// dedupStrings returns xs with duplicates removed, preserving first-seen order.
func dedupStrings(xs []string) []string {
	seen := make(map[string]bool, len(xs))
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// ---- AWS::EC2::VPC -> kind: Vpc ----
//
// A kube-ovn Vpc (an isolated network domain / router). The AWS VPC-level CidrBlock has no kind: Vpc
// field — in kube-ovn the subnets carry the CIDRs, not the VPC — so it is an informational caveat.
func translateEC2VPC(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"CidrBlock": true, "EnableDnsSupport": true, "EnableDnsHostnames": true,
		"InstanceTenancy": true, "Tags": true, "CidrBlockAssociations": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Vpc", Name: ctx.name(id), Spec: map[string]any{}}
	if _, ok := props["CidrBlock"]; ok {
		m.Caveats = append(m.Caveats, "CidrBlock is informational — in kube-ovn the subnets carry the CIDRs, not the VPC; the VPC-level range does not map to a field (the EC2 API reports it: DescribeVpcs)")
	}
	m.Caveats = append(m.Caveats, awsViewCaveats(props, "Tags")...)
	for _, p := range []string{"EnableDnsSupport", "EnableDnsHostnames", "InstanceTenancy", "CidrBlockAssociations"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — no kind: Vpc equivalent (DNS is cluster-wide; tenancy and extra ranges don't map)")
		}
	}
	return m, f
}

// ---- AWS::EC2::Subnet -> kind: Subnet ----
//
// A kube-ovn Subnet with real OVN isolation (#120). CidrBlock -> cidr (faithful, required); a VpcId
// !Ref to an in-stack AWS::EC2::VPC -> vpc; MapPublicIpOnLaunch -> private (public subnet => not
// private). AvailabilityZone/tags have no equivalent (caveats).
func translateEC2Subnet(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"CidrBlock": true, "VpcId": true, "AvailabilityZone": true, "MapPublicIpOnLaunch": true,
		"Tags": true, "AssignIpv6AddressOnCreation": true, "Ipv6CidrBlock": true, "OutpostArn": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	spec := map[string]any{}
	if cidr, ok := concrete(props["CidrBlock"]); ok && cidr != "" {
		spec["cidr"] = cidr
	} else {
		f = append(f, Finding{"Resource " + id, "CidrBlock is required to create a Subnet"})
	}
	// VpcId: a !Ref to an in-stack AWS::EC2::VPC maps to that kind: Vpc.
	if ctx != nil {
		if raw, ok := ctx.rawProps(id); ok {
			if t, ok := refTarget(raw["VpcId"]); ok {
				if r, in := ctx.template.Resources[t]; in && r.Type == "AWS::EC2::VPC" {
					spec["vpc"] = ctx.name(t)
				}
			}
		}
	}
	// A public subnet (MapPublicIpOnLaunch) is NOT private; otherwise private (default) — OVN isolated.
	if _, ok := props["MapPublicIpOnLaunch"]; ok {
		pub, ff := boolProp(id, props, "MapPublicIpOnLaunch", false)
		f = append(f, ff...)
		spec["private"] = !pub
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Subnet", Name: ctx.name(id), Spec: spec}
	for _, p := range []string{"AvailabilityZone", "AssignIpv6AddressOnCreation", "Ipv6CidrBlock", "OutpostArn"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — no kind: Subnet equivalent (one flat cluster, no AZ; IPv6 doesn't map)")
		}
	}
	m.Caveats = append(m.Caveats, awsViewCaveats(props, "Tags")...)
	return m, f
}

// ---- AWS::EC2::VPCEndpoint -> kind: VpcEndpoint ----
//
// A private DNS alias to the one aws-shim front door for an AWS service (the open-infra VpcEndpoint
// semantics — see platform/networking/kube-ovn/vpcendpoint-xrd.yaml). ServiceName -> service,
// VpcEndpointType carried for fidelity, a VpcId !Ref to an in-stack AWS::EC2::VPC -> vpc. Endpoint
// policies / route tables / subnets / SGs don't map: every service routes to the shim and access
// control is IAM/Cedar at the shim, not per-endpoint (caveats, never a silent unenforced policy).
func translateEC2VPCEndpoint(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"ServiceName": true, "VpcId": true, "VpcEndpointType": true, "PolicyDocument": true,
		"RouteTableIds": true, "SubnetIds": true, "SecurityGroupIds": true, "PrivateDnsEnabled": true, "Tags": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	spec := map[string]any{}
	if sn, ok := concrete(props["ServiceName"]); ok && sn != "" {
		spec["service"] = serviceFromServiceName(sn)
	} else {
		f = append(f, Finding{"Resource " + id, "ServiceName is required to create a VpcEndpoint"})
	}
	// VpcEndpointType (Gateway|Interface); AWS defaults to Gateway. Carried for fidelity (both route to the shim).
	etype := "Gateway"
	if v, ok := concrete(props["VpcEndpointType"]); ok && v != "" {
		etype = v
	}
	spec["vpcEndpointType"] = etype
	// VpcId: a !Ref to an in-stack AWS::EC2::VPC -> the owning kind: Vpc (optional, fidelity).
	if ctx != nil {
		if raw, ok := ctx.rawProps(id); ok {
			if t, ok := refTarget(raw["VpcId"]); ok {
				if r, in := ctx.template.Resources[t]; in && r.Type == "AWS::EC2::VPC" {
					spec["vpc"] = ctx.name(t)
				}
			}
		}
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "VpcEndpoint", Name: ctx.name(id), Spec: spec}
	if _, ok := props["PolicyDocument"]; ok {
		m.Caveats = append(m.Caveats, "PolicyDocument dropped — the VpcEndpoint is a private DNS alias to the aws-shim; access through it is governed by IAM/Cedar at the shim, not a per-endpoint policy")
	}
	for _, p := range []string{"RouteTableIds", "SubnetIds", "SecurityGroupIds", "PrivateDnsEnabled", "Tags"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — every service endpoint routes to the one aws-shim front door; route tables/subnets/SGs/private-DNS-toggle/tags don't map")
		}
	}
	return m, f
}

// serviceFromServiceName extracts the service token from an AWS endpoint ServiceName
// ("com.amazonaws.<region>.<service…>" -> "<service…>", e.g. s3 / dynamodb / ecr.dkr), falling back to
// the last dotted token for an unrecognized shape.
func serviceFromServiceName(sn string) string {
	parts := strings.Split(sn, ".")
	if len(parts) >= 4 && parts[0] == "com" && parts[1] == "amazonaws" {
		return strings.Join(parts[3:], ".")
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return sn
}

// ---- AWS::EC2::SecurityGroup -> kind: SecurityGroup ----
//
// A default-deny allow-rule set (platform/abstraction/securitygroup-xrd.yaml). CFN inline
// SecurityGroupIngress/SecurityGroupEgress rules map to spec.ingress/egress, with FAIL-CLOSED fidelity:
// anything kind: SecurityGroup cannot express EXACTLY (a protocol other than TCP/UDP, a port range wider
// than maxExpandedPortRange, an out-of-stack SG reference, an IPv6 CIDR) REFUSES the whole resource rather
// than emit a looser rule — an over-permissive security group is precisely the silent defect this must
// never produce. Only TCP/UDP on a single port, a small range (expanded to its exact port list), or
// all-ports, with a CidrIp source or a SourceSecurityGroupId that !Refs an in-stack
// AWS::EC2::SecurityGroup translate. Standalone AWS::EC2::SecurityGroupIngress/Egress resources are NOT
// handled here (author the rules inline on the group or natively).
func translateEC2SecurityGroup(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"GroupDescription": true, "GroupName": true, "VpcId": true,
		"SecurityGroupIngress": true, "SecurityGroupEgress": true, "Tags": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	// Iterate the RAW rules so a SourceSecurityGroupId !Ref can be followed to an in-stack logical id
	// (the resolver would have turned it into an unusable placeholder).
	raw := props
	if ctx != nil {
		if r, ok := ctx.rawProps(id); ok {
			raw = r
		}
	}
	spec := map[string]any{}
	ingress, inF := sgRules(id, raw["SecurityGroupIngress"], false, ctx)
	f = append(f, inF...)
	egress, egF := sgRules(id, raw["SecurityGroupEgress"], true, ctx)
	f = append(f, egF...)

	// Collate standalone AWS::EC2::SecurityGroupIngress/Egress resources whose GroupId !Refs this SG —
	// the common pattern for breaking SG-to-SG circular references. Each is ONE rule; convert it with the
	// same fail-closed sgRules and append. Their own translators are no-ops when in-stack (refuse external).
	if ctx != nil {
		for _, rid := range ctx.sgStandaloneRules(id, "AWS::EC2::SecurityGroupIngress") {
			rr, _ := ctx.rawProps(rid)
			rules, rf := sgRules(rid, []any{rr}, false, ctx)
			f = append(f, rf...)
			ingress = append(ingress, rules...)
		}
		for _, rid := range ctx.sgStandaloneRules(id, "AWS::EC2::SecurityGroupEgress") {
			rr, _ := ctx.rawProps(rid)
			rules, rf := sgRules(rid, []any{rr}, true, ctx)
			f = append(f, rf...)
			egress = append(egress, rules...)
		}
	}
	if len(ingress) > 0 {
		spec["ingress"] = ingress
	}
	if len(egress) > 0 {
		spec["egress"] = egress
	}

	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "SecurityGroup", Name: ctx.name(id), Spec: spec}
	if _, ok := props["VpcId"]; ok {
		m.Caveats = append(m.Caveats, "VpcId dropped — a kind: SecurityGroup is enforced cluster-wide by membership label, not scoped to a VPC")
	}
	m.Caveats = append(m.Caveats, awsViewCaveats(props, "GroupName", "GroupDescription", "Tags")...)
	return m, f
}

// sgRules translates a CFN SecurityGroupIngress/Egress rule list into kind: SecurityGroup ingress/egress
// entries. egress=true selects the Destination* fields. It is FAIL-CLOSED: a rule it cannot map exactly
// produces a Finding (which blocks the whole resource) rather than a looser emitted rule.
func sgRules(id string, rawList any, egress bool, ctx *stackCtx) ([]any, []Finding) {
	var f []Finding
	dir := "ingress"
	peerKey, sgField := "from", "SourceSecurityGroupId"
	if egress {
		dir, peerKey, sgField = "egress", "to", "DestinationSecurityGroupId"
	}
	items, ok := listEntries(rawList, ctx)
	if !ok {
		return nil, []Finding{{"Resource " + id, "the " + dir + " rules do not resolve to a list of rules — refusing rather than dropping them"}}
	}
	var out []any
	for i, it := range items {
		r, ok := it.(map[string]any)
		if !ok {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s rule %d is not an object", dir, i)})
			continue
		}
		rule := map[string]any{}

		// Resolve the rule's SCALAR fields (CidrIp/ports/protocol) through the stack resolver so a
		// `!Ref Param` becomes the parameter's value (and an unresolvable intrinsic stays a placeholder
		// concrete() refuses). The rule is iterated raw ONLY so a SourceSecurityGroupId !Ref below can be
		// followed to its in-stack logical id — never to emit an intrinsic literally as a value.
		proto, _ := concrete(ctx.resolveVal(r["IpProtocol"]))
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "tcp":
			rule["protocol"] = "TCP"
		case "udp":
			rule["protocol"] = "UDP"
		default:
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s rule %d: IpProtocol %q not expressible — kind: SecurityGroup allows only TCP or UDP (split by protocol or author natively)", dir, i, proto)})
			continue
		}

		// Ports — single port, a small range (expanded to its exact list), or all-ports; a wider range
		// cannot be expressed as a ports LIST faithfully.
		ports, perr := sgPorts(ctx.resolveVal(r["FromPort"]), ctx.resolveVal(r["ToPort"]))
		if perr != "" {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s rule %d: %s", dir, i, perr)})
			continue
		}
		if len(ports) > 0 {
			rule["ports"] = ports
		} // empty = all ports (kind: SecurityGroup convention)

		// Source/destination — a CidrIp, or a SecurityGroup reference. Exactly one. The SG reference is
		// resolved exactly like SecurityGroupIds (sgRefName): an in-stack AWS::EC2::SecurityGroup !Ref
		// (followed from the raw form) → its kind: SecurityGroup name; a parameter whose VALUE names a
		// kind: SecurityGroup (the cross-stack case — a sibling stack's SG name passed in as a param) →
		// that name; a raw sg- id → refused (opaque, like an AMI).
		peer := map[string]any{}
		if cidr, ok := concrete(ctx.resolveVal(r["CidrIp"])); ok && cidr != "" {
			peer["cidr"] = cidr
		} else if _, hasSG := r[sgField]; hasSG {
			name, refuseRaw := sgRefName(r[sgField], ctx)
			if name == "" && !refuseRaw {
				// Not an in-stack !Ref — resolve a parameter value to a kind: SecurityGroup name.
				name, refuseRaw = sgRefName(ctx.resolveVal(r[sgField]), ctx)
			}
			switch {
			case refuseRaw:
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s rule %d: %s is a raw AWS sg- id (opaque) — !Ref an in-stack AWS::EC2::SecurityGroup, or pass a parameter naming a kind: SecurityGroup", dir, i, sgField)})
				continue
			case name == "":
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s rule %d: %s must !Ref an in-stack AWS::EC2::SecurityGroup or resolve to a kind: SecurityGroup name (an out-of-stack sg- id or a cross-resource GetAtt cannot be resolved)", dir, i, sgField)})
				continue
			default:
				peer["securityGroup"] = name
			}
		} else if _, ok := r["CidrIpv6"]; ok {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s rule %d: CidrIpv6 does not map — kind: SecurityGroup CIDR enforcement is IPv4 (author natively)", dir, i)})
			continue
		} else {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s rule %d: needs a CidrIp or a SourceSecurityGroupId/DestinationSecurityGroupId; a prefix-list or self-reference source does not map", dir, i)})
			continue
		}
		rule[peerKey] = []any{peer}
		out = append(out, rule)
	}
	return out, f
}

// maxExpandedPortRange is the widest FromPort–ToPort range expanded into an explicit port list (a
// kind: SecurityGroup ports list, or the ports an Elastic IP publishes on a VM's LAN IP). A list of N
// ports is EXACTLY the range, so expanding a small one is faithful; a wider range stays a refusal (SG)
// or an unpublished caveat (EIP) rather than a list of hundreds of entries.
const maxExpandedPortRange = 16

// sgPorts maps a CFN FromPort/ToPort to a kind: SecurityGroup ports list. A single port -> [port]; a
// small range (<= maxExpandedPortRange ports) -> its explicit port list (exact, not an approximation);
// the full range (0-65535, or FromPort -1) or both absent -> empty (all ports); any wider range -> an
// error (kind: SecurityGroup takes a list of ports, not a range — refuse rather than approximate).
func sgPorts(fromRaw, toRaw any) ([]any, string) {
	from, okF := cfnPort(fromRaw)
	to, okT := cfnPort(toRaw)
	// A port that is set but is not a number (e.g. !GetAtt DB.Endpoint.Port, which does not resolve
	// before deploy) must not read as absent: absent means ALL ports.
	if (fromRaw != nil && !okF) || (toRaw != nil && !okT) {
		return nil, fmt.Sprintf("FromPort/ToPort (%v/%v) is not a concrete port number — refusing rather than opening every port", portShown(fromRaw), portShown(toRaw))
	}
	if !okF && !okT {
		return nil, "" // no ports -> all ports
	}
	if !okF || !okT {
		return nil, "a rule with only one of FromPort/ToPort is malformed"
	}
	if from < 0 || (from == 0 && to == 65535) {
		return nil, "" // all ports
	}
	if from == to {
		return []any{from}, ""
	}
	if to < from || from < 1 || to > 65535 {
		return nil, fmt.Sprintf("port range %d-%d is malformed", from, to)
	}
	if n := to - from + 1; n <= maxExpandedPortRange {
		ports := make([]any, 0, n)
		for p := from; p <= to; p++ {
			ports = append(ports, p)
		}
		return ports, ""
	}
	return nil, fmt.Sprintf("port range %d-%d (%d ports) does not map — kind: SecurityGroup takes a list of ports, not a range; ranges of up to %d ports expand, wider ones refuse (split into single-port rules or author natively)", from, to, to-from+1, maxExpandedPortRange)
}

// portShown renders a FromPort/ToPort value for a message ("unset" when absent).
func portShown(v any) string {
	if v == nil {
		return "unset"
	}
	return fmt.Sprint(v)
}

// cfnPort reads a CFN port value (a JSON number, int, or numeric string).
func cfnPort(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case string:
		if n == "" {
			return 0, false
		}
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

// collatedChildren returns the logical ids of INCLUDED resources of cfnType whose raw property refProp
// is a !Ref/!GetAtt to targetID — the shared shape of every collation (an SG's standalone rules, a
// pool's clients, an API's children, …). The `included` guard is the point: a child the template gates
// OFF with a false Condition must NOT be folded into its parent (otherwise a rule/policy the operator
// turned off is deployed anyway — the fail-open class first found on standalone SG rules). Deterministic.
func (c *stackCtx) collatedChildren(cfnType, refProp, targetID string) []string {
	var ids []string
	for cid, res := range c.template.Resources {
		if res.Type != cfnType || !c.included(res) {
			continue
		}
		raw, _ := c.rawProps(cid)
		if t, ok := getAttTarget(raw[refProp]); ok && t == targetID {
			ids = append(ids, cid)
		}
	}
	sortStrs(ids)
	return ids
}

// sgStandaloneRules returns the INCLUDED in-stack logical ids of `cfnType` (AWS::EC2::SecurityGroupIngress
// or ...Egress) whose GroupId names sgID (sgGroupIDTarget) — the standalone rules collated into that SG.
func (c *stackCtx) sgStandaloneRules(sgID, cfnType string) []string {
	var ids []string
	for cid, res := range c.template.Resources {
		if res.Type != cfnType || !c.included(res) {
			continue
		}
		raw, _ := c.rawProps(cid)
		if t, ok := sgGroupIDTarget(raw["GroupId"]); ok && t == sgID {
			ids = append(ids, cid)
		}
	}
	sortStrs(ids)
	return ids
}

// sgGroupIDTarget is the security group a rule's raw GroupId names: !Ref <sg> or !GetAtt <sg>.GroupId,
// which for a VPC security group are both its id, so AWS accepts either. Any other attribute (a group's
// VpcId, say) names no group.
func sgGroupIDTarget(raw any) (string, bool) {
	if t, ok := refTarget(raw); ok {
		return t, true
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return "", false
	}
	switch ga := m["Fn::GetAtt"].(type) {
	case []any:
		if len(ga) == 2 && fmt.Sprint(ga[1]) == "GroupId" {
			if s, ok := ga[0].(string); ok {
				return s, true
			}
		}
	case string:
		if s, ok := strings.CutSuffix(ga, ".GroupId"); ok && s != "" {
			return s, true
		}
	}
	return "", false
}

// translateEC2SecurityGroupRule is the no-op half of the standalone-rule collation: a
// SecurityGroupIngress/Egress whose GroupId !Refs an in-stack AWS::EC2::SecurityGroup provisions nothing
// on its own (the group collates its rule, fail-closed, in translateEC2SecurityGroup). Unknown props are
// refused, and a rule targeting an out-of-stack group is refused (its rule can't attach to a group we
// don't manage — author it inline on the group or natively).
func translateEC2SecurityGroupRule(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"GroupId": true, "GroupName": true, "IpProtocol": true, "FromPort": true, "ToPort": true,
		"CidrIp": true, "CidrIpv6": true, "Description": true,
		"SourceSecurityGroupId": true, "DestinationSecurityGroupId": true,
	}
	f := blockUnknownProps(id, props, known)
	// A rule has one source (ingress) or destination (egress); a second one beside it is refused, never
	// ignored. GroupName names a default-VPC group by name, which has no open-infra form (use GroupId).
	var sources []string
	for _, k := range []string{"CidrIp", "CidrIpv6", "SourceSecurityGroupId", "DestinationSecurityGroupId"} {
		if v, ok := props[k]; ok && v != nil {
			sources = append(sources, k)
		}
	}
	if len(sources) > 1 {
		f = append(f, Finding{"Resource " + id, "a security group rule has one source or destination, but this one sets " + strings.Join(sources, " and ") + " — split it into one rule each"})
	}
	if _, ok := props["GroupName"]; ok {
		f = append(f, Finding{"Resource " + id, "GroupName (a default-VPC group by name) is not translatable — name the group with GroupId: !Ref an in-stack AWS::EC2::SecurityGroup"})
	}
	inStack := false
	if ctx != nil {
		if raw, ok := ctx.rawProps(id); ok {
			if t, named := sgGroupIDTarget(raw["GroupId"]); named {
				if r, in := ctx.template.Resources[t]; in && r.Type == "AWS::EC2::SecurityGroup" {
					inStack = true
				}
			}
		}
	}
	if !inStack {
		f = append(f, Finding{"Resource " + id, "GroupId must name an in-stack AWS::EC2::SecurityGroup (!Ref it or !GetAtt its GroupId) — a standalone rule on an out-of-stack group can't be attached (author it inline on the group or natively)"})
	}
	return nil, f // collated into the group (or refused above)
}

// ---- Structural EC2 networking resources -> implicit (no-op) ----
//
// Some CloudFormation networking resources exist only to wire two other resources together, and on
// open-infra that wiring lives INSIDE the kind they attach to — so they provision nothing standalone
// (structural, like an ECS Cluster). A no-op (nil Manifest) keeps a template that carries them from
// blocking:
//   - InternetGateway / VPCGatewayAttachment: the border device is a kind: NatGateway and the
//     "attachment" is a kind: Vpc default route to it (public reachability = NatGateway + ElasticIp).
//   - SubnetNetworkAclAssociation: ACL rules live on the target kind: Subnet spec.acls.
//   - SubnetRouteTableAssociation: kube-ovn routes are VPC-scoped (kind: Vpc spec.routes).
//
// Each is still closed-world: a property that would change something (a VPN gateway attachment) refuses.
// A network ACL association refuses: ACL rules live on the kind: Subnet (spec.acls), and an
// AWS::EC2::NetworkAcl has no translator, so the ACL it names is one the stack cannot carry — dropping
// the association would leave the subnet without the rules it names.
func translateEC2ImplicitGateway(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	typ := ""
	if ctx != nil {
		typ = ctx.template.Resources[id].Type
	}
	switch typ {
	case "AWS::EC2::InternetGateway":
		return nil, blockUnknownProps(id, props, map[string]bool{"Tags": true})
	case "AWS::EC2::VPCGatewayAttachment":
		return nil, blockUnknownProps(id, props, map[string]bool{"VpcId": true, "InternetGatewayId": true})
	case "AWS::EC2::SubnetRouteTableAssociation":
		return nil, blockUnknownProps(id, props, map[string]bool{"SubnetId": true, "RouteTableId": true})
	case "AWS::EC2::SubnetNetworkAclAssociation":
		f := blockUnknownProps(id, props, map[string]bool{"SubnetId": true, "NetworkAclId": true})
		return nil, append(f, Finding{"Resource " + id, "a network ACL association has no open-infra form — the ACL's rules are not in the template (AWS::EC2::NetworkAcl does not translate), and dropping the association would leave the subnet without them; author the rules on the kind: Subnet (spec.acls)"})
	}
	return nil, nil
}

// ---- AWS::EC2::RouteTable -> (implicit) ----
//
// A route table is a pure container. In kube-ovn routes are VPC-scoped (kind: Vpc spec.routes), not
// a standalone table, so a RouteTable provisions nothing on its own — the routes that "live in" it
// are the AWS::EC2::Route resources, each translated in its own right. Deployable as a no-op so a
// template that carries a RouteTable is not blocked; a RouteTable's only properties are VpcId (the
// in-stack binding is implicit) and Tags, so anything else refuses fail-closed.
func translateEC2RouteTable(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"VpcId": true, "Tags": true}
	return nil, blockUnknownProps(id, props, known)
}

// ---- AWS::EC2::Route -> (implicit) for the default-egress case, else refuse ----
//
// One AWS route is a DestinationCidrBlock plus a target (a gateway/nat/peering/instance id). A
// kind: Vpc spec.routes entry needs cidr -> a NEXT-HOP IP, and the open-infra border device is a
// kind: NatGateway whose internalIp AWS auto-assigns and the template never carries. So exactly one
// shape translates faithfully, and it translates to nothing to create:
//
//	the default route 0.0.0.0/0 (or ::/0) -> an in-stack AWS::EC2::InternetGateway
//
// On open-infra a public subnet's internet egress is a property of having a kind: NatGateway border
// device (which plays the Internet-Gateway role on a flat /24), and the VPC's default route to it is
// set when the NatGateway is authored natively — the CFN default route carries no further derivable
// fact, so it is implicit (provisions nothing, like the InternetGateway it targets). Any OTHER route
// — a non-default CIDR, or a target that is not an in-stack InternetGateway (a NatGateway, a VPC
// peering, an instance, a raw igw-/nat- id) — carries real next-hop intent we cannot derive, so it
// REFUSES fail-closed (never a silently-dropped route) and points at authoring the route natively.
func translateEC2Route(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"RouteTableId": true, "DestinationCidrBlock": true, "DestinationIpv6CidrBlock": true,
		"GatewayId": true, "NatGatewayId": true, "VpcPeeringConnectionId": true,
		"InstanceId": true, "NetworkInterfaceId": true, "TransitGatewayId": true,
		"CarrierGatewayId": true, "EgressOnlyInternetGatewayId": true,
		"LocalGatewayId": true, "VpcEndpointId": true, "CoreNetworkArn": true,
	}
	if f := blockUnknownProps(id, props, known); len(f) > 0 {
		return nil, f
	}
	// AWS gives a route one target; a second one set beside it is refused, never ignored.
	var targets []string
	for _, k := range []string{"GatewayId", "NatGatewayId", "VpcPeeringConnectionId", "InstanceId", "NetworkInterfaceId",
		"TransitGatewayId", "CarrierGatewayId", "EgressOnlyInternetGatewayId", "LocalGatewayId", "VpcEndpointId", "CoreNetworkArn"} {
		if v, ok := props[k]; ok && v != nil {
			targets = append(targets, k)
		}
	}
	if len(targets) > 1 {
		return nil, []Finding{{"Resource " + id, "a route has one target, but this one sets " + strings.Join(targets, " and ") + " — CloudFormation refuses it too"}}
	}
	if _, ok := props["DestinationIpv6CidrBlock"]; ok && props["DestinationCidrBlock"] != nil {
		return nil, []Finding{{"Resource " + id, "a route has one destination, but this one sets DestinationCidrBlock and DestinationIpv6CidrBlock"}}
	}
	cidr, _ := concrete(props["DestinationCidrBlock"])
	if cidr == "" {
		cidr, _ = concrete(props["DestinationIpv6CidrBlock"])
	}
	isDefault := cidr == "0.0.0.0/0" || cidr == "::/0"

	// The target must be a !Ref to an in-stack AWS::EC2::InternetGateway for the implicit case.
	igwTarget := false
	if ctx != nil {
		if raw, ok := ctx.rawProps(id); ok {
			if t, isRef := refTarget(raw["GatewayId"]); isRef {
				if r, in := ctx.template.Resources[t]; in && r.Type == "AWS::EC2::InternetGateway" {
					igwTarget = true
				}
			}
		}
	}
	if isDefault && igwTarget {
		// Default internet egress == having a NatGateway border device; nothing standalone to create.
		return nil, nil
	}
	return nil, []Finding{{"Resource " + id,
		"only the default route 0.0.0.0/0 -> an in-stack AWS::EC2::InternetGateway translates (it is implicit: egress is a property of the kind: NatGateway border device). This route targets something else, or a non-default CIDR — author it on the kind: Vpc (spec.routes: cidr -> the NatGateway internalIp), so no next-hop is fabricated"}}
}

// ---- AWS::DynamoDB::Table -> kind: Table ----
//
// open-infra's Table is a thin declarative front for the aws-shim's DynamoDB data layer
// (FerretDB): it registers a table's name + key schema so items are writable without a runtime
// CreateTable, and (a #104-added TTL) a TTL attribute the shim's reaper enforces. So the KEY
// SCHEMA maps faithfully — the partition/sort key and their scalar types (S/N/B) — TTL maps, and
// GLOBAL SECONDARY INDEXES map (name + key schema; backed by a Mongo index, a GSI Query filters on
// those attributes). What does NOT map is everything else DynamoDB provisions that the
// FerretDB-backed store does not model: read/write capacity (ProvisionedThroughput), LOCAL
// secondary indexes, streams, per-table SSE, and PITR/import/restore. Those are behavior-bearing,
// so they BLOCK — a table that silently lacked its stream is the worst shape (looks created, wrong
// at query time). BillingMode is advisory metadata (there is no capacity behind the store), so it
// and ProvisionedThroughput are declared caveats rather than blockers.
func translateDynamoDBTable(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	// Only the properties we can honor are `known`; the long tail (LocalSecondaryIndexes,
	// StreamSpecification, SSESpecification, KinesisStreamSpecification,
	// PointInTimeRecoverySpecification, ImportSourceSpecification, …) is deliberately absent, so
	// blockUnknownProps refuses it — fail-closed, never a silent drop.
	known := map[string]bool{
		"TableName": true, "KeySchema": true, "AttributeDefinitions": true,
		"BillingMode": true, "ProvisionedThroughput": true, "TimeToLiveSpecification": true,
		"Tags": true, "DeletionProtectionEnabled": true, "TableClass": true,
		"GlobalSecondaryIndexes": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	f = append(f, shapeFindings(id, props, []string{"KeySchema", "AttributeDefinitions", "GlobalSecondaryIndexes"}, []string{"TimeToLiveSpecification"}, nil)...)

	// AttributeDefinitions gives each key attribute its scalar type.
	attrType := map[string]string{}
	if defs, ok := props["AttributeDefinitions"].([]any); ok {
		for _, d := range defs {
			dm, ok := d.(map[string]any)
			if !ok {
				continue
			}
			n, _ := concrete(dm["AttributeName"])
			t, _ := concrete(dm["AttributeType"])
			if n != "" && t != "" {
				attrType[n] = t
			}
		}
	}

	spec := map[string]any{}
	if tn, ok := concrete(props["TableName"]); ok && tn != "" {
		spec["tableName"] = tn
	}

	// KeySchema -> hashKey / rangeKey, joined with AttributeDefinitions for the type.
	hashName, rangeName := "", ""
	if ks, ok := props["KeySchema"].([]any); ok {
		for _, e := range ks {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			an, _ := concrete(em["AttributeName"])
			switch em["KeyType"] {
			case "HASH":
				hashName = an
			case "RANGE":
				rangeName = an
			}
		}
	}
	if hashName == "" {
		f = append(f, Finding{"Resource " + id, "a Table requires a KeySchema with a HASH (partition) key"})
	} else {
		spec["hashKey"] = dynamoKeyAttr(id, hashName, attrType, &f)
	}
	if rangeName != "" {
		spec["rangeKey"] = dynamoKeyAttr(id, rangeName, attrType, &f)
	}

	if bm, ok := concrete(props["BillingMode"]); ok && bm != "" {
		spec["billingMode"] = bm
	}

	// TTL maps to the shim's reaper (#104). Enabled without an attribute is a malformed request.
	if ttl, ok := props["TimeToLiveSpecification"].(map[string]any); ok {
		enabled, ff := boolProp(id, ttl, "Enabled", false)
		f = append(f, ff...)
		attr, _ := concrete(ttl["AttributeName"])
		if enabled {
			if attr == "" {
				f = append(f, Finding{"Resource " + id, "TimeToLiveSpecification is Enabled but names no AttributeName"})
			} else {
				spec["ttlAttribute"] = attr
			}
		}
	}

	// Global secondary indexes: name + key schema map (backed by a Mongo index; a GSI Query filters
	// on those attributes). Projection (KEYS_ONLY/INCLUDE) and per-index throughput don't apply —
	// the store keeps full items and has no capacity model — so they are caveats, not blocks.
	gsiProjection, gsiThroughput := false, false
	if gsiList, ok := props["GlobalSecondaryIndexes"].([]any); ok && len(gsiList) > 0 {
		var gsis []any
		for _, g := range gsiList {
			gm, ok := g.(map[string]any)
			if !ok {
				continue
			}
			gsi := map[string]any{}
			if n, ok := concrete(gm["IndexName"]); ok && n != "" {
				gsi["name"] = n
			} else {
				f = append(f, Finding{"Resource " + id, "a GlobalSecondaryIndex requires an IndexName"})
			}
			gh, gr := "", ""
			if ks, ok := gm["KeySchema"].([]any); ok {
				for _, e := range ks {
					em, ok := e.(map[string]any)
					if !ok {
						continue
					}
					an, _ := concrete(em["AttributeName"])
					switch em["KeyType"] {
					case "HASH":
						gh = an
					case "RANGE":
						gr = an
					}
				}
			}
			if gh == "" {
				f = append(f, Finding{"Resource " + id, "GlobalSecondaryIndex " + fmt.Sprint(gsi["name"]) + " requires a HASH key"})
			} else {
				gsi["hashKey"] = dynamoKeyAttr(id, gh, attrType, &f)
			}
			if gr != "" {
				gsi["rangeKey"] = dynamoKeyAttr(id, gr, attrType, &f)
			}
			if _, ok := gm["Projection"]; ok {
				gsiProjection = true
			}
			if _, ok := gm["ProvisionedThroughput"]; ok {
				gsiThroughput = true
			}
			gsis = append(gsis, gsi)
		}
		spec["globalSecondaryIndexes"] = gsis
	}

	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Table", Name: ctx.name(id), Spec: spec}
	if gsiProjection {
		m.Caveats = append(m.Caveats, "a GSI Projection (KEYS_ONLY/INCLUDE) is not enforced — the store keeps full items, so every index projects ALL")
	}
	if gsiThroughput {
		m.Caveats = append(m.Caveats, "per-GSI ProvisionedThroughput dropped — the store has no capacity model")
	}
	if _, ok := props["ProvisionedThroughput"]; ok {
		m.Caveats = append(m.Caveats, "ProvisionedThroughput dropped — the FerretDB-backed store has no read/write capacity model to provision")
	}
	if _, ok := props["BillingMode"]; ok {
		m.Caveats = append(m.Caveats, "BillingMode is advisory only — there is no capacity/billing behind the store")
	}
	for _, p := range []string{"Tags", "DeletionProtectionEnabled", "TableClass"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — no open-infra equivalent for the FerretDB-backed store")
		}
	}
	m.Caveats = append(m.Caveats, "the table functions only where the aws-shim DynamoDB front door is enabled (opt-in, off by default) — this registers the table's name + key schema, it does not stand up a separate managed service")
	return m, f
}

// dynamoKeyAttr builds a {name,type} key attribute, joining the KeySchema name to its
// AttributeDefinitions scalar type. A key with no matching definition, or a non-scalar type,
// blocks — the store keys items by these attributes, so an unknown key type is not guessable.
func dynamoKeyAttr(id, name string, attrType map[string]string, f *[]Finding) map[string]any {
	t := attrType[name]
	switch t {
	case "S", "N", "B":
	case "":
		*f = append(*f, Finding{"Resource " + id, "key attribute " + name + " has no matching AttributeDefinitions entry giving its type (S/N/B)"})
	default:
		*f = append(*f, Finding{"Resource " + id, "key attribute " + name + " has non-scalar type " + t + " — a DynamoDB key must be S, N, or B"})
	}
	return map[string]any{"name": name, "type": t}
}

// ---- AWS::IAM::User -> kind: User ----
//
// The IDENTITY maps: an open-infra User is a named principal that gets its permissions from
// group membership (a Group's ClusterRole), exactly the AWS best-practice shape (perms via
// groups, not inline user policies). So UserName + Groups translate; the permission model does
// NOT — an IAM user's ManagedPolicyArns / inline Policies / PermissionsBoundary are AWS policy
// documents (service:Action over ARNs) with no faithful open-infra RBAC form, and dropping them
// would silently strip the user's permissions. They BLOCK (attach permissions via open-infra
// Groups instead).
func translateIAMUser(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"UserName": true, "Groups": true, "ManagedPolicyArns": true, "Policies": true,
		"PermissionsBoundary": true, "LoginProfile": true, "Path": true, "Tags": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	for _, p := range []string{"ManagedPolicyArns", "Policies", "PermissionsBoundary"} {
		if _, ok := props[p]; ok {
			f = append(f, Finding{"Resource " + id, p + " has no faithful open-infra form — AWS policy documents (service:Action over ARNs) don't map to k8s RBAC; grant permissions via open-infra Group membership (a Group's ClusterRole), not policies on the user"})
		}
	}

	spec := map[string]any{"source": "local"}
	if n, ok := concrete(props["UserName"]); ok && n != "" {
		spec["displayName"] = n
	}
	if groups, ok := props["Groups"].([]any); ok && len(groups) > 0 {
		var gs []any
		for _, g := range groups {
			gv, cok := concrete(g)
			if !cok {
				f = append(f, Finding{"Resource " + id, "a group membership references a cross-resource value with no concrete name"})
				continue
			}
			gs = append(gs, gv)
		}
		spec["groups"] = gs
	}
	m := &Manifest{APIVersion: "iam.openinfra.dev/v1", Kind: "User", Name: ctx.name(id), Spec: spec}
	m.Caveats = append(m.Caveats, "the user is created without a password (source: local) — set a password separately; group names must name existing open-infra Groups (the authority relocation: permissions come from a Group's ClusterRole)")
	if _, ok := props["LoginProfile"]; ok {
		m.Caveats = append(m.Caveats, "LoginProfile dropped — set the user's password via an open-infra password Secret, not an inline console password")
	}
	if p, ok := concrete(props["Path"]); ok && p != "" && p != "/" {
		m.Caveats = append(m.Caveats, "Path "+p+" dropped — open-infra users have no IAM path")
	}
	return m, f
}

// ---- AWS::IAM::Role (EC2 instance-trust) -> kind: Role (trust: [vm]) ----
//
// The create-faithful part of an EC2 instance role is its TRUST: an AssumeRolePolicyDocument whose only
// principal is the ec2.amazonaws.com service maps to a kind: Role that trusts the "vm" service
// principal — assumable by a VM that names it as spec.instanceRole (the container-credentials path). That
// is the one trust shape derivable from the template; any OTHER principal (an AWS account/ARN, a
// federated/SAML/OIDC principal, or a mix) has no faithful open-infra form and REFUSES, exactly as a
// non-EC2 role did before.
//
// Permissions: the role's inline Policies ARE folded in, as companion kind: Policy objects (spec.dataPlane,
// appliesTo Role::<name>) via Manifest.Extra — the data-plane subset the shim fronts, imported by the same
// engine AWS::IAM::Policy uses — s3/sqs/…/ecr actions (ecr: Repository::<name> from a repository ARN, "*" for
// ecr:GetAuthorizationToken). A policy Resource that references an in-stack bucket/queue/… by !GetAtt <X>.Arn,
// or by ${X.Arn}/${X} inside an Fn::Sub (`!Sub "${Bucket.Arn}/*"`), is resolved to that resource's ARN first,
// so the common template shapes translate. ManagedPolicyArns stay a caveat (AWS-managed policies are not
// attached).
func translateIAMRole(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"AssumeRolePolicyDocument": true, "RoleName": true, "Description": true,
		"ManagedPolicyArns": true, "Policies": true, "PermissionsBoundary": true,
		"Path": true, "Tags": true, "MaxSessionDuration": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	svcs, ok := trustServices(props["AssumeRolePolicyDocument"])
	trust := []any{}
	appsyncTrust := false
	for _, s := range svcs {
		switch s {
		case "ec2.amazonaws.com":
			trust = []any{"vm"}
		case "appsync.amazonaws.com":
			appsyncTrust = true
		default:
			ok = false
		}
	}
	if !ok {
		f = append(f, Finding{"Resource " + id, "only an EC2 instance role or an AppSync service role translates: the AssumeRolePolicyDocument must Allow sts:AssumeRole for the ec2.amazonaws.com and/or appsync.amazonaws.com service principals and nothing else. A role trusting another service, an account/ARN, a federated/SAML/OIDC principal, or a mix with one of those has no template-derivable open-infra trust — author the kind: Role natively (spec.trust)"})
		return nil, f
	}
	spec := map[string]any{"trust": trust}
	if d, ok := concrete(props["Description"]); ok && d != "" {
		spec["description"] = d
	}
	m := &Manifest{APIVersion: "iam.openinfra.dev/v1", Kind: "Role", Name: ctx.name(id), Spec: spec}
	if appsyncTrust {
		// AppSync assumes a service role to reach a data source, and the role's policy bounds what the
		// source's resolvers may do. open-appsync reaches its sources with the engine's own connection, so
		// nothing assumes the role here: the trust entry has no open-infra principal and is left out, the
		// role exists (as on AWS, GetRole finds it) with its policies attached, and grants nothing.
		m.Caveats = append(m.Caveats, "trusted by the appsync.amazonaws.com service: the role exists with its policies, but nothing assumes it — open-appsync reaches its data sources with the engine's own connection, so the role's policies do not limit what the resolvers that use it read or write")
	}
	// Inline Policies -> companion kind: Policy objects (spec.dataPlane, appliesTo Role::<name>), which
	// govern this role's assumed sessions at the aws-shim. This is the narrow data-plane subset the
	// finding asked for: s3/sqs/... actions on recognizable in-stack ARNs, imported by the same engine
	// AWS::IAM::Policy uses. Fail-closed: any part the importer cannot honor blocks the whole Role (a
	// silently-dropped Allow/Deny is a scope hole).
	if pol, ok := props["Policies"]; ok {
		extras, pf := roleInlinePolicies(id, pol, ctx)
		if len(pf) > 0 {
			f = append(f, pf...)
			return nil, f
		}
		m.Extra = extras
		m.Caveats = append(m.Caveats, fmt.Sprintf("inline Policies translated to %d companion kind: Policy object(s) (spec.dataPlane, appliesTo Role::%s) that govern this role's assumed sessions — enforced where the aws-shim data-plane front doors are enabled (opt-in, off by default)", len(extras), ctx.name(id)))
	}
	if v, ok := props["ManagedPolicyArns"]; ok {
		extra, cav, mf := managedPolicyCompanions(id, ctx.name(id), v)
		f = append(f, mf...)
		m.Extra = append(m.Extra, extra...)
		m.Caveats = append(m.Caveats, cav...)
	}
	if _, ok := props["PermissionsBoundary"]; ok {
		m.Caveats = append(m.Caveats, "PermissionsBoundary not mapped — set spec.permissionBoundary to a kind: Policy natively if a boundary is required")
	}
	if n, ok := concrete(props["RoleName"]); ok && n != "" && n != m.Name {
		m.Caveats = append(m.Caveats, fmt.Sprintf("RoleName %q is not used — the role is kind: Role %q", n, m.Name))
	}
	if p, ok := concrete(props["Path"]); ok && p != "" && p != "/" {
		m.Caveats = append(m.Caveats, "Path "+p+" dropped — open-infra roles have no IAM path")
	}
	if v, ok := props["MaxSessionDuration"]; ok {
		// The role's session limit (spec.maxSessionDuration), enforced at sts:AssumeRole: 3600..43200
		// seconds, as AWS validates it.
		s, _ := concrete(v)
		secs, err := strconv.Atoi(s)
		if err != nil || secs < 3600 || secs > 43200 {
			f = append(f, Finding{"Resource " + id, "MaxSessionDuration must be a number of seconds from 3600 to 43200"})
			return nil, f
		}
		spec["maxSessionDuration"] = secs
	}
	return m, f
}

// roleInlinePolicies translates an IAM Role's inline Policies into companion kind: Policy manifests,
// each a data-plane policy (spec.dataPlane) whose appliesTo is this role (Role::<name>) so it governs
// the role's assumed sessions. It reuses the same importer as AWS::IAM::Policy, and is fail-closed:
// any statement the data plane cannot honor (an unfronted service, an unrecognizable ARN, a Condition)
// produces a Finding that blocks the Role rather than attaching a partial grant.
//
// It prefers the RAW Policies list (from ctx) so that a Resource given as !GetAtt <X>.Arn on an in-stack
// bucket/queue/… is synthesized to that resource's ARN before import (the common inline-policy shape);
// it falls back to the already-resolved list when there is no stack context.
func roleInlinePolicies(roleID string, resolved any, ctx *stackCtx) ([]*Manifest, []Finding) {
	list, _ := resolved.([]any)
	if ctx != nil {
		if raw, ok := ctx.rawProps(roleID); ok {
			if rawPol, ok := raw["Policies"]; ok {
				// Resolve the WHOLE raw Policies value, not each PolicyDocument in isolation: first
				// synthesize in-stack !GetAtt <X>.Arn to synthetic ARNs, then resolve the rest. This
				// evaluates an !If (Fn::If) wrapping an entry — or the whole list — and drops
				// AWS::NoValue branches, so a conditionally-included inline policy resolves to its
				// chosen branch. Reading the raw per-entry map instead made every !If-wrapped entry a
				// literal {Fn::If: ...} with no PolicyDocument, so it was always refused (the regression).
				if rl, ok := ctx.resolver.resolve(synthInStackARNs(rawPol, ctx)).([]any); ok {
					list = rl
				}
			}
		}
	}
	if list == nil {
		return nil, []Finding{{"Resource " + roleID, "Policies must be a list of { PolicyName, PolicyDocument }"}}
	}
	roleName := ctx.name(roleID)
	var out []*Manifest
	var f []Finding
	for i, entry := range list {
		p, ok := entry.(map[string]any)
		if !ok {
			f = append(f, Finding{"Resource " + roleID, fmt.Sprintf("Policies[%d] is not an object", i)})
			continue
		}
		doc, ok := p["PolicyDocument"]
		if !ok {
			f = append(f, Finding{"Resource " + roleID, fmt.Sprintf("Policies[%d] requires a PolicyDocument", i)})
			continue
		}
		pname := p["PolicyName"]
		// doc and pname are already fully resolved — the whole raw Policies list was run through
		// synthInStackARNs + resolve above, so in-stack ARNs and intrinsics are already applied.
		docJSON, err := json.Marshal(doc)
		if err != nil {
			f = append(f, Finding{"Resource " + roleID, fmt.Sprintf("Policies[%d] PolicyDocument is not serializable: %s", i, err.Error())})
			continue
		}
		stmts, unsupported, err := policyengine.ImportAWS(string(docJSON))
		if err != nil {
			f = append(f, Finding{"Resource " + roleID, fmt.Sprintf("Policies[%d] did not parse as an AWS policy: %s", i, err.Error())})
			continue
		}
		for _, u := range unsupported {
			f = append(f, Finding{"Resource " + roleID, fmt.Sprintf("Policies[%d]: cannot faithfully translate this policy: %s — narrow the inline policy to s3/sqs/dynamodb/... actions on recognizable in-stack ARNs with no conditions, or author a kind: Policy spec.dataPlane natively", i, u)})
		}
		for _, u := range unresolvedPolicyResources(stmts) {
			f = append(f, Finding{"Resource " + roleID, fmt.Sprintf("Policies[%d]: resource %s names a value that does not resolve here — a grant on it would name no real resource; reference an in-stack bucket/queue/table/function/topic (!GetAtt X.Arn, ${X.Arn}, ${X}) or a literal ARN", i, u)})
		}
		if len(stmts) == 0 && len(unsupported) == 0 {
			f = append(f, Finding{"Resource " + roleID, fmt.Sprintf("Policies[%d] has no statements the data plane can honor", i)})
		}
		if len(f) > 0 {
			continue // keep collecting findings across policies, but emit no partial manifest
		}
		name := companionPolicyName(roleName, "inline-"+strconv.Itoa(i))
		if n, ok := concrete(pname); ok && n != "" {
			name = companionPolicyName(roleName, k8sName(n))
		}
		out = append(out, &Manifest{
			APIVersion: "iam.openinfra.dev/v1", Kind: "Policy", Name: name,
			Spec: map[string]any{"dataPlane": map[string]any{
				"appliesTo":  []any{"Role::" + roleName},
				"statements": statementsToSpec(stmts),
			}},
		})
	}
	return out, f
}

// synthInStackARNs walks a raw policy document and replaces every {Fn::GetAtt: [X, Arn]} (or "X.Arn")
// that targets an in-stack resource of a shim-fronted type with that resource's synthetic ARN, so the
// policy importer resolves it to the right Bucket::/Queue::/… principal instead of refusing an
// unresolvable <X.Arn>. Inside an Fn::Sub string (both the string and the [string, vars] form) it does the
// same for ${X.Arn}, and for ${X} where X's Ref is a name or ARN (a bucket/table/function name, a topic
// ARN) — the `!Sub "${Bucket.Arn}/*"` / `!Sub "arn:aws:s3:::${Bucket}/*"` object-ARN forms. Every other
// node, and every other ${} (parameters, pseudo-parameters, Sub variables), is left for the normal
// resolver. This is the in-stack bucket/queue ARN case the inline-policy ask (B2) called for.
func synthInStackARNs(v any, ctx *stackCtx) any {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 1 {
			if ga, ok := t["Fn::GetAtt"]; ok {
				if id, attr, ok := splitGetAtt(ga); ok && attr == "Arn" {
					if arn, ok := inStackARN(id, ctx); ok {
						return arn
					}
				}
			}
			if sub, ok := t["Fn::Sub"]; ok {
				return map[string]any{"Fn::Sub": synthSubArg(sub, ctx)}
			}
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = synthInStackARNs(e, ctx)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = synthInStackARNs(e, ctx)
		}
		return out
	}
	return v
}

// synthSubArg rewrites an Fn::Sub argument for synthInStackARNs: in the template string, ${X.Arn} and ${X}
// naming an in-stack shim-fronted resource become that resource's ARN / Ref value; a [string, vars] form
// keeps its variables (walked for in-stack !GetAtt <X>.Arn themselves), and a name a variable defines is
// the variable's, never rewritten. Anything else is returned unchanged for the normal resolver.
func synthSubArg(arg any, ctx *stackCtx) any {
	switch a := arg.(type) {
	case string:
		return synthSubTemplate(a, nil, ctx)
	case []any:
		if len(a) == 0 {
			return arg
		}
		tmpl, ok := a[0].(string)
		if !ok {
			return arg
		}
		var varMap map[string]any
		if len(a) >= 2 {
			varMap, _ = a[1].(map[string]any)
		}
		out := make([]any, len(a))
		out[0] = synthSubTemplate(tmpl, varMap, ctx)
		for i := 1; i < len(a); i++ {
			out[i] = synthInStackARNs(a[i], ctx)
		}
		return out
	}
	return arg
}

// synthSubTemplate substitutes ${X.Arn} / ${X} for in-stack shim-fronted resources in an Fn::Sub template
// string, leaving every other ${} — a ${!Literal} escape, a Sub variable, a parameter, a pseudo-parameter,
// an attribute other than Arn, an out-of-stack or unfronted resource — exactly as written.
func synthSubTemplate(tmpl string, vars map[string]any, ctx *stackCtx) string {
	var b strings.Builder
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] == '$' && i+1 < len(tmpl) && tmpl[i+1] == '{' {
			end := strings.IndexByte(tmpl[i:], '}')
			if end < 0 {
				b.WriteString(tmpl[i:])
				break
			}
			name := tmpl[i+2 : i+end]
			whole := tmpl[i : i+end+1]
			i += end
			if v, ok := synthSubName(name, vars, ctx); ok {
				b.WriteString(v)
			} else {
				b.WriteString(whole)
			}
			continue
		}
		b.WriteByte(tmpl[i])
	}
	return b.String()
}

// synthSubName resolves one ${name} for synthSubTemplate: "X.Arn" → the in-stack ARN, "X" → the in-stack
// Ref value. ok=false leaves it to the normal resolver.
func synthSubName(name string, vars map[string]any, ctx *stackCtx) (string, bool) {
	if name == "" || strings.HasPrefix(name, "!") || strings.HasPrefix(name, "AWS::") {
		return "", false
	}
	if _, isVar := vars[name]; isVar {
		return "", false
	}
	var v string
	var ok bool
	if id, attr, dot := strings.Cut(name, "."); dot {
		if attr != "Arn" {
			return "", false
		}
		v, ok = inStackARN(id, ctx)
	} else {
		v, ok = inStackRef(name, ctx)
	}
	// A value that itself carries ${…} would be re-read as a substitution — never splice one in.
	if !ok || strings.Contains(v, "${") {
		return "", false
	}
	return v, true
}

// inStackRef is the Ref value of an in-stack resource of a shim-fronted type where that value is usable
// inside a policy ARN: a bucket's, table's, or function's name, or a topic's ARN (what Ref returns for each
// on AWS). ok=false otherwise — a queue's Ref is its URL, never part of an ARN.
func inStackRef(id string, ctx *stackCtx) (string, bool) {
	if ctx == nil {
		return "", false
	}
	res, in := ctx.template.Resources[id]
	if !in {
		return "", false
	}
	if v, ok := serviceRef(id, ctx); ok { // a stack queue/topic/parameter/key in the shim's own API store
		return v, true
	}
	if v, ok := serviceStatic(id, "", ctx); ok { // a stack secret, log group, rule, bus, repository or alarm (translate_service.go)
		return v, true
	}
	switch res.Type {
	case "AWS::S3::Bucket":
		return ctx.bucketName(id), true
	case "AWS::DynamoDB::Table":
		return inStackName(id, "TableName", ctx), true
	case "AWS::Lambda::Function":
		return ctx.functionName(id), true
	case "AWS::SNS::Topic":
		return inStackARN(id, ctx)
	case waitConditionHandleType:
		stack := ""
		if ctx.resolver != nil {
			stack, _ = ctx.resolver.pseudo["AWS::StackName"].(string)
		}
		return handleURL(ctx.signalURL, stack, id), true
	}
	return "", false
}

// inStackName is an in-stack resource's AWS name: its name property (QueueName/BucketName/…) when set to a
// concrete value, else the k8s-safe logical id — the same name the open-infra kind gets.
func inStackName(id, prop string, ctx *stackCtx) string {
	p, _ := ctx.resolveProps(id)
	if n, ok := concrete(p[prop]); ok && n != "" {
		return n
	}
	return ctx.name(id)
}

// inStackARN synthesizes the ARN of an in-stack resource of a shim-fronted type, using its AWS name
// (QueueName/BucketName/… when set, else the k8s-safe logical id — the same name the open-infra kind
// gets) so the imported data-plane policy scopes to the resource the app actually addresses. Region and
// account are the pseudo-param placeholders (open-infra has no real AWS account). ok=false for a type
// the shim does not front (the importer then refuses, as before).
func inStackARN(id string, ctx *stackCtx) (string, bool) {
	if ctx == nil {
		return "", false
	}
	if v, ok := serviceStatic(id, "Arn", ctx); ok {
		return v, true
	}
	res, in := ctx.template.Resources[id]
	if !in {
		return "", false
	}
	name := func(prop string) string { return inStackName(id, prop, ctx) }
	// The install's identity, so a synthesized ARN is the one the aws-shim reports for the resource.
	ident := awsidentity.Current()
	switch res.Type {
	case "AWS::S3::Bucket":
		return awsidentity.S3BucketARN(ctx.bucketName(id)), true
	case "AWS::SQS::Queue":
		return ident.RegionalARN("sqs", name("QueueName")), true
	case "AWS::SNS::Topic":
		return ident.RegionalARN("sns", name("TopicName")), true
	case "AWS::DynamoDB::Table":
		return ident.RegionalARN("dynamodb", "table/"+name("TableName")), true
	case "AWS::Lambda::Function":
		return ident.RegionalARN("lambda", "function:"+ctx.functionName(id)), true
	}
	return "", false
}

// trustServices returns the service principals an AssumeRolePolicyDocument trusts, sorted, when every
// statement Allows sts:AssumeRole for service principals and nothing else; ok is false for any other
// shape (an account/ARN, a federated principal, a Deny, another action). The caller decides which
// services have an open-infra form.
func trustServices(doc any) (svcs []string, ok bool) {
	m, isMap := doc.(map[string]any)
	if !isMap {
		return nil, false
	}
	stmts, isList := m["Statement"].([]any)
	if !isList || len(stmts) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	for _, raw := range stmts {
		s, isStmt := raw.(map[string]any)
		if !isStmt {
			return nil, false
		}
		if eff, _ := concrete(s["Effect"]); eff != "Allow" {
			return nil, false
		}
		p, isP := s["Principal"].(map[string]any)
		if !isP || len(p) != 1 {
			return nil, false
		}
		var names []any
		if l, isL := p["Service"].([]any); isL {
			names = l
		} else if _, has := p["Service"]; has {
			names = []any{p["Service"]}
		}
		if len(names) == 0 {
			return nil, false
		}
		for _, n := range names {
			svc, isStr := concrete(n)
			if !isStr || svc == "" {
				return nil, false
			}
			seen[svc] = true
		}
		if !allAssumeRole(s["Action"]) {
			return nil, false
		}
	}
	for s := range seen {
		svcs = append(svcs, s)
	}
	sort.Strings(svcs)
	return svcs, true
}

// onlyStringValue reports whether v is exactly want, either as a bare string or a single-element list.
func onlyStringValue(v any, want string) bool {
	if s, ok := concrete(v); ok {
		return s == want
	}
	if l, ok := v.([]any); ok && len(l) == 1 {
		s, ok := concrete(l[0])
		return ok && s == want
	}
	return false
}

// allAssumeRole reports whether every action in v is sts:AssumeRole (string or list).
func allAssumeRole(v any) bool {
	check := func(x any) bool { s, ok := concrete(x); return ok && s == "sts:AssumeRole" }
	if l, ok := v.([]any); ok {
		if len(l) == 0 {
			return false
		}
		for _, a := range l {
			if !check(a) {
				return false
			}
		}
		return true
	}
	return check(v)
}

// ---- AWS::IAM::InstanceProfile -> (implicit) ----
//
// An instance profile is the AWS container that binds a Role to an EC2 instance. open-infra binds the
// role directly on the VM (kind: VirtualMachine spec.instanceRole), so the profile provisions nothing
// on its own — an EC2::Instance's IamInstanceProfile is resolved THROUGH it to the role name. A no-op
// so a stack carrying it is not blocked.
func translateIAMInstanceProfile(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"Roles": true, "InstanceProfileName": true, "Path": true, "Tags": true}
	return nil, blockUnknownProps(id, props, known)
}

// resolveInstanceRole turns an EC2::Instance's IamInstanceProfile into a kind: Role name. It follows a
// !Ref/!GetAtt to an in-stack AWS::IAM::InstanceProfile, then that profile's first Roles entry (a
// !Ref to an in-stack AWS::IAM::Role), returning that role's k8s name. Returns ("", false) when it
// cannot resolve to an in-stack role (an out-of-stack profile/arn), so the caller can caveat rather
// than guess a role name.
func resolveInstanceRole(id string, ctx *stackCtx) (string, bool) {
	if ctx == nil {
		return "", false
	}
	raw, ok := ctx.rawProps(id)
	if !ok {
		return "", false
	}
	profID, ok := getAttTarget(raw["IamInstanceProfile"])
	if !ok {
		return "", false
	}
	prof, in := ctx.template.Resources[profID]
	if !in || prof.Type != "AWS::IAM::InstanceProfile" {
		return "", false
	}
	roles, ok := prof.Properties["Roles"].([]any)
	if !ok || len(roles) == 0 {
		return "", false
	}
	roleID, ok := getAttTarget(roles[0])
	if !ok {
		return "", false
	}
	if r, in := ctx.template.Resources[roleID]; !in || r.Type != "AWS::IAM::Role" {
		return "", false
	}
	return ctx.name(roleID), true
}

// ---- AWS::IAM::Policy -> kind: Policy (spec.dataPlane) ----
//
// The reason IAM::Policy was refused was that an AWS policy document has no faithful RBAC form. The
// data-plane policy engine (kind: Policy spec.dataPlane, Cedar-backed, enforced at the aws-shim)
// removes that barrier for exactly the actions the shim fronts — the services in
// policyengine.SupportedServices (the data-plane services — s3, dynamodb, lambda, sqs, sns, kinesis, kms,
// ssm, secretsmanager, ecr, ecs, logs, rds, ses, apigateway, cloudwatch, cloudfront, events, acm,
// cognito-idp, glue, athena, eks — and the control services the shim also checks per resource: iam,
// states, cloudformation, appsync), plus the EC2 front door's named actions
// (policyengine.SupportedActions). So this translator imports the
// DATA-PLANE part of the document (policyengine.ImportAWS) into a real, enforced Policy.
//
// It is fail-closed to a fault: a partially-translated security policy is worse than none (a dropped
// Deny or condition is a hole; a dropped Allow is a silent scope change). So if the importer reports
// ANY part it cannot honor — an action for a service with no data plane, an unrecognizable ARN, or a
// Condition (not importable yet) — the whole resource BLOCKS with a precise list, pointing the author
// at kind: Policy spec.dataPlane to express it natively. Only a policy that is PURELY actions on the
// fronted services (policyengine.SupportedServices) on recognizable ARNs with no conditions translates.
func translateIAMPolicy(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	return importAWSPolicyResource(id, props, ctx, "AWS::IAM::Policy", map[string]bool{
		"PolicyName": true, "PolicyDocument": true,
		"Groups": true, "Users": true, "Roles": true,
	})
}

// ---- AWS::IAM::ManagedPolicy -> kind: Policy (spec.dataPlane) ----
//
// Same story as IAM::Policy, and unlocked by the same engine: a ManagedPolicy's PolicyDocument has a
// data-plane part that now translates. A ManagedPolicy can carry inline Groups/Users/Roles
// attachments — those bind the imported dataPlane exactly as an inline policy's do. A STANDALONE
// ManagedPolicy (the usual shape — attached elsewhere via ManagedPolicyArns) names no principal here,
// so it still blocks loudly. ManagedPolicyName/Description/Path are metadata with no open-infra
// equivalent (declared caveats).
func translateManagedPolicy(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	return importAWSPolicyResource(id, props, ctx, "AWS::IAM::ManagedPolicy", map[string]bool{
		"ManagedPolicyName": true, "PolicyDocument": true, "Description": true, "Path": true,
		"Groups": true, "Users": true, "Roles": true,
	})
}

// importAWSPolicyResource is the shared core behind the IAM::Policy and IAM::ManagedPolicy
// translators: import the document's data-plane part into a kind: Policy spec.dataPlane bound to the
// resource's Users/Groups, fail-closed on anything unmappable. `known` is the per-type property
// allowlist; `cfnType` names the type in findings. With a stack context the document is re-resolved from
// its raw form through synthInStackARNs, so an in-stack resource referenced by !GetAtt X.Arn or ${X.Arn}/${X}
// inside an Fn::Sub resolves to its ARN exactly as in a Role's inline policy.
func importAWSPolicyResource(id string, props map[string]any, ctx *stackCtx, cfnType string, known map[string]bool) (*Manifest, []Finding) {
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	doc, ok := props["PolicyDocument"]
	if !ok {
		f = append(f, Finding{"Resource " + id, cfnType + " requires a PolicyDocument"})
		return nil, f
	}
	if ctx != nil {
		if raw, ok := ctx.rawProps(id); ok {
			if rawDoc, ok := raw["PolicyDocument"]; ok {
				doc = ctx.resolver.resolve(synthInStackARNs(rawDoc, ctx))
			}
		}
	}
	docJSON, err := json.Marshal(doc)
	if err != nil {
		f = append(f, Finding{"Resource " + id, "PolicyDocument is not serializable: " + err.Error()})
		return nil, f
	}
	stmts, unsupported, err := policyengine.ImportAWS(string(docJSON))
	if err != nil {
		f = append(f, Finding{"Resource " + id, "PolicyDocument did not parse as an AWS policy: " + err.Error()})
		return nil, f
	}
	for _, u := range unsupported {
		f = append(f, Finding{"Resource " + id, "cannot faithfully translate this policy: " + u +
			" — express the whole policy natively on kind: Policy spec.dataPlane, or narrow the CFN policy to s3/dynamodb/lambda actions on recognizable ARNs with no conditions"})
	}
	for _, u := range unresolvedPolicyResources(stmts) {
		f = append(f, Finding{"Resource " + id, "resource " + u + " names a value that does not resolve here — a grant on it would name no real resource; use a literal ARN"})
	}
	if len(stmts) == 0 && len(unsupported) == 0 {
		f = append(f, Finding{"Resource " + id, "PolicyDocument has no statements the data plane can honor"})
	}

	appliesTo, requires := iamPolicyPrincipals(id, props, ctx, &f)
	if len(appliesTo) == 0 && len(f) == 0 {
		f = append(f, Finding{"Resource " + id, cfnType + " names no Users or Groups — a policy must attach to at least one principal (a standalone policy attached elsewhere via ManagedPolicyArns is not translatable here; open-infra has no unattached policy grant)"})
	}
	if len(f) > 0 {
		return nil, f
	}

	spec := map[string]any{
		"dataPlane": map[string]any{
			"appliesTo":  appliesTo,
			"statements": statementsToSpec(stmts),
		},
	}
	m := &Manifest{APIVersion: "iam.openinfra.dev/v1", Kind: "Policy", Name: ctx.name(id), Spec: spec, Requires: requires}
	m.Caveats = append(m.Caveats,
		"enforced only at the aws-shim data-plane front doors (S3/DynamoDB/Lambda), which are opt-in (off by default); it does not grant or restrict the Kubernetes control plane (that stays RBAC + the permission boundary)",
		"appliesTo names must match existing open-infra Users/Groups; the policy tightens within a coarse RBAC grant (it can Deny, never widen)")
	for _, p := range []string{"PolicyName", "ManagedPolicyName", "Description", "Path"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" is metadata with no open-infra equivalent (the Policy is named after the stack resource) — dropped")
		}
	}
	if roles, ok := props["Roles"].([]any); ok && len(roles) > 0 {
		m.Caveats = append(m.Caveats,
			"a Roles attachment maps to dataPlane.appliesTo: [Role::<name>] and governs an assumed sts:AssumeRole session (#111) — but only once each named kind: Role exists and carries a trust policy (authored natively); until then the Role is unassumable (fail closed)")
	}
	return m, f
}

// iamPolicyPrincipals turns an inline policy's Users/Groups/Roles into dataPlane appliesTo principals.
// A Roles attachment is honored: the shim authenticates assumed-role sessions (sts:AssumeRole, #111) and
// the data-plane engine governs "Role::<name>" principals, so the attachment governs the assumed session.
//
// The kind: Policy is created in the stack's namespace, and a Policy outside the IAM home namespace
// governs only principals of its own namespace (dataplaneauthz canonAppliesTo): a home User or Group
// named here would be governed by nothing, so a Deny guardrail would silently not apply. So a User or
// Role is either an in-stack AWS::IAM::User / AWS::IAM::Role (followed by Ref or named by its name), or a
// principal that must already exist in the stack's namespace — deploy refuses while it does not, as AWS
// refuses a policy naming a user that does not exist. A Groups attachment refuses: groups are IAM home
// identities, out of a stack's reach.
func iamPolicyPrincipals(id string, props map[string]any, ctx *stackCtx, f *[]Finding) ([]any, []Requirement) {
	var out []any
	var requires []Requirement
	var raw map[string]any
	if ctx != nil {
		raw, _ = ctx.rawProps(id)
	}
	add := func(prop, kind, cfnType string) {
		list, ok := props[prop].([]any)
		if !ok {
			if v, set := props[prop]; set && v != nil {
				*f = append(*f, Finding{"Resource " + id, fmt.Sprintf("%s must be a list (got %v)", prop, v)})
			}
			return
		}
		rawList, _ := raw[prop].([]any)
		for i, e := range list {
			n := ""
			if i < len(rawList) {
				if t, ok := getAttTarget(rawList[i]); ok && ctx.isType(t, cfnType) {
					n = ctx.name(t)
				}
			}
			if n == "" {
				if s, cok := concrete(e); cok {
					n = s
				}
			}
			if n == "" {
				*f = append(*f, Finding{"Resource " + id, prop + " references a cross-resource value with no concrete name"})
				continue
			}
			if kind == "Group" {
				*f = append(*f, Finding{"Resource " + id, "Groups attaches the policy to IAM group " + n + ", which a stack's policy cannot govern — the policy is created in the stack's namespace, and a policy there governs only that namespace's principals, while groups are IAM home identities. Attach the policy to the group natively (a kind: Policy in the IAM home namespace) rather than deploy a policy that would apply to no one"})
				continue
			}
			if !ctx.isInStackName(n, cfnType) {
				requires = append(requires, Requirement{APIVersion: "iam.openinfra.dev/v1", Kind: kind, Name: n,
					Why: "a principal this policy governs (a stack's policy governs only principals in the stack's own namespace; a policy for an IAM home " + strings.ToLower(kind) + " is attached natively)"})
			}
			out = append(out, kind+"::"+n)
		}
	}
	add("Users", "User", "AWS::IAM::User")
	add("Groups", "Group", "")
	add("Roles", "Role", "AWS::IAM::Role")
	return out, requires
}

// unresolvedPolicyResources lists the imported resources (and NotResource exclusions) that still carry an
// unresolved placeholder — e.g. `arn:aws:s3:::${Queue}/*` resolves to Bucket::<ref:Queue>, a recognizable
// ARN shape naming nothing real. Emitting it would silently grant on (or exclude) a non-resource, so the
// caller refuses instead.
func unresolvedPolicyResources(stmts []policyengine.Statement) []string {
	var out []string
	for _, s := range stmts {
		for _, r := range append(append([]string{}, s.Resources...), s.NotResources...) {
			if placeholderRe.MatchString(r) {
				out = append(out, r)
			}
		}
	}
	return out
}

// statementsToSpec renders imported Statements as the kind: Policy spec.dataPlane statement shape.
func statementsToSpec(stmts []policyengine.Statement) []any {
	out := make([]any, 0, len(stmts))
	for _, s := range stmts {
		m := map[string]any{"effect": string(s.Effect)}
		if len(s.Actions) > 0 {
			m["actions"] = toAnySlice(s.Actions)
		}
		if len(s.NotActions) > 0 {
			m["notActions"] = toAnySlice(s.NotActions)
		}
		if len(s.Resources) > 0 {
			m["resources"] = toAnySlice(s.Resources)
		}
		if len(s.NotResources) > 0 {
			m["notResources"] = toAnySlice(s.NotResources)
		}
		if len(s.Condition) > 0 {
			c := map[string]any{}
			for k, v := range s.Condition {
				c[k] = v
			}
			m["condition"] = c
		}
		if len(s.IPConditions) > 0 {
			ips := make([]any, 0, len(s.IPConditions))
			for _, ip := range s.IPConditions {
				ips = append(ips, map[string]any{"key": ip.Key, "cidr": ip.CIDR, "negate": ip.Negate})
			}
			m["ipConditions"] = ips
		}
		if len(s.LikeConditions) > 0 {
			likes := make([]any, 0, len(s.LikeConditions))
			for _, lk := range s.LikeConditions {
				likes = append(likes, map[string]any{"key": lk.Key, "pattern": lk.Pattern, "negate": lk.Negate})
			}
			m["likeConditions"] = likes
		}
		if len(s.TimeConditions) > 0 {
			times := make([]any, 0, len(s.TimeConditions))
			for _, tc := range s.TimeConditions {
				times = append(times, map[string]any{"key": tc.Key, "op": tc.Op, "target": tc.Target})
			}
			m["timeConditions"] = times
		}
		out = append(out, m)
	}
	return out
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// ---- AWS::SSM::Parameter -> kind: Parameter ----
//
// open-infra's kind: Parameter is the SSM Parameter Store equivalent (a value stored under a
// hierarchical path in Vault KV-v2, materialized into a namespace Secret). The core maps cleanly:
// Name->path, Value->value, Type (String/SecureString). A StringList is stored as its plain
// comma-separated string (open-infra has no list-typed parameter — a declared caveat). Description/
// AllowedPattern/DataType/Tags are advisory metadata with no equivalent (caveats). Parameter
// `Policies` (expiration / no-change notification) are behavior-bearing — a Vault-backed parameter
// does not auto-expire, so silently dropping one would keep a value that should have expired: they
// BLOCK.
func translateSSMParameter(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	if ctx.servedBy(id) {
		return translateSSMParameterAPI(id, props, ctx)
	}
	known := map[string]bool{
		"Name": true, "Value": true, "Type": true, "Tier": true,
		"Description": true, "AllowedPattern": true, "DataType": true, "Tags": true, "Policies": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	// SSM Parameter Policies: an Expiration policy maps to spec.expiresAt (the parameter reaper sweeps
	// it, deleting the CR + its Vault entry + Secret). Notification policies have no equivalent — a
	// declared caveat, not a block. A malformed Policies string blocks (never silently ignored).
	expiresAt, hasNotify, perr := ssmExpiration(props["Policies"])
	if perr != nil {
		f = append(f, Finding{"Resource " + id, "SSM Parameter Policies did not parse: " + perr.Error()})
	}

	spec := map[string]any{}
	if name, ok := concrete(props["Name"]); ok && name != "" {
		spec["path"] = name
	} else {
		f = append(f, Finding{"Resource " + id, "AWS::SSM::Parameter requires a Name (the hierarchical path, e.g. /app/db/host)"})
	}
	if val, ok := concrete(props["Value"]); ok {
		spec["value"] = val
	} else if _, present := props["Value"]; !present {
		f = append(f, Finding{"Resource " + id, "AWS::SSM::Parameter requires a Value"})
	} else {
		f = append(f, Finding{"Resource " + id, "Parameter Value references a cross-resource value with no concrete result — a Parameter's value must be a literal"})
	}

	listCaveat := false
	switch t, _ := concrete(props["Type"]); t {
	case "", "String":
		spec["type"] = "String"
	case "SecureString":
		spec["type"] = "SecureString"
	case "StringList":
		spec["type"] = "String"
		listCaveat = true
	default:
		f = append(f, Finding{"Resource " + id, "unknown SSM Parameter Type " + t + " (expected String, StringList, or SecureString)"})
	}
	if tier, ok := concrete(props["Tier"]); ok && tier != "" {
		spec["tier"] = tier
	}
	if expiresAt != "" {
		spec["expiresAt"] = expiresAt
	}

	if len(f) > 0 {
		return nil, f
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Parameter", Name: ctx.name(id), Spec: spec}
	if hasNotify {
		m.Caveats = append(m.Caveats, "an SSM notification policy (ExpirationNotification/NoChangeNotification) was dropped — open-infra has no parameter-notification surface; the Expiration policy itself is honored via expiresAt")
	}
	if listCaveat {
		m.Caveats = append(m.Caveats, "Type StringList is stored as a plain comma-separated string — open-infra has no list-typed parameter, so per-element list semantics are not modeled")
	}
	for _, p := range []string{"Description", "AllowedPattern", "DataType", "Tags"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" is advisory metadata with no open-infra equivalent (dropped) — a Vault-backed parameter has no server-side validation/tagging")
		}
	}
	m.Caveats = append(m.Caveats, "the value is held in Vault (KV-v2, encrypted at rest) and materialized into the namespace's Secret — needs the platform Vault configured; consume it by adding `openinfra-parameters` to an Application/Function spec.secrets")
	return m, f
}

// ssmExpiration parses an SSM Parameter Policies value (a JSON string: a list of
// {Type, Version, Attributes}) — returning the Expiration policy's Timestamp (mapped to
// spec.expiresAt), whether a notification policy is present (a declared caveat), and a parse error.
func ssmExpiration(pol any) (expiresAt string, hasNotify bool, err error) {
	if pol == nil {
		return "", false, nil
	}
	s, ok := pol.(string)
	if !ok {
		b, e := json.Marshal(pol) // some templates give Policies as a structured list already
		if e != nil {
			return "", false, fmt.Errorf("Policies is neither a JSON string nor serializable")
		}
		s = string(b)
	}
	if strings.TrimSpace(s) == "" {
		return "", false, nil
	}
	var policies []map[string]any
	if e := json.Unmarshal([]byte(s), &policies); e != nil {
		return "", false, fmt.Errorf("expected a JSON array of policy objects: %w", e)
	}
	// Every policy is checked against AWS's shape — {Type, Version "1.0", Attributes} — so a policy of an
	// unknown type, or an Expiration without a usable Timestamp, refuses instead of being skipped (a
	// value the template meant to expire would otherwise be kept).
	for i, p := range policies {
		if p == nil {
			return "", false, fmt.Errorf("policy %d is not an object", i)
		}
		for k := range p {
			if k != "Type" && k != "Version" && k != "Attributes" {
				return "", false, fmt.Errorf("policy %d has %s, which SSM does not define (Type, Version, Attributes)", i, k)
			}
		}
		if v, set := p["Version"]; set && v != "1.0" {
			return "", false, fmt.Errorf("policy %d Version must be \"1.0\" (got %v)", i, v)
		}
		attrs, _ := p["Attributes"].(map[string]any)
		if a, set := p["Attributes"]; set && attrs == nil {
			return "", false, fmt.Errorf("policy %d Attributes must be an object (got %v)", i, a)
		}
		switch typ, _ := p["Type"].(string); typ {
		case "Expiration":
			if expiresAt != "" {
				return "", false, fmt.Errorf("more than one Expiration policy")
			}
			ts, _ := attrs["Timestamp"].(string)
			if _, e := time.Parse(time.RFC3339Nano, ts); e != nil {
				return "", false, fmt.Errorf("the Expiration policy needs an ISO 8601 Attributes.Timestamp, such as 2030-01-01T00:00:00.000Z (got %v)", attrs["Timestamp"])
			}
			expiresAt = ts
		case "ExpirationNotification", "NoChangeNotification":
			hasNotify = true
		default:
			return "", false, fmt.Errorf("policy %d Type %v is not an SSM parameter policy (Expiration, ExpirationNotification, NoChangeNotification)", i, p["Type"])
		}
	}
	return expiresAt, hasNotify, nil
}

// ---- AWS::Cognito::UserPool -> kind: UserPool ----
//
// open-infra now hosts a pool (a Keycloak realm that issues OIDC tokens), so the CORE of a
// Cognito user pool maps: UserPoolName -> the realm. What does NOT transfer is Cognito-specific
// behavior. MFA enforcement and Lambda triggers are behavior-bearing and have no Keycloak-realm
// equivalent here, so they BLOCK (dropping them would silently weaken or change auth). The
// realm's own defaults cover password policy / schema / verification, so those are declared
// caveats (the pool still enforces a policy — just the realm's, not Cognito's exact rules).
func translateCognitoUserPool(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"UserPoolName": true, "MfaConfiguration": true, "Policies": true, "Schema": true,
		"LambdaConfig": true, "AutoVerifiedAttributes": true, "AliasAttributes": true,
		"UsernameAttributes": true, "EmailConfiguration": true, "SmsConfiguration": true,
		"AdminCreateUserConfig": true, "AccountRecoverySetting": true, "DeviceConfiguration": true,
		"UserPoolTags": true, "UsernameConfiguration": true, "VerificationMessageTemplate": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	// An MfaConfiguration that does not resolve to a value would read as OFF: refuse it.
	f = append(f, shapeFindings(id, props, nil, nil, []string{"MfaConfiguration", "UserPoolName"})...)

	if mfa, ok := concrete(props["MfaConfiguration"]); ok && mfa != "" && mfa != "OFF" {
		f = append(f, Finding{"Resource " + id, "MfaConfiguration " + mfa + " is not translatable — per-pool MFA enforcement has no faithful mapping; the realm's MFA is configured separately (refusing rather than silently not enforcing MFA)"})
	}
	if _, ok := props["LambdaConfig"]; ok {
		f = append(f, Finding{"Resource " + id, "LambdaConfig (pool triggers: PreSignUp/PostConfirmation/…) has no Keycloak-realm equivalent — refusing rather than silently dropping a custom auth flow"})
	}

	spec := map[string]any{}
	if n, ok := concrete(props["UserPoolName"]); ok && n != "" {
		spec["realm"] = k8sName(n)
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "UserPool", Name: ctx.name(id), Spec: spec}

	// Collate an in-stack UserPoolClient: kind: UserPool creates exactly ONE app client
	// (spec.clientId), so a single client's name maps; more than one has no home and refuses.
	if ctx != nil {
		clients := ctx.cognitoClients(id)
		if len(clients) > 1 {
			f = append(f, Finding{"Resource " + id, "more than one AWS::Cognito::UserPoolClient references this pool — kind: UserPool provisions a single app client (spec.clientId), so multiple clients have no faithful mapping"})
		} else if len(clients) == 1 {
			cp, _ := ctx.resolveProps(clients[0])
			if cn, ok := concrete(cp["ClientName"]); ok && cn != "" {
				spec["clientId"] = k8sName(cn)
			}
			// Each client setting the template sets is its own fidelity line: the realm client applies
			// Keycloak's defaults, so none of them is enforced as Cognito would.
			for _, p := range sortedKeys(cp) {
				if userPoolClientUnmodeled[p] {
					m.Caveats = append(m.Caveats, "UserPoolClient "+clients[0]+": "+p+" is not applied — the realm client uses Keycloak's defaults; only ClientName maps (to spec.clientId)")
				}
			}
		}
	}

	for _, p := range []string{"Policies", "Schema", "AutoVerifiedAttributes", "AliasAttributes",
		"UsernameAttributes", "EmailConfiguration", "SmsConfiguration", "AdminCreateUserConfig",
		"AccountRecoverySetting", "DeviceConfiguration", "UserPoolTags", "UsernameConfiguration",
		"VerificationMessageTemplate"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — the pool applies the realm's own defaults, not Cognito's exact configuration")
		}
	}
	return m, f
}

// userPoolClientUnmodeled are the UserPoolClient properties the realm client does not apply; each one
// a template sets is a line in the pool's fidelity summary. Anything else (bar UserPoolId, ClientName)
// refuses.
var userPoolClientUnmodeled = map[string]bool{
	"AllowedOAuthFlows": true, "AllowedOAuthFlowsUserPoolClient": true, "AllowedOAuthScopes": true,
	"CallbackURLs": true, "LogoutURLs": true, "DefaultRedirectURI": true, "GenerateSecret": true,
	"ExplicitAuthFlows": true, "SupportedIdentityProviders": true, "AccessTokenValidity": true,
	"IdTokenValidity": true, "RefreshTokenValidity": true, "TokenValidityUnits": true,
	"AuthSessionValidity": true, "PreventUserExistenceErrors": true, "ReadAttributes": true,
	"WriteAttributes": true, "EnableTokenRevocation": true, "EnablePropagateAdditionalUserContextData": true,
	"AnalyticsConfiguration": true,
}

// cognitoClients returns the in-stack AWS::Cognito::UserPoolClient logical ids whose UserPoolId
// references poolID, in deterministic order.
func (c *stackCtx) cognitoClients(poolID string) []string {
	return c.collatedChildren("AWS::Cognito::UserPoolClient", "UserPoolId", poolID)
}

// translateCognitoUserPoolClient is the no-op half of the collation: a client whose UserPoolId
// points at an in-stack UserPool provisions nothing on its own (the pool creates the app client).
// One pointing at a pool NOT in this stack is refused rather than silently dropped.
func translateCognitoUserPoolClient(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"UserPoolId": true, "ClientName": true}
	for p := range userPoolClientUnmodeled {
		known[p] = true
	}
	if f := blockUnknownProps(id, props, known); len(f) > 0 {
		return nil, f
	}
	raw, _ := ctx.rawProps(id)
	if poolID, ok := getAttTarget(raw["UserPoolId"]); ok {
		if pool, in := ctx.template.Resources[poolID]; in && pool.Type == "AWS::Cognito::UserPool" {
			return nil, nil // collated into the pool
		}
	}
	return nil, []Finding{{"Resource " + id, "its UserPoolId does not reference an AWS::Cognito::UserPool in this stack — a client can only attach to an in-stack pool (kind: UserPool provisions its own single app client)"}}
}

// ---- AWS::ECS::* -> kind: Application ----
//
// An ECS service is a long-lived container workload with a desired count behind a load balancer
// — which is exactly kind: Application (Deployment + Service + Ingress + HPA). ECS splits it
// across three resources, so this is a COLLATION: a Service (desired count + LB) references a
// TaskDefinition (the container spec); the Service translator reads both and merges them into
// one Application. A Cluster (a grouping) and a bare TaskDefinition are no-ops — they compose
// into a Service, or group nothing open-infra models.

// translateECSCluster: inert grouping (the k3s cluster is the cluster). Provisions nothing. Its name
// names nothing; a capacity provider or cluster setting would change where or how tasks run, which
// one Kubernetes cluster cannot honor, so those refuse rather than vanish.
func translateECSCluster(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	return nil, blockUnknownProps(id, props, map[string]bool{"ClusterName": true, "Tags": true})
}

// translateECSTaskDefinition: a container spec, not a workload — it runs nothing until a Service
// uses it. On its own it is a no-op; a referencing Service validates and translates it.
func translateECSTaskDefinition(_ string, _ map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	return nil, nil
}

// translateECSService: the collation. Service (desired count) + its referenced TaskDefinition
// (one container) -> one Application. Faithful: the container image/port/env; DesiredCount -> a
// fixed replica count. Refused: a multi-container task, a Command/EntryPoint override, task
// Volumes, or a Service not referencing an in-stack TaskDefinition. Caveats: LoadBalancers /
// NetworkConfiguration / LaunchType, and task Cpu/Memory / IAM roles / network mode.
func translateECSService(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"Cluster": true, "TaskDefinition": true, "DesiredCount": true, "LoadBalancers": true,
		"ServiceName": true, "LaunchType": true, "NetworkConfiguration": true, "Role": true,
		"DeploymentConfiguration": true, "HealthCheckGracePeriodSeconds": true, "PlatformVersion": true,
		"SchedulingStrategy": true, "PropagateTags": true, "EnableECSManagedTags": true,
		"ServiceRegistries": true, "Tags": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	f = append(f, shapeFindings(id, props, nil, nil, []string{"SchedulingStrategy"})...)

	// Follow the TaskDefinition reference to an in-stack AWS::ECS::TaskDefinition.
	rawSvc, _ := ctx.rawProps(id)
	tdID, ok := refTarget(rawSvc["TaskDefinition"])
	if !ok {
		f = append(f, Finding{"Resource " + id, "Service.TaskDefinition must be a !Ref to an in-stack AWS::ECS::TaskDefinition — an external task-definition ARN has no open-infra form"})
		return nil, f
	}
	tdRes, ok := ctx.template.Resources[tdID]
	if !ok || tdRes.Type != "AWS::ECS::TaskDefinition" {
		f = append(f, Finding{"Resource " + id, "Service.TaskDefinition references " + tdID + ", which is not an AWS::ECS::TaskDefinition in this stack"})
		return nil, f
	}
	td, _ := ctx.resolveProps(tdID)
	// The LB routes to a named container — that is the primary; the rest become sidecars.
	primaryName := ""
	if lbs, ok := props["LoadBalancers"].([]any); ok {
		for _, lb := range lbs {
			if lm, ok := lb.(map[string]any); ok {
				if n, _ := concrete(lm["ContainerName"]); n != "" {
					primaryName = n
					break
				}
			}
		}
	}
	spec, caveats, tdFindings := ecsTaskToApp(tdID, td, primaryName)
	f = append(f, tdFindings...)

	// DesiredCount -> a fixed replica count (ECS Service autoscaling is a separate resource).
	if dc, ok := props["DesiredCount"]; ok {
		n := toInt(dc)
		spec["scaling"] = map[string]any{"min": n, "max": n}
	}

	if len(f) > 0 {
		return nil, f
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Application", Name: ctx.name(id), Spec: spec, Caveats: caveats}
	// §2 (#117): the LB's HTTP target port maps to the app's Service port (the primary container's
	// PortMapping, already carried). The routing rules themselves live in separate ELB resources
	// (Listener/ListenerRule/TargetGroup) that aren't in scope, and the ELB DNS name is not a user
	// hostname — so an Ingress host/TLS needs Application.domain set natively. Say that precisely
	// rather than a blanket "LB dropped."
	if _, ok := props["LoadBalancers"]; ok {
		m.Caveats = append(m.Caveats, "LoadBalancers: the HTTP target port maps to the app's Service (in-cluster) port; to expose it over HTTPS with an Ingress + TLS, set Application.domain (the ELB DNS name doesn't transfer as a hostname). Target-group health-check tuning and L4/NLB specifics don't map.")
	}
	for _, p := range []string{"LaunchType", "ServiceName", "ServiceRegistries", "Role"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — open-infra exposes the app via Application.domain (Ingress+TLS); ECS launch-type/registry config has no direct form")
		}
	}
	// DAEMON runs one task on every node; an Application runs a replica count. Refuse rather than run it
	// on one node.
	if v, set := props["SchedulingStrategy"]; set && v != nil {
		if s, _ := concrete(v); s != "REPLICA" && s != "DAEMON" {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("SchedulingStrategy must be REPLICA or DAEMON (got %v)", v)})
		}
	}
	if s, _ := concrete(props["SchedulingStrategy"]); s == "DAEMON" {
		f = append(f, Finding{"Resource " + id, "SchedulingStrategy DAEMON (one task per node) has no Application form — an Application runs a replica count; refusing rather than running it on one node"})
	}
	for _, p := range []string{"DeploymentConfiguration", "HealthCheckGracePeriodSeconds", "PlatformVersion"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — an Application rolls out with the platform's rolling-update defaults")
		}
	}
	// NetworkConfiguration: the awsvpc subnet -> place the Application in a kind: Subnet (real OVN
	// isolation, #120); SecurityGroups stay a caveat (SG -> kind: SecurityGroup is a separate half).
	if nc, ok := props["NetworkConfiguration"].(map[string]any); ok {
		avc, _ := nc["AwsvpcConfiguration"].(map[string]any)
		switch name, reason := ecsFirstSubnet(id, avc, ctx); {
		case name != "":
			m.Spec["subnet"] = name
		case reason == "raw":
			f = append(f, Finding{"Resource " + id, "NetworkConfiguration subnet is a raw AWS subnet id (opaque) — name an open-infra kind: Subnet, or reference an in-stack AWS::EC2::Subnet"})
		default:
			m.Caveats = append(m.Caveats, "NetworkConfiguration subnet could not be resolved to a kind: Subnet — set the Application's subnet natively to place it in one")
		}
		if avc != nil {
			if sgs, ok := avc["SecurityGroups"].([]any); ok && len(sgs) > 0 {
				m.Caveats = append(m.Caveats, "NetworkConfiguration SecurityGroups dropped — SECURITY: attach kind: SecurityGroups natively (CFN SG translation is a follow-on); do not assume the isolation implied")
			}
		}
	}
	return m, f
}

// ecsFirstSubnet resolves the first awsvpc subnet to a kind: Subnet name — a !Ref to an in-stack
// AWS::EC2::Subnet, or a plain kind: Subnet name; a raw subnet- id refuses ("raw"). #120.
func ecsFirstSubnet(id string, avc map[string]any, ctx *stackCtx) (string, string) {
	if avc == nil {
		return "", "unresolved"
	}
	if ctx != nil {
		if raw, ok := ctx.rawProps(id); ok {
			if rnc, ok := raw["NetworkConfiguration"].(map[string]any); ok {
				if ravc, ok := rnc["AwsvpcConfiguration"].(map[string]any); ok {
					if subs, ok := ravc["Subnets"].([]any); ok && len(subs) > 0 {
						if t, ok := refTarget(subs[0]); ok {
							if r, in := ctx.template.Resources[t]; in && r.Type == "AWS::EC2::Subnet" {
								return ctx.name(t), ""
							}
						}
					}
				}
			}
		}
	}
	if subs, ok := avc["Subnets"].([]any); ok && len(subs) > 0 {
		if v, ok := concrete(subs[0]); ok && v != "" {
			if strings.HasPrefix(strings.ToLower(v), "subnet-") {
				return "", "raw"
			}
			return v, ""
		}
	}
	return "", "unresolved"
}

// ecsTaskToApp translates the TaskDefinition half: exactly one container -> image/port/env,
// returning the partial Application spec, the declared caveats, and any blocking findings.
func ecsTaskToApp(tdID string, td map[string]any, primaryName string) (map[string]any, []string, []Finding) {
	known := map[string]bool{
		"ContainerDefinitions": true, "Cpu": true, "Memory": true, "NetworkMode": true,
		"TaskRoleArn": true, "ExecutionRoleArn": true, "RequiresCompatibilities": true,
		"Family": true, "Volumes": true, "Tags": true, "RuntimePlatform": true,
	}
	var f []Finding
	var caveats []string
	f = append(f, blockUnknownProps(tdID, td, known)...)
	// Task Volumes (#117 §1): a shared scratch volume (no Host SourcePath, no EFS/Docker config) maps
	// to a pod emptyDir — the natural multi-container fit. A host-path bind mount, EFS, or Docker
	// volume has no safe/faithful Application form and refuses (never a silent drop of a mount).
	spec0 := map[string]any{}
	if v, set := td["Volumes"]; set && v != nil {
		if _, ok := v.([]any); !ok {
			f = append(f, Finding{"Resource " + tdID, "Volumes must be a list of task volumes"})
		}
	}
	if vols, ok := td["Volumes"].([]any); ok {
		var appVols []any
		for _, raw := range vols {
			v, _ := raw.(map[string]any)
			name, _ := concrete(v["Name"])
			if name == "" {
				f = append(f, Finding{"Resource " + tdID, "a task Volume requires a Name"})
				continue
			}
			hostBind := false
			if h, ok := v["Host"].(map[string]any); ok {
				if sp, _ := concrete(h["SourcePath"]); sp != "" {
					hostBind = true
				}
			}
			switch {
			case hostBind:
				f = append(f, Finding{"Resource " + tdID, "task Volume " + name + " is a host bind mount (Host.SourcePath) — no safe open-infra equivalent (a node host path); refusing rather than dropping it"})
			case v["EFSVolumeConfiguration"] != nil:
				f = append(f, Finding{"Resource " + tdID, "task Volume " + name + " is EFS — map it to a kind: FileShare natively (not yet wired into the Application collation); refusing rather than dropping a durable mount"})
			case v["DockerVolumeConfiguration"] != nil:
				f = append(f, Finding{"Resource " + tdID, "task Volume " + name + " is a Docker volume — no open-infra equivalent; refusing rather than dropping it"})
			default:
				appVols = append(appVols, map[string]any{"name": k8sName(name)})
			}
		}
		if len(appVols) > 0 {
			spec0["volumes"] = appVols
		}
	}
	for _, p := range []string{"Cpu", "Memory", "ExecutionRoleArn", "NetworkMode", "RequiresCompatibilities", "RuntimePlatform"} {
		if _, ok := td[p]; ok {
			caveats = append(caveats, "TaskDefinition "+p+" dropped — task-level sizing is via per-container resources/quotas; ExecutionRoleArn (the ECS agent's image-pull/log role) has no equivalent (the platform pulls images), and launch-compat/network-mode don't map")
		}
	}
	// TaskRoleArn -> workload identity (#117 §3): the task's application runs AS this role via the
	// Application's assumeRole (sts:AssumeRoleWithWebIdentity). Now possible because roles are
	// first-class assumable identities (#111). The named kind: Role must exist and its spec.trust
	// must name the app's ServiceAccount.
	if tra, ok := concrete(td["TaskRoleArn"]); ok && tra != "" {
		role := k8sName(iamRoleNameFromArn(tra))
		spec0["assumeRole"] = role
		caveats = append(caveats, "TaskRoleArn -> the app assumes kind: Role "+role+" via workload identity (sts:AssumeRoleWithWebIdentity); that Role must exist and its spec.trust must name this app's ServiceAccount")
	} else if _, present := td["TaskRoleArn"]; present {
		caveats = append(caveats, "TaskRoleArn could not be resolved (an unresolvable intrinsic) — set the Application's assumeRole natively to the kind: Role name")
	}

	spec := spec0 // carry the mapped shared volumes (emptyDir) + assumeRole, if any
	containers, _ := td["ContainerDefinitions"].([]any)
	if len(containers) == 0 {
		f = append(f, Finding{"Resource " + tdID, "a TaskDefinition requires at least one container"})
		return spec, caveats, f
	}
	// The primary container -> the Application's image/port/env/cpu/memory/volumeMounts; the rest ->
	// sidecars (same pod).
	primaryIdx := ecsPickPrimary(containers, primaryName)
	pc, _ := containers[primaryIdx].(map[string]any)
	for k, v := range ecsContainerSpec(tdID, fmt.Sprintf("%s.ContainerDefinitions[%d]", tdID, primaryIdx), pc, &f, &caveats) {
		spec[k] = v
	}
	var sidecars []any
	for i, cc := range containers {
		if i == primaryIdx {
			continue
		}
		cm, _ := cc.(map[string]any)
		cs := ecsContainerSpec(tdID, fmt.Sprintf("%s.ContainerDefinitions[%d]", tdID, i), cm, &f, &caveats)
		name, _ := concrete(cm["Name"])
		if name == "" {
			name = fmt.Sprintf("sidecar-%d", i)
		}
		side := map[string]any{"name": k8sName(name)}
		for _, k := range []string{"image", "port", "env", "cpu", "memory", "volumeMounts"} {
			if v, ok := cs[k]; ok {
				side[k] = v
			}
		}
		sidecars = append(sidecars, side)
	}
	if len(sidecars) > 0 {
		spec["sidecars"] = sidecars
		caveats = append(caveats, fmt.Sprintf("multi-container task: %q is the primary, the other %d container(s) map to Application sidecars (image/port/env/cpu/memory + shared-volume mounts carried; per-container health checks are not)", concreteOr(pc["Name"], "the primary"), len(sidecars)))
	}
	return spec, caveats, f
}

// ecsPickPrimary chooses the primary container: the one the load balancer names, else the first
// with a published port, else the first.
func ecsPickPrimary(containers []any, primaryName string) int {
	if primaryName != "" {
		for i, cc := range containers {
			if cm, ok := cc.(map[string]any); ok {
				if n, _ := concrete(cm["Name"]); n == primaryName {
					return i
				}
			}
		}
	}
	for i, cc := range containers {
		if cm, ok := cc.(map[string]any); ok {
			if ports, ok := cm["PortMappings"].([]any); ok && len(ports) > 0 {
				return i
			}
		}
	}
	return 0
}

// ecsContainerSpec maps one ECS container to the {image, port, env} an Application container takes.
// Command/EntryPoint overrides refuse (Application runs the image's entrypoint); the strict cknown
// allowlist blocks anything else.
func ecsContainerSpec(tdID, where string, c map[string]any, f *[]Finding, cav *[]string) map[string]any {
	cknown := map[string]bool{
		"Name": true, "Image": true, "PortMappings": true, "Environment": true, "Essential": true,
		"Cpu": true, "Memory": true, "MemoryReservation": true, "Command": true, "EntryPoint": true,
		"LogConfiguration": true, "Secrets": true, "HealthCheck": true, "DependsOn": true,
		"MountPoints": true,
	}
	*f = append(*f, blockUnknownProps(where, c, cknown)...)
	spec := map[string]any{}
	// Essential: false — on ECS the task keeps running when such a container exits; in a pod the container
	// is restarted instead (every container of an Application runs for the life of the pod).
	if v, set := c["Essential"]; set && v != nil {
		ess, ok := cfnBoolValue(v)
		switch {
		case !ok:
			*f = append(*f, Finding{"Resource " + tdID, fmt.Sprintf("a container's Essential must be true or false (got %v)", v)})
		case !ess:
			name, _ := concrete(c["Name"])
			*cav = append(*cav, "container "+name+" is Essential: false — when it exits it is restarted (as every container of the Application is), rather than left stopped while the task runs on")
		}
	}
	if img, ok := concrete(c["Image"]); ok && img != "" {
		spec["image"] = img
	} else {
		*f = append(*f, Finding{"Resource " + tdID, "container Image is required and must be a concrete image reference"})
	}
	for _, p := range []string{"Command", "EntryPoint"} {
		if _, ok := c[p]; ok {
			*f = append(*f, Finding{"Resource " + tdID, "container " + p + " override has no Application field — Application runs the image's entrypoint (refusing rather than ignoring it)"})
		}
	}
	if ports, ok := c["PortMappings"].([]any); ok && len(ports) > 0 {
		if p0, ok := ports[0].(map[string]any); ok {
			if cp, ok := p0["ContainerPort"]; ok {
				spec["port"] = toInt(cp)
			}
		}
		if len(ports) > 1 {
			*cav = append(*cav, fmt.Sprintf("container %v: only the first PortMapping is served — %d more were dropped", c["Name"], len(ports)-1))
		}
	}
	if _, ok := c["Secrets"]; ok {
		*cav = append(*cav, fmt.Sprintf("container %v: Secrets (environment variables from Secrets Manager / SSM) are not injected — the container starts without them; set them from a kind: Parameter or Secret natively", c["Name"]))
	}
	if _, ok := c["HealthCheck"]; ok {
		*cav = append(*cav, fmt.Sprintf("container %v: HealthCheck is not mapped — the platform does not run the container's health command", c["Name"]))
	}
	if _, ok := c["LogConfiguration"]; ok {
		*cav = append(*cav, fmt.Sprintf("container %v: LogConfiguration dropped — logs go to the platform's log pipeline", c["Name"]))
	}
	// Per-container resources (#117 §1): Cpu (CPU units, 1024 = 1 vCPU) -> cpu; Memory (or the soft
	// MemoryReservation) in MiB -> memory. A faithful correspondence, requested == limited.
	if cpu, ok := c["Cpu"]; ok {
		if u := toInt(cpu); u > 0 {
			spec["cpu"] = ecsCPU(u)
		}
	}
	if mem, ok := c["Memory"]; ok {
		if mi := toInt(mem); mi > 0 {
			spec["memory"] = fmt.Sprintf("%dMi", mi)
		}
	} else if mr, ok := c["MemoryReservation"]; ok {
		if mi := toInt(mr); mi > 0 {
			spec["memory"] = fmt.Sprintf("%dMi", mi)
		}
	}
	// MountPoints -> volumeMounts (#117 §1): the SourceVolume must be a task Volume mapped to an
	// emptyDir (validated in ecsTaskToApp); ContainerPath -> mountPath.
	if v, set := c["MountPoints"]; set && v != nil {
		if _, ok := v.([]any); !ok {
			*f = append(*f, Finding{"Resource " + tdID, "a container's MountPoints must be a list"})
		}
	}
	if mps, ok := c["MountPoints"].([]any); ok && len(mps) > 0 {
		var mounts []any
		for _, raw := range mps {
			mp, _ := raw.(map[string]any)
			sv, _ := concrete(mp["SourceVolume"])
			cp, _ := concrete(mp["ContainerPath"])
			if sv == "" || cp == "" {
				*f = append(*f, Finding{"Resource " + tdID, "a MountPoint needs both SourceVolume and ContainerPath"})
				continue
			}
			mounts = append(mounts, map[string]any{"name": k8sName(sv), "mountPath": cp})
		}
		if len(mounts) > 0 {
			spec["volumeMounts"] = mounts
		}
	}
	// DependsOn ordering has no faithful Application field (no init-container / startup-ordering
	// surface here) — named, not silently dropped.
	if _, ok := c["DependsOn"]; ok {
		*f = append(*f, Finding{"Resource " + tdID, "container DependsOn ordering has no Application equivalent — same-pod container startup ordering isn't expressible here (refusing rather than dropping an ordering guarantee); split the dependency into separate Applications or remove it"})
	}
	if envList := ecsEnv(tdID, c, f); len(envList) > 0 {
		spec["env"] = envList
	}
	return spec
}

// iamRoleNameFromArn extracts the role name from an IAM role ARN (arn:aws:iam::<acct>:role/<name>,
// possibly a path like role/path/<name>) or returns a bare name unchanged. The last path segment is
// the role name.
func iamRoleNameFromArn(arn string) string {
	if i := strings.Index(arn, ":role/"); i >= 0 {
		p := arn[i+len(":role/"):]
		if j := strings.LastIndex(p, "/"); j >= 0 {
			return p[j+1:]
		}
		return p
	}
	return arn
}

// ecsCPU converts ECS CPU units (1024 = 1 vCPU) to a Kubernetes millicore string.
func ecsCPU(units int) string {
	m := units * 1000 / 1024
	if m < 1 {
		m = 1
	}
	return fmt.Sprintf("%dm", m)
}

// concreteOr returns the concrete string of v, or def when it isn't concrete.
func concreteOr(v any, def string) string {
	if s, ok := concrete(v); ok && s != "" {
		return s
	}
	return def
}

// ecsEnv maps a container's Environment ([{Name,Value}]) to Application env ([{name,value}]).
func ecsEnv(tdID string, c map[string]any, f *[]Finding) []any {
	envs, ok := c["Environment"].([]any)
	if !ok {
		if v, set := c["Environment"]; set && v != nil {
			*f = append(*f, Finding{"Resource " + tdID, "a container's Environment must be a list of { Name, Value }"})
		}
		return nil
	}
	var out []any
	for _, e := range envs {
		em, ok := e.(map[string]any)
		name, _ := concrete(em["Name"])
		val, vok := concrete(em["Value"])
		if !ok || name == "" {
			*f = append(*f, Finding{"Resource " + tdID, "each Environment entry needs a Name (and a Value)"})
			continue
		}
		if !vok {
			*f = append(*f, Finding{"Resource " + tdID, "environment variable " + name + " resolves to a cross-resource value with no concrete form"})
			continue
		}
		out = append(out, map[string]any{"name": name, "value": val})
	}
	return out
}

func lambdaEnv(id string, _ map[string]any, props map[string]any, f *[]Finding) []any {
	envBlock, ok := props["Environment"].(map[string]any)
	if !ok {
		return nil
	}
	vars, ok := envBlock["Variables"].(map[string]any)
	if !ok {
		return nil
	}
	var out []any
	// stable order for a deterministic manifest
	names := sortedKeys(vars)
	for _, name := range names {
		val, ok := concrete(vars[name])
		if !ok {
			*f = append(*f, Finding{"Resource " + id, "environment variable " + name + " resolves to a cross-resource attribute with no concrete value (open-infra has no AWS ARNs)"})
			continue
		}
		out = append(out, map[string]any{"name": name, "value": val})
	}
	return out
}

// ---- AWS::RDS::DBInstance -> kind: Application (data-only, spec.database) ----
//
// open-infra has no standalone database kind — a managed DB is a data-only Application carrying a
// spec.database block (the shape the openinfra_database resource uses). So the ENGINE maps (with a
// lossy family fold) and MultiAZ -> highAvailability; what does NOT map is AWS's capacity/backup/
// network model. AllocatedStorage/DBInstanceClass have no open-infra knob (storage is the
// storageClass's, sizing is quotas/HPA) -> caveats. Master credentials are provisioned by open-infra
// and injected as DATABASE_URL, not set from the template -> caveat. StorageEncrypted is a guarantee
// there is no per-DB knob for -> BLOCK (never silently drop encryption). An unmappable engine blocks.
// rdsInstanceClasses maps common RDS instance classes to the CPU/memory an open-infra managed
// DB requests (#114). The correspondence is the class's published vCPU/RAM, requested as
// dedicated Kubernetes resources. HONEST LIMITS: open-infra does NOT model t-class burst credits
// (a burstable class gets its full vCPU as a request, not a credited baseline — more, not less),
// nor EBS-optimized throughput, nor Aurora's distributed storage. A class not listed here is not
// guessed at: it surfaces a caveat and the DB uses engine-default resources. This is the "common
// cases map faithfully, edges stay partial" rail — extend it deliberately, one verified class at a time.
var rdsInstanceClasses = map[string]struct{ cpu, mem string }{
	// burstable general purpose (t3 / t4g) — vCPU/RAM mapped; burst-credit accounting does not apply
	"db.t3.micro": {"2", "1Gi"}, "db.t4g.micro": {"2", "1Gi"},
	"db.t3.small": {"2", "2Gi"}, "db.t4g.small": {"2", "2Gi"},
	"db.t3.medium": {"2", "4Gi"}, "db.t4g.medium": {"2", "4Gi"},
	"db.t3.large": {"2", "8Gi"}, "db.t4g.large": {"2", "8Gi"},
	"db.t3.xlarge": {"4", "16Gi"}, "db.t4g.xlarge": {"4", "16Gi"},
	"db.t3.2xlarge": {"8", "32Gi"}, "db.t4g.2xlarge": {"8", "32Gi"},
	// general purpose (m5 / m6g / m6i)
	"db.m5.large": {"2", "8Gi"}, "db.m6g.large": {"2", "8Gi"}, "db.m6i.large": {"2", "8Gi"},
	"db.m5.xlarge": {"4", "16Gi"}, "db.m6g.xlarge": {"4", "16Gi"}, "db.m6i.xlarge": {"4", "16Gi"},
	"db.m5.2xlarge": {"8", "32Gi"}, "db.m6g.2xlarge": {"8", "32Gi"}, "db.m6i.2xlarge": {"8", "32Gi"},
	"db.m5.4xlarge": {"16", "64Gi"}, "db.m6g.4xlarge": {"16", "64Gi"}, "db.m6i.4xlarge": {"16", "64Gi"},
	// memory optimized (r5 / r6g)
	"db.r5.large": {"2", "16Gi"}, "db.r6g.large": {"2", "16Gi"},
	"db.r5.xlarge": {"4", "32Gi"}, "db.r6g.xlarge": {"4", "32Gi"},
	"db.r5.2xlarge": {"8", "64Gi"}, "db.r6g.2xlarge": {"8", "64Gi"},
}

func translateRDSDBInstance(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"Engine": true, "EngineVersion": true, "DBName": true, "DBInstanceIdentifier": true,
		"DBInstanceClass": true, "AllocatedStorage": true, "MasterUsername": true, "MasterUserPassword": true,
		"MultiAZ": true, "StorageEncrypted": true, "KmsKeyId": true, "Port": true, "StorageType": true,
		"Iops": true, "PubliclyAccessible": true, "BackupRetentionPeriod": true, "DBSubnetGroupName": true,
		"VPCSecurityGroups": true, "DBParameterGroupName": true, "PreferredMaintenanceWindow": true,
		"PreferredBackupWindow": true, "Tags": true, "DeletionProtection": true, "MultiAZStandbyEnabled": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	db := map[string]any{}
	eng, _ := concrete(props["Engine"])
	switch strings.ToLower(eng) {
	case "postgres", "aurora-postgresql":
		db["engine"] = "postgres"
	case "mysql", "mariadb", "aurora-mysql", "aurora":
		db["engine"] = "mysql"
	case "sqlserver-ex", "sqlserver-web", "sqlserver-se", "sqlserver-ee":
		db["engine"] = "babelfish"
	case "":
		f = append(f, Finding{"Resource " + id, "RDS Engine is required"})
	default:
		f = append(f, Finding{"Resource " + id, "RDS Engine " + eng + " has no open-infra engine (postgres/aurora-postgresql -> postgres; mysql/mariadb/aurora-mysql -> mysql; sqlserver-* -> babelfish)"})
	}
	if n, ok := concrete(props["DBName"]); ok && n != "" {
		db["name"] = n
	}
	multiAZ, ff := boolProp(id, props, "MultiAZ", false)
	f = append(f, ff...)
	if multiAZ {
		db["highAvailability"] = true
	}
	// Storage encryption: LUKS on longhorn-encrypted keyed by a customer kind: EncryptionKey (via an
	// in-stack KMS::Key). v1 supports the postgres engine only (CloudNativePG propagates the key
	// annotation to its PVCs); other engines' DB encryption is a follow-up, so they block.
	enc, ff := boolProp(id, props, "StorageEncrypted", false) // CloudFormation accepts true or "true"
	f = append(f, ff...)
	protected, ff := boolProp(id, props, "DeletionProtection", false)
	f = append(f, ff...)
	_, hasKms := props["KmsKeyId"]
	if enc || hasKms {
		if db["engine"] != "postgres" {
			f = append(f, Finding{"Resource " + id, "StorageEncrypted maps only for the postgres engine in v1 (CloudNativePG); DB encryption for mysql/babelfish is a follow-up (refusing rather than dropping an encryption guarantee)"})
		} else {
			db["storageEncrypted"] = true
			var kid string
			if ctx != nil {
				if raw, ok := ctx.rawProps(id); ok {
					if t, ok := getAttTarget(raw["KmsKeyId"]); ok {
						if k, in := ctx.template.Resources[t]; in && k.Type == "AWS::KMS::Key" {
							kid = t
						}
					}
				}
			}
			if kid != "" {
				db["encryptionKey"] = ctx.name(kid)
			} else {
				f = append(f, Finding{"Resource " + id, "an encrypted database needs KmsKeyId referencing an in-stack AWS::KMS::Key — open-infra keys DB storage with a customer kind: EncryptionKey, not an AWS-managed default key"})
			}
		}
	}

	// AllocatedStorage (GiB) -> the DB's storage size. A direct, faithful correspondence
	// (previously dropped, silently giving every DB the 5Gi default regardless of request). #114
	if as, ok := concrete(props["AllocatedStorage"]); ok && as != "" {
		db["size"] = as + "Gi"
	}
	// DBInstanceClass -> CPU/memory requests, for common classes (documented table above). #114
	if cls, ok := concrete(props["DBInstanceClass"]); ok && cls != "" {
		if r, known := rdsInstanceClasses[strings.ToLower(cls)]; known {
			db["cpu"] = r.cpu
			db["memory"] = r.mem
		} else {
			f = append(f, Finding{"Resource " + id, "DBInstanceClass " + cls + " is not in the mapping table — the DB provisions with engine-default resources; map a known class or set cpu/memory natively (open-infra does not guess a class's sizing)"})
		}
	}

	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Application", Name: ctx.name(id), Spec: map[string]any{"database": db}}
	// The mysql engine is backed by MariaDB — MySQL wire-compatible, but not MySQL itself. Server
	// version-specific features and collations do NOT transfer, which is exactly the trap in a MySQL 8
	// lift-and-shift: a schema/dump pinned to utf8mb4_0900_ai_ci (the 8.0 default collation, based on
	// Unicode 9.0 UCA) will FAIL to import because MariaDB has no such collation. Surface it loudly here
	// rather than let the import fail opaquely — the EngineVersion (when 8.x) sharpens the warning.
	if db["engine"] == "mysql" {
		msg := "the mysql engine is backed by MariaDB (MySQL wire-compatible, credentials injected as DATABASE_URL) — not MySQL itself. Server-specific collations do NOT transfer: a MySQL 8 schema/dump using utf8mb4_0900_ai_ci (the 8.0 default) will not import, since MariaDB lacks that collation — remap it (e.g. to utf8mb4_unicode_ci) in the dump before import. There is no real MySQL 8 engine today."
		if ev, ok := concrete(props["EngineVersion"]); ok && strings.HasPrefix(ev, "8.") {
			msg = "EngineVersion " + ev + ": " + msg
		}
		m.Caveats = append(m.Caveats, msg)
	}
	// StorageType/Iops are EBS-style perf knobs with no honest DB-storage equivalent here (same
	// disproven case as EC2::Volume IOPS): open-infra DB storage is a StorageClass PVC, not
	// provisioned-IOPS EBS — mapping the number would fabricate a performance contract.
	for _, p := range []string{"StorageType", "Iops"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — DB storage is a StorageClass PVC (Longhorn/local-path), not provisioned-IOPS EBS; the perf number does not map (mapping it would imply a guarantee the substrate can't hold)")
		}
	}
	for _, p := range []string{"MasterUsername", "MasterUserPassword"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — open-infra provisions the credentials and injects them as DATABASE_URL; they are not set from the template")
		}
	}
	for _, p := range []string{"PubliclyAccessible", "Port", "BackupRetentionPeriod", "PreferredMaintenanceWindow", "PreferredBackupWindow", "DBParameterGroupName"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — no open-infra equivalent (backups/params are platform-managed)")
		}
	}
	// DeletionProtection is honored by the stack: a delete (or an update removing this database) is
	// refused while it is set, as AWS refuses to delete a protected instance.
	if protected {
		m.Protected = true
	}
	if n, ok := concrete(props["DBInstanceIdentifier"]); ok && n != "" && n != m.Name {
		m.Caveats = append(m.Caveats, fmt.Sprintf("DBInstanceIdentifier %q is not used — the database is kind: Application %q", n, m.Name))
	}
	if v, ok := concrete(props["EngineVersion"]); ok && v != "" {
		m.Caveats = append(m.Caveats, "EngineVersion "+v+" is not pinned — the database runs the platform's PostgreSQL version")
	}
	if _, ok := props["MultiAZStandbyEnabled"]; ok {
		m.Caveats = append(m.Caveats, "MultiAZStandbyEnabled dropped — high availability follows MultiAZ only")
	}
	// Subnet-group / VPC-security-group references imply network isolation; dropping them quietly
	// would misrepresent a database as isolated when it is reachable on the flat cluster network.
	for _, p := range []string{"DBSubnetGroupName", "VPCSecurityGroups"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — SECURITY: the database runs on the flat cluster network with NO enforced network isolation; the subnet/security-group reference does NOT map here. Do not assume the isolation it implied.")
		}
	}
	return m, f
}

// ---- AWS::S3::Bucket -> kind: Bucket ----
//
// A standalone MinIO bucket (the object-storage analog of kind: Volume). BucketName maps, and — the
// fidelity gain over the old Application-sub-block mapping — VersioningConfiguration and
// LifecycleConfiguration (expiration rules) map too. An in-stack AWS::S3::BucketPolicy targeting this
// bucket is COLLATED in as spec.policy (a public "*"-principal policy only — an AWS IAM ARN principal
// doesn't resolve to a MinIO principal, so such a policy would be stored and silently NOT enforce; it
// refuses instead). BucketEncryption maps with a CAVEAT only when the deploy environment reports
// objectEncryption on (Capabilities.ObjectEncryption — encryption is the platform default for new buckets, not per-bucket);
// otherwise it REFUSES rather than deploy an unencrypted bucket the template asked to encrypt.
// CorsConfiguration REFUSES — per-bucket CORS is a MinIO ceiling (PutBucketCors returns
// MalformedXML; MinIO does CORS globally via MINIO_API_CORS_ALLOW_ORIGIN), so it is refused loudly
// rather than silently dropped. Website, notifications, replication, public-access and the rest block
// via the strict allowlist. Tags are a caveat.
func translateS3Bucket(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"BucketName": true, "VersioningConfiguration": true, "LifecycleConfiguration": true,
		"BucketEncryption": true, "CorsConfiguration": true, "Tags": true,
		"ObjectLockEnabled": true, "ObjectLockConfiguration": true,
		"PublicAccessBlockConfiguration": true, "OwnershipControls": true,
	}
	var f []Finding
	var noopNotes []string
	f = append(f, blockUnknownProps(id, props, known)...)

	// BucketEncryption is honored ONLY when the deploy environment has objectEncryption on
	// (Capabilities.ObjectEncryption: every NEW MinIO bucket gets default encryption, AES256 under the
	// platform MinIO's key — not merely a key being configured). Encryption is the platform's default,
	// not per-bucket, so when it's on the bucket maps with a CAVEAT (an aws:kms KMSMasterKeyID is not
	// used; the platform key is). When it's off or unknown it REFUSES — a template that asks for
	// encryption at rest must never deploy an unencrypted bucket with only a note to show for it.
	if be, ok := props["BucketEncryption"]; ok {
		alg := ""
		if m, _ := be.(map[string]any); m != nil {
			if sseList, _ := m["ServerSideEncryptionConfiguration"].([]any); len(sseList) > 0 {
				if r0, _ := sseList[0].(map[string]any); r0 != nil {
					if sd, _ := r0["ServerSideEncryptionByDefault"].(map[string]any); sd != nil {
						alg, _ = concrete(sd["SSEAlgorithm"])
					}
				}
			}
		}
		algNote := ""
		if alg != "" {
			algNote = " (" + alg + ")"
		}
		if ctx != nil && ctx.caps.ObjectEncryption {
			noopNotes = append(noopNotes, "BucketEncryption is honored by the platform's object encryption: every NEW bucket here gets default encryption at rest (AES256, i.e. SSE-S3, under the platform MinIO's key), so this bucket's objects are encrypted; the template's SSEAlgorithm"+algNote+"/KMSMasterKeyID are not applied individually (an aws:kms key is not used — the platform key is)")
		} else {
			f = append(f, Finding{"Resource " + id, "BucketEncryption" + algNote + " requires that new MinIO buckets be encrypted at rest by default (components.objectEncryption), and this deploy environment does not declare that — refusing rather than creating an unencrypted bucket the template asked to encrypt. Turn object encryption on (docs/encryption.md); then this bucket maps with a caveat."})
		}
	}
	if _, ok := props["CorsConfiguration"]; ok {
		f = append(f, Finding{"Resource " + id, "CorsConfiguration has no faithful open-infra mapping — MinIO does not support per-bucket CORS via the S3 API (PutBucketCors returns MalformedXML on this release); CORS is configured globally via MINIO_API_CORS_ALLOW_ORIGIN. Refusing rather than silently dropping."})
	}

	// PublicAccessBlockConfiguration — MinIO buckets are private-by-default with no ACLs, which IS the
	// all-public-access-blocked posture AWS hardening templates ask for. All-true/absent is a faithful
	// no-op. A field explicitly FALSE asks to LOOSEN public access, which open-infra has no faithful form
	// for — refuse rather than create a bucket that silently stays private despite the template.
	if pab, ok := props["PublicAccessBlockConfiguration"].(map[string]any); ok {
		loosened := false
		for _, k := range []string{"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"} {
			if isExplicitFalse(pab[k]) {
				loosened = true
				f = append(f, Finding{"Resource " + id, "PublicAccessBlockConfiguration." + k + "=false asks to loosen public access; MinIO buckets are private-by-default with no ACLs and cannot be made public this way — refusing rather than creating a bucket that stays private despite the template"})
			}
		}
		if !loosened {
			noopNotes = append(noopNotes, "PublicAccessBlockConfiguration is a no-op — MinIO buckets are already private with no public ACLs (all-blocked is the default posture)")
		}
	}

	// OwnershipControls — MinIO does not implement S3 ACLs, so BucketOwnerEnforced (ACLs disabled) is its
	// native, faithful posture: a no-op. ObjectWriter / BucketOwnerPreferred re-enable ACL-based ownership,
	// which MinIO can't honor and which can loosen access — refuse rather than silently ignore it.
	if oc, ok := props["OwnershipControls"].(map[string]any); ok {
		rules, _ := oc["Rules"].([]any)
		for _, rr := range rules {
			rm, _ := rr.(map[string]any)
			own, _ := concrete(rm["ObjectOwnership"])
			if own != "" && own != "BucketOwnerEnforced" {
				f = append(f, Finding{"Resource " + id, "OwnershipControls ObjectOwnership " + own + " re-enables S3 ACLs, which MinIO does not implement (only BucketOwnerEnforced — ACLs disabled — is faithful); refusing rather than silently ignoring an ownership mode that could loosen access"})
			}
		}
		noopNotes = append(noopNotes, "OwnershipControls is a no-op — MinIO has no S3 ACLs, so BucketOwnerEnforced (ACLs disabled) is already in force")
	}

	spec := map[string]any{}
	if bn, ok := concrete(props["BucketName"]); ok && bn != "" {
		spec["bucketName"] = bn
	} else if ctx != nil && ctx.namer != nil {
		// No BucketName: the name AWS gives an unnamed stack bucket, <stack>-<logical id>-<suffix>, unless
		// the stack recorded this bucket before (it keeps its name; naming.go).
		if n, set := ctx.namer.bucketName(id); set {
			spec["bucketName"] = n
		}
	}
	if vc, ok := props["VersioningConfiguration"].(map[string]any); ok {
		if st, _ := concrete(vc["Status"]); st == "Enabled" {
			spec["versioning"] = true
		}
	}
	if lc, ok := props["LifecycleConfiguration"].(map[string]any); ok {
		f = append(f, blockUnknownProps(id+".LifecycleConfiguration", lc, map[string]bool{"Rules": true})...)
		if rules := s3LifecycleRules(id, lc, &f); len(rules) > 0 {
			spec["lifecycleRules"] = rules
		}
	}
	// Object Lock (WORM) — MinIO enforces it natively. Map the DefaultRetention (the WORM policy the
	// audit store already proves in-house). A lock-enabled bucket with only per-object retention (no
	// default) refuses loudly rather than being created without the retention the user expects.
	_, lockEnabled := props["ObjectLockEnabled"]
	if olcv, set := props["ObjectLockConfiguration"]; set && olcv != nil {
		lockEnabled = true
		if ol, fs := s3ObjectLock(id, olcv); len(fs) > 0 {
			f = append(f, fs...)
		} else {
			spec["objectLock"] = ol
		}
	} else if lockEnabled {
		f = append(f, Finding{"Resource " + id, "ObjectLockEnabled without an ObjectLockConfiguration.Rule.DefaultRetention has no open-infra form yet — kind: Bucket objectLock sets a default retention (Mode + Days/Years); add one or manage per-object retention out of band"})
	}

	// Fold an in-stack AWS::S3::BucketPolicy targeting this bucket into spec.policy (#112). MinIO stores
	// a bucket policy verbatim via put-bucket-policy, but ONLY public ("*") principals resolve — an AWS
	// IAM ARN principal names an identity MinIO has never heard of, so a policy carrying one would be
	// applied and silently NOT enforce as written. That is the same security-expectation gap as the
	// db-stats/dataflow rule (refuse rather than apply something that won't enforce as intended): a
	// non-"*" principal REFUSES with no spec.policy, rather than deploying a policy that looks applied.
	if ctx != nil {
		if pid, ok := ctx.s3BucketPolicyFor(id); ok {
			sp, _ := ctx.resolveProps(pid)
			f = append(f, blockUnknownProps(pid, sp, map[string]bool{"Bucket": true, "PolicyDocument": true})...)
			doc, hasDoc := sp["PolicyDocument"]
			if s, isStr := doc.(string); isStr {
				// A Json property may be given as a JSON string; read the document it holds.
				var parsed map[string]any
				if err := json.Unmarshal([]byte(s), &parsed); err != nil || parsed == nil {
					f = append(f, Finding{"Resource " + pid, "BucketPolicy PolicyDocument is a string that is not a JSON policy document"})
				}
				doc = parsed
			} else if _, isMap := doc.(map[string]any); hasDoc && !isMap {
				f = append(f, Finding{"Resource " + pid, fmt.Sprintf("BucketPolicy PolicyDocument must be a policy document (got %v)", doc)})
			}
			// CloudFront read grants (OAC/OAI) are realized by the kind: StaticSite serving this bucket, not
			// stored as a MinIO policy (translate_cloudfront.go); doc is nil when nothing else remains.
			doc, cfNotes, cfFindings := ctx.cloudFrontBucketGrants(id, pid, doc)
			noopNotes = append(noopNotes, cfNotes...)
			f = append(f, cfFindings...)
			switch {
			case !hasDoc:
				f = append(f, Finding{"Resource " + pid, "AWS::S3::BucketPolicy requires a PolicyDocument"})
			case doc == nil:
				// every Statement was a CloudFront read grant the serving StaticSite holds — nothing to store
			case !s3PolicyPrincipalsPublic(doc):
				f = append(f, Finding{"Resource " + pid, "the BucketPolicy has a Statement whose Principal is not \"*\" (public) — AWS IAM ARN principals do not resolve to MinIO principals, so the policy would be stored but not enforce as intended; refusing rather than applying a policy that silently won't restrict as written. Use Principal \"*\" for a public policy, or govern identity-scoped access via open-infra IAM (kind: Policy spec.dataPlane at the aws-shim)."})
			case hasUnresolvedPlaceholder(doc):
				// An intrinsic that did not resolve to a concrete value (e.g. Resource: !Sub
				// "arn:aws:s3:::${Bucket}/*" with a generated bucket name) survives as "<ref:Bucket>" —
				// a policy that doesn't match the real bucket. Refuse rather than store it.
				f = append(f, Finding{"Resource " + pid, "BucketPolicy PolicyDocument still contains an unresolved intrinsic after resolution (e.g. a !Sub/!Ref ARN of a bucket with a generated name) — give the bucket an explicit BucketName the policy can reference, or author spec.policy natively; refusing rather than storing a policy that won't match the bucket"})
			default:
				b, err := json.Marshal(doc)
				if err != nil {
					f = append(f, Finding{"Resource " + pid, "BucketPolicy PolicyDocument is not serializable to JSON: " + err.Error()})
				} else {
					spec["policy"] = string(b)
				}
			}
		}
	}

	// Tags become the bucket's S3 tags (GetBucketTagging returns them), as on AWS.
	if raw, ok := props["Tags"]; ok {
		tags, dropped, tf := s3BucketTags(id, raw)
		f = append(f, tf...)
		if len(tf) == 0 && len(tags) > 0 {
			spec["tags"] = tags
		}
		noopNotes = append(noopNotes, dropped...)
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Bucket", Name: ctx.name(id), Spec: spec}
	m.Caveats = append(m.Caveats, noopNotes...)
	return m, f
}

// s3BucketTags reads an AWS::S3::Bucket's Tags ([{Key, Value}]) into a kind: Bucket's tags map. It refuses
// what S3 refuses — more than 50 tags, a key that is empty, longer than 128 characters or starts with
// "aws:" (reserved), a value longer than 256, a duplicate key — and drops, with a caveat, a tag whose key
// or value is not known when the stack is planned (an attribute of a resource not yet created).
func s3BucketTags(id string, raw any) (tags map[string]any, dropped []string, f []Finding) {
	list, ok := raw.([]any)
	if !ok {
		return nil, nil, []Finding{{"Resource " + id, "Tags must be a list of {Key, Value}"}}
	}
	if len(list) > 50 {
		return nil, nil, []Finding{{"Resource " + id, fmt.Sprintf("Tags has %d tags; S3 allows at most 50", len(list))}}
	}
	tags = map[string]any{}
	for i, e := range list {
		m, _ := e.(map[string]any)
		k, kok := concrete(m["Key"])
		v, vok := concrete(m["Value"])
		where := fmt.Sprintf("Resource %s.Tags[%d]", id, i)
		switch {
		case !kok || !vok:
			dropped = append(dropped, fmt.Sprintf("Tags[%d] dropped — its Key or Value is not known when the stack is planned", i))
			continue
		case k == "" || len(k) > 128:
			return nil, nil, []Finding{{where, "a tag Key is 1-128 characters"}}
		case strings.HasPrefix(strings.ToLower(k), "aws:"):
			return nil, nil, []Finding{{where, "a tag Key may not start with aws: (reserved for AWS)"}}
		case len(v) > 256:
			return nil, nil, []Finding{{where, "a tag Value is at most 256 characters"}}
		}
		if _, dup := tags[k]; dup {
			return nil, nil, []Finding{{where, "duplicate tag Key " + k}}
		}
		tags[k] = v
	}
	return tags, dropped, nil
}

// hasUnresolvedPlaceholder reports whether any string leaf in v is an unresolved resolver placeholder
// (e.g. "<ref:X>") — so a collated document carrying an intrinsic that didn't resolve to a concrete
// value is refused rather than stored. Walks maps/slices (marshaling-independent, so it is not fooled
// by json.Marshal's HTML-escaping of "<"/">").
func hasUnresolvedPlaceholder(v any) bool {
	switch t := v.(type) {
	case string:
		return placeholderRe.MatchString(t)
	case map[string]any:
		for _, e := range t {
			if hasUnresolvedPlaceholder(e) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if hasUnresolvedPlaceholder(e) {
				return true
			}
		}
	}
	return false
}

// isExplicitFalse reports whether v is an explicit boolean false (as a Go bool, or the string "false"
// from a templated value) — distinct from an absent/nil value. Used where an explicit false is a
// meaningful loosening signal (e.g. a PublicAccessBlock field) that an absent default is not.
func isExplicitFalse(v any) bool {
	switch t := v.(type) {
	case bool:
		return !t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "false")
	}
	return false
}

// ---- AWS::S3::BucketPolicy -> collated into its in-stack AWS::S3::Bucket ----
//
// A BucketPolicy has no standalone open-infra form: it rides its bucket as kind: Bucket spec.policy,
// read by translateS3Bucket. So when its Bucket resolves to an in-stack AWS::S3::Bucket it is a no-op
// here (the bucket anchor reads it). A BucketPolicy whose Bucket is NOT in this stack refuses rather
// than silently dropping — we can't apply a policy to a bucket we don't manage.
func translateS3BucketPolicy(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	if ctx != nil {
		if _, ok := ctx.s3BucketPolicyTarget(id); ok {
			return nil, nil // collated into its in-stack AWS::S3::Bucket (spec.policy)
		}
		if name, ok := concrete(props["Bucket"]); ok && name != "" {
			if f := blockUnknownProps(id, props, map[string]bool{"Bucket": true, "PolicyDocument": true}); len(f) > 0 {
				return nil, f
			}
			return nil, ctx.externalBucketPolicy(id, name, props["PolicyDocument"])
		}
	}
	return nil, []Finding{{"Resource " + id, "an AWS::S3::BucketPolicy must reference an in-stack AWS::S3::Bucket — its Bucket names/Refs a bucket not in this stack, and a policy over an unmanaged bucket is not translatable (it is collated into the referenced kind: Bucket as spec.policy)"}}
}

// externalBucketPolicy checks a policy over a bucket outside the stack (another stack's, by Fn::ImportValue
// or a parameter). It holds only for statements that grant CloudFront read to a distribution of this stack
// serving that bucket: those are realized by the distribution's kind: StaticSite (its scoped reader) and
// stored nowhere. Any other statement would change a policy that belongs to the bucket's own stack — that
// stack's kind: Bucket carries it — so it refuses.
func (c *stackCtx) externalBucketPolicy(id, bucket string, doc any) []Finding {
	m, _ := doc.(map[string]any)
	var stmts []any
	switch s := m["Statement"].(type) {
	case []any:
		stmts = s
	case map[string]any:
		stmts = []any{s}
	}
	if len(stmts) == 0 {
		return []Finding{{"Resource " + id, "the PolicyDocument has no Statement"}}
	}
	serving := c.cloudFrontDistributionsServingExternal(bucket)
	var f []Finding
	for i, s := range stmts {
		sm, _ := s.(map[string]any)
		kind := c.cloudFrontPrincipal(sm["Principal"])
		if kind == "" {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("BucketPolicy Statement %d changes the policy of bucket %s, which is not in this stack — its policy belongs to the stack that created it (its kind: Bucket's spec.policy); only a CloudFront read grant for this stack's distribution is realized here (by its StaticSite)", i, bucket)})
			continue
		}
		if why := c.cloudFrontGrantProblem(sm, kind, serving); why != "" {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("BucketPolicy Statement %d %s", i, why)})
		}
	}
	return f
}

// s3BucketPolicyTarget returns the logical id of the in-stack AWS::S3::Bucket that BucketPolicy
// `policyID`'s raw Bucket property references — a !Ref/!GetAtt to an in-stack bucket, or a plain
// string naming one (by BucketName or logical id) — and whether such an in-stack bucket was found.
func (c *stackCtx) s3BucketPolicyTarget(policyID string) (string, bool) {
	raw, ok := c.rawProps(policyID)
	if !ok {
		return "", false
	}
	b := raw["Bucket"]
	// A !Ref / !GetAtt: it targets an in-stack bucket only if the referenced logical id is one.
	if t, ok := getAttTarget(b); ok {
		if r, in := c.template.Resources[t]; in && r.Type == "AWS::S3::Bucket" {
			return t, true
		}
		return "", false
	}
	// A plain string bucket name: match it against an in-stack bucket's BucketName or logical id.
	if name, ok := b.(string); ok && name != "" {
		for bid, r := range c.template.Resources {
			if r.Type != "AWS::S3::Bucket" {
				continue
			}
			if bid == name {
				return bid, true
			}
			if bn, ok := r.Properties["BucketName"].(string); ok && bn == name {
				return bid, true
			}
		}
	}
	return "", false
}

// s3BucketPolicyFor returns, deterministically, the logical id of an in-stack AWS::S3::BucketPolicy
// whose Bucket resolves to bucketID (the bucket collates it into spec.policy).
func (c *stackCtx) s3BucketPolicyFor(bucketID string) (string, bool) {
	var ids []string
	for pid, res := range c.template.Resources {
		if res.Type == "AWS::S3::BucketPolicy" && c.included(res) {
			ids = append(ids, pid) // a conditioned-OFF BucketPolicy must NOT be collated (it would be a public policy, deployed despite being gated off)
		}
	}
	sortStrs(ids)
	for _, pid := range ids {
		if t, ok := c.s3BucketPolicyTarget(pid); ok && t == bucketID {
			return pid, true
		}
	}
	return "", false
}

// s3PolicyPrincipalsPublic reports whether EVERY Statement in a bucket-policy document has a public
// principal — "*" or {"AWS": "*"} / {"AWS": ["*"]}. Anything else (an AWS IAM ARN, a Service
// principal, a mixed list, or a missing Principal) makes it non-public: MinIO can't resolve it, so the
// caller refuses rather than applying a policy that won't enforce as written.
func s3PolicyPrincipalsPublic(doc any) bool {
	m, ok := doc.(map[string]any)
	if !ok {
		return false
	}
	var stmts []any
	switch s := m["Statement"].(type) {
	case []any:
		stmts = s
	case map[string]any:
		stmts = []any{s}
	}
	if len(stmts) == 0 {
		return false
	}
	for _, s := range stmts {
		sm, ok := s.(map[string]any)
		if !ok {
			return false
		}
		p, ok := sm["Principal"]
		if !ok || !isPublicPrincipal(p) {
			return false
		}
	}
	return true
}

// isPublicPrincipal reports whether a single Statement's Principal is the public wildcard in any of
// its accepted forms: "*", {"AWS": "*"}, or {"AWS": ["*"]} (a one-element list of exactly "*").
func isPublicPrincipal(p any) bool {
	switch v := p.(type) {
	case string:
		return v == "*"
	case map[string]any:
		aws, ok := v["AWS"]
		if !ok || len(v) != 1 { // exactly {"AWS": ...} — no Service/Federated/CanonicalUser alongside
			return false
		}
		switch a := aws.(type) {
		case string:
			return a == "*"
		case []any:
			if len(a) != 1 {
				return false
			}
			s, ok := a[0].(string)
			return ok && s == "*"
		}
	}
	return false
}

// s3ObjectLock maps an ObjectLockConfiguration to kind: Bucket objectLock: its Rule.DefaultRetention's
// Mode (GOVERNANCE or COMPLIANCE) and exactly one of Days or Years, a positive whole number, as AWS
// requires. Every other shape refuses — a configuration that is not an object, an ObjectLockEnabled
// other than Enabled, a key AWS does not define, a period of the wrong shape — because a bucket created
// without the retention the template asked for cannot get it back for objects already written.
func s3ObjectLock(id string, v any) (map[string]any, []Finding) {
	where := "Resource " + id
	olc, ok := v.(map[string]any)
	if !ok {
		return nil, []Finding{{where, fmt.Sprintf("ObjectLockConfiguration must be an object (got %v)", v)}}
	}
	f := blockUnknownProps(id+".ObjectLockConfiguration", olc, map[string]bool{"ObjectLockEnabled": true, "Rule": true})
	if e, set := olc["ObjectLockEnabled"]; set {
		if s, _ := concrete(e); s != "Enabled" {
			f = append(f, Finding{where, fmt.Sprintf("ObjectLockConfiguration.ObjectLockEnabled must be Enabled (got %v)", e)})
		}
	}
	rule, ok := olc["Rule"].(map[string]any)
	if !ok {
		return nil, append(f, Finding{where, "ObjectLockConfiguration needs a Rule.DefaultRetention with Mode GOVERNANCE or COMPLIANCE — kind: Bucket objectLock sets a default retention; manage per-object retention out of band"})
	}
	f = append(f, blockUnknownProps(id+".ObjectLockConfiguration.Rule", rule, map[string]bool{"DefaultRetention": true})...)
	dr, ok := rule["DefaultRetention"].(map[string]any)
	if !ok {
		return nil, append(f, Finding{where, "ObjectLockConfiguration needs a Rule.DefaultRetention with Mode GOVERNANCE or COMPLIANCE"})
	}
	f = append(f, blockUnknownProps(id+".ObjectLockConfiguration.Rule.DefaultRetention", dr, map[string]bool{"Mode": true, "Days": true, "Years": true})...)
	mode, _ := concrete(dr["Mode"])
	if mode != "GOVERNANCE" && mode != "COMPLIANCE" {
		f = append(f, Finding{where, "ObjectLockConfiguration needs a Rule.DefaultRetention with Mode GOVERNANCE or COMPLIANCE"})
	}
	ol := map[string]any{"mode": mode}
	_, hasDays := dr["Days"]
	_, hasYears := dr["Years"]
	switch {
	case hasDays && hasYears:
		f = append(f, Finding{where, "ObjectLock DefaultRetention takes Days or Years, not both"})
	case hasDays || hasYears:
		k, out := "Days", "days"
		if hasYears {
			k, out = "Years", "years"
		}
		if n, ok := positiveWhole(dr[k]); ok {
			ol[out] = n
		} else {
			f = append(f, Finding{where, fmt.Sprintf("ObjectLock DefaultRetention.%s must be a positive whole number (got %v)", k, dr[k])})
		}
	default:
		f = append(f, Finding{where, "ObjectLock DefaultRetention needs a Days or Years period"})
	}
	if len(f) > 0 {
		return nil, f
	}
	return ol, nil
}

// positiveWhole reads a resolved number — a YAML/JSON number, or a numeric string as a parameter gives
// one — that must be a whole number above zero.
func positiveWhole(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, n > 0
	case float64:
		if n > 0 && n == math.Trunc(n) && n < 1<<31 {
			return int(n), true
		}
		return 0, false
	}
	s, ok := concrete(v)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// s3LifecycleRules maps an S3 LifecycleConfiguration to kind: Bucket lifecycleRules. Supported per
// rule: Id, Status (Enabled), a Prefix (top-level or Filter.Prefix), ExpirationInDays, and
// NoncurrentVersionExpiration.NoncurrentDays. Anything else on a rule (Transitions, an absolute
// ExpirationDate, tag/size filters, abort-multipart) blocks — a lifecycle rule that silently
// dropped its transition or kept objects past their expiry is the worst shape.
func s3LifecycleRules(id string, lc map[string]any, f *[]Finding) []any {
	*f = append(*f, shapeFindings(id+".LifecycleConfiguration", lc, []string{"Rules"}, nil, nil)...)
	rules, _ := lc["Rules"].([]any)
	var out []any
	for i, r := range rules {
		where := fmt.Sprintf("%s.LifecycleConfiguration.Rules[%d]", id, i)
		rm, ok := r.(map[string]any)
		if !ok {
			*f = append(*f, Finding{"Resource " + where, fmt.Sprintf("a lifecycle rule must be an object (got %v)", r)})
			continue
		}
		rknown := map[string]bool{"Id": true, "Status": true, "Prefix": true, "Filter": true, "ExpirationInDays": true, "NoncurrentVersionExpiration": true}
		*f = append(*f, blockUnknownProps(where, rm, rknown)...)
		*f = append(*f, shapeFindings(where, rm, nil, []string{"Filter", "NoncurrentVersionExpiration"}, []string{"Id", "Status", "Prefix"})...)

		rule := map[string]any{}
		if rid, ok := concrete(rm["Id"]); ok && rid != "" {
			rule["id"] = rid
		} else {
			rule["id"] = fmt.Sprintf("rule-%d", i)
		}
		if st, _ := concrete(rm["Status"]); st != "" && st != "Enabled" {
			*f = append(*f, Finding{"Resource " + id, "lifecycle rule " + fmt.Sprint(rule["id"]) + " Status " + st + " is not applied — only Enabled rules map"})
		}
		_, hasPrefix := rm["Prefix"]
		fl, hasFilter := rm["Filter"].(map[string]any)
		if hasPrefix && hasFilter {
			// AWS refuses a rule with both: the top-level Prefix is the legacy form of Filter.Prefix.
			*f = append(*f, Finding{"Resource " + id, "lifecycle rule " + fmt.Sprint(rule["id"]) + " sets both Prefix and Filter — use one (Filter.Prefix)"})
		}
		if p, ok := concrete(rm["Prefix"]); ok && p != "" {
			rule["prefix"] = p
		} else if hasFilter {
			for _, k := range sortedKeys(fl) {
				if k != "Prefix" {
					*f = append(*f, Finding{"Resource " + id, "lifecycle rule " + fmt.Sprint(rule["id"]) + " Filter." + k + " is not supported — only a Prefix filter maps"})
				}
			}
			*f = append(*f, shapeFindings(where+".Filter", fl, nil, nil, []string{"Prefix"})...)
			if p, ok := concrete(fl["Prefix"]); ok && p != "" {
				rule["prefix"] = p
			}
		}
		if ed, ok := rm["ExpirationInDays"]; ok {
			if n, ok := positiveWhole(ed); ok {
				rule["expireDays"] = n
			} else {
				*f = append(*f, Finding{"Resource " + id, fmt.Sprintf("lifecycle rule %v ExpirationInDays must be a positive whole number (got %v)", rule["id"], ed)})
			}
		}
		if nve, ok := rm["NoncurrentVersionExpiration"].(map[string]any); ok {
			*f = append(*f, blockUnknownProps(where+".NoncurrentVersionExpiration", nve, map[string]bool{"NoncurrentDays": true})...)
			if n, ok := positiveWhole(nve["NoncurrentDays"]); ok {
				rule["noncurrentExpireDays"] = n
			} else {
				*f = append(*f, Finding{"Resource " + id, fmt.Sprintf("lifecycle rule %v NoncurrentVersionExpiration.NoncurrentDays must be a positive whole number (got %v)", rule["id"], nve["NoncurrentDays"])})
			}
		}
		if rule["expireDays"] == nil && rule["noncurrentExpireDays"] == nil {
			*f = append(*f, Finding{"Resource " + id, "lifecycle rule " + fmt.Sprint(rule["id"]) + " has no supported action (ExpirationInDays or NoncurrentVersionExpiration.NoncurrentDays)"})
		}
		out = append(out, rule)
	}
	return out
}

// ---- AWS::SQS::Queue -> kind: Queue (a work queue) ----
//
// A standalone managed queue backed by a NATS JetStream WorkQueue stream (each message to one
// consumer, removed on ack — SQS semantics). QueueName -> the stream/subject, MessageRetentionPeriod
// -> retentionHours. FIFO and per-queue encryption BLOCK (JetStream ordering/dedup differs; no
// per-queue KMS). Visibility/delay/DLQ-redrive are consumer-side on the app's JetStream consumer,
// so they are declared caveats.
func translateSQSQueue(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	if ctx.servedBy(id) {
		return translateSQSQueueAPI(id, props, ctx)
	}
	known := map[string]bool{
		"QueueName": true, "MessageRetentionPeriod": true, "Tags": true, "FifoQueue": true,
		"VisibilityTimeout": true, "DelaySeconds": true, "RedrivePolicy": true, "KmsMasterKeyId": true,
		"ReceiveMessageWaitTimeSeconds": true, "MaximumMessageSize": true, "ContentBasedDeduplication": true,
		"DeduplicationScope": true, "FifoThroughputLimit": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	if _, ok := props["KmsMasterKeyId"]; ok {
		f = append(f, Finding{"Resource " + id, "KmsMasterKeyId is not translatable — no per-queue encryption"})
	}
	spec := map[string]any{}
	// FIFO (#116): FifoQueue:true, or a QueueName ending in .fifo, maps to a JetStream FIFO stream
	// (per-group subject ordering + a 5m publish-dedup window). The .fifo suffix is stripped — a NATS
	// stream name cannot contain a dot (the per-group subject token is appended by the producer).
	fifo, ff := boolProp(id, props, "FifoQueue", false)
	f = append(f, ff...)
	qn, _ := concrete(props["QueueName"])
	if strings.HasSuffix(qn, ".fifo") {
		fifo = true
		qn = strings.TrimSuffix(qn, ".fifo")
	}
	if qn != "" {
		spec["queueName"] = qn
	}
	if fifo {
		spec["fifo"] = true
	}
	if r, ok := props["MessageRetentionPeriod"]; ok {
		hrs := toInt(r) / 3600
		if hrs < 1 {
			hrs = 1
		}
		spec["retentionHours"] = hrs
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Queue", Name: ctx.name(id), Spec: spec}
	// FIFO-specific residue: dedup is honored via the Nats-Msg-Id header (the stream carries the
	// window), but there is no front door to auto-hash the body for ContentBasedDeduplication, and
	// dedup scope / throughput-limit have no equivalent — named, not silently dropped.
	if fifo {
		if _, ok := props["ContentBasedDeduplication"]; ok {
			m.Caveats = append(m.Caveats, "ContentBasedDeduplication: dedup is enforced on the Nats-Msg-Id header within the window; the producer must set it (to a content hash) — open-infra has no front door to auto-hash the message body")
		}
		for _, p := range []string{"DeduplicationScope", "FifoThroughputLimit"} {
			if _, ok := props[p]; ok {
				m.Caveats = append(m.Caveats, p+" dropped — dedup is always per-message-group (subject) scope; FIFO throughput on JetStream differs from SQS and is not modelled")
			}
		}
	} else if _, ok := props["ContentBasedDeduplication"]; ok {
		m.Caveats = append(m.Caveats, "ContentBasedDeduplication ignored — it applies only to a FIFO queue")
	}
	if !fifo {
		for _, p := range []string{"DeduplicationScope", "FifoThroughputLimit"} {
			if _, ok := props[p]; ok {
				m.Caveats = append(m.Caveats, p+" ignored — it applies only to a FIFO queue")
			}
		}
	}
	for _, p := range []string{"VisibilityTimeout", "DelaySeconds", "RedrivePolicy", "ReceiveMessageWaitTimeSeconds", "MaximumMessageSize", "Tags"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — SQS delivery semantics (visibility/delay/DLQ) are configured on the app's JetStream consumer, not the queue")
		}
	}
	return m, f
}

// ---- AWS::SNS::Topic -> kind: Queue (a fan-out topic) ----
//
// A standalone pub/sub topic backed by a NATS JetStream Limits stream (messages retained for the
// window; every consumer reads them independently — SNS fan-out). TopicName -> the stream/subject.
// FIFO and encryption BLOCK. Inline Subscriptions are classified per-protocol (#113): a `lambda` sub
// to an in-stack Function is fine (the Function anchor folds the topic's stream into its spec.queues,
// so no Finding here); every other protocol — sqs/http/email/sms/etc — refuses honestly, since
// open-infra has no push-delivery surface for it (consumers read the stream themselves).
func translateSNSTopic(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	if ctx.servedBy(id) {
		return translateSNSTopicAPI(id, props, ctx)
	}
	known := map[string]bool{
		"TopicName": true, "DisplayName": true, "Tags": true, "FifoTopic": true,
		"KmsMasterKeyId": true, "ContentBasedDeduplication": true, "Subscription": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	fifoTopic, ff := boolProp(id, props, "FifoTopic", false)
	f = append(f, ff...)
	if fifoTopic {
		f = append(f, Finding{"Resource " + id, "a FIFO topic is not translatable — JetStream ordering/dedup differs from SNS FIFO"})
	}
	if _, ok := props["KmsMasterKeyId"]; ok {
		f = append(f, Finding{"Resource " + id, "KmsMasterKeyId is not translatable — no per-topic encryption"})
	}
	// Classify each inline Subscription. Read the raw property list (when we have a stack context) so a
	// lambda Endpoint's {Fn::GetAtt}/{Ref} is still followable to an in-stack Function logical id.
	f = append(f, snsInlineSubscriptionShape(id, props)...)
	subsRaw := props["Subscription"]
	if ctx != nil {
		if raw, ok := ctx.rawProps(id); ok {
			subsRaw = raw["Subscription"]
		}
	}
	if subs, ok := subsRaw.([]any); ok {
		for _, s := range subs {
			sm, ok := s.(map[string]any)
			if !ok {
				continue // refused by snsInlineSubscriptionShape
			}
			proto, _ := concrete(sm["Protocol"])
			if msg, _ := ctx.classifySNSSub(proto, sm["Endpoint"]); msg != "" {
				f = append(f, Finding{"Resource " + id, msg})
			}
		}
	}
	spec := map[string]any{"fanout": true}
	if tn, ok := concrete(props["TopicName"]); ok && tn != "" {
		spec["queueName"] = tn
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Queue", Name: ctx.name(id), Spec: spec}
	for _, p := range []string{"DisplayName", "Tags", "ContentBasedDeduplication"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — no open-infra equivalent")
		}
	}
	return m, f
}

// snsInlineSubscriptionShape refuses an AWS::SNS::Topic Subscription of the wrong shape: AWS defines it
// as a list of {Endpoint, Protocol} objects, both required. A value that is not a list, an entry that
// is not an object, an entry missing either key or carrying another (a FilterPolicy belongs on an
// AWS::SNS::Subscription resource) would otherwise be skipped — a subscriber the template declared
// would silently never receive the topic's messages.
func snsInlineSubscriptionShape(id string, props map[string]any) []Finding {
	v, set := props["Subscription"]
	if !set || v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return []Finding{{"Resource " + id, fmt.Sprintf("Subscription must be a list of {Endpoint, Protocol} (got %v)", v)}}
	}
	var f []Finding
	for i, s := range list {
		where := fmt.Sprintf("%s.Subscription[%d]", id, i)
		sm, ok := s.(map[string]any)
		if !ok {
			f = append(f, Finding{"Resource " + where, fmt.Sprintf("each Subscription must be an object with Protocol and Endpoint (got %v)", s)})
			continue
		}
		f = append(f, blockUnknownProps(where, sm, map[string]bool{"Endpoint": true, "Protocol": true})...)
		for _, k := range []string{"Endpoint", "Protocol"} {
			if _, has := sm[k]; !has {
				f = append(f, Finding{"Resource " + where, "a Subscription needs both Protocol and Endpoint (missing " + k + ")"})
			}
		}
	}
	return f
}

// ---- AWS::SNS::Subscription -> collated into the subscriber's kind: Function (spec.queues) ----
//
// Only a `lambda` subscription to an in-stack AWS::Lambda::Function has a faithful open-infra form:
// the Function reads the topic's JetStream stream directly (the Function anchor folds the topic into
// its spec.queues), so this resource provisions nothing on its own — a no-op, like an S3::BucketPolicy
// riding its bucket. Everything else refuses honestly rather than silently dropping the delivery
// wiring: a topic not in this stack (nothing we manage to subscribe to), a lambda Endpoint that is not
// an in-stack Function, an `sqs` sub (open-infra builds no topic→queue bridge — point the consumer at
// the topic stream via spec.queues instead), and http/https/email/email-json/sms/application/firehose
// (open-infra has no outward push-delivery surface).
func translateSNSSubscription(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	if ctx == nil {
		return nil, []Finding{{"Resource " + id, "an AWS::SNS::Subscription must reference an in-stack AWS::SNS::Topic"}}
	}
	if ctx.servedBy(id) {
		return translateSNSSubscriptionAPI(id, props, ctx)
	}
	// A subscription collates into the subscribing Function and has no manifest of its own to carry a
	// caveat, so every delivery setting beyond the topic, protocol and endpoint refuses: FilterPolicy in
	// particular, since the Function would otherwise receive every message on the topic.
	known := map[string]bool{"TopicArn": true, "Protocol": true, "Endpoint": true, "Region": true}
	if f := blockUnknownProps(id, props, known); len(f) > 0 {
		for i := range f {
			f[i].Reason += " (a subscription's filter and delivery settings are not applied — the subscriber would receive every message on the topic)"
		}
		return nil, f
	}
	raw, _ := ctx.rawProps(id)
	// The TopicArn must resolve to an in-stack AWS::SNS::Topic — we only subscribe to a topic we manage.
	if t, ok := getAttTarget(raw["TopicArn"]); !ok || !ctx.isType(t, "AWS::SNS::Topic") {
		return nil, []Finding{{"Resource " + id, "an AWS::SNS::Subscription must reference an in-stack AWS::SNS::Topic — its TopicArn names/Refs a topic not in this stack, and a subscription to a topic we don't manage is not translatable (a lambda subscription is collated into the subscribing kind: Function as spec.queues)"}}
	}
	proto, _ := concrete(props["Protocol"])
	if msg, _ := ctx.classifySNSSub(proto, raw["Endpoint"]); msg != "" {
		return nil, []Finding{{"Resource " + id, msg}}
	}
	return nil, nil // a lambda sub to an in-stack Function — the Function anchor collates it (spec.queues)
}

// classifySNSSub classifies one SNS subscription by its Protocol and raw Endpoint. It returns a
// refusing message when the subscription has no faithful open-infra form, or ("", fnID) when it is a
// `lambda` subscription whose Endpoint resolves to an in-stack AWS::Lambda::Function (fnID) — the case
// the subscribing Function collates into spec.queues. A nil receiver (no stack context) treats a
// lambda sub as unresolvable and refuses it.
func (c *stackCtx) classifySNSSub(protocol string, endpointRaw any) (msg string, fnID string) {
	switch strings.ToLower(protocol) {
	case "lambda":
		if c != nil {
			if eid, ok := getAttTarget(endpointRaw); ok && c.isType(eid, "AWS::Lambda::Function") {
				return "", eid
			}
		}
		return "a lambda SNS subscription's Endpoint must resolve to an in-stack AWS::Lambda::Function (the subscribing Function reads the topic stream via spec.queues) — an out-of-stack or non-Function endpoint has no open-infra delivery target", ""
	case "sqs":
		return "an SQS subscription needs a topic→queue stream bridge, which open-infra does not build — instead give the consumer `spec.queues: [<topic>]` so it reads the topic stream directly", ""
	case "http", "https", "email", "email-json", "sms", "application", "firehose":
		return "no open-infra outward-delivery surface for the \"" + protocol + "\" SNS subscription protocol", ""
	default:
		return "SNS subscription protocol \"" + protocol + "\" is not translatable", ""
	}
}

// isType reports whether logical id `rid` is an in-stack resource of the given CFN type.
func (c *stackCtx) isType(rid, cfnType string) bool {
	r, in := c.template.Resources[rid]
	return in && r.Type == cfnType
}

// snsTopicQueueName returns the JetStream stream/queue name an AWS::SNS::Topic maps to — resolved the
// SAME way translateSNSTopic does (TopicName when concrete, else the topic's kind name) — so a subscriber
// that adds this to spec.queues reads exactly the stream the topic creates.
func snsTopicQueueName(topicID string, topicProps map[string]any, ctx *stackCtx) string {
	if tn, ok := concrete(topicProps["TopicName"]); ok && tn != "" {
		return tn
	}
	return ctx.name(topicID)
}

// snsQueuesForFunction returns, in stable (deduped, sorted) order, the stream name of every in-stack
// AWS::SNS::Topic that a `lambda` SNS subscription targets at Function fnID — whether via a standalone
// AWS::SNS::Subscription or an inline Subscription on the topic. Folding these into the Function's
// spec.queues is how an SNS→Lambda subscription is honored: the Function consumes the topic's stream.
func (c *stackCtx) snsQueuesForFunction(fnID string) []string {
	if c != nil && c.caps.SNSAPI {
		return nil // the SNS front door delivers to the Function itself (service.go); no stream to read
	}
	seen := map[string]bool{}
	var names []string
	add := func(topicID string) {
		tp, _ := c.resolveProps(topicID)
		if qn := snsTopicQueueName(topicID, tp, c); qn != "" && !seen[qn] {
			seen[qn] = true
			names = append(names, qn)
		}
	}
	var ids []string
	for rid := range c.template.Resources {
		ids = append(ids, rid)
	}
	sortStrs(ids)
	for _, rid := range ids {
		res := c.template.Resources[rid]
		if !c.included(res) {
			continue // a conditioned-OFF Subscription/Topic must not fold a queue into the Function
		}
		switch res.Type {
		case "AWS::SNS::Subscription":
			raw, _ := c.rawProps(rid)
			sp, _ := c.resolveProps(rid)
			if proto, _ := concrete(sp["Protocol"]); strings.ToLower(proto) != "lambda" {
				continue
			}
			if eid, ok := getAttTarget(raw["Endpoint"]); !ok || eid != fnID {
				continue
			}
			if tid, ok := getAttTarget(raw["TopicArn"]); ok && c.isType(tid, "AWS::SNS::Topic") {
				add(tid)
			}
		case "AWS::SNS::Topic":
			raw, _ := c.rawProps(rid)
			subs, ok := raw["Subscription"].([]any)
			if !ok {
				continue
			}
			for _, s := range subs {
				sm, ok := s.(map[string]any)
				if !ok {
					continue
				}
				if proto, _ := concrete(sm["Protocol"]); strings.ToLower(proto) != "lambda" {
					continue
				}
				if eid, ok := getAttTarget(sm["Endpoint"]); ok && eid == fnID {
					add(rid)
				}
			}
		}
	}
	sortStrs(names)
	return names
}

// ---- AWS::AppSync::GraphQLApi (+ Schema/DataSource/Resolver/FunctionConfiguration) -> kind: GraphQLApi ----
//
// AppSync splits one API across several resources that all point back at the API via `ApiId`. This
// is a COLLATION (the ECS pattern): the GraphQLApi is the anchor and reads its in-stack children —
// the GraphQLSchema (the SDL), every DataSource, and every Resolver (unit or pipeline, pulling in
// the FunctionConfigurations a pipeline references) — merging them into one kind: GraphQLApi. The
// payoff is open-appsync's whole reason to exist: a resolver's VTL is byte-for-byte identical, so
// Request/ResponseMappingTemplate carry over verbatim.
//
// Faithful: schema SDL, unit + pipeline resolvers (VTL and APPSYNC_JS), and the data-source types
// open-appsync has (dynamodb, http, none, opensearch, eventbridge). Refused (fail-loud, never a
// silent half-API): a Lambda-ARN data source (an AWS ARN is not an open-infra Function URL), a
// relational source with no DSN, and any S3-location template/definition. Caveat: AuthenticationType
// (open-appsync enforces auth via @aws_* schema directives + an apiKeysSecret, configured separately)
// and a dynamodb source's spec.mongoURI (a deploy-time FerretDB endpoint, not knowable here).
func translateAppSyncGraphQLApi(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"Name": true, "AuthenticationType": true, "AdditionalAuthenticationProviders": true,
		"LogConfig": true, "UserPoolConfig": true, "OpenIDConnectConfig": true,
		"LambdaAuthorizerConfig": true, "XrayEnabled": true, "Tags": true, "ApiType": true,
		"IntrospectionConfig": true, "QueryDepthLimit": true, "ResolverCountLimit": true,
		"Visibility": true, "MergedApiExecutionRoleArn": true, "OwnerContact": true,
		"EnvironmentVariables": true, "HealthMetricsConfig": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	spec := map[string]any{}

	// schema: the in-stack GraphQLSchema whose ApiId -> this API.
	for _, cid := range ctx.appsyncChildren("AWS::AppSync::GraphQLSchema", id) {
		sp, _ := ctx.resolveProps(cid)
		f = append(f, blockUnknownProps(cid, sp, map[string]bool{"ApiId": true, "Definition": true, "DefinitionS3Location": true})...)
		f = append(f, shapeFindings(cid, sp, nil, nil, []string{"Definition"})...)
		if _, ok := sp["DefinitionS3Location"]; ok {
			f = append(f, Finding{"Resource " + cid, "GraphQLSchema DefinitionS3Location is not translatable — the SDL must be inline (Definition)"})
		}
		if def, ok := concrete(sp["Definition"]); ok && def != "" {
			spec["schema"] = def
		}
	}

	// data sources.
	var dataSources []any
	var childCaveats []string // what a data source / resolver / function asks for that does not apply here
	hasDynamo := false
	for _, cid := range ctx.appsyncChildren("AWS::AppSync::DataSource", id) {
		sp, _ := ctx.resolveProps(cid)
		ds, isDynamo := appsyncDataSource(cid, sp, &f, &childCaveats)
		hasDynamo = hasDynamo || isDynamo
		dataSources = append(dataSources, ds)
	}
	if len(dataSources) > 0 {
		spec["dataSources"] = dataSources
	}

	// resolvers (required — a GraphQLApi with no resolver can't be created).
	var resolvers []any
	for _, cid := range ctx.appsyncChildren("AWS::AppSync::Resolver", id) {
		resolvers = append(resolvers, ctx.appsyncResolver(cid, &f, &childCaveats))
	}
	if len(resolvers) == 0 {
		f = append(f, Finding{"Resource " + id, "a GraphQLApi requires at least one AWS::AppSync::Resolver in the stack (open-infra's GraphQLApi resolves fields from its resolver list)"})
	} else {
		spec["resolvers"] = resolvers
	}

	// Auth: open-appsync enforces the schema's @aws_* directives and serves a field with none as public,
	// where AWS applies the API's default AuthenticationType. Refuse unless every way into the graph (each
	// root operation field) is protected by a directive.
	at, _ := concrete(props["AuthenticationType"])
	if sdl, _ := spec["schema"].(string); sdl != "" {
		missing, scanned := rootFieldsWithoutAuth(sdl)
		switch {
		case !scanned:
			f = append(f, Finding{"Resource " + id, "the schema could not be checked for auth directives — refusing rather than risking fields served without authentication"})
		case len(missing) > 0:
			dir := defaultAuthDirective[at]
			if dir == "" {
				dir = "an @aws_* directive"
			}
			f = append(f, Finding{"Resource " + id, "root fields " + strings.Join(missing, ", ") + " carry no auth directive — on AWS they would use the default AuthenticationType " + at + ", but open-appsync would serve them unauthenticated; add " + dir + " to each field or to its type"})
		}
	}
	if v, set := props["Visibility"]; set && v != nil {
		if s, _ := concrete(v); s != "GLOBAL" && s != "PRIVATE" {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("Visibility must be GLOBAL or PRIVATE (got %v)", v)})
		}
	}
	if v, set := props["ApiType"]; set && v != nil {
		if _, ok := concrete(v); !ok {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("ApiType must be GRAPHQL or MERGED (got %v)", v)})
		}
	}
	if v, _ := concrete(props["Visibility"]); v == "PRIVATE" {
		f = append(f, Finding{"Resource " + id, "Visibility PRIVATE (reachable only through VPC endpoints) has no open-appsync form — refusing rather than serving the API more widely"})
	}
	if t, _ := concrete(props["ApiType"]); t != "" && t != "GRAPHQL" {
		f = append(f, Finding{"Resource " + id, "ApiType " + t + " is not supported — open-appsync serves a single (non-merged) GraphQL API"})
	}
	if ic, _ := concrete(props["IntrospectionConfig"]); ic == "DISABLED" {
		spec["limits"] = map[string]any{"introspection": "disabled"}
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "GraphQLApi", Name: ctx.name(id), Spec: spec}
	if at != "" {
		m.Caveats = append(m.Caveats, "AuthenticationType "+at+" is enforced only through the schema's @aws_* directives (each root field carries one) — open-appsync has no API-wide default mode; @aws_api_key needs an apiKeysSecret configured separately")
	}
	for _, p := range []string{"AdditionalAuthenticationProviders", "UserPoolConfig", "OpenIDConnectConfig", "LambdaAuthorizerConfig"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" is not translated — the platform validates each @aws_* mode with its own identity providers, and the caller's permissions decide; the pools/issuers/authorizer this names are not consulted")
		}
	}
	for _, p := range []string{"LogConfig", "XrayEnabled", "EnvironmentVariables", "ResolverCountLimit", "HealthMetricsConfig", "OwnerContact", "MergedApiExecutionRoleArn"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — no open-appsync equivalent")
		}
	}
	if q, ok := props["QueryDepthLimit"]; ok && q != nil {
		// AWS takes 0 (no limit) through 75; anything else is refused there, so it is refused here too
		// rather than serving the API with no depth limit.
		if n, isNum := positiveWhole(q); isNum && n <= 75 {
			lim, _ := spec["limits"].(map[string]any)
			if lim == nil {
				lim = map[string]any{}
				spec["limits"] = lim
			}
			lim["maxDepth"] = n
		} else if s, _ := concrete(q); s != "0" {
			f = append(f, Finding{"Resource " + id, fmt.Sprintf("QueryDepthLimit must be a whole number from 0 to 75 (got %v)", q)})
		}
	}
	if hasDynamo {
		m.Caveats = append(m.Caveats, "a dynamodb data source needs spec.mongoURI (the FerretDB endpoint) set at deploy time — it is not derivable from the template, and the source fails closed at load until set")
	}
	m.Caveats = append(m.Caveats, childCaveats...)
	return m, f
}

// translateAppSyncChild is the no-op half of the collation: a Schema/DataSource/Resolver/
// FunctionConfiguration whose ApiId points at an in-stack GraphQLApi provisions nothing on its own
// (the API anchor reads it). But one pointing at an API NOT in this stack is REFUSED rather than
// silently dropped — we can't attach to an API we don't manage.
func translateAppSyncChild(id string, _ map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	raw, _ := ctx.rawProps(id)
	apiID, ok := getAttTarget(raw["ApiId"])
	if ok {
		if api, in := ctx.template.Resources[apiID]; in && api.Type == "AWS::AppSync::GraphQLApi" {
			return nil, nil // collated into the API
		}
	}
	return nil, []Finding{{"Resource " + id, "its ApiId does not reference an AWS::AppSync::GraphQLApi in this stack — an AppSync sub-resource can only attach to an in-stack API"}}
}

// appsyncChildren returns, in deterministic order, the logical ids of resources of cfnType whose
// ApiId references apiID.
func (c *stackCtx) appsyncChildren(cfnType, apiID string) []string {
	return c.collatedChildren(cfnType, "ApiId", apiID)
}

// appsyncDataSource maps one AWS::AppSync::DataSource to an open-appsync data source; the bool
// reports whether it is a dynamodb source (so the caller can surface the mongoURI caveat).
func appsyncDataSource(cid string, sp map[string]any, f *[]Finding, cav *[]string) (map[string]any, bool) {
	known := map[string]bool{
		"ApiId": true, "Name": true, "Type": true, "Description": true, "ServiceRoleArn": true,
		"DynamoDBConfig": true, "LambdaConfig": true, "HttpConfig": true, "MetricsConfig": true,
		"RelationalDatabaseConfig": true, "OpenSearchServiceConfig": true, "ElasticsearchConfig": true,
		"EventBridgeConfig": true,
	}
	*f = append(*f, blockUnknownProps(cid, sp, known)...)
	appsyncMetricsConfig(cid, "data source", sp, f, cav)
	// ServiceRoleArn names the role AppSync assumes to reach the source, and that role's policy bounds
	// what the source's resolvers may do. open-appsync reaches each source with the engine's own
	// connection instead, so the role does not narrow anything: reported, never silently dropped.
	if v, set := sp["ServiceRoleArn"]; set && v != nil {
		if s, ok := v.(string); !ok || s == "" {
			*f = append(*f, Finding{"Resource " + cid, fmt.Sprintf("ServiceRoleArn must be a role ARN (got %v)", v)})
		} else {
			*cav = append(*cav, "data source "+cid+": its ServiceRoleArn is not assumed — open-appsync reaches the source with the engine's own connection, so that role's policy does not limit what the resolvers using it can read or write")
		}
	}
	name, _ := concrete(sp["Name"])
	ds := map[string]any{"name": name}
	dynamo := false
	// A data source's config is the one its Type takes; another set beside it would be ignored, so it refuses.
	typ, _ := concrete(sp["Type"])
	configFor := map[string][]string{
		"AMAZON_DYNAMODB": {"DynamoDBConfig"}, "HTTP": {"HttpConfig"}, "AMAZON_EVENTBRIDGE": {"EventBridgeConfig"},
		"AMAZON_OPENSEARCH_SERVICE": {"OpenSearchServiceConfig", "ElasticsearchConfig"}, "AMAZON_ELASTICSEARCH": {"OpenSearchServiceConfig", "ElasticsearchConfig"},
		"AWS_LAMBDA": {"LambdaConfig"}, "RELATIONAL_DATABASE": {"RelationalDatabaseConfig"}, "NONE": nil,
	}
	if allowed, known := configFor[typ]; known {
		for _, k := range []string{"DynamoDBConfig", "LambdaConfig", "HttpConfig", "RelationalDatabaseConfig", "OpenSearchServiceConfig", "ElasticsearchConfig", "EventBridgeConfig"} {
			if _, set := sp[k]; !set {
				continue
			}
			ok := false
			for _, a := range allowed {
				ok = ok || a == k
			}
			if !ok {
				*f = append(*f, Finding{"Resource " + cid, k + " does not go with a " + typ + " data source — CloudFormation takes the config of the source's Type only"})
			}
		}
	}
	switch t := typ; t {
	case "AMAZON_DYNAMODB":
		ds["type"] = "dynamodb"
		dynamo = true
		if cfg, ok := sp["DynamoDBConfig"].(map[string]any); ok {
			if tbl, ok := concrete(cfg["TableName"]); ok && tbl != "" {
				ds["collection"] = tbl
			}
		}
	case "HTTP":
		ds["type"] = "http"
		if cfg, ok := sp["HttpConfig"].(map[string]any); ok {
			if ep, ok := concrete(cfg["Endpoint"]); ok && ep != "" {
				ds["endpoint"] = ep
			}
		}
	case "NONE":
		ds["type"] = "none"
	case "AMAZON_OPENSEARCH_SERVICE", "AMAZON_ELASTICSEARCH":
		ds["type"] = "opensearch"
		for _, k := range []string{"OpenSearchServiceConfig", "ElasticsearchConfig"} {
			if cfg, ok := sp[k].(map[string]any); ok {
				if ep, ok := concrete(cfg["Endpoint"]); ok && ep != "" {
					ds["endpoint"] = ep
				}
			}
		}
	case "AMAZON_EVENTBRIDGE":
		ds["type"] = "eventbridge"
	case "AWS_LAMBDA":
		*f = append(*f, Finding{"Resource " + cid, "a Lambda data source (AWS_LAMBDA) has no faithful form — an AWS LambdaFunctionArn is not an open-infra Function URL; remap to a lambda data source with the kind: Function URL as its endpoint, or an http source"})
	case "RELATIONAL_DATABASE":
		*f = append(*f, Finding{"Resource " + cid, "a relational data source has no faithful form — provide a connectionSecret with a DSN out of band (the AWS RelationalDatabaseConfig names a cluster ARN, not a DSN)"})
	default:
		*f = append(*f, Finding{"Resource " + cid, "data source Type " + t + " is not supported by open-appsync"})
	}
	return ds, dynamo
}

// appsyncResolver maps one AWS::AppSync::Resolver to an open-appsync resolver (unit or pipeline, VTL
// or APPSYNC_JS). Every property is read in its AWS shape; a value of another shape refuses rather than
// being skipped (a resolver that silently ran the wrong code, or no code, is the worst outcome).
func (c *stackCtx) appsyncResolver(cid string, f *[]Finding, cav *[]string) map[string]any {
	sp, _ := c.resolveProps(cid)
	known := map[string]bool{
		"ApiId": true, "TypeName": true, "FieldName": true, "DataSourceName": true, "Kind": true,
		"RequestMappingTemplate": true, "ResponseMappingTemplate": true, "PipelineConfig": true,
		"RequestMappingTemplateS3Location": true, "ResponseMappingTemplateS3Location": true,
		"Runtime": true, "Code": true, "CodeS3Location": true, "MaxBatchSize": true,
		"CachingConfig": true, "SyncConfig": true, "MetricsConfig": true,
	}
	*f = append(*f, blockUnknownProps(cid, sp, known)...)
	appsyncS3Locations(cid, sp, f)
	appsyncBatchAndSync(cid, sp, f)
	appsyncMetricsConfig(cid, "resolver", sp, f, cav)

	r := map[string]any{}
	if t, ok := concrete(sp["TypeName"]); ok {
		r["type"] = t
	}
	if fld, ok := concrete(sp["FieldName"]); ok {
		r["field"] = fld
	}
	isJS, code := appsyncCode(cid, sp, f)
	r["runtime"] = "appsync-vtl"
	if isJS {
		r["runtime"] = "appsync-js"
	}
	appsyncCachingConfig(cid, sp, f, cav)

	kind := "UNIT"
	if v, set := sp["Kind"]; set && v != nil {
		kind, _ = concrete(v)
		if kind != "UNIT" && kind != "PIPELINE" {
			*f = append(*f, Finding{"Resource " + cid, fmt.Sprintf("Kind must be UNIT or PIPELINE (got %v)", v)})
		}
	}
	if kind == "PIPELINE" {
		// A pipeline resolver: a VTL one's Request/Response templates are its before/after steps; a
		// JavaScript one's Code is one module whose request(ctx) runs before the functions and whose
		// response(ctx) runs after them. PipelineConfig names the FunctionConfigurations, in order.
		if isJS {
			r["before"], r["after"] = code, code
		} else {
			if req, ok := concrete(sp["RequestMappingTemplate"]); ok && req != "" {
				r["before"] = req
			}
			if resp, ok := concrete(sp["ResponseMappingTemplate"]); ok && resp != "" {
				r["after"] = resp
			}
		}
		r["functions"] = c.appsyncPipelineFunctions(cid, f, cav)
	} else {
		if _, set := sp["PipelineConfig"]; set {
			*f = append(*f, Finding{"Resource " + cid, "PipelineConfig belongs to a PIPELINE resolver — this one's Kind is UNIT, so its functions would not run"})
		}
		// A unit resolver binds one data source with a request/response template (or JS code).
		if isJS {
			r["request"] = code
		} else {
			if req, ok := concrete(sp["RequestMappingTemplate"]); ok && req != "" {
				r["request"] = req
			}
			if resp, ok := concrete(sp["ResponseMappingTemplate"]); ok && resp != "" {
				r["response"] = resp
			}
		}
		if dsn := c.resolveDSName(cid, "DataSourceName"); dsn != "" {
			r["dataSource"] = dsn
		} else {
			*f = append(*f, Finding{"Resource " + cid, "a unit resolver requires a DataSourceName naming an in-stack AWS::AppSync::DataSource"})
		}
	}
	return r
}

// appsyncPipelineFunctions maps a pipeline resolver's PipelineConfig.Functions (references to
// AWS::AppSync::FunctionConfiguration) to open-appsync pipeline functions.
func (c *stackCtx) appsyncPipelineFunctions(cid string, f *[]Finding, cav *[]string) []any {
	raw, _ := c.rawProps(cid)
	pcv, set := raw["PipelineConfig"]
	pc, ok := pcv.(map[string]any)
	if !set || !ok {
		*f = append(*f, Finding{"Resource " + cid, fmt.Sprintf("a PIPELINE resolver needs a PipelineConfig with its Functions (got %v)", pcv)})
		return nil
	}
	*f = append(*f, blockUnknownProps(cid+".PipelineConfig", pc, map[string]bool{"Functions": true})...)
	fnRefs, ok := pc["Functions"].([]any)
	if !ok || len(fnRefs) == 0 {
		*f = append(*f, Finding{"Resource " + cid, fmt.Sprintf("PipelineConfig.Functions must list the resolver's FunctionConfigurations (got %v)", pc["Functions"])})
		return nil
	}
	var out []any
	for _, ref := range fnRefs {
		fid, ok := getAttTarget(ref)
		if !ok {
			*f = append(*f, Finding{"Resource " + cid, "a PipelineConfig function must reference an in-stack AWS::AppSync::FunctionConfiguration"})
			continue
		}
		fnRes, in := c.template.Resources[fid]
		if !in || fnRes.Type != "AWS::AppSync::FunctionConfiguration" {
			*f = append(*f, Finding{"Resource " + cid, "PipelineConfig references " + fid + ", which is not an AWS::AppSync::FunctionConfiguration in this stack"})
			continue
		}
		fp, _ := c.resolveProps(fid)
		fnknown := map[string]bool{
			"ApiId": true, "Name": true, "DataSourceName": true, "Description": true,
			"RequestMappingTemplate": true, "ResponseMappingTemplate": true, "FunctionVersion": true,
			"RequestMappingTemplateS3Location": true, "ResponseMappingTemplateS3Location": true,
			"Runtime": true, "Code": true, "CodeS3Location": true, "MaxBatchSize": true, "SyncConfig": true,
		}
		*f = append(*f, blockUnknownProps(fid, fp, fnknown)...)
		appsyncS3Locations(fid, fp, f)
		appsyncBatchAndSync(fid, fp, f)
		fn := map[string]any{"runtime": "appsync-vtl"}
		if dsn := c.resolveDSName(fid, "DataSourceName"); dsn != "" {
			fn["dataSource"] = dsn
		} else {
			*f = append(*f, Finding{"Resource " + fid, "a FunctionConfiguration requires a DataSourceName naming an in-stack AWS::AppSync::DataSource"})
		}
		if isJS, code := appsyncCode(fid, fp, f); isJS {
			// A JavaScript function is one module (request + response); the engine reads it as the
			// function's source, and the response field (required by the kind) carries the same module.
			fn["runtime"], fn["request"], fn["response"] = "appsync-js", code, code
		} else {
			if req, ok := concrete(fp["RequestMappingTemplate"]); ok {
				fn["request"] = req
			}
			if resp, ok := concrete(fp["ResponseMappingTemplate"]); ok {
				fn["response"] = resp
			}
		}
		out = append(out, fn)
	}
	return out
}

// appsyncS3Locations refuses a template or code fetched from S3: the engine serves inline sources only.
func appsyncS3Locations(cid string, sp map[string]any, f *[]Finding) {
	for _, k := range []string{"RequestMappingTemplateS3Location", "ResponseMappingTemplateS3Location", "CodeS3Location"} {
		if _, ok := sp[k]; ok {
			*f = append(*f, Finding{"Resource " + cid, k + " is not translatable — mapping templates / code must be inline, not fetched from S3"})
		}
	}
}

// appsyncCode reads a resolver or function's Runtime and Code: Runtime, when set, must be AWS's only
// JavaScript runtime ({Name: APPSYNC_JS, RuntimeVersion: 1.0.0}) and then takes inline Code and no
// mapping templates; Code without that Runtime refuses, since AWS runs no code for a VTL resolver.
func appsyncCode(cid string, sp map[string]any, f *[]Finding) (isJS bool, code string) {
	where := "Resource " + cid
	if v, set := sp["Runtime"]; set && v != nil {
		rt, ok := v.(map[string]any)
		if !ok {
			*f = append(*f, Finding{where, fmt.Sprintf("Runtime must be {Name: APPSYNC_JS, RuntimeVersion: 1.0.0} (got %v)", v)})
		} else {
			*f = append(*f, blockUnknownProps(cid+".Runtime", rt, map[string]bool{"Name": true, "RuntimeVersion": true})...)
			name, _ := concrete(rt["Name"])
			ver, _ := concrete(rt["RuntimeVersion"])
			if name != "APPSYNC_JS" || ver != "1.0.0" {
				*f = append(*f, Finding{where, fmt.Sprintf("Runtime %v %v is not served — the JavaScript runtime is APPSYNC_JS 1.0.0", rt["Name"], rt["RuntimeVersion"])})
			} else {
				isJS = true
			}
		}
	}
	cv, hasCode := sp["Code"]
	switch {
	case isJS && !hasCode:
		if _, s3 := sp["CodeS3Location"]; !s3 {
			*f = append(*f, Finding{where, "an APPSYNC_JS resolver or function needs its Code inline"})
		}
	case isJS:
		s, ok := cv.(string)
		if !ok || strings.TrimSpace(s) == "" {
			*f = append(*f, Finding{where, fmt.Sprintf("Code must be the JavaScript module's source (got %v)", cv)})
		}
		code = s
		for _, k := range []string{"RequestMappingTemplate", "ResponseMappingTemplate"} {
			if _, set := sp[k]; set {
				*f = append(*f, Finding{where, k + " does not go with an APPSYNC_JS Runtime — a JavaScript resolver's request and response are in its Code"})
			}
		}
	case hasCode:
		*f = append(*f, Finding{where, "Code needs Runtime {Name: APPSYNC_JS, RuntimeVersion: 1.0.0} — without it the resolver is VTL and the code would never run"})
	}
	return isJS, code
}

// appsyncBatchAndSync reads MaxBatchSize and SyncConfig. Batching (BatchInvoke to a Lambda source) and
// conflict detection (versioned data sources) have no open-appsync form, so a value that turns either
// on refuses; MaxBatchSize 0 and ConflictDetection NONE are their off settings and change nothing.
func appsyncBatchAndSync(cid string, sp map[string]any, f *[]Finding) {
	where := "Resource " + cid
	if v, set := sp["MaxBatchSize"]; set && v != nil {
		if s, _ := concrete(v); s != "0" {
			if _, ok := positiveWhole(v); ok {
				*f = append(*f, Finding{where, "MaxBatchSize turns on BatchInvoke batching, which open-appsync does not do — each item would be resolved one call at a time"})
			} else {
				*f = append(*f, Finding{where, fmt.Sprintf("MaxBatchSize must be a whole number from 0 to 2000 (got %v)", v)})
			}
		}
	}
	if v, set := sp["SyncConfig"]; set && v != nil {
		sc, ok := v.(map[string]any)
		if !ok {
			*f = append(*f, Finding{where, fmt.Sprintf("SyncConfig must be an object (got %v)", v)})
			return
		}
		*f = append(*f, blockUnknownProps(cid+".SyncConfig", sc, map[string]bool{"ConflictDetection": true, "ConflictHandler": true, "LambdaConflictHandlerConfig": true})...)
		switch d, _ := concrete(sc["ConflictDetection"]); d {
		case "NONE":
		case "VERSION":
			*f = append(*f, Finding{where, "SyncConfig ConflictDetection VERSION (versioned data sources, as Amplify DataStore uses) is not supported by open-appsync — writes would not be version-checked"})
		default:
			*f = append(*f, Finding{where, fmt.Sprintf("SyncConfig.ConflictDetection must be VERSION or NONE (got %v)", sc["ConflictDetection"])})
		}
	}
}

// appsyncMetricsConfig reads a resolver or data source's MetricsConfig: DISABLED changes nothing; ENABLED
// asks for enhanced CloudWatch metrics, which the engine does not emit — reported, not dropped.
func appsyncMetricsConfig(cid, what string, sp map[string]any, f *[]Finding, cav *[]string) {
	v, set := sp["MetricsConfig"]
	if !set || v == nil {
		return
	}
	switch s, _ := concrete(v); s {
	case "DISABLED":
	case "ENABLED":
		*cav = append(*cav, what+" "+cid+": MetricsConfig ENABLED asks for enhanced metrics, which open-appsync does not emit")
	default:
		*f = append(*f, Finding{"Resource " + cid, fmt.Sprintf("MetricsConfig must be ENABLED or DISABLED (got %v)", v)})
	}
}

// appsyncCachingConfig reads a resolver's CachingConfig ({Ttl 1-3600, CachingKeys of $context paths}).
// On AWS it takes effect only with an API cache (AWS::AppSync::ApiCache, per-resolver caching), and an
// API cache has no open-infra form, so a stack that deploys here has none: as on AWS, nothing is cached.
// It is reported, so a reader does not take the resolver for cached.
func appsyncCachingConfig(cid string, sp map[string]any, f *[]Finding, cav *[]string) {
	v, set := sp["CachingConfig"]
	if !set || v == nil {
		return
	}
	where := "Resource " + cid
	cc, ok := v.(map[string]any)
	if !ok {
		*f = append(*f, Finding{where, fmt.Sprintf("CachingConfig must be an object (got %v)", v)})
		return
	}
	*f = append(*f, blockUnknownProps(cid+".CachingConfig", cc, map[string]bool{"Ttl": true, "CachingKeys": true})...)
	if n, ok := positiveWhole(cc["Ttl"]); !ok || n > 3600 {
		*f = append(*f, Finding{where, fmt.Sprintf("CachingConfig.Ttl must be a whole number of seconds from 1 to 3600 (got %v)", cc["Ttl"])})
	}
	if kv, set := cc["CachingKeys"]; set {
		keys, ok := kv.([]any)
		if !ok {
			*f = append(*f, Finding{where, fmt.Sprintf("CachingConfig.CachingKeys must be a list of $context paths (got %v)", kv)})
		}
		for _, k := range keys {
			if s, ok := k.(string); !ok || !(strings.HasPrefix(s, "$context.") || strings.HasPrefix(s, "$ctx.")) {
				*f = append(*f, Finding{where, fmt.Sprintf("each CachingConfig.CachingKeys entry must be a $context path, such as $context.arguments.id (got %v)", k)})
			}
		}
	}
	*cav = append(*cav, "resolver "+cid+": CachingConfig takes effect only with an API cache (AWS::AppSync::ApiCache with per-resolver caching), which this stack does not have — as on AWS, its responses are not cached")
}

// resolveDSName reads a resolver/function's DataSourceName (field) — a literal name, or a
// !Ref/!GetAtt to an in-stack AWS::AppSync::DataSource whose Name is what open-appsync references.
func (c *stackCtx) resolveDSName(id, field string) string {
	raw, _ := c.rawProps(id)
	if dsID, ok := getAttTarget(raw[field]); ok {
		if ds, in := c.template.Resources[dsID]; in && ds.Type == "AWS::AppSync::DataSource" {
			dp, _ := c.resolveProps(dsID)
			if n, ok := concrete(dp["Name"]); ok {
				return n
			}
		}
	}
	sp, _ := c.resolveProps(id)
	if n, ok := concrete(sp[field]); ok {
		return n
	}
	return ""
}

// getAttTarget returns the logical id a raw property references via `{Ref: X}` or
// `{Fn::GetAtt: [X, attr]}` (long or `X.attr` short form).
func getAttTarget(rawProp any) (string, bool) {
	m, ok := rawProp.(map[string]any)
	if !ok {
		return "", false
	}
	if id, ok := m["Ref"].(string); ok {
		return id, true
	}
	if ga, ok := m["Fn::GetAtt"]; ok {
		switch v := ga.(type) {
		case []any:
			if len(v) > 0 {
				if s, ok := v[0].(string); ok {
					return s, true
				}
			}
		case string:
			if i := strings.Index(v, "."); i > 0 {
				return v[:i], true
			}
			return v, true
		}
	}
	return "", false
}

// placeholderTargetRe recovers the logical id from a resolver placeholder ("<ref:X>" / "<X.attr>").
var placeholderTargetRe = regexp.MustCompile(`^<(?:ref:([A-Za-z0-9]+)|([A-Za-z0-9]+)\.[A-Za-z0-9.]+)>$`)

// placeholderTarget returns the logical id a RESOLVED value references when it is exactly a resolver
// placeholder for an in-stack resource — e.g. a reference wrapped in another intrinsic
// (!If [Cond, !Ref X, !Ref AWS::NoValue] resolves to "<ref:X>"), whose raw form getAttTarget can't see.
func placeholderTarget(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	m := placeholderTargetRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	if m[1] != "" {
		return m[1], true
	}
	return m[2], true
}

// sortStrs insertion-sorts a small string slice in place (keeps the dependency tiny, matching
// sortedKeys), so a collation emits its children in a deterministic order.
func sortStrs(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// blockUnknownProps records a blocking finding for every property the translator does not
// explicitly handle. This is the fail-closed heart of create translation: an unhandled
// property means we cannot honor the resource as written.
func blockUnknownProps(id string, props map[string]any, known map[string]bool) []Finding {
	if knownPropsSeen != nil {
		knownPropsSeen(id, known)
	}
	var f []Finding
	for _, k := range sortedKeys(props) {
		if !known[k] {
			f = append(f, Finding{"Resource " + id, "property " + k + " is not translatable — refusing rather than silently dropping it"})
		}
	}
	return f
}

// knownPropsSeen, when set (the fidelity guard test), receives every accepted-property set a translator
// checks, so the test can prove each accepted property is either used or reported. id is the resource's
// logical id, or for a nested block its path below it ("Web.MetadataOptions",
// "Web.BlockDeviceMappings[0].Ebs"), so the test can set each nested property in turn.
var knownPropsSeen func(id string, known map[string]bool)

// shapeFindings refuses each named property that is set to a value of the wrong shape: a list property
// that is not a list, an object property that is not an object, a scalar property that is not a concrete
// scalar (an intrinsic that resolved to something else, or did not resolve). A translator that reads such
// a value with a type assertion would otherwise skip it — the property silently ignored.
func shapeFindings(id string, props map[string]any, lists, objects, scalars []string) []Finding {
	var f []Finding
	for _, k := range lists {
		if v, ok := props[k]; ok && v != nil {
			if _, isList := v.([]any); !isList {
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s must be a list (got %v)", k, v)})
			}
		}
	}
	for _, k := range objects {
		if v, ok := props[k]; ok && v != nil {
			if _, isMap := v.(map[string]any); !isMap {
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s must be an object (got %v)", k, v)})
			}
		}
	}
	for _, k := range scalars {
		if v, ok := props[k]; ok && v != nil {
			if _, isScalar := concrete(v); !isScalar {
				f = append(f, Finding{"Resource " + id, fmt.Sprintf("%s must be a value (got %v, which does not resolve to one)", k, v)})
			}
		}
	}
	return f
}

// reportKnown reports an accepted-property set a translator checks by hand rather than through
// blockUnknownProps (it refuses unknown keys with its own message).
func reportKnown(id string, known map[string]bool) {
	if knownPropsSeen != nil {
		knownPropsSeen(id, known)
	}
}

var placeholderRe = regexp.MustCompile(`<(ref:|param:|unsupported:|base64:)|<[A-Za-z0-9_]+\.[A-Za-z0-9_]+>|<AWS::`)

// concrete returns the string form of a resolved value only if it is a real, usable value —
// not a placeholder the resolver emitted for something it could not resolve. ok=false means
// "we do not have a concrete value", which callers must treat as a blocker, never a guess.
func concrete(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	// A non-scalar (an unresolved intrinsic like {Ref: X}, or any structured value) is never a usable
	// scalar. fmt.Sprint would render {Ref: X} as "map[Ref:X]" — which slips past placeholderRe and
	// would be emitted as if it were a real value (e.g. a CIDR). Refuse it: callers treat ok=false as a
	// blocker, which is the fail-CLOSED outcome. Resolve the value (through the stack resolver) before
	// calling concrete if a concrete scalar is expected.
	switch v.(type) {
	case map[string]any, []any:
		return "", false
	}
	s := fmt.Sprint(v)
	if placeholderRe.MatchString(s) {
		return "", false
	}
	return s, true
}

var nonName = regexp.MustCompile(`[^a-z0-9-]+`)

// k8sName turns a CFN logical id into an RFC1123 resource name.
func k8sName(logicalID string) string {
	n := nonName.ReplaceAllString(strings.ToLower(logicalID), "-")
	return strings.Trim(n, "-")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// insertion sort keeps the dependency tiny; maps here are small.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
