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
package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Manifest is a concrete open-infra resource to apply.
type Manifest struct {
	APIVersion string
	Kind       string
	Name       string
	Spec       map[string]any
	Caveats    []string // declared, non-silent losses (e.g. a KMS key policy that has no equivalent)
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

// translators is the create-fidelity registry. A CFN type is create-provisionable only if it
// appears here AND its translator accepts every property. Grow it the gated way.
var translators = map[string]translator{
	"AWS::KMS::Key":                       translateKMSKey,
	"AWS::Lambda::Function":               translateLambdaFunction,
	"AWS::StepFunctions::StateMachine":    translateStateMachine,
	"AWS::EC2::Volume":                    translateVolume,
	"AWS::DynamoDB::Table":                translateDynamoDBTable,
	"AWS::IAM::User":                      translateIAMUser,
	"AWS::Cognito::UserPool":              translateCognitoUserPool,
	"AWS::Cognito::UserPoolClient":        translateCognitoUserPoolClient,
	"AWS::ECS::Service":                   translateECSService,
	"AWS::ECS::TaskDefinition":            translateECSTaskDefinition,
	"AWS::ECS::Cluster":                   translateECSCluster,
	"AWS::RDS::DBInstance":                translateRDSDBInstance,
	"AWS::S3::Bucket":                     translateS3Bucket,
	"AWS::SQS::Queue":                     translateSQSQueue,
	"AWS::SNS::Topic":                     translateSNSTopic,
	"AWS::AppSync::GraphQLApi":            translateAppSyncGraphQLApi,
	"AWS::AppSync::GraphQLSchema":         translateAppSyncChild,
	"AWS::AppSync::DataSource":            translateAppSyncChild,
	"AWS::AppSync::Resolver":              translateAppSyncChild,
	"AWS::AppSync::FunctionConfiguration": translateAppSyncChild,
}

// hasTranslator reports whether a type can be created (not merely planned).
func hasTranslator(cfnType string) bool { _, ok := translators[cfnType]; return ok }

// ---- AWS::KMS::Key -> kind: EncryptionKey ----
//
// Faithful: Description, EnableKeyRotation (-> rotationDays), KeySpec (-> keyType).
// Declared caveat: KeyPolicy (Vault-managed key; access is governed by open-infra IAM, not a
// per-key policy). Anything else blocks.
func translateKMSKey(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{"Description": true, "EnableKeyRotation": true, "KeySpec": true, "KeyPolicy": true, "Enabled": true, "Tags": true}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	spec := map[string]any{}
	if d, ok := concrete(props["Description"]); ok && d != "" {
		spec["description"] = d
	}
	if v, ok := props["EnableKeyRotation"]; ok {
		if b, ok := v.(bool); ok && b {
			spec["rotationDays"] = 365 // AWS annual rotation
		}
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
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: k8sName(id), Spec: spec}
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
func translateLambdaFunction(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
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
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Function", Name: k8sName(id), Spec: spec}
	if _, ok := props["Role"]; ok {
		m.Caveats = append(m.Caveats, "Lambda Role dropped — open-infra Functions connect via injected secrets/env, they do not assume an IAM role")
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
func translateStateMachine(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"DefinitionString": true, "Definition": true, "RoleArn": true, "StateMachineName": true,
		"StateMachineType": true, "LoggingConfiguration": true, "TracingConfiguration": true,
		"Tags": true, "DefinitionS3Location": true, "DefinitionSubstitutions": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	if _, ok := props["DefinitionS3Location"]; ok {
		f = append(f, Finding{"Resource " + id, "DefinitionS3Location is not translatable — the ASL must be inline (DefinitionString/Definition), not fetched from S3"})
	}
	if _, ok := props["DefinitionSubstitutions"]; ok {
		f = append(f, Finding{"Resource " + id, "DefinitionSubstitutions is not applied — provide a fully-resolved ASL definition rather than one with ${} substitutions"})
	}
	if t, ok := concrete(props["StateMachineType"]); ok && t != "" && t != "STANDARD" {
		f = append(f, Finding{"Resource " + id, "StateMachineType " + t + " is not supported — open-infra runs STANDARD-semantics workflows (EXPRESS has different execution/history semantics)"})
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
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "StateMachine", Name: k8sName(id), Spec: spec}
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
	if v, ok := props["MultiAttachEnabled"].(bool); ok && v {
		spec["shared"] = true
	}
	// Encryption: open-infra encrypts with a CUSTOMER key (kind: EncryptionKey / Vault Transit), so
	// KmsKeyId must reference an in-stack AWS::KMS::Key (which maps to that EncryptionKey). There is
	// no default-managed key — Encrypted without a mappable KmsKeyId blocks rather than inventing one.
	encrypted, _ := props["Encrypted"].(bool)
	_, hasKms := props["KmsKeyId"]
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
		if kid != "" {
			spec["encryptionKey"] = k8sName(kid)
		} else {
			f = append(f, Finding{"Resource " + id, "an encrypted volume needs KmsKeyId referencing an in-stack AWS::KMS::Key — open-infra keys volumes with a customer kind: EncryptionKey (via that KMS key), not an AWS-managed default key"})
		}
	}
	if _, ok := props["SnapshotId"]; ok {
		f = append(f, Finding{"Resource " + id, "SnapshotId is not translatable — an AWS EBS snapshot id has no open-infra VolumeSnapshot equivalent to restore from"})
	}

	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Volume", Name: k8sName(id), Spec: spec}
	for _, p := range []string{"AvailabilityZone", "VolumeType", "Iops", "Throughput"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — open-infra volumes are Longhorn on one flat cluster (no AZ / EBS volume-type / provisioned IOPS)")
		}
	}
	return m, f
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
func translateDynamoDBTable(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
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
		enabled, _ := ttl["Enabled"].(bool)
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

	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Table", Name: k8sName(id), Spec: spec}
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
func translateIAMUser(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
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
	m := &Manifest{APIVersion: "iam.openinfra.dev/v1", Kind: "User", Name: k8sName(id), Spec: spec}
	m.Caveats = append(m.Caveats, "the user is created without a password (source: local) — set a password separately; group names must name existing open-infra Groups (the authority relocation: permissions come from a Group's ClusterRole)")
	if _, ok := props["LoginProfile"]; ok {
		m.Caveats = append(m.Caveats, "LoginProfile dropped — set the user's password via an open-infra password Secret, not an inline console password")
	}
	return m, f
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
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "UserPool", Name: k8sName(id), Spec: spec}

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
			m.Caveats = append(m.Caveats, "the UserPoolClient's OAuth config (flows/scopes/callback+logout URLs, GenerateSecret, ExplicitAuthFlows) is not translated — the realm client applies Keycloak defaults; only its name maps to spec.clientId")
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

// cognitoClients returns the in-stack AWS::Cognito::UserPoolClient logical ids whose UserPoolId
// references poolID, in deterministic order.
func (c *stackCtx) cognitoClients(poolID string) []string {
	var ids []string
	for cid, res := range c.template.Resources {
		if res.Type != "AWS::Cognito::UserPoolClient" {
			continue
		}
		raw, _ := c.rawProps(cid)
		if t, ok := getAttTarget(raw["UserPoolId"]); ok && t == poolID {
			ids = append(ids, cid)
		}
	}
	sortStrs(ids)
	return ids
}

// translateCognitoUserPoolClient is the no-op half of the collation: a client whose UserPoolId
// points at an in-stack UserPool provisions nothing on its own (the pool creates the app client).
// One pointing at a pool NOT in this stack is refused rather than silently dropped.
func translateCognitoUserPoolClient(id string, _ map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
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

// translateECSCluster: inert grouping (the k3s cluster is the cluster). Provisions nothing.
func translateECSCluster(_ string, _ map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	return nil, nil
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
	spec, caveats, tdFindings := ecsTaskToApp(tdID, td)
	f = append(f, tdFindings...)

	// DesiredCount -> a fixed replica count (ECS Service autoscaling is a separate resource).
	if dc, ok := props["DesiredCount"]; ok {
		n := toInt(dc)
		spec["scaling"] = map[string]any{"min": n, "max": n}
	}

	if len(f) > 0 {
		return nil, f
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Application", Name: k8sName(id), Spec: spec, Caveats: caveats}
	for _, p := range []string{"LoadBalancers", "NetworkConfiguration", "LaunchType", "ServiceName", "ServiceRegistries", "Role"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — open-infra exposes the app via Application.domain (Ingress+TLS) on one flat cluster network; ECS LB/subnet/launch-type config has no direct form")
		}
	}
	return m, f
}

// ecsTaskToApp translates the TaskDefinition half: exactly one container -> image/port/env,
// returning the partial Application spec, the declared caveats, and any blocking findings.
func ecsTaskToApp(tdID string, td map[string]any) (map[string]any, []string, []Finding) {
	known := map[string]bool{
		"ContainerDefinitions": true, "Cpu": true, "Memory": true, "NetworkMode": true,
		"TaskRoleArn": true, "ExecutionRoleArn": true, "RequiresCompatibilities": true,
		"Family": true, "Volumes": true, "Tags": true, "RuntimePlatform": true,
	}
	var f []Finding
	var caveats []string
	f = append(f, blockUnknownProps(tdID, td, known)...)
	if _, ok := td["Volumes"]; ok {
		f = append(f, Finding{"Resource " + tdID, "task Volumes have no faithful Application form — refusing rather than dropping a mount"})
	}
	for _, p := range []string{"Cpu", "Memory", "TaskRoleArn", "ExecutionRoleArn", "NetworkMode", "RequiresCompatibilities", "RuntimePlatform"} {
		if _, ok := td[p]; ok {
			caveats = append(caveats, "TaskDefinition "+p+" dropped — open-infra sizes via quotas/HPA and connects via secrets/env, not task IAM roles / launch-compat / network mode")
		}
	}

	spec := map[string]any{}
	containers, _ := td["ContainerDefinitions"].([]any)
	if len(containers) != 1 {
		f = append(f, Finding{"Resource " + tdID, fmt.Sprintf("a TaskDefinition maps to an Application only with exactly one container (got %d) — Application runs a single container; sidecars have no form", len(containers))})
		return spec, caveats, f
	}
	c, _ := containers[0].(map[string]any)
	cknown := map[string]bool{
		"Name": true, "Image": true, "PortMappings": true, "Environment": true, "Essential": true,
		"Cpu": true, "Memory": true, "MemoryReservation": true, "Command": true, "EntryPoint": true,
		"LogConfiguration": true, "Secrets": true, "HealthCheck": true,
	}
	f = append(f, blockUnknownProps(tdID, c, cknown)...)

	if img, ok := concrete(c["Image"]); ok && img != "" {
		spec["image"] = img
	} else {
		f = append(f, Finding{"Resource " + tdID, "container Image is required and must be a concrete image reference"})
	}
	for _, p := range []string{"Command", "EntryPoint"} {
		if _, ok := c[p]; ok {
			f = append(f, Finding{"Resource " + tdID, "container " + p + " override has no Application field — Application runs the image's entrypoint (refusing rather than ignoring it)"})
		}
	}
	if ports, ok := c["PortMappings"].([]any); ok && len(ports) > 0 {
		if p0, ok := ports[0].(map[string]any); ok {
			if cp, ok := p0["ContainerPort"]; ok {
				spec["port"] = toInt(cp)
			}
		}
	}
	if envList := ecsEnv(tdID, c, &f); len(envList) > 0 {
		spec["env"] = envList
	}
	return spec, caveats, f
}

// ecsEnv maps a container's Environment ([{Name,Value}]) to Application env ([{name,value}]).
func ecsEnv(tdID string, c map[string]any, f *[]Finding) []any {
	envs, ok := c["Environment"].([]any)
	if !ok {
		return nil
	}
	var out []any
	for _, e := range envs {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		name, _ := concrete(em["Name"])
		val, vok := concrete(em["Value"])
		if name == "" {
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
	if v, ok := props["MultiAZ"].(bool); ok && v {
		db["highAvailability"] = true
	}
	// Storage encryption: LUKS on longhorn-encrypted keyed by a customer kind: EncryptionKey (via an
	// in-stack KMS::Key). v1 supports the postgres engine only (CloudNativePG propagates the key
	// annotation to its PVCs); other engines' DB encryption is a follow-up, so they block.
	enc, _ := props["StorageEncrypted"].(bool)
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
				db["encryptionKey"] = k8sName(kid)
			} else {
				f = append(f, Finding{"Resource " + id, "an encrypted database needs KmsKeyId referencing an in-stack AWS::KMS::Key — open-infra keys DB storage with a customer kind: EncryptionKey, not an AWS-managed default key"})
			}
		}
	}

	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Application", Name: k8sName(id), Spec: map[string]any{"database": db}}
	for _, p := range []string{"AllocatedStorage", "StorageType", "Iops", "DBInstanceClass"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — open-infra has no per-DB capacity/storage knob (storage is the storageClass's, sizing is via quotas/HPA)")
		}
	}
	for _, p := range []string{"MasterUsername", "MasterUserPassword"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — open-infra provisions the credentials and injects them as DATABASE_URL; they are not set from the template")
		}
	}
	for _, p := range []string{"VPCSecurityGroups", "DBSubnetGroupName", "PubliclyAccessible", "Port", "BackupRetentionPeriod", "PreferredMaintenanceWindow", "PreferredBackupWindow", "DBParameterGroupName", "DeletionProtection"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — no open-infra equivalent (one flat cluster network; backups/params are platform-managed)")
		}
	}
	return m, f
}

// ---- AWS::S3::Bucket -> kind: Bucket ----
//
// A standalone MinIO bucket (the object-storage analog of kind: Volume). BucketName maps, and — the
// fidelity gain over the old Application-sub-block mapping — VersioningConfiguration and
// LifecycleConfiguration (expiration rules) map too. BucketEncryption REFUSES with a pointer to the
// opt-in objectEncryption stack (per-bucket SSE isn't declarable here) rather than creating an
// unencrypted bucket that looks encrypted. Policy, website, CORS, notifications, replication,
// object-lock, public-access and the rest block via the strict allowlist. Tags are a caveat.
func translateS3Bucket(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"BucketName": true, "VersioningConfiguration": true, "LifecycleConfiguration": true,
		"BucketEncryption": true, "Tags": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)

	if _, ok := props["BucketEncryption"]; ok {
		f = append(f, Finding{"Resource " + id, "BucketEncryption is not translatable here — per-bucket SSE requires the opt-in objectEncryption stack (SSE-KMS via KES→Vault, applied at the MinIO-tenant level); refusing rather than creating an unencrypted bucket that looks encrypted"})
	}

	spec := map[string]any{}
	if bn, ok := concrete(props["BucketName"]); ok && bn != "" {
		spec["bucketName"] = bn
	}
	if vc, ok := props["VersioningConfiguration"].(map[string]any); ok {
		if st, _ := concrete(vc["Status"]); st == "Enabled" {
			spec["versioning"] = true
		}
	}
	if lc, ok := props["LifecycleConfiguration"].(map[string]any); ok {
		if rules := s3LifecycleRules(id, lc, &f); len(rules) > 0 {
			spec["lifecycleRules"] = rules
		}
	}

	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Bucket", Name: k8sName(id), Spec: spec}
	if _, ok := props["Tags"]; ok {
		m.Caveats = append(m.Caveats, "Tags dropped — no open-infra equivalent for a MinIO bucket")
	}
	return m, f
}

// s3LifecycleRules maps an S3 LifecycleConfiguration to kind: Bucket lifecycleRules. Supported per
// rule: Id, Status (Enabled), a Prefix (top-level or Filter.Prefix), ExpirationInDays, and
// NoncurrentVersionExpiration.NoncurrentDays. Anything else on a rule (Transitions, an absolute
// ExpirationDate, tag/size filters, abort-multipart) blocks — a lifecycle rule that silently
// dropped its transition or kept objects past their expiry is the worst shape.
func s3LifecycleRules(id string, lc map[string]any, f *[]Finding) []any {
	rules, _ := lc["Rules"].([]any)
	var out []any
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		rknown := map[string]bool{"Id": true, "Status": true, "Prefix": true, "Filter": true, "ExpirationInDays": true, "NoncurrentVersionExpiration": true}
		*f = append(*f, blockUnknownProps(id+" lifecycle rule", rm, rknown)...)

		rule := map[string]any{}
		if rid, ok := concrete(rm["Id"]); ok && rid != "" {
			rule["id"] = rid
		} else {
			rule["id"] = fmt.Sprintf("rule-%d", i)
		}
		if st, _ := concrete(rm["Status"]); st != "" && st != "Enabled" {
			*f = append(*f, Finding{"Resource " + id, "lifecycle rule " + fmt.Sprint(rule["id"]) + " Status " + st + " is not applied — only Enabled rules map"})
		}
		if p, ok := concrete(rm["Prefix"]); ok && p != "" {
			rule["prefix"] = p
		} else if fl, ok := rm["Filter"].(map[string]any); ok {
			for k := range fl {
				if k != "Prefix" {
					*f = append(*f, Finding{"Resource " + id, "lifecycle rule " + fmt.Sprint(rule["id"]) + " Filter." + k + " is not supported — only a Prefix filter maps"})
				}
			}
			if p, ok := concrete(fl["Prefix"]); ok && p != "" {
				rule["prefix"] = p
			}
		}
		if ed, ok := rm["ExpirationInDays"]; ok {
			rule["expireDays"] = toInt(ed)
		}
		if nve, ok := rm["NoncurrentVersionExpiration"].(map[string]any); ok {
			if nd, ok := nve["NoncurrentDays"]; ok {
				rule["noncurrentExpireDays"] = toInt(nd)
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
func translateSQSQueue(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"QueueName": true, "MessageRetentionPeriod": true, "Tags": true, "FifoQueue": true,
		"VisibilityTimeout": true, "DelaySeconds": true, "RedrivePolicy": true, "KmsMasterKeyId": true,
		"ReceiveMessageWaitTimeSeconds": true, "MaximumMessageSize": true, "ContentBasedDeduplication": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	if v, ok := props["FifoQueue"].(bool); ok && v {
		f = append(f, Finding{"Resource " + id, "a FIFO queue is not translatable — JetStream ordering/dedup semantics differ from SQS FIFO (refusing rather than silently changing delivery guarantees)"})
	}
	if _, ok := props["KmsMasterKeyId"]; ok {
		f = append(f, Finding{"Resource " + id, "KmsMasterKeyId is not translatable — no per-queue encryption"})
	}
	spec := map[string]any{}
	if qn, ok := concrete(props["QueueName"]); ok && qn != "" {
		spec["queueName"] = qn
	}
	if r, ok := props["MessageRetentionPeriod"]; ok {
		hrs := toInt(r) / 3600
		if hrs < 1 {
			hrs = 1
		}
		spec["retentionHours"] = hrs
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Queue", Name: k8sName(id), Spec: spec}
	for _, p := range []string{"VisibilityTimeout", "DelaySeconds", "RedrivePolicy", "ReceiveMessageWaitTimeSeconds", "MaximumMessageSize", "ContentBasedDeduplication", "Tags"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — SQS delivery semantics (visibility/delay/DLQ/dedup) are configured on the app's JetStream consumer, not the queue")
		}
	}
	return m, f
}

// ---- AWS::SNS::Topic -> kind: Queue (a fan-out topic) ----
//
// A standalone pub/sub topic backed by a NATS JetStream Limits stream (messages retained for the
// window; every consumer reads them independently — SNS fan-out). TopicName -> the stream/subject.
// FIFO and encryption BLOCK. Inline Subscriptions BLOCK — SNS subscribers (SQS/Lambda/HTTP targets)
// have no open-infra fan-out wiring; consumers subscribe to the topic's stream themselves.
func translateSNSTopic(id string, props map[string]any, _ *stackCtx) (*Manifest, []Finding) {
	known := map[string]bool{
		"TopicName": true, "DisplayName": true, "Tags": true, "FifoTopic": true,
		"KmsMasterKeyId": true, "ContentBasedDeduplication": true, "Subscription": true,
	}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	if v, ok := props["FifoTopic"].(bool); ok && v {
		f = append(f, Finding{"Resource " + id, "a FIFO topic is not translatable — JetStream ordering/dedup differs from SNS FIFO"})
	}
	if _, ok := props["KmsMasterKeyId"]; ok {
		f = append(f, Finding{"Resource " + id, "KmsMasterKeyId is not translatable — no per-topic encryption"})
	}
	if _, ok := props["Subscription"]; ok {
		f = append(f, Finding{"Resource " + id, "inline Subscriptions are not translatable — SNS subscribers (SQS/Lambda/HTTP) have no open-infra fan-out target; consumers subscribe to the topic's stream themselves (refusing rather than silently dropping the delivery wiring)"})
	}
	spec := map[string]any{"fanout": true}
	if tn, ok := concrete(props["TopicName"]); ok && tn != "" {
		spec["queueName"] = tn
	}
	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Queue", Name: k8sName(id), Spec: spec}
	for _, p := range []string{"DisplayName", "Tags", "ContentBasedDeduplication"} {
		if _, ok := props[p]; ok {
			m.Caveats = append(m.Caveats, p+" dropped — no open-infra equivalent")
		}
	}
	return m, f
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
		if _, ok := sp["DefinitionS3Location"]; ok {
			f = append(f, Finding{"Resource " + cid, "GraphQLSchema DefinitionS3Location is not translatable — the SDL must be inline (Definition)"})
		}
		if def, ok := concrete(sp["Definition"]); ok && def != "" {
			spec["schema"] = def
		}
	}

	// data sources.
	var dataSources []any
	hasDynamo := false
	for _, cid := range ctx.appsyncChildren("AWS::AppSync::DataSource", id) {
		sp, _ := ctx.resolveProps(cid)
		ds, isDynamo := appsyncDataSource(cid, sp, &f)
		hasDynamo = hasDynamo || isDynamo
		dataSources = append(dataSources, ds)
	}
	if len(dataSources) > 0 {
		spec["dataSources"] = dataSources
	}

	// resolvers (required — a GraphQLApi with no resolver can't be created).
	var resolvers []any
	for _, cid := range ctx.appsyncChildren("AWS::AppSync::Resolver", id) {
		resolvers = append(resolvers, ctx.appsyncResolver(cid, &f))
	}
	if len(resolvers) == 0 {
		f = append(f, Finding{"Resource " + id, "a GraphQLApi requires at least one AWS::AppSync::Resolver in the stack (open-infra's GraphQLApi resolves fields from its resolver list)"})
	} else {
		spec["resolvers"] = resolvers
	}

	m := &Manifest{APIVersion: "openinfra.dev/v1", Kind: "GraphQLApi", Name: k8sName(id), Spec: spec}
	if at, ok := concrete(props["AuthenticationType"]); ok && at != "" {
		m.Caveats = append(m.Caveats, "AuthenticationType "+at+" is not translated to enforcement — open-appsync enforces auth via @aws_* directives in the schema (+ an apiKeysSecret for @aws_api_key); configure it separately")
	}
	if hasDynamo {
		m.Caveats = append(m.Caveats, "a dynamodb data source needs spec.mongoURI (the FerretDB endpoint) set at deploy time — it is not derivable from the template, and the source fails closed at load until set")
	}
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
	var ids []string
	for cid, res := range c.template.Resources {
		if res.Type != cfnType {
			continue
		}
		raw, _ := c.rawProps(cid)
		if t, ok := getAttTarget(raw["ApiId"]); ok && t == apiID {
			ids = append(ids, cid)
		}
	}
	sortStrs(ids)
	return ids
}

// appsyncDataSource maps one AWS::AppSync::DataSource to an open-appsync data source; the bool
// reports whether it is a dynamodb source (so the caller can surface the mongoURI caveat).
func appsyncDataSource(cid string, sp map[string]any, f *[]Finding) (map[string]any, bool) {
	known := map[string]bool{
		"ApiId": true, "Name": true, "Type": true, "Description": true, "ServiceRoleArn": true,
		"DynamoDBConfig": true, "LambdaConfig": true, "HttpConfig": true, "MetricsConfig": true,
		"RelationalDatabaseConfig": true, "OpenSearchServiceConfig": true, "ElasticsearchConfig": true,
		"EventBridgeConfig": true,
	}
	*f = append(*f, blockUnknownProps(cid, sp, known)...)
	name, _ := concrete(sp["Name"])
	ds := map[string]any{"name": name}
	dynamo := false
	switch t, _ := concrete(sp["Type"]); t {
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

// appsyncResolver maps one AWS::AppSync::Resolver to an open-appsync resolver (unit or pipeline).
func (c *stackCtx) appsyncResolver(cid string, f *[]Finding) map[string]any {
	sp, _ := c.resolveProps(cid)
	known := map[string]bool{
		"ApiId": true, "TypeName": true, "FieldName": true, "DataSourceName": true, "Kind": true,
		"RequestMappingTemplate": true, "ResponseMappingTemplate": true, "PipelineConfig": true,
		"RequestMappingTemplateS3Location": true, "ResponseMappingTemplateS3Location": true,
		"Runtime": true, "Code": true, "CodeS3Location": true, "MaxBatchSize": true,
		"CachingConfig": true, "SyncConfig": true, "MetricsConfig": true,
	}
	*f = append(*f, blockUnknownProps(cid, sp, known)...)
	for _, k := range []string{"RequestMappingTemplateS3Location", "ResponseMappingTemplateS3Location", "CodeS3Location"} {
		if _, ok := sp[k]; ok {
			*f = append(*f, Finding{"Resource " + cid, k + " is not translatable — mapping templates / code must be inline, not fetched from S3"})
		}
	}

	r := map[string]any{}
	if t, ok := concrete(sp["TypeName"]); ok {
		r["type"] = t
	}
	if fld, ok := concrete(sp["FieldName"]); ok {
		r["field"] = fld
	}
	isJS := false
	if rt, ok := sp["Runtime"].(map[string]any); ok {
		if n, _ := concrete(rt["Name"]); n == "APPSYNC_JS" {
			isJS = true
			r["runtime"] = "appsync-js"
		}
	}
	if !isJS {
		r["runtime"] = "appsync-vtl"
	}

	if kind, _ := concrete(sp["Kind"]); kind == "PIPELINE" {
		// A pipeline resolver: its Request/Response templates are before/after, and PipelineConfig
		// names the FunctionConfigurations to run in order.
		if req, ok := concrete(sp["RequestMappingTemplate"]); ok && req != "" {
			r["before"] = req
		}
		if resp, ok := concrete(sp["ResponseMappingTemplate"]); ok && resp != "" {
			r["after"] = resp
		}
		r["functions"] = c.appsyncPipelineFunctions(cid, f)
	} else {
		// A unit resolver binds one data source with a request/response template (or JS code).
		if isJS {
			if code, ok := concrete(sp["Code"]); ok && code != "" {
				r["request"] = code
			}
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
func (c *stackCtx) appsyncPipelineFunctions(cid string, f *[]Finding) []any {
	raw, _ := c.rawProps(cid)
	pc, _ := raw["PipelineConfig"].(map[string]any)
	fnRefs, _ := pc["Functions"].([]any)
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
		fn := map[string]any{"runtime": "appsync-vtl"}
		if dsn := c.resolveDSName(fid, "DataSourceName"); dsn != "" {
			fn["dataSource"] = dsn
		} else {
			*f = append(*f, Finding{"Resource " + fid, "a FunctionConfiguration requires a DataSourceName naming an in-stack AWS::AppSync::DataSource"})
		}
		if req, ok := concrete(fp["RequestMappingTemplate"]); ok {
			fn["request"] = req
		}
		if resp, ok := concrete(fp["ResponseMappingTemplate"]); ok {
			fn["response"] = resp
		}
		out = append(out, fn)
	}
	return out
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
	var f []Finding
	for _, k := range sortedKeys(props) {
		if !known[k] {
			f = append(f, Finding{"Resource " + id, "property " + k + " is not translatable — refusing rather than silently dropping it"})
		}
	}
	return f
}

var placeholderRe = regexp.MustCompile(`<(ref:|param:|unsupported:|base64:)|<[A-Za-z0-9_]+\.[A-Za-z0-9_]+>|<AWS::`)

// concrete returns the string form of a resolved value only if it is a real, usable value —
// not a placeholder the resolver emitted for something it could not resolve. ok=false means
// "we do not have a concrete value", which callers must treat as a blocker, never a guess.
func concrete(v any) (string, bool) {
	if v == nil {
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
