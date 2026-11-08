// Plan construction for the CFN engine (Phase 1) — the read-only dry-run.
//
// BuildPlan turns a template into a verdict WITHOUT provisioning anything. The verdict is the
// honesty rail:
//
//	PROVISIONABLE                — every included resource maps to a faithful kind, every
//	                               intrinsic resolved, dependencies order cleanly.
//	PROVISIONABLE_WITH_CAVEATS   — same, but at least one resource maps only `partial`
//	                               (lossy); the caveats are listed loudly.
//	REJECTED                     — at least one blocker: an unsupported/gated resource type,
//	                               an unsupported intrinsic, a macro Transform, a missing
//	                               required parameter, a broken reference, or a dependency
//	                               cycle. The exact blockers are listed; nothing is provisioned.
//
// The cardinal rule: never silently drop or approximate something we cannot model. If
// in doubt, REJECT and say exactly why.
package cfn

import (
	"fmt"
	"sort"
	"strings"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

type Verdict string

const (
	Provisionable            Verdict = "PROVISIONABLE"
	ProvisionableWithCaveats Verdict = "PROVISIONABLE_WITH_CAVEATS"
	Rejected                 Verdict = "REJECTED"
)

type PlannedResource struct {
	LogicalID string
	CFNType   string
	Kind      string
	Status    Status
	Note      string
	// Deployable is the honest create-fidelity fact: the type maps to a kind AND has a create
	// translator, so `cfn deploy` will accept it. A resource that maps at plan but has no
	// translator (an IAM Role, an EC2 Instance) is Deployable=false — plan-supported is not
	// create-faithful, and deploy (all-or-nothing) refuses a stack that contains one.
	Deployable bool
	Included   bool     // false when a Condition excluded it
	Condition  string   // the gating condition, if any
	DependsOn  []string // resolved dependency ids (included resources only)
	// TranslateRefusals holds property-level refusals the create translator raised when plan ran the
	// translate gate (the same gate deploy runs in buildManifests). Non-empty means deploy WOULD
	// refuse this resource; each refusal is also a plan Blocker, so the verdict reflects it.
	TranslateRefusals []string `json:",omitempty"`
	// Caveats are this template's own declared losses for the resource, from its create translator:
	// properties accepted but not emulated (no-ops, approximations). They make up the plan's fidelity
	// summary, so a pass on open-infra never reads as covering more than it did.
	Caveats []string `json:",omitempty"`
}

// FidelityItem is one property the plan accepted but open-infra does not emulate faithfully.
type FidelityItem struct {
	Resource string
	Detail   string
}

type Plan struct {
	Verdict   Verdict
	Order     []string          // included resources in provisioning order
	Resources []PlannedResource // all resources, in template order
	Findings  []Finding         // intrinsic/reference problems
	Blockers  []string          // human-readable REJECTED reasons
	// Fidelity lists every accepted-but-not-emulated property across the included resources, in
	// template order (each resource's Caveats), and the resource attributes open-infra does not act on.
	// Empty only when the translate gate ran and every translator reported none.
	Fidelity []FidelityItem `json:",omitempty"`
	// GateSkipped says why the translate gate did not run ("" when it did). Without it, property-level
	// fidelity was not checked at plan time, so an empty per-property summary claims nothing.
	GateSkipped string `json:",omitempty"`
	// deps is each included resource's dependencies (what Order is sorted by): what must be complete
	// before it is created (readiness.go).
	deps map[string][]string
}

// FidelityStack is the FidelityItem.Resource of a line about the whole stack rather than one resource.
const FidelityStack = "(stack)"

// BuildPlan parses a template and produces a dry-run plan. params supplies parameter values
// (overriding defaults); stackName seeds AWS::StackName. It never contacts the cluster.
func BuildPlan(data []byte, params map[string]string, stackName string) (*Plan, error) {
	return BuildPlanWithExports(data, params, nil, stackName)
}

// BuildPlanWithExports is BuildPlan with a cross-stack Exports map (export name -> value) made
// available to Fn::ImportValue. BuildPlan passes nil (no exports supplied). It plans with ZERO
// capabilities — i.e. fail-closed for anything that depends on the deploy environment.
func BuildPlanWithExports(data []byte, params, exports map[string]string, stackName string) (*Plan, error) {
	return BuildPlanWithCaps(data, params, exports, stackName, Capabilities{})
}

// Capabilities are facts about the DEPLOY ENVIRONMENT that a translator's verdict depends on. Plan
// and deploy must evaluate a template with the SAME capabilities, so a PROVISIONABLE* plan still
// means deploy won't refuse. The zero value is fail-closed: an unknown capability is treated as
// absent. The in-cluster aws-shim CloudFormation doorway sets them from its environment; the CLI
// (outside the cluster, unable to vouch for them) leaves them zero.
type Capabilities struct {
	// ObjectEncryption: this environment GUARANTEES that a NEW MinIO bucket is encrypted at rest by
	// default. That is an outcome, not a component: MinIO carrying a key while only the buckets someone
	// ran `mc encrypt set` on are encrypted is not enough, because a bucket the CloudFormation front door
	// creates later would still be unencrypted. The platform's object-encryption switch (written once
	// MinIO's key works and kind: Bucket's setup gives new buckets default encryption) is that guarantee.
	// When true, an S3 BucketEncryption maps with a caveat; when false it REFUSES, rather than deploying
	// an unencrypted bucket the template asked to encrypt.
	ObjectEncryption bool
	// SQSAPI, SNSAPI, SSMAPI and KMSAPI: this environment serves that AWS API from its own store, so a
	// stack's queue, topic (and subscriptions), parameter, or key (and aliases) is created IN that store —
	// usable through the API by the name or ARN the stack reports (service.go). Off (the CLI, or a shim
	// without that data layer), the translators keep their kind mappings, which the APIs cannot see.
	SQSAPI, SNSAPI, SSMAPI, KMSAPI bool
	// SQSURLBase is the endpoint a stack's queue URLs name (scheme://host[:port]); "" names AWS's.
	SQSURLBase string
	// SecretsManagerAPI, LogsAPI, EventsAPI, ECRAPI and CloudWatchAPI: this environment serves that AWS API
	// from its own store, so a stack's secret, log group, EventBridge rule or bus, ECR repository or alarm
	// is created IN that store, through that front door and under the caller's authority
	// (translate_service.go). These types have no other mapping, so without the API (the CLI) they refuse.
	SecretsManagerAPI, LogsAPI, EventsAPI, ECRAPI, CloudWatchAPI bool
	// ECRRepositoryHost is the registry host an ECR repository's URI starts with (RepositoryUri is
	// <host>/<name>); "" leaves Fn::GetAtt RepositoryUri unresolved before deploy.
	ECRRepositoryHost string
	// EC2AddressAPI: this environment keeps Elastic IP allocations of their own (an address held for its
	// stack whether or not an instance is associated, translate_ec2eip.go), so an EIP associated with
	// nothing in its stack allocates one, and an EIPAssociation can name one by its AllocationId from
	// another stack. Off (the CLI), an EIP must be associated with an in-stack instance.
	EC2AddressAPI bool
	// LambdaPackageStore: this environment stores a zip Lambda's deployment package as Lambda does (its
	// COPY storage): a Code.S3Bucket/S3Key object is read at deploy with the caller's authority and kept
	// where only the function's own pods fetch it (the aws-shim front door, DeployOptions.Packages). Off
	// (the CLI), an S3 package refuses; inline Code.ZipFile still deploys, as a ConfigMap of its source.
	LambdaPackageStore bool
	// ValidatedDomains are the domains this environment has validated ownership of: ACM's domain
	// validation, done once by the operator (certificates.validatedDomains). A certificate for a name under
	// one is issued by the platform's ACM-style CA (ClusterIssuer openinfra-acm: signed by the platform root,
	// name-constrained to these domains), so a client that trusts the root trusts it, as browsers trust
	// ACM's. When set, a CloudFront alias outside them refuses: on AWS its certificate would stay
	// PENDING_VALIDATION. Empty (none configured, or the CLI), sites keep the self-signed openinfra-issuer.
	ValidatedDomains []string
	// KeyPairs are the EC2 key pairs this environment holds (the aws-shim's ImportKeyPair/CreateKeyPair),
	// key name -> OpenSSH public key. An instance's KeyName carries that key into the VM's spec.sshKey, and
	// a KeyName it does not hold refuses, as AWS's InvalidKeyPair.NotFound. nil (the CLI, or a shim without
	// the key-pair store): KeyName is a caveat and no key is injected.
	KeyPairs map[string]string
	// NestedStacks: this environment creates a nested stack (AWS::CloudFormation::Stack) as a stack of its
	// own (nested_stacks.go). Off (the CLI, which flattens nested stacks first), the type refuses.
	NestedStacks bool
}

// underValidatedDomain reports whether host is one of domains or a subdomain of one.
func underValidatedDomain(host string, domains []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range domains {
		d = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*."), ".")
		if d != "" && (host == d || strings.HasSuffix(host, "."+d)) {
			return true
		}
	}
	return false
}

// BuildPlanWithCaps is BuildPlanWithExports with explicit deploy-environment Capabilities.
func BuildPlanWithCaps(data []byte, params, exports map[string]string, stackName string, caps Capabilities) (*Plan, error) {
	return BuildPlanForStack(data, params, exports, stackName, "", caps)
}

// BuildPlanForStack is BuildPlanWithCaps for one stack instance: AWS::StackId resolves to stackID ("" =
// the derived StackId of stackName — DeployOptions.StackID).
func BuildPlanForStack(data []byte, params, exports map[string]string, stackName, stackID string, caps Capabilities) (*Plan, error) {
	t, err := Parse(data)
	if err != nil {
		return nil, err
	}
	plan := &Plan{Verdict: Provisionable}

	// A macro/SAM Transform means the template is expanded server-side before deploy — we
	// cannot honor it, so it is a hard blocker rather than a silent drop.
	if t.Transform != nil {
		plan.Blockers = append(plan.Blockers, "template uses Transform (macro/SAM) — not supported; the expanded form is not what open-infra provisions")
	}

	// Resolve parameters: supplied value > default. A required parameter with neither is a
	// blocker — we will not plan against an unknown value.
	pvals := map[string]any{}
	var missing []string
	for name, p := range t.Parameters {
		if v, ok := params[name]; ok {
			pvals[name] = v
		} else if p.hasDef {
			pvals[name] = p.Default
		} else {
			// Seed a placeholder so Refs to it resolve cleanly — the missing-value
			// blocker below is the single, precise reason; no redundant "undefined Ref".
			pvals[name] = "<param:" + name + ">"
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		plan.Blockers = append(plan.Blockers, "parameter "+name+" has no default and no value supplied (pass -param "+name+"=…)")
	}
	// The value checks CloudFormation makes before it creates anything (params.go), so a CLI deploy
	// refuses what the doorway refuses: a value for an undeclared parameter, a value outside its
	// constraints, a malformed constraint.
	plan.Blockers = append(plan.Blockers, paramDeclBlockers(t)...)
	if unk := unknownParams(t, params, nil); len(unk) > 0 {
		plan.Blockers = append(plan.Blockers, "Parameters: ["+strings.Join(unk, ", ")+"] do not exist in the template")
	}
	if len(missing) == 0 {
		if msg := staticParamError(t, params, nil); strings.HasPrefix(msg, "Parameter '") {
			plan.Blockers = append(plan.Blockers, msg)
		}
	}

	r := newResolver(t, pvals, strMapToAny(exports), pseudoParamsFor(stackName, stackID))
	r.evalConditions()

	// Decide inclusion + mapping for every resource, walking properties only for included ones.
	deps := map[string][]string{}
	for _, id := range t.rawOrder {
		res := t.Resources[id]
		included := true
		if res.Condition != "" {
			included = r.conds[res.Condition]
		}
		entry := Lookup(res.Type)
		pr := PlannedResource{
			LogicalID:  id,
			CFNType:    res.Type,
			Kind:       entry.Kind,
			Status:     entry.Status,
			Note:       entry.Note,
			Deployable: entry.mappable() && hasTranslator(res.Type),
			Included:   included,
			Condition:  res.Condition,
		}
		if included {
			plan.Blockers = append(plan.Blockers, attributeBlockers(id, res)...)
			d := r.resolveResource(id, res)
			d = append(d, res.DependsOn...)
			deps[id] = d
			pr.DependsOn = dedupSorted(d)
			if !entry.mappable() {
				plan.Blockers = append(plan.Blockers,
					fmt.Sprintf("%s (%s): %s — %s", id, res.Type, entry.Status, noteOr(entry.Note, "no backing kind")))
			} else if !hasTranslator(res.Type) {
				// Maps to a kind at plan but has no create translator: deploy (all-or-nothing) refuses it
				// with "has no create translator", so plan must REJECT too — a PROVISIONABLE* verdict that
				// deploy would refuse is the overstatement #344 is closing. The structural reason is the note.
				plan.Blockers = append(plan.Blockers,
					fmt.Sprintf("%s (%s): maps to kind: %s at plan but has no create translator — deploy refuses it (%s)", id, res.Type, entry.Kind, noteOr(entry.Note, "documented structural refusal; author it natively")))
			}
		}
		plan.Resources = append(plan.Resources, pr)
	}
	plan.Findings = r.findings
	for _, f := range r.findings {
		plan.Blockers = append(plan.Blockers, f.Where+": "+f.Reason)
	}
	// An Output must resolve once the stack is deployed: one naming an attribute open-infra does not
	// provide is refused now, before anything is created (outputs.go).
	plan.Blockers = append(plan.Blockers, outputReferenceBlockers(t, r.conds)...)

	// Translate gate: run the create translators now so a property-level refusal — which otherwise
	// surfaces only at deploy (buildManifests) — is reported HERE, making a PROVISIONABLE* verdict mean
	// deploy won't balk. plan stays read-only (translators provision nothing; a fresh resolver keeps
	// this pass from double-reporting the intrinsic findings above). Skipped when a required parameter
	// is missing (already a blocker; placeholder values would add noise), and for the interleaved deploy
	// path (custom resources / REST v1 API), whose Fn::GetAtt values resolve only during apply — running
	// the translators now could refuse falsely, so those stacks keep the mapping-only verdict.
	// A REST v1 stack's API Gateway resources collate from their own properties and the logical graph
	// alone (no attribute that resolves during deploy), so their gate runs even when the rest of the stack's
	// cannot: their refusals and caveats reach the plan and the change set.
	// A nested stack's Outputs resolve only once it is created as well (nested_stacks.go), so such a stack
	// gates only its AWS::CloudFormation::Stack resources, whose sentinel reads its own properties alone.
	gateAll := len(missing) == 0 && t.Transform == nil && !hasCustomResources(t) && !hasAPIGatewayRestV1(t) && !hasNestedStacks(t)
	gateAPIGateway := !gateAll && len(missing) == 0 && t.Transform == nil && !hasCustomResources(t) && hasAPIGatewayRestV1(t)
	gateNested := !gateAll && len(missing) == 0 && t.Transform == nil && hasNestedStacks(t)
	if gateAll || gateAPIGateway || gateNested {
		byID := map[string]*PlannedResource{}
		for i := range plan.Resources {
			byID[plan.Resources[i].LogicalID] = &plan.Resources[i]
		}
		seen := map[string]bool{}
		for _, b := range plan.Blockers {
			seen[b] = true
		}
		tr := newResolver(t, pvals, strMapToAny(exports), pseudoParamsFor(stackName, stackID))
		tr.evalConditions()
		tctx := &stackCtx{template: t, resolver: tr, caps: caps, namer: newPhysNamer(stackName, nil)}
		tr.staticRef = func(id string) (string, bool) { return inStackRef(id, tctx) }
		tr.staticAtt = func(id, attr string) (string, bool) { return serviceAtt(id, attr, tctx) }
		for _, id := range t.rawOrder {
			res := t.Resources[id]
			if res.Condition != "" && !tr.conds[res.Condition] {
				continue
			}
			if !gateAll && !(gateAPIGateway && strings.HasPrefix(res.Type, "AWS::ApiGateway::")) && !(gateNested && res.Type == StackTypeName) {
				continue
			}
			tf := translatorFor(res.Type)
			if tf == nil {
				continue // unmappable/undeployable is already reported above; don't double-count here
			}
			tr.where = "Resource " + id
			resolved, _ := tr.resolve(res.Properties).(map[string]any)
			m, fs := tf(id, resolved, tctx)
			if pr := byID[id]; pr != nil {
				pr.Caveats = append(manifestCaveats(m), attributeCaveats(res)...)
				for _, c := range pr.Caveats {
					plan.Fidelity = append(plan.Fidelity, FidelityItem{Resource: id, Detail: c})
				}
			}
			for _, f := range fs {
				if pr := byID[id]; pr != nil {
					pr.TranslateRefusals = append(pr.TranslateRefusals, f.Reason)
				}
				if msg := f.Where + ": " + f.Reason; !seen[msg] {
					seen[msg] = true
					plan.Blockers = append(plan.Blockers, msg)
				}
			}
		}
	}
	if gateAPIGateway {
		plan.GateSkipped = "the stack has an API Gateway REST API, whose other resources' attributes resolve only during deploy"
		plan.Fidelity = append(plan.Fidelity, FidelityItem{Resource: FidelityStack,
			Detail: "property-level fidelity was checked at plan time for the API Gateway resources only (" + plan.GateSkipped + "); deploy still refuses any property it cannot translate, but losses it accepts in the other resources are not listed here"})
		for i := range plan.Resources {
			pr := &plan.Resources[i]
			if !pr.Included || strings.HasPrefix(t.Resources[pr.LogicalID].Type, "AWS::ApiGateway::") {
				continue
			}
			for _, c := range attributeCaveats(t.Resources[pr.LogicalID]) {
				pr.Caveats = append(pr.Caveats, c)
				plan.Fidelity = append(plan.Fidelity, FidelityItem{Resource: pr.LogicalID, Detail: c})
			}
		}
	} else if !gateAll {
		// The gate did not run, so the summary cannot list property-level losses: say so, and still
		// list the resource attributes (they do not need the translators).
		switch {
		case len(missing) > 0:
			plan.GateSkipped = "a required parameter has no value"
		case t.Transform != nil:
			plan.GateSkipped = "the template uses a Transform"
		default:
			plan.GateSkipped = "the stack has a custom resource or an API Gateway REST API, whose attributes resolve only during deploy"
		}
		plan.Fidelity = append(plan.Fidelity, FidelityItem{Resource: FidelityStack,
			Detail: "property-level fidelity was not checked at plan time (" + plan.GateSkipped + "); deploy still refuses any property it cannot translate, but losses it accepts are not listed here"})
		for i := range plan.Resources {
			pr := &plan.Resources[i]
			if !pr.Included {
				continue
			}
			for _, c := range attributeCaveats(t.Resources[pr.LogicalID]) {
				pr.Caveats = append(pr.Caveats, c)
				plan.Fidelity = append(plan.Fidelity, FidelityItem{Resource: pr.LogicalID, Detail: c})
			}
		}
	}

	// An instance collates the volumes attached to it (AWS::EC2::VolumeAttachment), so it is created after
	// them: its VM starts with their disks. A volume that names the instance only for its Availability Zone
	// (a value open-infra does not use) no longer waits for it.
	for _, id := range t.rawOrder {
		res := t.Resources[id]
		if res.Type != "AWS::EC2::VolumeAttachment" {
			continue
		}
		inst, _ := refTarget(res.Properties["InstanceId"])
		vol, _ := refTarget(res.Properties["VolumeId"])
		if _, ok := deps[inst]; !ok || t.Resources[vol].Type != "AWS::EC2::Volume" {
			continue
		}
		deps[inst] = append(deps[inst], vol)
		var keep []string
		for _, d := range deps[vol] {
			if d != inst {
				keep = append(keep, d)
			}
		}
		deps[vol] = keep
	}

	// Dependency ordering over included resources only.
	var included []string
	incDeps := map[string][]string{}
	for _, pr := range plan.Resources {
		if pr.Included {
			included = append(included, pr.LogicalID)
			incDeps[pr.LogicalID] = deps[pr.LogicalID]
		}
	}
	if ord, err := order(included, incDeps); err != nil {
		plan.Blockers = append(plan.Blockers, err.Error())
	} else {
		plan.Order = ord
	}
	plan.deps = incDeps

	// Final verdict. A stack that maps but contains a resource with no create translator is never
	// reported as cleanly PROVISIONABLE — deploy (all-or-nothing) would refuse it, so that is a
	// caveat, surfaced honestly rather than discovered at deploy.
	switch {
	case len(plan.Blockers) > 0:
		plan.Verdict = Rejected
	case plan.hasPartial() || plan.hasUndeployable() || len(plan.Fidelity) > 0:
		// Any fidelity line is a caveat: a stack open-infra does not fully emulate is never reported as
		// cleanly PROVISIONABLE.
		plan.Verdict = ProvisionableWithCaveats
	default:
		plan.Verdict = Provisionable
	}
	return plan, nil
}

// ValidatePlan is the plan ValidateTemplate reports: the template checked without parameter values, as
// AWS validates a template — a parameter with no default is not a blocker, nor is a finding that only
// arises because such a parameter has no value yet. Everything else (an unsupported type, a broken
// reference, a cycle, an Output that will not resolve) still refuses.
func ValidatePlan(data []byte, exports map[string]string, stackName string, caps Capabilities) (*Plan, error) {
	plan, err := BuildPlanWithCaps(data, nil, exports, stackName, caps)
	if err != nil {
		return nil, err
	}
	kept := plan.Blockers[:0]
	for _, b := range plan.Blockers {
		if (strings.HasPrefix(b, "parameter ") && strings.Contains(b, " has no default and no value supplied")) || strings.Contains(b, "<param:") ||
			strings.HasPrefix(b, "Parameter '") {
			continue
		}
		kept = append(kept, b)
	}
	plan.Blockers = kept
	switch {
	case len(plan.Blockers) > 0:
		plan.Verdict = Rejected
	case plan.hasPartial() || plan.hasUndeployable() || len(plan.Fidelity) > 0:
		plan.Verdict = ProvisionableWithCaveats
	default:
		plan.Verdict = Provisionable
	}
	return plan, nil
}

// ParameterDefaults returns each template parameter's Default as a string (a parameter with none is
// absent) — what DescribeStacks lists for a parameter the stack was not given.
func ParameterDefaults(data []byte) map[string]string {
	t, err := Parse(data)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for name, p := range t.Parameters {
		if !p.hasDef {
			continue
		}
		switch v := p.Default.(type) {
		case []any:
			parts := make([]string, 0, len(v))
			for _, e := range v {
				parts = append(parts, fmt.Sprint(e))
			}
			out[name] = strings.Join(parts, ",")
		default:
			out[name] = fmt.Sprint(v)
		}
	}
	return out
}

func (p *Plan) hasPartial() bool {
	for _, r := range p.Resources {
		if r.Included && r.Status == Partial {
			return true
		}
	}
	return false
}

// hasUndeployable reports whether any included resource maps to a kind but has no create
// translator (plan-supported, not create-faithful) — deploy would refuse the whole stack.
func (p *Plan) hasUndeployable() bool {
	for _, r := range p.Resources {
		if r.Included && r.Kind != "" && !r.Deployable {
			return true
		}
	}
	return false
}

// pseudoParams returns the AWS pseudo-parameter values used for resolution: the install's identity
// (awsidentity.Current — the account, region and partition the aws-shim reports), and the stack's own
// StackId, the same ARN the CloudFormation front door returns for it. An ARN a template builds from
// them therefore matches the ARN the shim reports, as on AWS.
func pseudoParams(stackName string) map[string]any { return pseudoParamsFor(stackName, "") }

// pseudoParamsFor is pseudoParams for one stack instance: AWS::StackId is stackID, or the derived StackId
// of stackName when stackID is "" (a stack from before StackIds were per instance). The stack acts in the
// account its StackId names (stackIdentity): a member account's stack resolves AWS::AccountId to its own
// account, the management account's exactly as before.
func pseudoParamsFor(stackName, stackID string) map[string]any {
	if stackName == "" {
		stackName = "openinfra-stack"
	}
	id := stackIdentity(stackID)
	if stackID == "" {
		stackID = id.StackID(stackName)
	}
	return map[string]any{
		"AWS::Region":           id.Region,
		"AWS::AccountId":        id.AccountID,
		"AWS::Partition":        awsidentity.Partition,
		"AWS::URLSuffix":        awsidentity.URLSuffix,
		"AWS::StackName":        stackName,
		"AWS::StackId":          stackID,
		"AWS::NoValue":          nil,
		"AWS::NotificationARNs": []any{},
	}
}

// stackID is the StackId of the stack these options deploy: StackID, else the derived StackId of its name.
func (o DeployOptions) stackID() string {
	if o.StackID != "" {
		return o.StackID
	}
	return awsidentity.Current().StackID(o.StackName)
}

// stackIdentity is the identity of the account a stack instance acts in: the install's (the management
// account's, unchanged) with the account its StackId names. A StackId that names no 12-digit account, or
// the install's own, is the install's identity exactly.
func stackIdentity(stackID string) awsidentity.Identity {
	return awsidentity.Current().ForAccount(awsidentity.AccountOfARN(stackID), "")
}

// adoptStackID gives the options the StackId the stack's record names, when they name none: an update,
// delete, change set or recovery of an existing stack resolves AWS::StackId as its create did.
func (o *DeployOptions) adoptStackID(rec *StackRecord) {
	if o.StackID == "" && rec != nil {
		o.StackID = rec.StackID
	}
}

// strMapToAny lifts a string-keyed string map to an any-valued one (exports, for Fn::ImportValue).
func strMapToAny(m map[string]string) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func dedupSorted(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func noteOr(note, fallback string) string {
	if note == "" {
		return fallback
	}
	return note
}

// manifestCaveats collects a translated resource's declared losses, its companions' included, without
// repeats. A translator that folds a resource into another (nil manifest) reports its caveats there.
func manifestCaveats(m *Manifest) []string {
	if m == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	var walk func(*Manifest)
	walk = func(x *Manifest) {
		if x == nil {
			return
		}
		for _, c := range x.Caveats {
			if c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
		for _, e := range x.Extra {
			walk(e)
		}
	}
	walk(m)
	return out
}
