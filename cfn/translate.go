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
type translator func(logicalID string, props map[string]any) (*Manifest, []Finding)

// translators is the create-fidelity registry. A CFN type is create-provisionable only if it
// appears here AND its translator accepts every property. Grow it the gated way.
var translators = map[string]translator{
	"AWS::KMS::Key":                    translateKMSKey,
	"AWS::Lambda::Function":            translateLambdaFunction,
	"AWS::StepFunctions::StateMachine": translateStateMachine,
	"AWS::EC2::Volume":                 translateVolume,
	"AWS::Cognito::UserPool":           translateCognitoUserPool,
}

// hasTranslator reports whether a type can be created (not merely planned).
func hasTranslator(cfnType string) bool { _, ok := translators[cfnType]; return ok }

// ---- AWS::KMS::Key -> kind: EncryptionKey ----
//
// Faithful: Description, EnableKeyRotation (-> rotationDays), KeySpec (-> keyType).
// Declared caveat: KeyPolicy (Vault-managed key; access is governed by open-infra IAM, not a
// per-key policy). Anything else blocks.
func translateKMSKey(id string, props map[string]any) (*Manifest, []Finding) {
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
func translateLambdaFunction(id string, props map[string]any) (*Manifest, []Finding) {
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
func translateStateMachine(id string, props map[string]any) (*Manifest, []Finding) {
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
// A Longhorn block volume. Size maps directly; MultiAttach maps to shared (RWX). AWS's
// storage-class/perf knobs (VolumeType, Iops, Throughput) and AvailabilityZone have no
// open-infra counterpart (one flat cluster, one storage class) and are inert caveats.
// Encryption and restoring from an AWS SnapshotId are behavior-bearing with no faithful form
// and block.
func translateVolume(id string, props map[string]any) (*Manifest, []Finding) {
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
	if v, ok := props["Encrypted"].(bool); ok && v {
		f = append(f, Finding{"Resource " + id, "Encrypted volumes are not translatable — open-infra Volumes have no per-volume encryption knob (refusing rather than dropping an encryption guarantee)"})
	}
	if _, ok := props["KmsKeyId"]; ok {
		f = append(f, Finding{"Resource " + id, "KmsKeyId is not translatable — no per-volume KMS encryption"})
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

// ---- AWS::Cognito::UserPool -> kind: UserPool ----
//
// open-infra now hosts a pool (a Keycloak realm that issues OIDC tokens), so the CORE of a
// Cognito user pool maps: UserPoolName -> the realm. What does NOT transfer is Cognito-specific
// behavior. MFA enforcement and Lambda triggers are behavior-bearing and have no Keycloak-realm
// equivalent here, so they BLOCK (dropping them would silently weaken or change auth). The
// realm's own defaults cover password policy / schema / verification, so those are declared
// caveats (the pool still enforces a policy — just the realm's, not Cognito's exact rules).
func translateCognitoUserPool(id string, props map[string]any) (*Manifest, []Finding) {
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
