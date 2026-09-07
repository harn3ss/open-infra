package policyengine

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
)

// SupportedServices are the AWS data-plane services the aws-shim enforces, so an AWS policy's
// statements for these can be honored faithfully. Anything else is reported, never silently granted.
var SupportedServices = map[string]bool{"s3": true, "dynamodb": true, "lambda": true}

// condType classifies a populated request-context attribute by value type, which fixes the AWS
// condition operators that map onto it faithfully.
type condType int

const (
	condBool condType = iota // a boolean attr — the Bool operator
	condIP                   // a string attr holding an IP — IpAddress / NotIpAddress (or an exact StringEquals)
)

// ConditionKey is one request-context attribute the aws-shim's requestContext() populates and that the
// AWS importer may therefore map a condition onto. Aliases are the key spellings accepted in an
// imported AWS Condition (e.g. "aws:SourceIp" resolves to the "sourceIp" attr).
//
// THE KEY-POPULATION INVARIANT (security-critical). This registry is the SINGLE source of truth for
// which condition keys are importable, and its Attr set MUST equal the attributes requestContext()
// actually sets. A condition is honored ONLY if its key resolves here, because honoring a condition on
// a key the shim never populates is a fail-open hole: in Cedar a `forbid ... when <absent attr>` is
// SKIPPED, so the Deny silently never fires. Adding an entry here without also populating that attr in
// the shim reopens that hole — the drift test in the aws-shim package
// (TestSupportedConditionKeysMatchRequestContext) fails if the two ever diverge. (Belt-and-braces, the
// engine additionally DENIES a forbid whose read attribute is absent or malformed — see engine.go.)
type ConditionKey struct {
	Attr    string
	Type    condType
	Aliases []string
}

// SupportedConditionKeys is the condition-import whitelist. Everything not expressible through it stays
// refused (the wholesale fail-closed behavior the importer began with).
var SupportedConditionKeys = []ConditionKey{
	{Attr: "authenticated", Type: condBool, Aliases: []string{"authenticated"}},
	{Attr: "sourceIp", Type: condIP, Aliases: []string{"aws:SourceIp", "sourceIp"}},
}

// SupportedConditionAttrs is the set of request-context attributes the importer may reference — the
// exact set requestContext() must populate. The aws-shim drift test compares this to requestContext().
func SupportedConditionAttrs() map[string]bool {
	m := make(map[string]bool, len(SupportedConditionKeys))
	for _, k := range SupportedConditionKeys {
		m[k.Attr] = true
	}
	return m
}

func resolveConditionKey(key string) (ConditionKey, bool) {
	for _, k := range SupportedConditionKeys {
		for _, a := range k.Aliases {
			if a == key {
				return k, true
			}
		}
	}
	return ConditionKey{}, false
}

// ImportAWS converts an AWS IAM policy document (JSON) into open-infra data-plane Statements. It
// returns the statements for the supported services and a list of parts it could NOT honor — actions
// for services with no open-infra data plane, ARNs it can't map, or conditions (not importable yet).
// Those are reported so the caller can refuse rather than silently grant or drop them. Effect and
// wildcards ("s3:*", "*") carry over faithfully.
func ImportAWS(policyDocument string) ([]Statement, []string, error) {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyDocument), &doc); err != nil {
		return nil, nil, fmt.Errorf("not a JSON policy document: %w", err)
	}
	var raw []map[string]any
	if err := json.Unmarshal(doc.Statement, &raw); err != nil {
		var one map[string]any
		if json.Unmarshal(doc.Statement, &one) != nil {
			return nil, nil, fmt.Errorf("policy Statement must be an object or an array")
		}
		raw = []map[string]any{one}
	}

	var out []Statement
	var unsupported []string
	for i, st := range raw {
		effect := Effect(awsStr(st["Effect"]))
		if effect != Allow && effect != Deny {
			return nil, nil, fmt.Errorf("statement %d: Effect must be Allow or Deny", i)
		}
		var eq map[string]string
		var ips []IPCondition
		if rawCond, ok := st["Condition"]; ok {
			cm, isMap := rawCond.(map[string]any)
			if !isMap {
				unsupported = append(unsupported, fmt.Sprintf("statement %d: Condition must be an object", i))
				continue
			}
			var reason string
			var mapped bool
			eq, ips, reason, mapped = importCondition(cm)
			if !mapped {
				// Refuse the WHOLE statement — never emit it with the condition dropped. Dropping an
				// Allow's condition would WIDEN the grant; dropping a Deny's condition would widen the
				// deny. Either way the imported policy would be MORE permissive than authored, the very
				// fail-open the wholesale refusal guarded. Block it; author it natively on dataPlane.
				unsupported = append(unsupported, fmt.Sprintf("statement %d: Condition is not importable (%s) — author it natively on kind: Policy dataPlane", i, reason))
				continue
			}
		}
		actions, aUn := importActions(awsList(st["Action"]))
		unsupported = append(unsupported, aUn...)
		if len(actions) == 0 {
			continue // nothing data-plane here
		}
		resources, rUn := importResources(awsList(st["Resource"]))
		unsupported = append(unsupported, rUn...)
		if len(resources) == 0 {
			// A data-plane action with no mappable Resource would compile to a rule that matches
			// nothing (silently inert) — report it instead of emitting it.
			unsupported = append(unsupported, fmt.Sprintf("statement %d: %v has no mappable Resource (an identity policy must scope to an ARN or \"*\")", i, actions))
			continue
		}
		s := Statement{Effect: effect, Actions: actions, Resources: resources, IPConditions: ips}
		if len(eq) > 0 {
			s.Condition = eq
		}
		out = append(out, s)
	}
	return out, unsupported, nil
}

// importCondition maps a statement's AWS Condition block onto the whitelist. It returns the equality
// conditions (attr -> value; "true"/"false" for a Bool) and the IP CIDR conditions, plus ok=false with
// a reason if ANY operator / key / shape is not faithfully mappable — in which case the caller refuses
// the whole statement. Only Bool (on a boolean attr), single-valued StringEquals (on a non-boolean
// populated attr), and IpAddress / NotIpAddress (CIDR, on an IP attr) are honored; every other
// operator, an unpopulated key, and any multi-valued list stay refused (fail closed).
func importCondition(cond map[string]any) (eq map[string]string, ips []IPCondition, reason string, ok bool) {
	eq = map[string]string{}
	for op, kv := range cond {
		m, isMap := kv.(map[string]any)
		if !isMap {
			return nil, nil, fmt.Sprintf("operator %q has a non-object body", op), false
		}
		for key, rawVal := range m {
			ck, known := resolveConditionKey(key)
			if !known {
				return nil, nil, fmt.Sprintf("key %q is not a request attribute the shim populates", key), false
			}
			val, single := singleValue(rawVal)
			if !single {
				return nil, nil, fmt.Sprintf("%q on %q is multi-valued (only single-valued is importable)", op, key), false
			}
			switch op {
			case "Bool":
				if ck.Type != condBool || (val != "true" && val != "false") {
					return nil, nil, fmt.Sprintf("Bool on %q is not a boolean request attribute", key), false
				}
				eq[ck.Attr] = val
			case "StringEquals":
				if ck.Type == condBool {
					return nil, nil, fmt.Sprintf("StringEquals on boolean key %q is not faithful (use Bool)", key), false
				}
				eq[ck.Attr] = val
			case "IpAddress", "NotIpAddress":
				if ck.Type != condIP {
					return nil, nil, fmt.Sprintf("%q on non-IP key %q", op, key), false
				}
				// Validate with the SAME parser Cedar's ip() uses, so a value accepted here cannot then
				// error inside the compiled policy (an errored IP test would skip a forbid → fail open).
				if _, err := types.ParseIPAddr(val); err != nil {
					return nil, nil, fmt.Sprintf("%q value %q is not a valid IP or CIDR", op, val), false
				}
				ips = append(ips, IPCondition{Key: ck.Attr, CIDR: val, Negate: op == "NotIpAddress"})
			default:
				return nil, nil, fmt.Sprintf("operator %q is not importable", op), false
			}
		}
	}
	return eq, ips, "", true
}

// singleValue reads a single-valued AWS condition value (a string, a bool, or a one-element array).
// A multi-element array is NOT single-valued (ok=false) — multi-valued conditions stay refused.
func singleValue(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case []any:
		if len(x) == 1 {
			return singleValue(x[0])
		}
	}
	return "", false
}

// importActions keeps the actions for supported services (and a bare "*"), reporting the rest.
func importActions(actions []string) (kept, unsupported []string) {
	for _, a := range actions {
		if a == "*" {
			kept = append(kept, "*")
			continue
		}
		svc, _, ok := strings.Cut(a, ":")
		if ok && SupportedServices[svc] {
			kept = append(kept, a)
		} else {
			unsupported = append(unsupported, "action "+a+" has no open-infra data plane")
		}
	}
	return kept, unsupported
}

// importResources maps AWS ARNs to open-infra typed resources, reporting ARNs it can't map.
// Distinct ARNs can collapse to the same typed resource (a bucket ARN and its `/*` object ARN both
// map to Bucket::<name>, since open-infra scopes to the bucket), so the result is de-duplicated.
func importResources(arns []string) (kept, unsupported []string) {
	seen := map[string]bool{}
	add := func(res string) {
		if !seen[res] {
			seen[res] = true
			kept = append(kept, res)
		}
	}
	for _, r := range arns {
		if r == "*" {
			add("*")
			continue
		}
		if res, ok := arnToResource(r); ok {
			add(res)
		} else {
			unsupported = append(unsupported, "resource "+r+" is not a recognizable S3/DynamoDB/Lambda ARN")
		}
	}
	return kept, unsupported
}

// arnToResource maps an S3/DynamoDB/Lambda ARN to a "Type::id" (wildcards preserved via like-patterns).
func arnToResource(arn string) (string, bool) {
	parts := strings.SplitN(arn, ":", 6) // arn:aws:<svc>:<region>:<acct>:<resource>
	if len(parts) < 6 || parts[0] != "arn" {
		return "", false
	}
	svc, tail := parts[2], parts[5]
	switch svc {
	case "s3":
		bucket, _, _ := strings.Cut(tail, "/") // arn:aws:s3:::bucket[/key] -> Bucket::bucket
		if bucket == "" {
			return "", false
		}
		return "Bucket::" + bucket, true
	case "dynamodb":
		if name, ok := strings.CutPrefix(tail, "table/"); ok && name != "" {
			return "Table::" + name, true
		}
	case "lambda":
		if name, ok := strings.CutPrefix(tail, "function:"); ok && name != "" {
			return "Function::" + name, true
		}
	}
	return "", false
}

func awsStr(v any) string { s, _ := v.(string); return s }

// awsList reads an AWS policy field that is either a string or a list of strings.
func awsList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
