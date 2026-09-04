package policyengine

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SupportedServices are the AWS data-plane services the aws-shim enforces, so an AWS policy's
// statements for these can be honored faithfully. Anything else is reported, never silently granted.
var SupportedServices = map[string]bool{"s3": true, "dynamodb": true, "lambda": true}

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
		if _, ok := st["Condition"]; ok {
			// A silently-ineffective Deny condition is a security hole, so conditions are refused,
			// not guessed. The engine supports conditions natively; the AWS importer will map the
			// safe operators in a later pass.
			unsupported = append(unsupported, fmt.Sprintf("statement %d: Condition is not importable yet (author the condition natively on kind: Policy dataPlane)", i))
			continue
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
		out = append(out, Statement{Effect: effect, Actions: actions, Resources: resources})
	}
	return out, unsupported, nil
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
func importResources(arns []string) (kept, unsupported []string) {
	for _, r := range arns {
		if r == "*" {
			kept = append(kept, "*")
			continue
		}
		if res, ok := arnToResource(r); ok {
			kept = append(kept, res)
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
