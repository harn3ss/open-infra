// Package policyengine is open-infra's fine-grained authorization engine for the aws-shim data
// planes. It evaluates a request (principal, action, resource, context) against a principal's policy
// statements using Cedar — allow/deny with an explicit forbid overriding, request conditions, and
// default-deny: the model Kubernetes RBAC cannot express. See docs/policy-engine.md.
//
// It does NOT replace control-plane RBAC; it adds fine-grained authorization at the data-plane
// front doors (S3/DynamoDB/Lambda), and fails closed.
//
// Action/resource matching: an AWS action ("s3:GetObject", "s3:*") is matched as a STRING via Cedar
// `like` (so "s3:*" is a real prefix wildcard, which a Cedar Action entity id could not express).
// The request carries the action + typed resource ("Bucket::assets") in the Cedar context; each
// statement compiles to a permit/forbid whose `when` matches those strings.
package policyengine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// Effect is a statement's effect.
type Effect string

const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Statement is one open-infra policy statement (the shape carried on kind: Policy spec.dataPlane),
// mapping to a Cedar permit/forbid. An empty list or a lone "*" in Actions/Resources means "any";
// a "*" inside an entry (e.g. "s3:*", "Bucket::log-*") is a wildcard.
type Statement struct {
	Effect    Effect
	Actions   []string          // e.g. ["s3:GetObject","s3:*"] or ["*"]
	Resources []string          // "Type::id" e.g. ["Bucket::assets","Bucket::*"], or ["*"]
	Condition map[string]string // request-context keys that must equal these values ("true"/"false" => bool)
}

// Principal identifies the subject of a request (the SigV4-authenticated open-infra identity).
type Principal struct{ Type, ID string } // Type: User | Group | Key

// Resource identifies the object of a request.
type Resource struct{ Type, ID string } // Type: Bucket | Table | Function | GraphQLApi

// Request is one authorization question.
type Request struct {
	Principal Principal
	Action    string
	Resource  Resource
	Context   map[string]any // string/bool values (authenticated, sourceIp, ...)
}

// Decision is the engine's answer.
type Decision struct {
	Allowed bool
	Reason  string
}

// Engine holds a compiled Cedar policy set.
type Engine struct{ ps *cedar.PolicySet }

// NewEngine compiles open-infra statements into a Cedar policy set.
func NewEngine(statements []Statement) (*Engine, error) {
	var b strings.Builder
	for i, s := range statements {
		clause, err := s.toCedar(i)
		if err != nil {
			return nil, err
		}
		b.WriteString(clause)
		b.WriteString("\n")
	}
	ps, err := cedar.NewPolicySetFromBytes("openinfra.cedar", []byte(b.String()))
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return &Engine{ps: ps}, nil
}

// Authorize evaluates a request: an explicit Deny wins, else an Allow permits, else default-deny.
func (e *Engine) Authorize(r Request) Decision {
	ctx := types.RecordMap{
		"action":   types.String(r.Action),
		"resource": types.String(r.Resource.Type + "::" + r.Resource.ID),
	}
	for k, v := range r.Context {
		switch x := v.(type) {
		case string:
			ctx[types.String(k)] = types.String(x)
		case bool:
			ctx[types.String(k)] = types.Boolean(x)
		}
	}
	req := cedar.Request{
		Principal: types.NewEntityUID(entityType(r.Principal.Type), types.String(r.Principal.ID)),
		Action:    types.NewEntityUID("Action", "perform"),
		Resource:  types.NewEntityUID(entityType(r.Resource.Type), types.String(r.Resource.ID)),
		Context:   types.NewRecord(ctx),
	}
	if d, _ := e.ps.IsAuthorized(types.EntityMap{}, req); d == cedar.Allow {
		return Decision{Allowed: true, Reason: "allowed by policy"}
	}
	return Decision{Allowed: false, Reason: "no policy allows this action (default deny)"}
}

func entityType(t string) types.EntityType {
	if t == "" {
		return "Any"
	}
	return types.EntityType(t)
}

// toCedar renders one statement as a Cedar permit/forbid clause matching the request's action +
// resource strings (with `like` wildcards) plus any context conditions.
func (s Statement) toCedar(idx int) (string, error) {
	head := "permit"
	switch s.Effect {
	case Allow:
	case Deny:
		head = "forbid"
	default:
		return "", fmt.Errorf("statement %d: effect must be Allow or Deny, got %q", idx, s.Effect)
	}

	var conds []string
	if clause := matchAny("context.action", s.Actions); clause != "" {
		conds = append(conds, clause)
	}
	if !wildcard(s.Resources) {
		for _, r := range s.Resources {
			if r != "*" && !strings.Contains(r, "::") {
				return "", fmt.Errorf("statement %d: resource %q must be Type::id (e.g. Bucket::assets), a wildcard like Bucket::*, or *", idx, r)
			}
		}
		if clause := matchAny("context.resource", s.Resources); clause != "" {
			conds = append(conds, clause)
		}
	}
	for _, k := range sortedKeys(s.Condition) {
		v := s.Condition[k]
		if v == "true" || v == "false" {
			conds = append(conds, fmt.Sprintf("context.%s == %s", k, v)) // bool
		} else {
			conds = append(conds, fmt.Sprintf("context.%s == %q", k, v)) // string
		}
	}

	clause := head + " (\n  principal,\n  action,\n  resource\n)"
	if len(conds) > 0 {
		clause += "\nwhen { " + strings.Join(conds, " && ") + " }"
	}
	return clause + ";", nil
}

// matchAny renders an OR of equality / `like` tests for a set of values against a context field, or
// "" when the set is a wildcard (matches anything, so no constraint).
func matchAny(field string, values []string) string {
	if wildcard(values) {
		return ""
	}
	ors := make([]string, 0, len(values))
	for _, v := range values {
		if strings.Contains(v, "*") {
			ors = append(ors, fmt.Sprintf("%s like %q", field, v))
		} else {
			ors = append(ors, fmt.Sprintf("%s == %q", field, v))
		}
	}
	if len(ors) == 1 {
		return ors[0]
	}
	return "(" + strings.Join(ors, " || ") + ")"
}

func wildcard(xs []string) bool {
	return len(xs) == 0 || (len(xs) == 1 && xs[0] == "*")
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
