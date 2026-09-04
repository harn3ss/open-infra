// Package policyengine is open-infra's fine-grained authorization engine for the aws-shim data
// planes. It evaluates a request (principal, action, resource, context) against a principal's policy
// statements using Cedar — allow/deny with an explicit forbid overriding, request conditions, and
// default-deny: the model Kubernetes RBAC cannot express. See docs/policy-engine.md.
//
// It does NOT replace control-plane RBAC; it adds fine-grained authorization at the data-plane
// front doors (S3/DynamoDB/Lambda/AppSync), and fails closed.
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

// Statement is one open-infra policy statement (the shape carried on kind: Policy spec.statements),
// mapping to a Cedar permit/forbid. An empty list or a lone "*" in Actions/Resources means "any".
type Statement struct {
	Effect    Effect
	Actions   []string          // e.g. ["s3:GetObject","s3:PutObject"] or ["*"]
	Resources []string          // "Type::id" e.g. ["Bucket::assets"], or ["*"]
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

// Engine holds a compiled Cedar policy set for one principal (or a shared set).
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
	ctx := types.RecordMap{}
	for k, v := range r.Context {
		switch x := v.(type) {
		case string:
			ctx[types.String(k)] = types.String(x)
		case bool:
			ctx[types.String(k)] = types.Boolean(x)
		}
	}
	req := cedar.Request{
		Principal: types.NewEntityUID(types.EntityType(r.Principal.Type), types.String(r.Principal.ID)),
		Action:    types.NewEntityUID("Action", types.String(r.Action)),
		Resource:  types.NewEntityUID(types.EntityType(r.Resource.Type), types.String(r.Resource.ID)),
		Context:   types.NewRecord(ctx),
	}
	if d, _ := e.ps.IsAuthorized(types.EntityMap{}, req); d == cedar.Allow {
		return Decision{Allowed: true, Reason: "allowed by policy"}
	}
	return Decision{Allowed: false, Reason: "no policy allows this action (default deny)"}
}

// toCedar renders one statement as a Cedar permit/forbid clause.
func (s Statement) toCedar(idx int) (string, error) {
	head := "permit"
	switch s.Effect {
	case Allow:
	case Deny:
		head = "forbid"
	default:
		return "", fmt.Errorf("statement %d: effect must be Allow or Deny, got %q", idx, s.Effect)
	}

	var conds []string // extra `when` clauses (multi-resource + context conditions)

	// Action set is allowed directly in the Cedar scope.
	action := "action"
	if !wildcard(s.Actions) {
		uids := make([]string, 0, len(s.Actions))
		for _, a := range s.Actions {
			uids = append(uids, fmt.Sprintf(`Action::%q`, a))
		}
		action = "action in [" + strings.Join(uids, ", ") + "]"
	}

	// The Cedar scope's `resource` takes only `== entity` (or `in parent`), not a set — so a single
	// resource goes in the scope, and multiple resources become a `resource in [..]` condition.
	resource := "resource"
	if !wildcard(s.Resources) {
		uids := make([]string, 0, len(s.Resources))
		for _, r := range s.Resources {
			t, id, ok := strings.Cut(r, "::")
			if !ok || t == "" || id == "" {
				return "", fmt.Errorf("statement %d: resource %q must be Type::id (e.g. Bucket::assets) or *", idx, r)
			}
			uids = append(uids, fmt.Sprintf(`%s::%q`, t, id))
		}
		if len(uids) == 1 {
			resource = "resource == " + uids[0]
		} else {
			conds = append(conds, "resource in ["+strings.Join(uids, ", ")+"]")
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

	clause := fmt.Sprintf("%s (\n  principal,\n  %s,\n  %s\n)", head, action, resource)
	if len(conds) > 0 {
		clause += "\nwhen { " + strings.Join(conds, " && ") + " }"
	}
	return clause + ";", nil
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
