package iamauthz

import (
	"github.com/harn3ss/open-infra/policyengine"
)

// AuthorizeTrust evaluates a role's trust policy — its AssumeRolePolicyDocument, as written — for one
// assume of the role by p: allowed when a statement whose Principal names p allows action (sts:AssumeRole)
// and no statement naming p denies it. Each statement's Condition is evaluated against reqCtx exactly as an
// identity policy's is: aws:MultiFactorAuthPresent and aws:MultiFactorAuthAge with AWS's absent-key
// semantics, an Allow whose condition the platform cannot evaluate grants nothing, and a Deny with one
// applies unconditionally.
//
// The front doors read the principals a role trusts from its spec.trust; this adds what spec.trust cannot
// carry — the document's conditions — on top, so an assume must pass both. A document with no Condition
// adds nothing (spec.trust already holds its principals) and is allowed as is; one that does not parse
// allows nothing.
func AuthorizeTrust(document string, p Principal, action, roleARN string, reqCtx map[string]any) (bool, string) {
	raw, err := documentStatements(document)
	if err != nil {
		return false, "the role's trust policy does not parse: " + err.Error()
	}
	conditioned := false
	for _, st := range raw {
		if _, ok := st["Condition"]; ok {
			conditioned = true
		}
	}
	if !conditioned {
		return true, ""
	}
	stmts, _, err := ParseResourcePolicy(document)
	if err != nil {
		return false, "the role's trust policy does not parse: " + err.Error()
	}
	typed, arnAcct := mapResource(roleARN)
	resAcct := arnAcct
	if resAcct == "" {
		resAcct = arnAccount(roleARN)
	}
	if resAcct == "" || resAcct == "*" {
		resAcct = p.AccountID()
	}
	ctx := make(map[string]any, len(reqCtx)+2)
	for k, v := range reqCtx {
		ctx[k] = v
	}
	ctx[resourceAccountKey] = resAcct
	ctx[principalAccountKey] = p.AccountID()
	rt, rid := splitTyped(typed)
	req := policyengine.Request{
		Principal: policyengine.Principal{Type: string(p.Type), ID: p.ID},
		Action:    action,
		Resource:  policyengine.Resource{Type: rt, ID: rid},
		Context:   ctx,
	}
	allowed := false
	for _, rs := range stmts {
		if rs.appliesToPrincipal(p) == "" {
			continue
		}
		eng, err := policyengine.NewEngine([]policyengine.Statement{rs.Statement})
		if err != nil {
			return false, "the role's trust policy does not compile: " + err.Error()
		}
		d := eng.Authorize(req)
		if d.ExplicitDeny {
			return false, "denied by an explicit Deny in the role's trust policy"
		}
		if d.Allowed {
			allowed = true
		}
	}
	if !allowed {
		return false, "the role's trust policy does not allow " + p.ARN() + " to " + action + " (no statement naming it allows it, or its conditions are not met)"
	}
	return true, ""
}
