package iamauthz

import (
	"encoding/json"
	"strings"

	"github.com/harn3ss/open-infra/policyengine"
)

// TrustStatements is a role's trust (its spec.trust) as the role's resource policy for sts:AssumeRole,
// passed to the evaluator with WithResourcePolicy: a trust policy is the role's resource-based policy, so
// AWS's evaluation logic decides an assume with it. Another account's role then needs both the trust and
// the caller's own policy; within one account a trust naming the caller itself is enough on its own, and
// one naming the account delegates to the account's policies.
//
// Each entry is read as an AWS trust policy's principal:
//
//	"*"                    anyone, of any account
//	"arn:…"                that principal; an account's root ARN is every principal of that account
//	a 12-digit account id  that account (its root ARN)
//	"<name>", "User::<n>"  that user of the ROLE's account: another account's principal is named by its
//	                       ARN, never by a bare name
//	"Role::<name>"         that role of the role's account
//
// Entries that name no IAM principal (a ServiceAccount, an OIDC provider, the VM instance principal, a
// role outside the IAM home) are left out: no sts:AssumeRole caller is one. The trust policy's written
// conditions are AuthorizeTrust's, checked as well.
func TrustStatements(trust []string, roleAccount string) ([]ResourceStatement, error) {
	if roleAccount == "" {
		roleAccount = ManagementAccount
	}
	var principals []string
	for _, t := range trust {
		t = strings.TrimSpace(t)
		switch {
		case t == "":
		case t == "*", strings.HasPrefix(t, "arn:"):
			principals = append(principals, t)
		case len(t) == 12 && strings.Trim(t, "0123456789") == "":
			principals = append(principals, "arn:aws:iam::"+t+":root")
		case strings.HasPrefix(t, "User::"):
			principals = append(principals, "arn:aws:iam::"+roleAccount+":user/"+strings.TrimPrefix(t, "User::"))
		case strings.HasPrefix(t, "Role::"):
			principals = append(principals, "arn:aws:iam::"+roleAccount+":role/"+strings.TrimPrefix(t, "Role::"))
		case strings.ContainsAny(t, ":/") || t == "vm":
			// not an IAM principal
		default:
			principals = append(principals, "arn:aws:iam::"+roleAccount+":user/"+t)
		}
	}
	if len(principals) == 0 {
		return nil, nil
	}
	doc, err := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Effect": "Allow", "Principal": map[string]any{"AWS": principals}, "Action": "sts:AssumeRole",
		}},
	})
	if err != nil {
		return nil, err
	}
	stmts, _, err := ParseResourcePolicy(string(doc))
	return stmts, err
}

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
