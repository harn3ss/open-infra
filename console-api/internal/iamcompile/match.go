package iamcompile

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/harn3ss/open-infra/policyengine"
)

// glob reports whether s matches pattern p, where "*" is the only wildcard (any run of characters,
// including none). Everything else is literal — AWS's "?" included: in an Allow the evaluator keeps it
// literal (narrower), and in a Deny it has already been read as "*" (iamauthz). Case-sensitive.
func glob(p, s string) bool {
	if !strings.Contains(p, "*") {
		return p == s
	}
	parts := strings.Split(p, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

// actionMatches reports whether an IAM action pattern list names action (AWS action names are
// case-insensitive).
func actionMatches(patterns []string, action string) bool {
	a := strings.ToLower(action)
	for _, p := range patterns {
		if glob(strings.ToLower(p), a) {
			return true
		}
	}
	return false
}

// statementActs reports whether a statement applies to an action, and whether it does so only through a
// complement (NotAction). A complement over AWS's action space never reaches the operator surface: the
// raw Kubernetes objects and composites are platform internals no AWS document was written about, so
// AWS's PowerUserAccess (NotAction iam:*) grants AWS services, not Secrets and RBAC objects.
func statementActs(st policyengine.Statement, action string) bool {
	if len(st.NotActions) > 0 {
		if strings.HasPrefix(strings.ToLower(action), operatorPrefix+":") {
			return false
		}
		return !actionMatches(st.NotActions, action)
	}
	return actionMatches(st.Actions, action)
}

const operatorPrefix = "openinfra-operator"

// rawARNPrefix marks a resource kept as its written ARN (iamauthz's form for an unfronted service).
const rawARNPrefix = "ARN::"

var typedCache sync.Map // ARN -> string

// typedOf is the resource string a request for arn is evaluated against: the typed resource the AWS
// importer maps a fronted service's ARN to (Bucket::b, Queue::q …), or the ARN as written ("ARN::<arn>")
// for any other service — exactly as iamauthz compiles a policy document's Resource, so a compiled
// statement and a request naming the same resource always meet.
func typedOf(arn string) string {
	if arn == "*" || arn == "" {
		return "*"
	}
	if v, ok := typedCache.Load(arn); ok {
		return v.(string)
	}
	out := rawARNPrefix + arn
	doc, _ := json.Marshal(map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Action": "*", "Resource": arn}}})
	if stmts, unsupported, err := policyengine.ImportAWS(string(doc)); err == nil && len(unsupported) == 0 &&
		len(stmts) == 1 && len(stmts[0].Resources) == 1 && stmts[0].Resources[0] != "*" {
		out = stmts[0].Resources[0]
	}
	typedCache.Store(arn, out)
	return out
}

// conditionScope classifies a statement's conditions for the control plane, which carries none of the
// request keys IAM conditions test. The one key it can honour is the resource's account
// (iamauthz's resourceAccount, set for an ARN that names an account): equal to the principal's own
// account, it is no constraint; another account's, the statement concerns resources the principal's
// control-plane grants never reach. ok=false: the statement does not apply here at all. conditional=true:
// some other condition remains (an Allow is then dropped, a Deny applied unconditionally).
func conditionScope(st policyengine.Statement, account string) (ok, conditional bool) {
	return conditionScopeFor(st, account, "")
}

// passRoleServices are the services a role is passed to on this platform, each where its pass is checked:
// a VirtualMachine's instance role (ec2), an Application's task role (ecs-tasks), a Function's execution
// role (lambda), a state machine's execution role (states). iam:PassRole is compiled for each of them too
// (passRoleVerbFor), so a grant limited by iam:PassedToService passes a role to its service alone.
var passRoleServices = []string{"ec2.amazonaws.com", "ecs-tasks.amazonaws.com", "lambda.amazonaws.com", "states.amazonaws.com"}

// passRoleVerbFor is the RBAC verb for passing a role to service, beside passrole (any service): the
// admission policies (platform/security/pass-role.yaml) accept either.
func passRoleVerbFor(service string) string { return "passrole:" + service }

// conditionScopeFor is conditionScope for an iam:PassRole decision that passes the role to service (""
// for any other decision): there the request carries iam:PassedToService (passedToService), so a condition
// on it is evaluated, not left conditional.
func conditionScopeFor(st policyengine.Statement, account, service string) (ok, conditional bool) {
	for k, v := range st.Condition {
		if k == "resourceAccount" {
			if v != account {
				return false, false
			}
			continue
		}
		conditional = true
	}
	for _, lc := range st.LikeConditions {
		if lc.Key == "resourceAccount" {
			if glob(lc.Pattern, account) == lc.Negate {
				return false, false
			}
			continue
		}
		conditional = true
	}
	// A condition on a key AWS leaves out of some requests (aws:MultiFactorAuth*) is a condition too: the
	// control plane carries none of these keys, so it drops such an Allow and applies such a Deny always.
	// iam:PassedToService alone is known, on a PassRole decision for a service.
	for _, kc := range st.KeyConditions {
		if kc.Key == "passedToService" && service != "" {
			if !passedToServiceMatches(kc, service) {
				return false, false
			}
			continue
		}
		conditional = true
	}
	if len(st.IPConditions) > 0 || len(st.TimeConditions) > 0 {
		conditional = true
	}
	return true, conditional
}

// passedToServiceMatches evaluates a condition on iam:PassedToService for a request that carries service.
func passedToServiceMatches(kc policyengine.KeyCondition, service string) bool {
	switch kc.Op {
	case policyengine.KeyNull:
		return kc.Value == "false" // the key is present
	case "==":
		return service == kc.Value
	case "!=":
		return service != kc.Value
	case "like":
		return glob(kc.Value, service)
	case "!like":
		return !glob(kc.Value, service)
	}
	return false
}

// onlyPassedToService reports whether a statement's one condition is iam:PassedToService: a PassRole
// statement compiled per service, not dropped.
func onlyPassedToService(st policyengine.Statement) bool {
	if len(st.LikeConditions) > 0 || len(st.IPConditions) > 0 || len(st.TimeConditions) > 0 || len(st.KeyConditions) == 0 {
		return false
	}
	for k := range st.Condition {
		if k != "resourceAccount" {
			return false
		}
	}
	for _, kc := range st.KeyConditions {
		if kc.Key != "passedToService" {
			return false
		}
	}
	return true
}
