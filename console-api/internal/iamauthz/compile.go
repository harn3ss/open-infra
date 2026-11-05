package iamauthz

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/harn3ss/open-infra/policyengine"
)

// The evaluator compiles AWS JSON policy documents itself, statement by statement, so it can honour a
// document as AWS does wherever the platform can and never widen it where it can't:
//
//   - Actions and NotActions are kept verbatim. An action of a service the platform does not front only
//     ever matches a request for that action, so keeping it is faithful (the AWS importer drops them,
//     because the data-plane front doors have nothing to match them against).
//   - Each Resource / NotResource ARN maps to the platform's typed resource (Bucket::b, Queue::q …) as the
//     AWS importer maps it; an ARN it does not recognise is kept as written ("ARN::<arn>", matched with
//     AWS's wildcards), so a request naming that ARN matches exactly what the author wrote.
//   - An ARN that names an account constrains the statement to resources in that account
//     (resourceAccount, set on every request).
//   - A condition the platform supports (policyengine.SupportedConditionKeys) carries over. An Allow
//     whose condition is not supported is dropped (narrower); a Deny whose condition is not supported is
//     applied unconditionally (narrower). Each is reported.
//   - A Deny NotResource that excludes an account-specific ARN excludes it in its written form, so the
//     Deny covers that resource in every other account rather than none (narrower).

// resourceAccountKey and principalAccountKey are request-context attributes the evaluator always sets:
// the account the resource and the principal belong to.
const (
	resourceAccountKey  = "resourceAccount"
	principalAccountKey = "principalAccount"
)

// rawARNPrefix marks a resource kept as its written ARN.
const rawARNPrefix = "ARN::"

// CompileDocument compiles an AWS JSON policy document (identity-based) into statements, reporting each
// part it could not honour faithfully. A malformed document is an error.
func CompileDocument(document string) ([]policyengine.Statement, []string, error) {
	raw, err := documentStatements(document)
	if err != nil {
		return nil, nil, err
	}
	var out []policyengine.Statement
	var report []string
	for i, st := range raw {
		stmts, notes, err := compileStatement(st)
		if err != nil {
			return nil, nil, fmt.Errorf("statement %d: %w", i, err)
		}
		for _, n := range notes {
			report = append(report, fmt.Sprintf("statement %d: %s", i, n))
		}
		out = append(out, stmts...)
	}
	return out, report, nil
}

func documentStatements(document string) ([]map[string]any, error) {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return nil, fmt.Errorf("not a JSON policy document: %w", err)
	}
	if len(doc.Statement) == 0 {
		return nil, nil
	}
	var raw []map[string]any
	if err := json.Unmarshal(doc.Statement, &raw); err != nil {
		var one map[string]any
		if json.Unmarshal(doc.Statement, &one) != nil {
			return nil, fmt.Errorf("policy Statement must be an object or an array")
		}
		raw = []map[string]any{one}
	}
	return raw, nil
}

func compileStatement(st map[string]any) ([]policyengine.Statement, []string, error) {
	effect := policyengine.Effect(str(st["Effect"]))
	if effect != policyengine.Allow && effect != policyengine.Deny {
		return nil, nil, fmt.Errorf("Effect must be Allow or Deny")
	}
	_, hasA := st["Action"]
	_, hasNA := st["NotAction"]
	_, hasR := st["Resource"]
	_, hasNR := st["NotResource"]
	if hasA && hasNA {
		return nil, nil, fmt.Errorf("a statement cannot set both Action and NotAction")
	}
	if hasR && hasNR {
		return nil, nil, fmt.Errorf("a statement cannot set both Resource and NotResource")
	}
	var notes []string
	base := policyengine.Statement{Effect: effect}
	if cond, ok := st["Condition"]; ok {
		c, why := importCondition(effect, cond)
		switch {
		case why == "":
			base.Condition, base.IPConditions, base.LikeConditions, base.TimeConditions =
				c.Condition, c.IPConditions, c.LikeConditions, c.TimeConditions
		case effect == policyengine.Allow:
			return nil, []string{"Allow dropped: its condition is not supported (" + why + ")"}, nil
		default:
			notes = append(notes, "Deny applied unconditionally: its condition is not supported ("+why+")")
		}
	}
	if hasNA {
		base.NotActions = list(st["NotAction"])
		if len(base.NotActions) == 0 {
			base.NotActions, base.Actions = nil, []string{"*"}
		}
	} else {
		base.Actions = list(st["Action"])
		if len(base.Actions) == 0 {
			return nil, append(notes, "no Action: the statement matches nothing"), nil
		}
	}
	if hasNR {
		excl := list(st["NotResource"])
		if len(excl) == 0 {
			base.Resources = []string{"*"}
			return []policyengine.Statement{base}, notes, nil
		}
		for _, arn := range excl {
			typed, acct := mapResource(arn)
			if acct != "" && effect == policyengine.Deny {
				typed = rawARNPrefix + arn // keep the account: the Deny then excludes less, never more
			}
			base.NotResources = append(base.NotResources, typed)
		}
		return []policyengine.Statement{base}, notes, nil
	}
	arns := list(st["Resource"])
	if !hasR {
		arns = []string{"*"}
	}
	// Group the resources by the account their ARN names, one statement per account constraint.
	byAcct := map[string][]string{}
	var order []string
	for _, arn := range arns {
		typed, acct := mapResource(arn)
		if _, seen := byAcct[acct]; !seen {
			order = append(order, acct)
		}
		byAcct[acct] = append(byAcct[acct], typed)
	}
	var out []policyengine.Statement
	for _, acct := range order {
		s := base
		s.Resources = byAcct[acct]
		if effect == policyengine.Deny {
			// AWS's single-character wildcard has no Cedar equivalent: a Deny reads it as "*" (it then
			// covers at least what the author wrote); an Allow keeps it literal (narrower).
			for i, r := range s.Resources {
				s.Resources[i] = strings.ReplaceAll(r, "?", "*")
			}
		}
		if acct != "" {
			s.Condition = withCondition(s.Condition, resourceAccountKey, acct)
			if strings.ContainsAny(acct, "*?") {
				delete(s.Condition, resourceAccountKey)
				s.LikeConditions = append(append([]policyengine.LikeCondition{}, s.LikeConditions...),
					policyengine.LikeCondition{Key: resourceAccountKey, Pattern: strings.ReplaceAll(acct, "?", "*")})
			}
		}
		out = append(out, s)
	}
	return out, notes, nil
}

func withCondition(m map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(m)+1)
	for a, b := range m {
		out[a] = b
	}
	out[k] = v
	return out
}

// mapResource maps one AWS Resource value to the platform's resource string and the account the ARN
// names ("" for none or any): "*" stays "*"; an ARN of a fronted service becomes its typed resource; any
// other ARN is kept as written; a typed resource ("Bucket::b") passes through.
func mapResource(arn string) (string, string) {
	if arn == "*" || arn == "" {
		return "*", ""
	}
	if !strings.HasPrefix(arn, "arn:") {
		return arn, ""
	}
	acct := arnAccount(arn)
	if acct == "*" {
		acct = ""
	}
	if typed, ok := typedARN(arn); ok {
		return typed, acct
	}
	return rawARNPrefix + arn, ""
}

// arnAccount is the account field of an ARN (arn:partition:service:region:account:resource).
func arnAccount(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

var typedCache sync.Map // ARN -> typedResult

type typedResult struct {
	typed string
	ok    bool
}

// typedARN maps an ARN to its typed resource exactly as the AWS policy importer does (by importing a
// one-statement document naming it), so a request and a policy naming the same ARN always meet.
func typedARN(arn string) (string, bool) {
	if v, ok := typedCache.Load(arn); ok {
		r := v.(typedResult)
		return r.typed, r.ok
	}
	doc, _ := json.Marshal(map[string]any{"Statement": []any{map[string]any{"Effect": "Allow", "Action": "*", "Resource": arn}}})
	stmts, unsupported, err := policyengine.ImportAWS(string(doc))
	r := typedResult{}
	if err == nil && len(unsupported) == 0 && len(stmts) == 1 && len(stmts[0].Resources) == 1 && stmts[0].Resources[0] != "*" {
		r = typedResult{typed: stmts[0].Resources[0], ok: true}
	}
	typedCache.Store(arn, r)
	return r.typed, r.ok
}

type conditions struct {
	Condition      map[string]string
	IPConditions   []policyengine.IPCondition
	LikeConditions []policyengine.LikeCondition
	TimeConditions []policyengine.TimeCondition
}

// importCondition maps an AWS Condition block with the AWS importer (by importing a one-statement
// document carrying it); why is non-empty when the platform cannot honour it.
func importCondition(effect policyengine.Effect, cond any) (conditions, string) {
	if _, ok := cond.(map[string]any); !ok {
		return conditions{}, "Condition must be an object"
	}
	doc, _ := json.Marshal(map[string]any{"Statement": []any{map[string]any{
		"Effect": string(effect), "Action": "*", "Resource": "*", "Condition": cond}}})
	stmts, unsupported, err := policyengine.ImportAWS(string(doc))
	if err != nil {
		return conditions{}, err.Error()
	}
	if len(unsupported) > 0 || len(stmts) != 1 {
		why := strings.Join(unsupported, "; ")
		if why == "" {
			why = "not importable"
		}
		return conditions{}, why
	}
	s := stmts[0]
	return conditions{s.Condition, s.IPConditions, s.LikeConditions, s.TimeConditions}, ""
}

// ResourceStatement is one statement of a resource-based policy (a bucket, queue, topic, key, function
// or repository policy): the statement plus the principals it names.
type ResourceStatement struct {
	policyengine.Statement
	// Principals are the statement's Principal values, normalised: "*" (anyone), an account
	// "arn:aws:iam::<acct>:root", a user / role / assumed-role ARN, or a service name
	// ("sns.amazonaws.com"). NotPrincipal lists the principals it does NOT apply to.
	Principals    []string
	NotPrincipals []string
}

// ParseResourcePolicy compiles an AWS resource-based policy document.
func ParseResourcePolicy(document string) ([]ResourceStatement, []string, error) {
	raw, err := documentStatements(document)
	if err != nil {
		return nil, nil, err
	}
	var out []ResourceStatement
	var report []string
	for i, st := range raw {
		principals, err := principalList(st["Principal"])
		if err != nil {
			return nil, nil, fmt.Errorf("statement %d: %w", i, err)
		}
		notPrincipals, err := principalList(st["NotPrincipal"])
		if err != nil {
			return nil, nil, fmt.Errorf("statement %d: %w", i, err)
		}
		if len(principals) == 0 && len(notPrincipals) == 0 {
			report = append(report, fmt.Sprintf("statement %d: no Principal: it applies to no one", i))
			continue
		}
		stmts, notes, err := compileStatement(st)
		if err != nil {
			return nil, nil, fmt.Errorf("statement %d: %w", i, err)
		}
		for _, n := range notes {
			report = append(report, fmt.Sprintf("statement %d: %s", i, n))
		}
		for _, s := range stmts {
			out = append(out, ResourceStatement{Statement: s, Principals: principals, NotPrincipals: notPrincipals})
		}
	}
	return out, report, nil
}

// principalList normalises an AWS Principal / NotPrincipal value.
func principalList(v any) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		if x != "*" {
			return nil, fmt.Errorf("Principal must be \"*\" or an object")
		}
		return []string{"*"}, nil
	case map[string]any:
		var out []string
		for k, val := range x {
			for _, p := range list(val) {
				switch k {
				case "AWS":
					out = append(out, normaliseAWSPrincipal(p))
				case "Service":
					out = append(out, p)
				case "Federated", "CanonicalUser":
					out = append(out, k+":"+p)
				default:
					return nil, fmt.Errorf("unknown principal type %q", k)
				}
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("Principal must be \"*\" or an object")
}

// normaliseAWSPrincipal turns a bare account id into its root ARN.
func normaliseAWSPrincipal(p string) string {
	if len(p) == 12 && strings.Trim(p, "0123456789") == "" {
		return "arn:aws:iam::" + p + ":root"
	}
	return p
}

// principalMatch classifies how a resource statement's principal entries name the caller: "public"
// ("*"), "account" (the caller's account root ARN), "specific" (the caller's own user, role or session
// ARN, or service), or "" (not named).
func principalMatch(entries []string, p Principal) string {
	acct := p.AccountID()
	self := p.ARN()
	roleARN := ""
	if p.Type == Role {
		q := p
		q.Session = nil
		roleARN = q.ARN()
	}
	best := ""
	for _, e := range entries {
		switch {
		case e == "*":
			if best == "" {
				best = "public"
			}
		case e == "arn:aws:iam::"+acct+":root":
			if best != "specific" {
				best = "account"
			}
		case p.Type == Service && e == p.ID:
			return "specific"
		case e == self || (roleARN != "" && e == roleARN):
			return "specific"
		case strings.Contains(e, "*") && (globMatch(e, self) || (roleARN != "" && globMatch(e, roleARN))):
			return "specific"
		}
	}
	return best
}

// appliesToPrincipal reports how a resource statement applies to the caller ("" = not at all).
func (r ResourceStatement) appliesToPrincipal(p Principal) string {
	if len(r.NotPrincipals) > 0 {
		if principalMatch(r.NotPrincipals, p) != "" {
			return ""
		}
		return "public" // NotPrincipal: everyone else
	}
	return principalMatch(r.Principals, p)
}

// globMatch matches s against an AWS wildcard pattern (* and ?).
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	switch pattern[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if globMatch(pattern[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		return s != "" && globMatch(pattern[1:], s[1:])
	}
	return s != "" && pattern[0] == s[0] && globMatch(pattern[1:], s[1:])
}

func str(v any) string { s, _ := v.(string); return s }

func list(v any) []string {
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
