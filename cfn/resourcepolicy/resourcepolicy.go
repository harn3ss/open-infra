// Package resourcepolicy reads an SQS queue policy or an SNS topic policy, in the part this platform
// honors: grants that let an AWS service deliver to the queue or topic.
//
// On AWS a queue policy is what lets an SNS topic (or an EventBridge rule) send to the queue, and a topic
// policy what lets CloudWatch, EventBridge or another service publish to the topic. Here those deliveries
// are made by the aws-shim itself, so such a grant is honored where the shim delivers: a statement whose
// principal is a service (`{"Service": "sns.amazonaws.com"}`), or every principal (`"*"`) narrowed by a
// source condition (`aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOwner`), decides whether that
// delivery is made.
//
// A grant to a user or role is not honored here: who may call the SQS and SNS APIs is decided by IAM
// (the caller's kind: Policy and RBAC), one policy world. Such a statement, and anything else this
// package cannot honor faithfully (another condition, NotPrincipal/NotAction/NotResource, a Resource that
// is not the queue or topic, a public grant with no condition), is refused: the whole policy, never a
// part of it, so a stack or API call never believes it set access that does nothing or less than it said.
// An Allow to the account root (the "delegate to IAM" statement) is that default here, so it is skipped.
package resourcepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Policy is a parsed queue or topic policy: the statements that decide service deliveries.
type Policy struct {
	Statements []Statement
}

// Statement is one honored statement.
type Statement struct {
	Sid      string
	Allow    bool
	Any      bool     // every principal (narrowed by Conditions)
	Services []string // service principals, lower-case ("sns.amazonaws.com")
	Actions  []string // lower-case action patterns ("sqs:sendmessage", "sqs:*")
	// Conditions all hold for the statement to apply (AND); a condition holds when the request's value
	// matches any of its values (OR).
	Conditions []Condition
}

// Condition is one source condition.
type Condition struct {
	Key    string   // "aws:sourcearn" or "aws:sourceaccount"
	Like   bool     // ArnLike/StringLike: values are patterns (* and ?)
	Values []string // as written
}

// Request is a delivery the shim is about to make: a service principal doing Action on the resource on
// behalf of the source (the topic or rule) in SourceAccount.
type Request struct {
	Service       string // "sns.amazonaws.com", "events.amazonaws.com", "cloudwatch.amazonaws.com"
	Action        string // "sqs:SendMessage", "sns:Publish"
	SourceArn     string
	SourceAccount string
}

// Parse reads doc, the policy of the resource whose ARN is resourceARN (an SQS queue or SNS topic ARN;
// its service decides which actions belong to it). It refuses what cannot be honored (see the package
// comment).
func Parse(doc, resourceARN string) (*Policy, error) {
	svc := arnPart(resourceARN, 2)
	if svc != "sqs" && svc != "sns" {
		return nil, fmt.Errorf("a resource policy here is for an SQS queue or SNS topic, not %q", resourceARN)
	}
	if strings.TrimSpace(doc) == "" {
		return nil, errors.New("the policy document is empty")
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return nil, errors.New("the policy document is not a JSON object")
	}
	stmts, err := statements(d["Statement"])
	if err != nil {
		return nil, err
	}
	p := &Policy{}
	elsewhere := 0 // statements for another queue or topic the policy is attached to
	for i, st := range stmts {
		s, skip, err := parseStatement(st, svc, resourceARN)
		if err != nil {
			label := fmt.Sprintf("statement %d", i)
			if sid, _ := st["Sid"].(string); sid != "" {
				label = fmt.Sprintf("statement %q", sid)
			}
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if !skip {
			p.Statements = append(p.Statements, s)
		} else if applies, _ := checkResource(st["Resource"], resourceARN); !applies {
			elsewhere++
		}
	}
	// A policy every statement of which is for other resources says nothing about this one: refused, as
	// a policy that would grant nothing it seems to.
	if len(p.Statements) == 0 && elsewhere > 0 {
		return nil, fmt.Errorf("no statement of the policy is for this resource (%s): each Resource names another queue or topic", resourceARN)
	}
	return p, nil
}

func statements(raw json.RawMessage) ([]map[string]any, error) {
	t := strings.TrimSpace(string(raw))
	if t == "" || t == "null" {
		return nil, errors.New("the policy has no Statement")
	}
	if t[0] == '{' {
		var one map[string]any
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, errors.New("malformed Statement")
		}
		return []map[string]any{one}, nil
	}
	var many []map[string]any
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, errors.New("malformed Statement")
	}
	if len(many) == 0 {
		return nil, errors.New("the policy has no Statement")
	}
	return many, nil
}

func parseStatement(st map[string]any, svc, resourceARN string) (Statement, bool, error) {
	var s Statement
	s.Sid, _ = st["Sid"].(string)
	for _, k := range []string{"NotPrincipal", "NotAction", "NotResource"} {
		if _, ok := st[k]; ok {
			return s, false, fmt.Errorf("%s is not honored here", k)
		}
	}
	switch st["Effect"] {
	case "Allow":
		s.Allow = true
	case "Deny":
	default:
		return s, false, errors.New(`Effect must be "Allow" or "Deny"`)
	}
	acts, err := actions(st["Action"], svc)
	if err != nil {
		return s, false, err
	}
	s.Actions = acts
	applies, err := checkResource(st["Resource"], resourceARN)
	if err != nil {
		return s, false, err
	}
	conds, err := conditions(st["Condition"])
	if err != nil {
		return s, false, err
	}
	s.Conditions = conds
	everyone, services, accounts, err := principals(st["Principal"])
	if err != nil {
		return s, false, err
	}
	if len(accounts) > 0 {
		if len(services) > 0 || everyone {
			return s, false, errors.New("a statement naming the account root together with other principals is not honored here; split it")
		}
		if !s.Allow {
			return s, false, errors.New("a Deny to an account or IAM principal is decided by IAM here, not by a resource policy; express it as a kind: Policy")
		}
		return s, true, nil // the delegate-to-IAM default: identity-based authorization already decides
	}
	if everyone && len(conds) == 0 {
		return s, false, errors.New(`a grant to every principal ("*") with no aws:SourceArn/aws:SourceAccount condition would make the resource public; it is not honored here — grant callers through IAM`)
	}
	s.Any, s.Services = everyone, services
	return s, !applies, nil // a statement for another resource the policy is attached to does not apply here
}

func strList(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func actions(v any, svc string) ([]string, error) {
	raw, ok := strList(v)
	if !ok || len(raw) == 0 {
		return nil, errors.New("Action must be a string or a list of strings")
	}
	out := make([]string, 0, len(raw))
	for _, a := range raw {
		l := strings.ToLower(strings.TrimSpace(a))
		switch {
		case l == "*":
			out = append(out, svc+":*")
		case strings.HasPrefix(l, svc+":"):
			out = append(out, l)
		default:
			return nil, fmt.Errorf("action %q is not an %s action (an %s resource policy governs only %s)", a, svc, svc, strings.ToUpper(svc))
		}
	}
	return out, nil
}

// checkResource accepts "*", an absent Resource, this resource's ARN (by service and name: the shim
// addresses a queue or topic by its name whatever account or region an ARN names), or a pattern that
// matches its ARN.
//
// One policy may be attached to several queues or topics (an AWS::SQS::QueuePolicy's Queues: [A, B], with
// Resource: [A's ARN, B's ARN]): as on AWS, a statement applies to the resources its Resource matches, so
// an entry naming another queue (or topic) is not refused — and a statement none of whose entries is this
// resource does not apply to it (applies=false). An entry that is not a queue (or topic) ARN at all still
// refuses the policy.
func checkResource(v any, resourceARN string) (applies bool, err error) {
	if v == nil {
		return true, nil
	}
	res, ok := strList(v)
	if !ok {
		return false, errors.New("Resource must be a string or a list of strings")
	}
	for _, r := range res {
		if r == "*" || SameResource(r, resourceARN) || (strings.ContainsAny(r, "*?") && Glob(r, resourceARN)) {
			applies = true
			continue
		}
		if svc := arnPart(r, 2); svc != "" && svc == arnPart(resourceARN, 2) && arnPart(r, 5) != "" {
			continue // another queue (or topic) of the same service: the statement is for it
		}
		return false, fmt.Errorf("Resource %q is not this resource (%s)", r, resourceARN)
	}
	return applies, nil
}

// SameResource reports whether two ARNs name the same queue or topic: the same service and name.
func SameResource(a, b string) bool {
	sa, sb := arnPart(a, 2), arnPart(b, 2)
	return sa != "" && sa == sb && arnPart(a, 5) != "" && arnPart(a, 5) == arnPart(b, 5) && !strings.ContainsAny(a, "*?")
}

// arnPart is the i-th ':'-separated field of an ARN (the last one keeps any later ':'), "" if absent.
func arnPart(arn string, i int) string {
	f := strings.SplitN(arn, ":", 6)
	if len(f) != 6 || f[0] != "arn" || i >= len(f) {
		return ""
	}
	return f[i]
}

func principals(v any) (everyone bool, services, accounts []string, err error) {
	switch t := v.(type) {
	case nil:
		return false, nil, nil, errors.New("a statement needs a Principal")
	case string:
		if t == "*" {
			return true, nil, nil, nil
		}
		return false, nil, nil, fmt.Errorf("Principal %q is not honored here", t)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vals, ok := strList(t[k])
			if !ok || len(vals) == 0 {
				return false, nil, nil, fmt.Errorf("Principal %s must be a string or a list of strings", k)
			}
			switch k {
			case "Service":
				for _, s := range vals {
					services = append(services, strings.ToLower(strings.TrimSpace(s)))
				}
			case "AWS":
				for _, a := range vals {
					switch {
					case a == "*":
						everyone = true
					case isAccount(a):
						accounts = append(accounts, a)
					default:
						return false, nil, nil, fmt.Errorf("principal %q: a grant to a user or role is decided by IAM here, not by a resource policy; give that identity a kind: Policy", a)
					}
				}
			default:
				return false, nil, nil, fmt.Errorf("a %s principal is not honored here", k)
			}
		}
		return everyone, services, accounts, nil
	}
	return false, nil, nil, errors.New("Principal must be \"*\" or an object")
}

// isAccount reports whether a principal is an account: its 12-digit id or its root ARN.
func isAccount(p string) bool {
	if strings.HasPrefix(p, "arn:") {
		return arnPart(p, 2) == "iam" && arnPart(p, 5) == "root"
	}
	if len(p) != 12 {
		return false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func conditions(v any) ([]Condition, error) {
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("Condition must be an object")
	}
	ops := make([]string, 0, len(m))
	for op := range m {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	var out []Condition
	for _, op := range ops {
		keys, ok := m[op].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("condition %s must map keys to values", op)
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			key := strings.ToLower(k)
			if key == "aws:sourceowner" {
				key = "aws:sourceaccount" // SNS's older name for the same thing
			}
			var like bool
			switch {
			case key == "aws:sourcearn" && (op == "ArnEquals" || op == "StringEquals"):
			case key == "aws:sourcearn" && (op == "ArnLike" || op == "StringLike"):
				like = true
			case key == "aws:sourceaccount" && op == "StringEquals":
			case key == "aws:sourceaccount" && op == "StringLike":
				like = true
			default:
				return nil, fmt.Errorf("condition %s on %s is not honored here (aws:SourceArn with ArnEquals/ArnLike/StringEquals/StringLike, and aws:SourceAccount/aws:SourceOwner with StringEquals/StringLike, are)", op, k)
			}
			vals, ok := strList(keys[k])
			if !ok || len(vals) == 0 {
				return nil, fmt.Errorf("condition %s %s must be a string or a list of strings", op, k)
			}
			out = append(out, Condition{Key: key, Like: like, Values: vals})
		}
	}
	return out, nil
}

// Allows reports whether the policy lets req happen: a matching Deny refuses it, else a matching Allow
// grants it, else it is refused.
func (p *Policy) Allows(req Request) bool {
	allowed := false
	for _, s := range p.Statements {
		if !s.matches(req) {
			continue
		}
		if !s.Allow {
			return false
		}
		allowed = true
	}
	return allowed
}

func (s Statement) matches(req Request) bool {
	if !s.Any {
		svc := strings.ToLower(req.Service)
		found := false
		for _, x := range s.Services {
			if x == svc {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	act := strings.ToLower(req.Action)
	found := false
	for _, a := range s.Actions {
		if Glob(a, act) {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	for _, c := range s.Conditions {
		if !c.holds(req) {
			return false
		}
	}
	return true
}

func (c Condition) holds(req Request) bool {
	have := req.SourceAccount
	if c.Key == "aws:sourcearn" {
		have = req.SourceArn
	}
	if have == "" {
		return false
	}
	for _, v := range c.Values {
		switch {
		case c.Like && Glob(v, have):
			return true
		case !c.Like && c.Key == "aws:sourcearn" && (v == have || SameResource(v, have)):
			return true
		case !c.Like && c.Key == "aws:sourceaccount" && v == have:
			return true
		}
	}
	return false
}

// Glob matches s against an IAM pattern: * any run of characters (including ':' and '/'), ? one.
func Glob(pattern, s string) bool {
	p, x := 0, 0
	star, mark := -1, 0
	for x < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[x]):
			p++
			x++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, x
			p++
		case star >= 0:
			p = star + 1
			mark++
			x = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
