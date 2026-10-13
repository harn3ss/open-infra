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
//
// NotActions/NotResources are the COMPLEMENT axes (AWS NotAction/NotResource): "any action/resource
// EXCEPT these". They are mutually exclusive with their positive sibling — a statement sets Actions OR
// NotActions, never both (toCedar errors on both, fail closed). A NotX set compiles to a negated match
// (`!(context.X == … || …)`) in the SAME always-present scope term the positive match uses, so it never
// introduces the absent-key fail-open the value conditions guard against. A NotX set reduced to "exclude
// everything" (a lone "*") compiles to `false` — the statement then matches nothing, the faithful meaning
// of "all except all".
type Statement struct {
	Effect         Effect
	Actions        []string          // e.g. ["s3:GetObject","s3:*"] or ["*"]
	NotActions     []string          // complement of Actions (AWS NotAction): "any action except these"
	Resources      []string          // "Type::id" e.g. ["Bucket::assets","Bucket::*"], or ["*"]
	NotResources   []string          // complement of Resources (AWS NotResource): "any resource except these"
	Condition      map[string]string // request-context keys that must equal these values ("true"/"false" => bool)
	IPConditions   []IPCondition     // aws:SourceIp-style CIDR conditions, evaluated via Cedar's ipaddr extension
	LikeConditions []LikeCondition   // StringLike/StringNotLike wildcard conditions, evaluated via Cedar's `like`
	TimeConditions []TimeCondition   // aws:CurrentTime Date* conditions, evaluated via Cedar's datetime extension
}

// IPCondition is a CIDR test on a request-context attribute that holds an IP (today only "sourceIp",
// populated by the aws-shim's requestContext()). It renders to Cedar's ipaddr extension —
// context.<Key> is in (Negate=false) or not in (Negate=true, the AWS NotIpAddress operator) the CIDR.
// Key MUST be an attribute the shim actually populates (see SupportedConditionKeys); a condition on an
// unpopulated key is a fail-open hole for a Deny (the forbid silently never fires), which the import
// whitelist + the engine's absent/malformed-key handling below prevent.
type IPCondition struct {
	Key    string // request-context attribute, e.g. "sourceIp"
	CIDR   string // e.g. "10.0.0.0/8" (a bare address is treated as /32 by Cedar's ip())
	Negate bool   // true => NotIpAddress (source must NOT be in the range)
}

// LikeCondition is a wildcard test on a string request-context attribute (today "username"), from an
// AWS StringLike/StringNotLike condition. It renders to Cedar's `context.<Key> like "<Pattern>"`
// (Negate=true => the AWS StringNotLike, so the test is `!(... like ...)`). The pattern uses `*` as the
// only wildcard (AWS `?` is refused at import since Cedar can't express it). Like IPConditions, the Key
// MUST be a shim-populated attribute, and the forbid absent-key guard in toCedar keeps a Deny gated on
// it fail-closed when the attribute is absent.
type LikeCondition struct {
	Key     string // request-context attribute, e.g. "username"
	Pattern string // Cedar `like` pattern, `*` wildcard (e.g. "admin-*")
	Negate  bool   // true => StringNotLike (must NOT match)
}

// TimeCondition is a datetime comparison on a time-valued request-context attribute (today
// "currentTime"), from an AWS Date* condition operator. It renders to Cedar's datetime extension:
// datetime(context.<Key>) <Op> datetime("<Target>"), where Op is one of < <= > >= (DateLessThan,
// DateLessThanEquals, DateGreaterThan, DateGreaterThanEquals). Target is a Cedar-parseable datetime
// string (validated at import, so it can't error at eval). The attribute carries an RFC3339 string the
// shim populates; like IPConditions it is sanitized to "absent" if unparseable, so the forbid absent-key
// guard keeps a Deny gated on it fail-closed.
type TimeCondition struct {
	Key    string // request-context attribute, e.g. "currentTime"
	Op     string // "<", "<=", ">", ">="
	Target string // Cedar datetime literal argument, e.g. "2025-01-01T00:00:00Z"
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

// Engine holds a compiled Cedar policy set plus the set of context attributes any IP condition reads
// (ipKeys), which Authorize sanitises so a malformed IP cannot make a Deny fail open.
type Engine struct {
	ps       *cedar.PolicySet
	ipKeys   map[string]bool
	timeKeys map[string]bool
}

// NewEngine compiles open-infra statements into a Cedar policy set.
func NewEngine(statements []Statement) (*Engine, error) {
	return newEngine(statements, "")
}

// NewEngineWithBoundary compiles the identity statements together with a permission-boundary guard:
// the boundary Policy's Allow statements form a ceiling, rendered as ONE Cedar `forbid ... unless {…}`
// so the effective permission is the INTERSECTION of the identity policies and the boundary. Cedar's
// forbid-overrides-allow precedence makes the ceiling exact and fail-closed — nothing the boundary
// does not carve out can be allowed, no matter what an identity Allow says. A boundary that allows
// nothing forbids everything; a boundary that allows "*" on "*" imposes no ceiling.
func NewEngineWithBoundary(statements, boundary []Statement) (*Engine, error) {
	guard, err := compileBoundary(boundary)
	if err != nil {
		return nil, err
	}
	return newEngine(statements, guard)
}

func newEngine(statements []Statement, extra string) (*Engine, error) {
	var b strings.Builder
	ipKeys := map[string]bool{}
	timeKeys := map[string]bool{}
	for i, s := range statements {
		clause, err := s.toCedar(i)
		if err != nil {
			return nil, err
		}
		b.WriteString(clause)
		b.WriteString("\n")
		for _, ip := range s.IPConditions {
			ipKeys[ip.Key] = true
		}
		for _, tc := range s.TimeConditions {
			timeKeys[tc.Key] = true
		}
	}
	if extra != "" {
		b.WriteString(extra)
		b.WriteString("\n")
	}
	ps, err := cedar.NewPolicySetFromBytes("openinfra.cedar", []byte(b.String()))
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return &Engine{ps: ps, ipKeys: ipKeys, timeKeys: timeKeys}, nil
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
	// Sanitise IP-typed attributes so a malformed value cannot make a Deny fail OPEN. An IP condition
	// renders to ip(context.<key>).isInRange(...); if context.<key> is absent OR is present but not a
	// parseable IP, ip() ERRORS at eval — and an errored `when` SKIPS a forbid, so a Deny gated on it
	// would silently never fire. toCedar already guards a forbid to also fire when the key is ABSENT;
	// here we collapse "present but unparseable" into "absent" by deleting it, so the same guard denies.
	// (A permit with such a term errors and is skipped, falling through to default-deny — already
	// closed.) types.ParseIPAddr is the exact parser Cedar's ip() uses, so a value kept here cannot
	// then error inside Cedar.
	for k := range e.ipKeys {
		key := types.String(k)
		v, ok := ctx[key]
		if !ok {
			continue
		}
		s, isStr := v.(types.String)
		if !isStr {
			delete(ctx, key)
			continue
		}
		if _, err := types.ParseIPAddr(string(s)); err != nil {
			delete(ctx, key)
		}
	}
	// Sanitise datetime-typed attributes the same way: a time condition renders to
	// datetime(context.<key>) <op> datetime(...); if context.<key> is present but not a parseable Cedar
	// datetime, datetime() ERRORS at eval → an errored `when` skips a forbid → fail OPEN. Collapse
	// "present but unparseable" into "absent" so the forbid absent-key guard denies. types.ParseDatetime
	// is the exact parser Cedar's datetime() uses, so a value kept here cannot then error inside Cedar.
	for k := range e.timeKeys {
		key := types.String(k)
		v, ok := ctx[key]
		if !ok {
			continue
		}
		s, isStr := v.(types.String)
		if !isStr {
			delete(ctx, key)
			continue
		}
		if _, err := types.ParseDatetime(string(s)); err != nil {
			delete(ctx, key)
		}
	}
	// The reserved keys are set LAST so a caller's context can never clobber the action/resource
	// the statements match against (a control-plane request, for instance, carries its own
	// "resource" attribute — that must not shadow the typed resource being authorized).
	ctx["action"] = types.String(r.Action)
	ctx["resource"] = types.String(r.Resource.Type + "::" + r.Resource.ID)
	req := cedar.Request{
		Principal: types.NewEntityUID(entityType(r.Principal.Type), types.String(r.Principal.ID)),
		Action:    types.NewEntityUID("Action", "perform"),
		Resource:  types.NewEntityUID(entityType(r.Resource.Type), types.String(r.Resource.ID)),
		Context:   types.NewRecord(ctx),
	}
	d, diag := e.ps.IsAuthorized(types.EntityMap{}, req)
	if d == cedar.Allow {
		return Decision{Allowed: true, Reason: "allowed by policy"}
	}
	// Distinguish the two denials — they are different security events an audit log must not
	// conflate. A non-empty diagnostic reason set means an explicit `forbid` (a Deny overriding an
	// allow) determined the decision; an empty set means nothing permitted the action at all.
	if len(diag.Reasons) > 0 {
		return Decision{Allowed: false, Reason: "denied by an explicit forbid policy"}
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
//
// Fail-closed asymmetry between permit and forbid. A permit whose condition reads an ABSENT context
// attribute errors at eval and is SKIPPED — the request falls through to default-deny, so a permit
// fails closed naturally. A forbid is the opposite: an errored `when` skips the forbid, so a Deny
// gated on an absent attribute would silently NEVER fire (fail OPEN) — exactly the hole the AWS
// condition importer's wholesale refusal used to protect. So a forbid's VALUE conditions
// (context-attribute tests, as opposed to the always-present action/resource scope) are guarded: the
// forbid ALSO fires when any attribute it reads is absent, i.e. an unpopulated key DENIES. Malformed
// IP values are collapsed to "absent" in Authorize, so this guard covers them too.
func (s Statement) toCedar(idx int) (string, error) {
	head := "permit"
	forbid := false
	switch s.Effect {
	case Allow:
	case Deny:
		head, forbid = "forbid", true
	default:
		return "", fmt.Errorf("statement %d: effect must be Allow or Deny, got %q", idx, s.Effect)
	}

	// Scope: action + resource (a positive match, or the COMPLEMENT of a NotAction/NotResource set).
	// These read context.action / context.resource, which the engine ALWAYS sets, so they never fail on
	// an absent attribute and never need the forbid guard — including the negated (complement) form.
	var scope []string
	actClause, err := scopeClause("context.action", s.Actions, s.NotActions, idx, "Action", false)
	if err != nil {
		return "", err
	}
	if actClause != "" {
		scope = append(scope, actClause)
	}
	resClause, err := scopeClause("context.resource", s.Resources, s.NotResources, idx, "Resource", true)
	if err != nil {
		return "", err
	}
	if resClause != "" {
		scope = append(scope, resClause)
	}

	// Value conditions: tests on caller-supplied context attributes (authenticated, sourceIp, ...).
	// keys collects every attribute they read, for the forbid absent-key guard.
	var value, keys []string
	for _, k := range sortedKeys(s.Condition) {
		v := s.Condition[k]
		if v == "true" || v == "false" {
			value = append(value, fmt.Sprintf("context.%s == %s", k, v)) // bool
		} else {
			value = append(value, fmt.Sprintf("context.%s == %q", k, v)) // string
		}
		keys = append(keys, k)
	}
	for _, ip := range s.IPConditions {
		if ip.Key == "" || ip.CIDR == "" {
			return "", fmt.Errorf("statement %d: IP condition needs a key and a CIDR", idx)
		}
		test := fmt.Sprintf("ip(context.%s).isInRange(ip(%q))", ip.Key, ip.CIDR)
		if ip.Negate {
			test = "!(" + test + ")"
		}
		value = append(value, test)
		keys = append(keys, ip.Key)
	}
	for _, lk := range s.LikeConditions {
		if lk.Key == "" || lk.Pattern == "" {
			return "", fmt.Errorf("statement %d: like condition needs a key and a pattern", idx)
		}
		test := fmt.Sprintf("context.%s like \"%s\"", lk.Key, cedarPattern(lk.Pattern))
		if lk.Negate {
			test = "!(" + test + ")"
		}
		value = append(value, test)
		keys = append(keys, lk.Key)
	}
	for _, tc := range s.TimeConditions {
		if tc.Key == "" || tc.Op == "" || tc.Target == "" {
			return "", fmt.Errorf("statement %d: time condition needs a key, operator, and target", idx)
		}
		switch tc.Op {
		case "<", "<=", ">", ">=":
		default:
			return "", fmt.Errorf("statement %d: time condition operator %q must be one of < <= > >=", idx, tc.Op)
		}
		value = append(value, fmt.Sprintf("datetime(context.%s) %s datetime(%q)", tc.Key, tc.Op, tc.Target))
		keys = append(keys, tc.Key)
	}

	terms := scope
	if len(value) > 0 {
		joined := strings.Join(value, " && ")
		if forbid {
			has := make([]string, 0, len(keys))
			for _, k := range dedupe(keys) {
				has = append(has, "context has "+k)
			}
			// Fire the forbid when any read attribute is absent (fail closed) OR the conditions match.
			terms = append(terms, "(!("+strings.Join(has, " && ")+") || ("+joined+"))")
		} else {
			terms = append(terms, joined)
		}
	}

	clause := head + " (\n  principal,\n  action,\n  resource\n)"
	if len(terms) > 0 {
		clause += "\nwhen { " + strings.Join(terms, " && ") + " }"
	}
	return clause + ";", nil
}

// compileBoundary renders a permission boundary — the Allow statements of a boundary Policy — as one
// Cedar forbid clause: forbid every request UNLESS it matches one of the boundary's allowed
// (action, resource) shapes. forbid-overrides then makes the effective permission the exact
// intersection of the identity policies and this ceiling. A boundary that allows nothing forbids
// everything (fail closed); an Allow with wildcard action AND resource imposes no ceiling (no clause).
// Boundary CONDITIONS are intentionally not part of the ceiling: a boundary is an action/resource
// ceiling, and folding a condition into the `unless` could make the forbid evaporate on an absent key
// (fail open). Non-Allow statements do not widen a ceiling, so they are ignored here.
func compileBoundary(boundary []Statement) (string, error) {
	var permits []string
	for i, s := range boundary {
		if s.Effect != Allow {
			continue
		}
		// A boundary Allow with a NotAction/NotResource is a complement ceiling ("everything except …").
		// Route it through scopeClause too, so such a boundary narrows rather than being misread as a
		// wildcard "no ceiling" (which would fail OPEN — the identity policies would stand unbounded).
		actClause, err := scopeClause("context.action", s.Actions, s.NotActions, i, "Action", false)
		if err != nil {
			return "", fmt.Errorf("boundary %w", err)
		}
		resClause, err := scopeClause("context.resource", s.Resources, s.NotResources, i, "Resource", true)
		if err != nil {
			return "", fmt.Errorf("boundary %w", err)
		}
		var match []string
		if actClause != "" {
			match = append(match, actClause)
		}
		if resClause != "" {
			match = append(match, resClause)
		}
		if len(match) == 0 {
			return "", nil // allows everything → no ceiling
		}
		permits = append(permits, "("+strings.Join(match, " && ")+")")
	}
	head := "forbid (\n  principal,\n  action,\n  resource\n)"
	if len(permits) == 0 {
		return head + ";", nil // allows nothing → forbid everything (fail closed)
	}
	return head + "\nunless { " + strings.Join(permits, " || ") + " };", nil
}

// cedarPattern escapes a string for use inside a Cedar `like` pattern literal: `\` and `"` are escaped
// so they can't break out of the literal, while `*` is left intact as Cedar's wildcard (matching the
// AWS StringLike `*`). AWS `?` is refused at import, so it never reaches here.
func cedarPattern(p string) string {
	p = strings.ReplaceAll(p, `\`, `\\`)
	p = strings.ReplaceAll(p, `"`, `\"`)
	return p
}

func dedupe(xs []string) []string {
	seen := make(map[string]bool, len(xs))
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// scopeClause renders the action/resource axis of a statement: the positive set via matchAny (empty or
// a lone "*" => "any", no constraint), OR — when a NotX (complement) set is given — the negation of that
// set (AWS NotAction/NotResource: "any X except these"). The positive and complement sets are mutually
// exclusive (an AWS statement carries Action or NotAction, never both); both present is a malformed
// statement and errors (fail closed). `typed` requires each resource entry to be Type::id / a wildcard /
// "*". `axis` ("Action"/"Resource") names the field in errors.
func scopeClause(field string, positive, negative []string, idx int, axis string, typed bool) (string, error) {
	if len(positive) > 0 && len(negative) > 0 {
		return "", fmt.Errorf("statement %d: a statement cannot set both %s and Not%s (AWS allows only one)", idx, axis, axis)
	}
	if typed {
		for _, r := range append(append([]string{}, positive...), negative...) {
			if r != "*" && r != "" && !strings.Contains(r, "::") {
				return "", fmt.Errorf("statement %d: %s %q must be Type::id (e.g. Bucket::assets), a wildcard like Bucket::*, or *", idx, strings.ToLower(axis), r)
			}
		}
	}
	if len(negative) > 0 {
		return complementClause(field, negative), nil
	}
	return matchAny(field, positive), nil
}

// complementClause renders the Cedar match for a NotAction/NotResource set: the negation of matchAny over
// the excluded values ("match anything that is NOT one of these"). An exclude set that is itself a
// wildcard ("exclude everything") renders to the constant `false`, so the statement matches nothing — the
// faithful meaning of "all except all" (an Allow then grants nothing, a Deny denies nothing). Because the
// term only reads context.<field> (always set by the engine) it never errors at eval, so it is safe in a
// forbid without the absent-key guard.
func complementClause(field string, exclude []string) string {
	if wildcard(exclude) {
		return "false"
	}
	return "!(" + matchAny(field, exclude) + ")"
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
