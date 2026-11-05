// Package iamauthz is open-infra's one authorization evaluator: every front door (the aws-shim, the
// console, the IAM→RBAC compiler) asks it the same question — may this principal perform this AWS action
// on this resource — and gets AWS's answer, computed with AWS's evaluation logic over IAM policy:
//
//  1. An explicit Deny in any applicable policy wins: identity policies (the user's and its groups', or
//     the role's), the resource's policy, the permission boundary, the session policy, a service
//     control policy.
//  2. A service control policy (the optional SCP hook) must allow.
//  3. Within the principal's own account, an identity policy OR the resource policy (naming the caller,
//     or "*") must allow. Across accounts, an identity policy AND the resource policy (naming the caller
//     or its account) must both allow.
//  4. A permission boundary, when the principal has one, must also allow (it intersects).
//  5. A session policy, when the session has one, must also allow (it intersects).
//  6. Otherwise: denied (default deny). A principal with no policy can do nothing.
//
// The account's root user is allowed everything in its own account (an explicit Deny in the resource's
// policy still applies); across accounts it needs the resource policy, like anyone else.
//
// Rollout is controlled by a mode (IAM_AUTHZ): legacy (the old decision, untouched), shadow (both are
// computed, a difference is logged as "iam-shadow …", the old decision is returned) and enforce (this
// package decides). A principal whose User or Role object carries the label openinfra.dev/iam-authz:
// enforce is evaluated in enforce mode while the platform runs shadow: the per-principal canary.
package iamauthz

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/policyengine"
)

// Mode is how far IAM policy decides.
type Mode string

const (
	// ModeLegacy returns the legacy decision; IAM policy is not evaluated.
	ModeLegacy Mode = "legacy"
	// ModeShadow evaluates IAM policy, logs where it differs from the legacy decision, and returns the
	// legacy decision.
	ModeShadow Mode = "shadow"
	// ModeEnforce returns the IAM policy decision.
	ModeEnforce Mode = "enforce"
)

// EnvMode is the environment variable that sets the platform mode.
const EnvMode = "IAM_AUTHZ"

// CanaryLabel on a kind: User or kind: Role, with value CanaryEnforce, puts that principal in enforce
// mode while the platform runs shadow.
const (
	CanaryLabel   = "openinfra.dev/iam-authz"
	CanaryEnforce = "enforce"
)

// ParseMode reads a mode; anything unrecognised is legacy (the safe default: nothing changes).
func ParseMode(s string) Mode {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeShadow:
		return ModeShadow
	case ModeEnforce:
		return ModeEnforce
	}
	return ModeLegacy
}

// ModeFromEnv is the mode IAM_AUTHZ sets (legacy when unset).
func ModeFromEnv() Mode { return ParseMode(os.Getenv(EnvMode)) }

// Decision is the evaluator's answer.
type Decision struct {
	Allowed bool
	// ExplicitDeny reports that a Deny statement decided it (not default deny, not a boundary or session
	// policy that does not reach the action).
	ExplicitDeny bool
	Reason       string
	// MatchedPolicy names the policy that decided: the one that allowed, or the one whose Deny denied.
	MatchedPolicy string
	// Mode is the mode the decision was returned in.
	Mode Mode
}

// SCPFunc is a service control policy hook: whether the principal's organization allows the action at
// all. explicit marks a Deny statement (as opposed to an SCP that simply does not allow it).
type SCPFunc func(ctx context.Context, p Principal, action, resource string) (allowed, explicit bool, reason string)

// Evaluator answers authorization questions over a cached IAM policy world.
type Evaluator struct {
	cache  *Cache
	mode   Mode
	logger *slog.Logger
	scp    SCPFunc

	mu      sync.Mutex
	gen     uint64
	engines map[string]*policyengine.Engine
}

// Option configures an Evaluator.
type Option func(*Evaluator)

// WithMode sets the platform mode (default: ModeFromEnv).
func WithMode(m Mode) Option { return func(e *Evaluator) { e.mode = m } }

// WithLogger sets where shadow differences are logged (default: slog.Default).
func WithLogger(l *slog.Logger) Option { return func(e *Evaluator) { e.logger = l } }

// WithSCP installs a service control policy hook.
func WithSCP(f SCPFunc) Option { return func(e *Evaluator) { e.scp = f } }

// New builds an Evaluator over a loader, caching its World for ttl.
func New(load Loader, ttl time.Duration, opts ...Option) *Evaluator {
	return NewWithCache(NewCache(load, ttl), opts...)
}

// NewWithCache builds an Evaluator sharing an existing Cache (so the legacy data-plane checker and the
// evaluator read one policy world).
func NewWithCache(c *Cache, opts ...Option) *Evaluator {
	e := &Evaluator{cache: c, mode: ModeFromEnv(), logger: slog.Default(), engines: map[string]*policyengine.Engine{}}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Mode is the platform mode.
func (e *Evaluator) Mode() Mode {
	if e == nil {
		return ModeLegacy
	}
	return e.mode
}

// ModeFor is the mode a principal is evaluated in: the platform mode, except that a canary-labelled User
// or Role is in enforce while the platform is in shadow. Legacy is a full rollback: no label overrides it.
func (e *Evaluator) ModeFor(ctx context.Context, p Principal) Mode {
	m := e.Mode()
	if m != ModeShadow {
		return m
	}
	if p.Type != User && p.Type != Role {
		return m
	}
	w, _, err := e.cache.Get(ctx)
	if err == nil && w.Enforce[p.Key()] {
		return ModeEnforce
	}
	return m
}

// Decide is the decision a front door acts on, for the principal's mode: legacy runs only legacy; shadow
// runs both, logs a difference, and returns legacy's; enforce returns IAM policy's. legacy may be nil
// when a front door has no legacy decision (then legacy and shadow deny, failing closed).
func (e *Evaluator) Decide(ctx context.Context, p Principal, action, resource string, reqCtx map[string]any,
	legacy func() (bool, string), opts ...RequestOption) Decision {
	runLegacy := func(m Mode) Decision {
		if legacy == nil {
			return Decision{Reason: "no legacy decision for this action", Mode: m}
		}
		ok, why := legacy()
		return Decision{Allowed: ok, Reason: why, Mode: m}
	}
	m := e.ModeFor(ctx, p)
	switch m {
	case ModeEnforce:
		d := e.Authorize(ctx, p, action, resource, reqCtx, opts...)
		d.Mode = ModeEnforce
		return d
	case ModeShadow:
		old := runLegacy(ModeShadow)
		d := e.Authorize(ctx, p, action, resource, reqCtx, opts...)
		if d.Allowed != old.Allowed {
			e.logger.Info("iam-shadow "+verdict(d.Allowed), "action", action, "resource", resource,
				"principal", p.ARN(), "legacy", verdict(old.Allowed), "reason", d.Reason, "policy", d.MatchedPolicy)
		}
		return old
	}
	return runLegacy(ModeLegacy)
}

func verdict(ok bool) string {
	if ok {
		return "allow"
	}
	return "deny"
}

// RequestOption adds to one authorization question.
type RequestOption func(*request)

type request struct {
	account  string
	resource []ResourceStatement
}

// WithResourceAccount names the account the resource belongs to (default: the account its ARN names,
// else the principal's own).
func WithResourceAccount(acct string) RequestOption { return func(r *request) { r.account = acct } }

// WithResourcePolicy supplies the resource's own policy (a bucket, queue, topic, key, function or
// repository policy).
func WithResourcePolicy(stmts []ResourceStatement) RequestOption {
	return func(r *request) { r.resource = stmts }
}

// Authorize evaluates one request with AWS's evaluation logic, whatever the mode. resource is an ARN
// ("arn:aws:s3:::assets/report.csv") or the platform's typed resource ("Bucket::assets/report.csv");
// "*" or "" is an action on no particular resource. reqCtx is the condition context (authenticated,
// sourceIp, username, currentTime). It fails closed: a policy world that cannot be loaded, or a policy
// that cannot be compiled, denies.
func (e *Evaluator) Authorize(ctx context.Context, p Principal, action, resource string, reqCtx map[string]any,
	opts ...RequestOption) Decision {
	if e == nil || !e.cache.Enabled() {
		if p.Type == Root {
			return Decision{Allowed: true, Reason: "the account's root user", MatchedPolicy: "root"}
		}
		return Decision{Reason: "no IAM policy world (default deny)"}
	}
	var ro request
	for _, o := range opts {
		o(&ro)
	}
	w, gen, err := e.cache.Get(ctx)
	if err != nil {
		return Decision{Reason: "IAM policy load failed: " + err.Error()}
	}
	typed, arnAcct := mapResource(resource)
	resAcct := ro.account
	if resAcct == "" {
		resAcct = arnAcct
	}
	if resAcct == "" {
		resAcct = p.AccountID()
	}
	rctx := make(map[string]any, len(reqCtx)+2)
	for k, v := range reqCtx {
		rctx[k] = v
	}
	rctx[resourceAccountKey] = resAcct
	rctx[principalAccountKey] = p.AccountID()
	rt, rid := splitTyped(typed)
	req := policyengine.Request{
		Principal: policyengine.Principal{Type: string(p.Type), ID: p.ID},
		Action:    action,
		Resource:  policyengine.Resource{Type: rt, ID: rid},
		Context:   rctx,
	}
	same := resAcct == p.AccountID()

	// The resource's policy, as it applies to this caller.
	var rpDeny, rpPublic, rpAccount, rpSpecific bool
	var rpMatched string
	for i, rs := range ro.resource {
		how := rs.appliesToPrincipal(p)
		if how == "" {
			continue
		}
		eng, err := policyengine.NewEngine([]policyengine.Statement{rs.Statement})
		if err != nil {
			return Decision{Reason: fmt.Sprintf("resource policy statement %d does not compile: %v", i, err)}
		}
		d := eng.Authorize(req)
		switch {
		case d.ExplicitDeny:
			rpDeny = true
		case d.Allowed:
			switch how {
			case "specific":
				rpSpecific = true
			case "account":
				rpAccount = true
			default:
				rpPublic = true
			}
			rpMatched = "resource-policy"
		}
	}
	if rpDeny {
		return Decision{ExplicitDeny: true, Reason: "denied by an explicit Deny in the resource's policy", MatchedPolicy: "resource-policy"}
	}

	// A service control policy bounds every principal of a member account, its root included (the hook
	// decides which accounts it governs; AWS exempts the management account).
	if e.scp != nil {
		ok, explicit, why := e.scp(ctx, p, action, typed)
		if !ok {
			if why == "" {
				why = "not allowed by the organization's service control policy"
			}
			return Decision{ExplicitDeny: explicit, Reason: why, MatchedPolicy: "scp"}
		}
	}

	if p.Type == Root {
		if same {
			return Decision{Allowed: true, Reason: "the account's root user", MatchedPolicy: "root"}
		}
		if rpSpecific || rpAccount || rpPublic {
			return Decision{Allowed: true, Reason: "allowed across accounts by the resource's policy", MatchedPolicy: rpMatched}
		}
		return Decision{Reason: "a resource in another account needs its resource policy to allow this (default deny)"}
	}

	// Identity policies.
	var idAllow bool
	var idMatched string
	if p.Type == User || p.Type == Role {
		groups := p.Groups
		if p.Type == Role {
			groups = nil
		}
		for _, pol := range w.PoliciesFor(string(p.Type), p.ID, groups) {
			eng, err := e.engine(gen, pol)
			if err != nil {
				return Decision{Reason: "policy " + pol.Name + " does not compile: " + err.Error()}
			}
			d := eng.Authorize(req)
			if d.ExplicitDeny {
				return Decision{ExplicitDeny: true, Reason: "denied by an explicit Deny in policy " + pol.Name, MatchedPolicy: pol.Name}
			}
			if d.Allowed && !idAllow {
				idAllow, idMatched = true, pol.Name
			}
		}
	}

	// The permission boundary's own Deny statements, and the session policy's, are explicit denies too.
	hasBoundary, boundary := false, []policyengine.Statement(nil)
	if p.Type == User || p.Type == Role {
		hasBoundary, boundary = w.BoundaryFor(string(p.Type), p.ID)
	}
	var session []policyengine.Statement
	if p.Session != nil {
		session = p.Session.Policies
	}
	for _, set := range []struct {
		name  string
		stmts []policyengine.Statement
	}{{"the permission boundary", boundary}, {"the session policy", session}} {
		if denied, err := explicitDeny(set.stmts, req); err != nil {
			return Decision{Reason: set.name + " does not compile: " + err.Error()}
		} else if denied {
			return Decision{ExplicitDeny: true, Reason: "denied by an explicit Deny in " + set.name, MatchedPolicy: set.name}
		}
	}

	var allowed bool
	matched := idMatched
	if same {
		allowed = idAllow || rpSpecific || rpPublic
		if !idAllow {
			matched = rpMatched
		}
	} else {
		allowed = idAllow && (rpSpecific || rpAccount || rpPublic)
	}
	if !allowed {
		if !same && idAllow {
			return Decision{Reason: "a resource in another account needs its resource policy to allow this too (default deny)"}
		}
		return Decision{Reason: "no policy allows this action (default deny)"}
	}
	if hasBoundary {
		ok, err := within(boundary, req)
		if err != nil {
			return Decision{Reason: "the permission boundary does not compile: " + err.Error()}
		}
		if !ok {
			return Decision{Reason: "denied by the permission boundary (the action is outside it)", MatchedPolicy: "boundary"}
		}
	}
	if len(session) > 0 {
		ok, err := within(session, req)
		if err != nil {
			return Decision{Reason: "the session policy does not compile: " + err.Error()}
		}
		if !ok {
			return Decision{Reason: "denied by the session policy (the action is outside it)", MatchedPolicy: "session-policy"}
		}
	}
	return Decision{Allowed: true, Reason: "allowed by policy " + matched, MatchedPolicy: matched}
}

// engine is a policy's compiled engine, reused for the World generation it was compiled in.
func (e *Evaluator) engine(gen uint64, pol Policy) (*policyengine.Engine, error) {
	if pol.Name == "" {
		return policyengine.NewEngine(pol.Statements)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gen != gen {
		e.gen, e.engines = gen, map[string]*policyengine.Engine{}
	}
	if eng, ok := e.engines[pol.Name]; ok {
		return eng, nil
	}
	eng, err := policyengine.NewEngine(pol.Statements)
	if err != nil {
		return nil, err
	}
	e.engines[pol.Name] = eng
	return eng, nil
}

// allowAll is a statement that allows everything: the identity side of a ceiling check.
var allowAll = policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"*"}, Resources: []string{"*"}}

// within reports whether a request is inside a ceiling's Allow statements (a permission boundary or a
// session policy). A ceiling with no Allow statement allows nothing.
func within(ceiling []policyengine.Statement, req policyengine.Request) (bool, error) {
	eng, err := policyengine.NewEngineWithBoundary([]policyengine.Statement{allowAll}, ceiling)
	if err != nil {
		return false, err
	}
	return eng.Authorize(req).Allowed, nil
}

// explicitDeny reports whether a set's Deny statements deny the request.
func explicitDeny(stmts []policyengine.Statement, req policyengine.Request) (bool, error) {
	var denies []policyengine.Statement
	for _, s := range stmts {
		if s.Effect == policyengine.Deny {
			denies = append(denies, s)
		}
	}
	if len(denies) == 0 {
		return false, nil
	}
	eng, err := policyengine.NewEngine(append([]policyengine.Statement{allowAll}, denies...))
	if err != nil {
		return false, err
	}
	return eng.Authorize(req).ExplicitDeny, nil
}

// splitTyped splits a typed resource "Type::id" (or "ARN::<arn>"); "*" is an action on no resource.
func splitTyped(typed string) (string, string) {
	if typed == "*" || typed == "" {
		return "Any", "*"
	}
	if t, id, ok := strings.Cut(typed, "::"); ok {
		return t, id
	}
	return "Any", typed
}
