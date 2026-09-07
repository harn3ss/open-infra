// Package dataplaneauthz applies fine-grained kind: Policy data-plane statements to aws-shim
// requests, using the Cedar-backed policyengine. It is ADDITIVE to the shim's coarse RBAC
// (SubjectAccessReview): a data-plane policy can only refine within a grant the coarse check already
// allowed — the caller AND's this verdict with RBAC — so it can tighten (Deny), never loosen. When
// no data-plane policy names a principal, the coarse decision stands unchanged. It fails closed: a
// load or compile error denies.
package dataplaneauthz

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/policyengine"
)

// PolicyDoc is one kind: Policy's data-plane block — its name, statements, and the principals its
// own appliesTo axis directly governs. Name is how a principal's spec.policies references it (the
// managed-attachment axis); AppliesTo is the inline/direct axis a Policy uses to name its own
// principals. Both feed the SAME Cedar set — one policy world, no second evaluator.
type PolicyDoc struct {
	Name       string // the kind: Policy name — how spec.policies attaches it to a principal
	Statements []policyengine.Statement
	AppliesTo  []string // "User::alice", "Group::eng", "Role::deployer", or "*"
}

// Snapshot is one atomic read of the data-plane policy world: every kind: Policy's dataPlane block
// (Docs), plus the managed-attachment index (Attach) mapping a principal to the Policy names attached
// to it via its spec.policies. Loading both together keeps the two attachment axes consistent within
// one TTL window — a principal's attached Policies confer their dataPlane authority (so a Role's
// attached Policies govern an assumed session), exactly as the inline appliesTo axis does.
type Snapshot struct {
	Docs []PolicyDoc
	// Attach maps a principal key — "Role::<name>", "User::<name>", or "Group::<name>" — to the
	// Policy names on that principal's spec.policies. Group members inherit a Group's attached
	// Policies. nil/empty means the managed axis contributes nothing (inline appliesTo still applies).
	Attach map[string][]string
	// Boundary maps a principal key — "Role::<name>" or "User::<name>" — to its spec.permissionBoundary
	// (a kind: Policy name). The boundary Policy's dataPlane Allow statements are the CEILING: the
	// effective permission is the intersection of the principal's identity policies and the boundary,
	// compiled as a Cedar forbid-unless guard. It caps a principal that is already governed for the
	// request's service (a data-plane boundary tightens existing data-plane grants; it does not itself
	// make an otherwise-ungoverned principal governed). Groups carry no boundary. nil/empty ⇒ no ceiling.
	Boundary map[string]string
}

// Loader returns the current data-plane policy world (kind: Policy docs + the managed-attachment
// index), e.g. read from the cluster.
type Loader func(context.Context) (Snapshot, error)

// Checker resolves + evaluates data-plane policies for a principal, caching the loaded snapshot.
type Checker struct {
	load    Loader
	ttl     time.Duration
	mu      sync.Mutex
	cache   Snapshot
	err     error
	fetched time.Time
	seeded  bool
}

// New builds a Checker. A nil loader disables it (Authorize always reports "not governed").
func New(load Loader, ttl time.Duration) *Checker { return &Checker{load: load, ttl: ttl} }

// Authorize returns (allowed, governed, reason). Governance is PER-SERVICE: a principal is governed
// for the request's service (the action prefix, e.g. "s3") only if one of their statements names that
// service (or "*"). governed=false means no data-plane policy covers this service for this principal,
// so the caller's coarse RBAC decision stands unchanged — an S3 policy never affects DynamoDB access.
// governed=true means the principal is in allow-list mode for that service (AWS-style default-deny,
// forbid overriding); `allowed` is the fail-closed verdict, which the caller AND's with coarse RBAC,
// so a data-plane policy can only tighten within the service it governs.
func (c *Checker) Authorize(ctx context.Context, principalType, principalID string, groups []string,
	action, resType, resID string, reqCtx map[string]any) (allowed, governed bool, reason string) {
	if c == nil || c.load == nil {
		return true, false, "data-plane policy disabled"
	}
	snap, err := c.get(ctx)
	if err != nil {
		return false, true, "data-plane policy load failed: " + err.Error() // fail closed
	}
	service := action
	if i := strings.IndexByte(action, ':'); i > 0 {
		service = action[:i]
	}
	// Gather this principal's data-plane statements from BOTH attachment axes, one policy world:
	//   (1) inline/direct — a Policy whose own dataPlane.appliesTo names this principal (or "*");
	//   (2) managed — a Policy named in the principal's (or one of its groups') spec.policies.
	// Both contribute their statements to the same Cedar set. A Policy reached by both paths is
	// contributed once (dedup by name), so an inline+attached policy can't double its statements.
	byName := make(map[string]PolicyDoc, len(snap.Docs))
	for _, d := range snap.Docs {
		if d.Name != "" {
			byName[d.Name] = d
		}
	}
	var stmts []policyengine.Statement
	seen := make(map[string]bool)
	add := func(d PolicyDoc) {
		if d.Name != "" {
			if seen[d.Name] {
				return
			}
			seen[d.Name] = true
		}
		stmts = append(stmts, d.Statements...)
	}
	for _, d := range snap.Docs {
		if appliesTo(d.AppliesTo, principalType, principalID, groups) {
			add(d)
		}
	}
	for _, name := range attachedPolicyNames(snap.Attach, principalType, principalID, groups) {
		if d, ok := byName[name]; ok {
			add(d)
		}
	}
	governs := false
	for _, s := range stmts {
		if coversService(s.Actions, service) {
			governs = true
			break
		}
	}
	if !governs {
		return true, false, "no data-plane policy governs " + service + " for this principal"
	}
	// Permission boundary (§4): if this principal (its User, or the Role it assumed) carries a
	// spec.permissionBoundary, cap the compiled set with the boundary Policy's Allow ceiling — the
	// effective permission is the intersection. A named-but-unresolvable boundary compiles to a
	// deny-all ceiling (nil boundary statements ⇒ forbid everything), so a missing/typo'd boundary
	// fails CLOSED rather than silently lifting the cap.
	eng, err := c.engineFor(stmts, byName, snap.Boundary[principalType+"::"+principalID])
	if err != nil {
		return false, true, "data-plane policy compile error: " + err.Error() // fail closed
	}
	d := eng.Authorize(policyengine.Request{
		Principal: policyengine.Principal{Type: principalType, ID: principalID},
		Action:    action,
		Resource:  policyengine.Resource{Type: resType, ID: resID},
		Context:   reqCtx,
	})
	return d.Allowed, true, d.Reason
}

// engineFor compiles the principal's identity statements, applying a permission boundary when one is
// named. With no boundary it is the plain engine. With a boundary it uses the boundary Policy's
// dataPlane Allow statements as the ceiling (NewEngineWithBoundary): an unresolvable boundary name
// yields nil ceiling statements, which compiles to a deny-all boundary (fail closed).
func (c *Checker) engineFor(stmts []policyengine.Statement, byName map[string]PolicyDoc, boundary string) (*policyengine.Engine, error) {
	if boundary == "" {
		return policyengine.NewEngine(stmts)
	}
	return policyengine.NewEngineWithBoundary(stmts, byName[boundary].Statements)
}

func (c *Checker) get(ctx context.Context) (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seeded && time.Since(c.fetched) < c.ttl {
		return c.cache, c.err
	}
	snap, err := c.load(ctx)
	if err != nil && c.seeded {
		// A refresh blip on an already-warm cache must not deny ALL data-plane traffic — that
		// would turn a transient control-plane hiccup into a shim-wide outage. Serve the last
		// good snapshot and back off a TTL before retrying. (Cold start with no known policies
		// still fails closed, below.) A just-added Deny is thus delayed by at most one extra TTL
		// while the control plane is unreachable — bounded, and the coarse SAR still applies.
		c.fetched = time.Now()
		return c.cache, c.err
	}
	c.cache, c.err, c.fetched, c.seeded = snap, err, time.Now(), true
	return snap, err
}

// attachedPolicyNames returns the Policy names attached to this principal via a managed spec.policies:
// its own ("Role::"/"User::"/"Group::"+id) plus those attached to each Group it belongs to (group
// members inherit a Group's attached Policies). Group keys drop the "openinfra:" impersonation prefix
// on both sides, exactly as appliesTo matches groups.
func attachedPolicyNames(attach map[string][]string, ptype, pid string, groups []string) []string {
	if len(attach) == 0 {
		return nil
	}
	var names []string
	names = append(names, attach[ptype+"::"+pid]...)
	for _, g := range groups {
		names = append(names, attach["Group::"+strings.TrimPrefix(g, "openinfra:")]...)
	}
	return names
}

// coversService reports whether any action names the given service (e.g. "s3") — "s3:..." or "*" —
// so a principal is only governed for services their statements actually mention.
func coversService(actions []string, service string) bool {
	for _, a := range actions {
		if a == "*" || strings.HasPrefix(a, service+":") {
			return true
		}
	}
	return false
}

// appliesTo reports whether a policy's appliesTo list names the principal or one of its groups.
// Group names are compared with the "openinfra:" impersonation prefix stripped on both sides.
func appliesTo(list []string, ptype, pid string, groups []string) bool {
	self := ptype + "::" + pid
	for _, e := range list {
		if e == "*" || e == self {
			return true
		}
		t, name, ok := strings.Cut(e, "::")
		if !ok || t != "Group" {
			continue
		}
		want := strings.TrimPrefix(name, "openinfra:")
		for _, g := range groups {
			if strings.TrimPrefix(g, "openinfra:") == want {
				return true
			}
		}
	}
	return false
}
