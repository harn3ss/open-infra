package iamauthz

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/policyengine"
)

// Policy is one IAM policy as the evaluator sees it: its canonical name (how a principal's
// spec.policies attaches it), its compiled statements, and — for a policy that names its own
// principals (kind: Policy spec.dataPlane.appliesTo) — the principals it governs directly.
//
// Statements come from either source a kind: Policy may carry, merged: the AWS JSON document
// (spec.document, compiled by CompileDocument) and the native data-plane statements
// (spec.dataPlane.statements). Report records what compiling the document could not honour
// faithfully: a dropped Allow (narrower) or a Deny applied more broadly (narrower) — never widened.
type Policy struct {
	Name       string
	ARN        string
	Statements []policyengine.Statement
	AppliesTo  []string // "User::alice", "Group::eng", "Role::deployer", "*", or "*@<namespace>"
	Report     []string
}

// World is one atomic read of the IAM policy world.
type World struct {
	// Docs is every Policy with statements.
	Docs []Policy
	// Attach maps a principal key — "Role::<id>", "User::<id>" or "Group::<name>" — to the Policy names
	// on that principal's spec.policies. Group members inherit a Group's attached Policies.
	Attach map[string][]string
	// Boundary maps a principal key — "Role::<id>" or "User::<id>" — to its spec.permissionBoundary (a
	// Policy name). A name that resolves to no Policy compiles to a deny-all ceiling (fail closed).
	Boundary map[string]string
	// Inline maps a principal key ("User::<id>", "Group::<name>", "Role::<id>") to its inline policies
	// (spec.inlinePolicies: AWS's PutUserPolicy / PutGroupPolicy / PutRolePolicy).
	Inline map[string][]Policy
	// Enforce marks the principals (by key) whose object carries the canary label
	// openinfra.dev/iam-authz: enforce: they are evaluated in enforce mode while the platform runs shadow.
	Enforce map[string]bool
}

// Loader returns the current IAM policy world, e.g. read from the cluster.
type Loader func(context.Context) (World, error)

// Cache holds the last World a Loader returned for a TTL. A refresh error on a warm cache serves the last
// good World and backs off a TTL (a control-plane blip must not deny all traffic); a cold cache that
// cannot load fails closed (the error is returned).
type Cache struct {
	load    Loader
	ttl     time.Duration
	mu      sync.Mutex
	cache   World
	err     error
	fetched time.Time
	seeded  bool
	gen     uint64 // incremented whenever a new World is stored, so compiled engines can be reused per World
}

// NewCache builds a Cache over load. A nil load means "no policy world" (Get returns an empty World).
func NewCache(load Loader, ttl time.Duration) *Cache { return &Cache{load: load, ttl: ttl} }

// Enabled reports whether a loader is configured.
func (c *Cache) Enabled() bool { return c != nil && c.load != nil }

// Get returns the current World (and its generation), loading it if the TTL has passed.
func (c *Cache) Get(ctx context.Context) (World, uint64, error) {
	if !c.Enabled() {
		return World{}, 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seeded && time.Since(c.fetched) < c.ttl {
		return c.cache, c.gen, c.err
	}
	w, err := c.load(ctx)
	if err != nil && c.seeded {
		c.fetched = time.Now()
		return c.cache, c.gen, c.err
	}
	c.cache, c.err, c.fetched, c.seeded = w, err, time.Now(), true
	c.gen++
	return w, c.gen, err
}

// PolicyKey is the World key of a principal: "<Type>::<id>".
func PolicyKey(ptype, id string) string { return ptype + "::" + id }

// ByName indexes the World's Docs by name.
func (w World) ByName() map[string]Policy {
	byName := make(map[string]Policy, len(w.Docs))
	for _, d := range w.Docs {
		if d.Name != "" {
			byName[d.Name] = d
		}
	}
	return byName
}

// PoliciesFor returns every policy that applies to a principal — from the inline/direct axis (a Policy
// whose appliesTo names it, one of its groups, or "*"), the managed axis (its own and its groups'
// spec.policies) and its inline policies (its own and its groups') — each once. groups are group names,
// with or without the "openinfra:" impersonation prefix.
func (w World) PoliciesFor(ptype, pid string, groups []string) []Policy {
	byName := w.ByName()
	var out []Policy
	seen := map[string]bool{}
	add := func(p Policy) {
		if p.Name != "" {
			if seen[p.Name] {
				return
			}
			seen[p.Name] = true
		}
		out = append(out, p)
	}
	for _, d := range w.Docs {
		if AppliesTo(d.AppliesTo, ptype, pid, groups) {
			add(d)
		}
	}
	for _, name := range AttachedPolicyNames(w.Attach, ptype, pid, groups) {
		if d, ok := byName[name]; ok {
			add(d)
		}
	}
	keys := []string{PolicyKey(ptype, pid)}
	for _, g := range groups {
		keys = append(keys, PolicyKey("Group", strings.TrimPrefix(g, "openinfra:")))
	}
	for _, k := range keys {
		for i, p := range w.Inline[k] {
			p.Name = "inline:" + k + ":" + inlineName(p, i)
			add(p)
		}
	}
	return out
}

func inlineName(p Policy, i int) string {
	if p.Name != "" {
		return p.Name
	}
	return "#" + strings.Repeat("i", i+1)
}

// StatementsFor is PoliciesFor flattened to statements (the legacy data-plane gathering).
func (w World) StatementsFor(ptype, pid string, groups []string) []policyengine.Statement {
	var stmts []policyengine.Statement
	for _, p := range w.PoliciesFor(ptype, pid, groups) {
		stmts = append(stmts, p.Statements...)
	}
	return stmts
}

// BoundaryFor returns the principal's permission boundary: whether it has one, and the boundary
// Policy's statements (nil when the named Policy does not exist, which compiles to deny-all).
func (w World) BoundaryFor(ptype, pid string) (has bool, stmts []policyengine.Statement) {
	name, ok := w.Boundary[PolicyKey(ptype, pid)]
	if !ok || name == "" {
		return false, nil
	}
	return true, w.ByName()[name].Statements
}

// AttachedPolicyNames returns the Policy names attached to a principal via a managed spec.policies: its
// own plus those attached to each Group it belongs to. Group keys drop the "openinfra:" prefix.
func AttachedPolicyNames(attach map[string][]string, ptype, pid string, groups []string) []string {
	if len(attach) == 0 {
		return nil
	}
	var names []string
	names = append(names, attach[PolicyKey(ptype, pid)]...)
	for _, g := range groups {
		names = append(names, attach[PolicyKey("Group", strings.TrimPrefix(g, "openinfra:"))]...)
	}
	return names
}

// AppliesTo reports whether a policy's appliesTo list names the principal or one of its groups. Group
// names are compared with the "openinfra:" impersonation prefix stripped on both sides.
func AppliesTo(list []string, ptype, pid string, groups []string) bool {
	self := ptype + "::" + pid
	for _, e := range list {
		if e == "*" || e == self {
			return true
		}
		// A namespaced Policy's "*" (CanonAppliesTo): every principal of that namespace, whose canonical
		// ids are "<ns>/<name>" — never a home principal (bare id) or a group.
		if ns, ok := strings.CutPrefix(e, StarInNamespacePrefix); ok {
			if strings.HasPrefix(pid, ns+"/") {
				return true
			}
			continue
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

// CoversService reports whether any action names the given service (e.g. "s3") — "s3:..." or "*".
func CoversService(actions []string, service string) bool {
	for _, a := range actions {
		if a == "*" || strings.HasPrefix(a, service+":") {
			return true
		}
	}
	return false
}

// NotActionsCoverService reports whether a NotAction (complement) set governs the given service: it does
// unless the exclusion wipes out the whole service ("*" or "<service>:*").
func NotActionsCoverService(notActions []string, service string) bool {
	if len(notActions) == 0 {
		return false
	}
	for _, na := range notActions {
		if na == "*" || na == service+":*" {
			return false
		}
	}
	return true
}

// ServiceOf is an action's service prefix ("s3" for "s3:GetObject").
func ServiceOf(action string) string {
	if i := strings.IndexByte(action, ':'); i > 0 {
		return action[:i]
	}
	return action
}
