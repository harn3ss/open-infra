// Package controlplaneauthz evaluates Kubernetes SubjectAccessReview requests against the Cedar
// policy engine, using kind: Policy spec.controlPlane statements. It is the core of the
// authorization-webhook spike (see docs/authz-webhook.md): the SAME evaluator as the data plane,
// over a control-plane vocabulary (a k8s verb -> Cedar action, resource.group -> resource type,
// namespace/name -> resource id). Governance here is REPLACEMENT semantics — default-deny
// allow-list, Cedar as the sole authority — not the data plane's additive, per-service tightening.
// The Checker only computes the decision; the webhook handler decides how to answer the API server
// (shadow: log and defer; enforce: return the decision).
package controlplaneauthz

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/policyengine"
	authzv1 "k8s.io/api/authorization/v1"
)

// PolicyDoc is one kind: Policy's control-plane block.
type PolicyDoc struct {
	Statements []policyengine.Statement
	AppliesTo  []string // "User::alice", "Group::eng", "ServiceAccount::ns/name", or "*"
}

// Loader returns the current control-plane policy docs.
type Loader func(context.Context) ([]PolicyDoc, error)

// Checker resolves + evaluates control-plane policies for a SubjectAccessReview, caching the corpus.
type Checker struct {
	load    Loader
	ttl     time.Duration
	mu      sync.Mutex
	cache   []PolicyDoc
	err     error
	fetched time.Time
	seeded  bool
}

// New builds a Checker. A nil loader disables it (Evaluate denies with a clear reason).
func New(load Loader, ttl time.Duration) *Checker { return &Checker{load: load, ttl: ttl} }

// Evaluate returns the Cedar decision for a SubjectAccessReview under default-deny allow-list
// semantics: a principal with no matching statement is denied. It fails closed on a load/compile
// error. It does not decide chain placement — the webhook wraps this per mode.
func (c *Checker) Evaluate(ctx context.Context, spec authzv1.SubjectAccessReviewSpec) policyengine.Decision {
	if c == nil || c.load == nil {
		return policyengine.Decision{Allowed: false, Reason: "control-plane authz disabled"}
	}
	docs, err := c.get(ctx)
	if err != nil {
		return policyengine.Decision{Allowed: false, Reason: "control-plane policy load failed: " + err.Error()}
	}
	var stmts []policyengine.Statement
	for _, d := range docs {
		if principalMatches(d.AppliesTo, spec) {
			stmts = append(stmts, d.Statements...)
		}
	}
	if len(stmts) == 0 {
		return policyengine.Decision{Allowed: false, Reason: "no control-plane policy grants this principal (default deny)"}
	}
	eng, err := policyengine.NewEngine(stmts)
	if err != nil {
		return policyengine.Decision{Allowed: false, Reason: "control-plane policy compile error: " + err.Error()}
	}
	return eng.Authorize(toRequest(spec))
}

// toRequest maps a SubjectAccessReview onto a policyengine.Request: the k8s verb is the action, the
// resource is "<resource>.<group>" (id "<namespace>/<name>"), and a non-resource URL is its path.
func toRequest(spec authzv1.SubjectAccessReviewSpec) policyengine.Request {
	principal := policyengine.Principal{Type: "User", ID: spec.User}
	if ra := spec.ResourceAttributes; ra != nil {
		rtype := ra.Resource
		if ra.Group != "" {
			rtype = ra.Resource + "." + ra.Group
		}
		id := ra.Name
		if ra.Namespace != "" {
			id = ra.Namespace + "/" + ra.Name
		}
		// Named to NOT collide with the engine's reserved "action"/"resource" context keys — these
		// are here only for future control-plane conditions (e.g. deny in the kube-system namespace).
		ctx := map[string]any{
			"namespace": ra.Namespace, "subresource": ra.Subresource,
			"apiGroup": ra.Group, "apiResource": ra.Resource,
		}
		return policyengine.Request{Principal: principal, Action: ra.Verb,
			Resource: policyengine.Resource{Type: rtype, ID: id}, Context: ctx}
	}
	if nra := spec.NonResourceAttributes; nra != nil {
		return policyengine.Request{Principal: principal, Action: nra.Verb,
			Resource: policyengine.Resource{Type: "NonResourceURL", ID: nra.Path}, Context: map[string]any{}}
	}
	return policyengine.Request{Principal: principal, Context: map[string]any{}}
}

// principalMatches reports whether a policy's appliesTo names the SAR's user, one of its groups, or
// (for a ServiceAccount principal) the "system:serviceaccount:<ns>:<name>" user the API server sends.
func principalMatches(list []string, spec authzv1.SubjectAccessReviewSpec) bool {
	for _, e := range list {
		if e == "*" {
			return true
		}
		t, val, ok := strings.Cut(e, "::")
		if !ok {
			continue
		}
		switch t {
		case "User":
			if val == spec.User {
				return true
			}
		case "ServiceAccount":
			if ns, name, ok := strings.Cut(val, "/"); ok && spec.User == "system:serviceaccount:"+ns+":"+name {
				return true
			}
		case "Group":
			want := strings.TrimPrefix(val, "openinfra:")
			for _, g := range spec.Groups {
				if strings.TrimPrefix(g, "openinfra:") == want {
					return true
				}
			}
		}
	}
	return false
}

// get caches the corpus and serves the last-good snapshot through a refresh blip (a control-plane
// read stall degrades to stale policy, never to deny-everything) — the same hardening the
// data-plane loader has. Cold start with no corpus fails closed.
func (c *Checker) get(ctx context.Context) ([]PolicyDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seeded && time.Since(c.fetched) < c.ttl {
		return c.cache, c.err
	}
	docs, err := c.load(ctx)
	if err != nil && c.seeded {
		c.fetched = time.Now()
		return c.cache, c.err
	}
	c.cache, c.err, c.fetched, c.seeded = docs, err, time.Now(), true
	return docs, err
}
