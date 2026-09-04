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

// PolicyDoc is one kind: Policy's data-plane block — its statements and the principals they apply to.
type PolicyDoc struct {
	Statements []policyengine.Statement
	AppliesTo  []string // "User::alice", "Group::eng", or "*"
}

// Loader returns the current data-plane policy docs (e.g. a list of kind: Policy from the cluster).
type Loader func(context.Context) ([]PolicyDoc, error)

// Checker resolves + evaluates data-plane policies for a principal, caching the loaded docs.
type Checker struct {
	load    Loader
	ttl     time.Duration
	mu      sync.Mutex
	cache   []PolicyDoc
	err     error
	fetched time.Time
	seeded  bool
}

// New builds a Checker. A nil loader disables it (Authorize always reports "not governed").
func New(load Loader, ttl time.Duration) *Checker { return &Checker{load: load, ttl: ttl} }

// Authorize returns (allowed, governed, reason). governed=false means no data-plane policy names
// this principal, so the caller's coarse RBAC decision stands. governed=true means a policy applies
// and `allowed` is its fail-closed verdict, which the caller must AND with the coarse decision.
func (c *Checker) Authorize(ctx context.Context, principalType, principalID string, groups []string,
	action, resType, resID string, reqCtx map[string]any) (allowed, governed bool, reason string) {
	if c == nil || c.load == nil {
		return true, false, "data-plane policy disabled"
	}
	docs, err := c.get(ctx)
	if err != nil {
		return false, true, "data-plane policy load failed: " + err.Error() // fail closed
	}
	var stmts []policyengine.Statement
	for _, d := range docs {
		if appliesTo(d.AppliesTo, principalType, principalID, groups) {
			stmts = append(stmts, d.Statements...)
		}
	}
	if len(stmts) == 0 {
		return true, false, "no data-plane policy applies to this principal"
	}
	eng, err := policyengine.NewEngine(stmts)
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

func (c *Checker) get(ctx context.Context) ([]PolicyDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seeded && time.Since(c.fetched) < c.ttl {
		return c.cache, c.err
	}
	docs, err := c.load(ctx)
	c.cache, c.err, c.fetched, c.seeded = docs, err, time.Now(), true
	return docs, err
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
