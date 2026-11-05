// Package dataplaneauthz is the legacy data-plane decision of the aws-shim front doors, now a thin
// adapter over internal/iamauthz (the one evaluator): the policy world, its loading and caching, and the
// gathering of a principal's policies all live there, and Checker.IAM() hands a front door the AWS
// evaluator over the SAME cached world.
//
// The legacy decision itself is unchanged: it is ADDITIVE to the shim's coarse RBAC (SubjectAccessReview)
// for a User — a data-plane policy can only refine within a grant the coarse check already allowed, so
// it can tighten (Deny), never loosen, and when no policy governs the request's service for the User the
// coarse decision stands. An assumed Role is closed: its policies alone, default deny. It fails closed: a
// load or compile error denies. Once IAM_AUTHZ=enforce, front doors call iamauthz instead, where a User
// too is exactly its policies (AWS's model).
package dataplaneauthz

import (
	"context"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/policyengine"
)

// PolicyDoc is one kind: Policy as the evaluator sees it (iamauthz.Policy).
type PolicyDoc = iamauthz.Policy

// Snapshot is one atomic read of the IAM policy world (iamauthz.World).
type Snapshot = iamauthz.World

// Loader returns the current policy world (iamauthz.Loader).
type Loader = iamauthz.Loader

// Checker resolves + evaluates data-plane policies for a principal, caching the loaded world.
type Checker struct {
	cache *iamauthz.Cache
	iam   *iamauthz.Evaluator
}

// New builds a Checker. A nil loader disables it (Authorize always reports "not governed").
func New(load Loader, ttl time.Duration) *Checker {
	c := iamauthz.NewCache(load, ttl)
	return &Checker{cache: c, iam: iamauthz.NewWithCache(c)}
}

// IAM is the AWS evaluator over this Checker's policy world (nil for a nil Checker).
func (c *Checker) IAM() *iamauthz.Evaluator {
	if c == nil {
		return nil
	}
	return c.iam
}

// Authorize returns (allowed, governed, reason). Governance is PER-SERVICE: a principal is governed
// for the request's service (the action prefix, e.g. "s3") only if one of their statements names that
// service (or "*"). governed=false means no data-plane policy covers this service for this principal,
// so the caller's coarse RBAC decision stands unchanged — an S3 policy never affects DynamoDB access.
// governed=true means the principal is in allow-list mode for that service (AWS-style default-deny,
// forbid overriding); `allowed` is the fail-closed verdict, which the caller AND's with coarse RBAC,
// so a data-plane policy can only tighten within the service it governs.
func (c *Checker) Authorize(ctx context.Context, principalType, principalID string, groups []string,
	action, resType, resID string, reqCtx map[string]any) (allowed, governed bool, reason string) {
	d := c.Decide(ctx, principalType, principalID, groups, action, resType, resID, reqCtx)
	return d.Allowed, d.Governed, d.Reason
}

// Decision is Authorize's verdict plus ExplicitDeny: a statement's Deny decided it (not default deny, not
// the permission boundary, not a load or compile failure). See policyengine.Decision.
type Decision struct {
	Allowed, Governed, ExplicitDeny bool
	Reason                          string
}

// Decide is Authorize, returning the whole Decision.
func (c *Checker) Decide(ctx context.Context, principalType, principalID string, groups []string,
	action, resType, resID string, reqCtx map[string]any) Decision {
	if c == nil || !c.cache.Enabled() {
		return Decision{Allowed: true, Reason: "data-plane policy disabled"}
	}
	snap, _, err := c.cache.Get(ctx)
	if err != nil {
		return Decision{Governed: true, Reason: "data-plane policy load failed: " + err.Error()} // fail closed
	}
	service := iamauthz.ServiceOf(action)
	// Both attachment axes (a Policy's own appliesTo, and the principal's or its groups' spec.policies),
	// plus inline policies, one policy world; a Policy reached twice contributes once.
	stmts := snap.StatementsFor(principalType, principalID, groups)
	// An assumed IAM Role is an INDEPENDENT principal (AWS model): its authority is EXACTLY its attached
	// policies, evaluated default-deny across every service. A User stays additive over coarse RBAC.
	closed := principalType == "Role"
	governs := false
	for _, s := range stmts {
		if iamauthz.CoversService(s.Actions, service) || iamauthz.NotActionsCoverService(s.NotActions, service) {
			governs = true
			break
		}
	}
	if !governs && !closed {
		return Decision{Allowed: true, Reason: "no data-plane policy governs " + service + " for this principal"}
	}
	// A permission boundary caps the compiled set (an unresolvable one compiles to deny-all, fail closed).
	var eng *policyengine.Engine
	if has, boundary := snap.BoundaryFor(principalType, principalID); has {
		eng, err = policyengine.NewEngineWithBoundary(stmts, boundary)
	} else {
		eng, err = policyengine.NewEngine(stmts)
	}
	if err != nil {
		return Decision{Governed: true, Reason: "data-plane policy compile error: " + err.Error()} // fail closed
	}
	d := eng.Authorize(policyengine.Request{
		Principal: policyengine.Principal{Type: principalType, ID: principalID},
		Action:    action,
		Resource:  policyengine.Resource{Type: resType, ID: resID},
		Context:   reqCtx,
	})
	return Decision{Allowed: d.Allowed, Governed: true, ExplicitDeny: d.ExplicitDeny, Reason: d.Reason}
}

// appliesTo reports whether a policy's appliesTo list names the principal or one of its groups.
func appliesTo(list []string, ptype, pid string, groups []string) bool {
	return iamauthz.AppliesTo(list, ptype, pid, groups)
}
