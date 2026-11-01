package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// deniedByDataPlane runs the fine-grained data-plane policy check AFTER the coarse SubjectAccessReview
// has already allowed the request. For a User it returns true only when a kind: Policy governs the
// principal and denies the (action, resource) — so it can only TIGHTEN a coarse grant, never widen it;
// it fails closed (a load/compile error denies), and a nil checker is a no-op. For an assumed role it is
// the closed check (allowedForAssumedRole): the role's policies are its whole authority, so anything they
// do not allow is denied — including when no data-plane engine is configured.
func deniedByDataPlane(ctx context.Context, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string, r *http.Request) (bool, string) {
	if claims.AssumedRole != "" {
		ok, reason := allowedForAssumedRole(ctx, authz, claims, action, resType, resID, r)
		return !ok, reason
	}
	allowed, governed, reason := authz.Authorize(ctx, claims.PrincipalType(), claims.PrincipalID(), claims.Groups,
		action, resType, resID, requestContext(claims, r))
	if governed && !allowed {
		return true, reason
	}
	return false, ""
}

// anyResource is the resource id an assumed role's data-plane check uses for an operation that names no
// single resource — a List/Describe-all, or a create whose resource has no name yet (CreateKey). It is
// AWS's Resource "*": a policy resource "*" or <Type>::* matches it; a grant scoped to one resource
// (<Type>::<name>) does not, so such an action needs a grant on "*" exactly as on AWS.
const anyResource = "*"

// scopeFor is the resource id the fine-grained check runs on: the named resource, or — for an assumed role
// only — anyResource when the op names none. A User's empty scope stays empty (unchanged behavior).
func scopeFor(claims iam.Claims, resID string) string {
	if resID == "" && claims.AssumedRole != "" {
		return anyResource
	}
	return resID
}

// dataPlaneDenied is the fine-grained check for a front door whose operations may name no resource. A User
// keeps the additive model exactly: checked where the op names a resource, not at all where it names none.
// An assumed role is ALWAYS checked, closed — an op that names no resource is checked on <resType>::*, so
// a role with no policy can list nothing and create nothing (AWS evaluates those actions on Resource "*").
func dataPlaneDenied(ctx context.Context, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string, r *http.Request) (bool, string) {
	resID = scopeFor(claims, resID)
	if resID == "" {
		return false, ""
	}
	return deniedByDataPlane(ctx, authz, claims, action, resType, resID, r)
}

// allowedForAssumedRole is the CLOSED (default-deny) data-plane check for an sts:AssumeRole session. An
// assumed kind: Role's complete authority is its data-plane policies (iam.CanDo deliberately passes a role,
// because k8s RBAC is not its authority), so the action is permitted only when the engine governs the role
// AND allows the action on the resource. A nil checker (data-plane engine not configured) reports
// "ungoverned", which DENIES here — fail closed, exactly as the S3 assumed-role path.
func allowedForAssumedRole(ctx context.Context, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string, r *http.Request) (bool, string) {
	allowed, governed, reason := authz.Authorize(ctx, "Role", claims.PrincipalID(), claims.Groups,
		action, resType, resID, requestContext(claims, r))
	if governed && allowed {
		return true, ""
	}
	if !governed || reason == "" {
		reason = "assumed role has no data-plane policy allowing " + action + " (default deny)"
	}
	return false, reason
}

// s3Action maps a decoded S3 op to its AWS action name (the 1:1 the mapping relies on).
func s3Action(kind string) string {
	switch kind {
	case "get", "head":
		return "s3:GetObject"
	case "put":
		return "s3:PutObject"
	case "delete":
		return "s3:DeleteObject"
	case "list-objects", "head-bucket":
		return "s3:ListBucket"
	case "list-buckets":
		return "s3:ListAllMyBuckets"
	}
	return "s3:" + kind
}

// requestContext is the Cedar condition context: the request is past SigV4 auth (authenticated), the
// source IP, the calling principal's name (username — the data-plane principal id: a User's name or an
// assumed Role's name), and the wall-clock time the request is evaluated (currentTime, for aws:CurrentTime
// Date* conditions). Each attribute here MUST stay in lockstep with policyengine's SupportedConditionKeys
// (the TestSupportedConditionKeysMatchRequestContext drift guard): supporting a condition key the shim
// never populates would make a Deny gated on it silently never fire. currentTime is ALWAYS populated —
// the datetime attr must never be absent, or a time-window Deny would fail open via the forbid guard.
func requestContext(claims iam.Claims, r *http.Request) map[string]any {
	c := map[string]any{
		"authenticated": true,
		// RFC3339 UTC with a trailing Z — the form cedar-go's datetime() parses (the import path validates
		// targets with the same parser, so both sides of every comparison are Cedar-parseable).
		"currentTime": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if r != nil {
		if ip := clientIP(r); ip != "" {
			c["sourceIp"] = ip
		}
	}
	if p := claims.PrincipalID(); p != "" {
		c["username"] = p
	}
	return c
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
