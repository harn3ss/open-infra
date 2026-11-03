package main

import (
	"context"
	"net/http"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
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
// keeps the additive model: checked where the op names a resource, and where it names none only for an
// explicit Deny of the action on every resource (<resType>::*).
// An assumed role is ALWAYS checked, closed — an op that names no resource is checked on <resType>::*, so
// a role with no policy can list nothing and create nothing (AWS evaluates those actions on Resource "*").
func dataPlaneDenied(ctx context.Context, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string, r *http.Request) (bool, string) {
	denied, _, reason := dataPlaneVerdict(ctx, authz, claims, action, resType, resID, r)
	return denied, reason
}

// dataPlaneVerdict is dataPlaneDenied plus whether the denial is an explicit Deny — a statement's Deny, as
// opposed to default deny, the permission boundary, or no engine. A front door that weighs one request
// against an alternative resource (SES: an address identity or its domain identity) needs the difference:
// an explicit Deny on either must win, while a missing grant on one is made up by the other.
func dataPlaneVerdict(ctx context.Context, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string, r *http.Request) (denied, explicit bool, reason string) {
	resID = scopeFor(claims, resID)
	if resID == "" {
		// A User's op that names no resource (a List/Describe-all) is checked on <resType>::*, AWS's
		// Resource "*", for an explicit Deny only: a Deny of the action on every resource holds, while a
		// governed User keeps the additive model (a missing grant on "*" denies nothing it did not before).
		d := authz.Decide(ctx, claims.PrincipalType(), claims.PrincipalID(), claims.Groups,
			action, resType, anyResource, requestContext(claims, r))
		if d.Governed && !d.Allowed && d.ExplicitDeny {
			return true, true, d.Reason
		}
		return false, false, ""
	}
	d := authz.Decide(ctx, claims.PrincipalType(), claims.PrincipalID(), claims.Groups,
		action, resType, resID, requestContext(claims, r))
	if claims.AssumedRole != "" {
		// Closed, as allowedForAssumedRole.
		if d.Governed && d.Allowed {
			return false, false, ""
		}
		reason = d.Reason
		if !d.Governed || reason == "" {
			reason = "assumed role has no data-plane policy allowing " + action + " (default deny)"
		}
		return true, d.Governed && d.ExplicitDeny, reason
	}
	// A User: additive over the coarse grant, as deniedByDataPlane.
	if d.Governed && !d.Allowed {
		return true, d.ExplicitDeny, d.Reason
	}
	return false, false, ""
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
// Date* conditions). It is s3authz.RequestContext, which the console's bucket browser uses too, so both
// feed the engine the same attributes. Each attribute MUST stay in lockstep with policyengine's
// SupportedConditionKeys (the TestSupportedConditionKeysMatchRequestContext drift guard): supporting a
// condition key the shim never populates would make a Deny gated on it silently never fire.
func requestContext(claims iam.Claims, r *http.Request) map[string]any {
	return s3authz.RequestContext(claims.PrincipalID(), r)
}

func clientIP(r *http.Request) string { return s3authz.ClientIP(r) }
