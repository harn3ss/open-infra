package main

import (
	"context"
	"net/http"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"k8s.io/client-go/kubernetes"
)

// decide is a front door's one authorization decision for an operation: may claims perform action on the
// resource resType::resID (resID "" is an operation that names no single resource, AWS's Resource "*").
//
// Who decides is the mode (IAM_AUTHZ, internal/iamauthz):
//   - legacy: legacy decides — the front door's own pre-IAM check, kept byte for byte (for most, the coarse
//     impersonated SubjectAccessReview and then the data-plane refinement: coarseThenDataPlane);
//   - shadow: legacy's answer is returned, and IAM policy's is computed beside it; a difference is logged
//     ("iam-shadow allow|deny action=… resource=… principal=… legacy=…");
//   - enforce: IAM policy alone, with AWS's evaluation logic — no SubjectAccessReview for a User; a User,
//     an assumed role and the account's root are each exactly what their policies (and the resource's
//     policy, opts) allow.
//
// A principal whose User or Role carries the canary label is in enforce while the platform is in shadow.
// A nil checker has no IAM policy world: legacy decides, whatever the mode.
func decide(ctx context.Context, r *http.Request, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string, legacy func() (bool, string), opts ...iamauthz.RequestOption) (bool, string) {
	d := decision(ctx, r, authz, claims, action, resType, resID, legacy, opts...)
	return d.Allowed, d.Reason
}

// decision is decide returning the whole iamauthz.Decision (ExplicitDeny, the mode it was made in). An
// enforce-mode denial's reason is AWS's message: who, which action, which resource, and why.
func decision(ctx context.Context, r *http.Request, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string, legacy func() (bool, string), opts ...iamauthz.RequestOption) iamauthz.Decision {
	p := principalOf(claims)
	res := typedResource(resType, resID)
	var reqCtx map[string]any
	if r != nil {
		reqCtx = requestContext(claims, r)
	} else {
		reqCtx = map[string]any{"authenticated": "true", "username": claims.PrincipalID()}
	}
	d := authz.IAM().Decide(ctx, p, action, res, reqCtx, legacy, opts...)
	if !d.Allowed && d.Mode == iamauthz.ModeEnforce {
		d.Reason = notAuthorized(p, action, res, d.Reason)
	}
	return d
}

// resourcePolicyOpt is the evaluator option carrying a resource's own policy document (a queue's Policy
// attribute, a topic's, a bucket policy …), read with fetch only when IAM policy decides (shadow or
// enforce): legacy never reads it. A missing policy adds nothing; one that does not parse grants nothing
// (its statements are left out, never widened).
func resourcePolicyOpt(authz *dataplaneauthz.Checker, fetch func() string) []iamauthz.RequestOption {
	if fetch == nil || authz.IAM().Mode() == iamauthz.ModeLegacy {
		return nil
	}
	doc := fetch()
	if doc == "" {
		return nil
	}
	stmts, _, err := iamauthz.ParseResourcePolicy(doc)
	if err != nil || len(stmts) == 0 {
		return nil
	}
	return []iamauthz.RequestOption{iamauthz.WithResourcePolicy(stmts)}
}

// principalOf is the principal claims are evaluated as, in the caller's account.
func principalOf(claims iam.Claims) iamauthz.Principal {
	return iamauthz.PrincipalFromClaims(claims, claims.Account)
}

// typedResource is the evaluator's resource for resType::resID: "<Type>::*" for an operation that names no
// single resource (AWS evaluates those on Resource "*"; a grant scoped to one resource does not reach it),
// "*" when the operation has no resource type at all.
func typedResource(resType, resID string) string {
	switch {
	case resType == "":
		return "*"
	case resID == "":
		return resType + "::*"
	}
	return resType + "::" + resID
}

// notAuthorized is AWS's access-denied message: "User: <arn> is not authorized to perform: <action> on
// resource: <resource>", with the evaluator's reason.
func notAuthorized(p iamauthz.Principal, action, resource, reason string) string {
	kind := "User"
	switch p.Type {
	case iamauthz.Role:
		kind = "Role"
	case iamauthz.Root:
		kind = "Root"
	}
	msg := kind + ": " + p.ARN() + " is not authorized to perform: " + action + " on resource: " + resource
	if reason != "" {
		msg += " (" + reason + ")"
	}
	return msg
}

// coarseThenDataPlane is the legacy decision most front doors made before IAM policy decided: the coarse
// impersonated SubjectAccessReview (iam.CanDo verb on group/resource ns/name), then the data-plane
// refinement (dataPlaneDenied action on resType::resID), answering with whichever denied first.
func coarseThenDataPlane(ctx context.Context, r *http.Request, cs kubernetes.Interface, authz *dataplaneauthz.Checker,
	claims iam.Claims, verb, group, resource, ns, name, action, resType, resID string) func() (bool, string) {
	return func() (bool, string) {
		if ok, why := iam.CanDo(ctx, cs, claims, verb, group, resource, ns, name); !ok {
			return false, why
		}
		if denied, why := dataPlaneDenied(ctx, authz, claims, action, resType, resID, r); denied {
			return false, why
		}
		return true, ""
	}
}

// coarseThenScopedDataPlane is coarseThenDataPlane with the per-resource refinement (deniedByDataPlane),
// for a front door whose operations always name their resource.
func coarseThenScopedDataPlane(ctx context.Context, r *http.Request, cs kubernetes.Interface, authz *dataplaneauthz.Checker,
	claims iam.Claims, verb, group, resource, ns, name, action, resType, resID string) func() (bool, string) {
	return func() (bool, string) {
		if ok, why := iam.CanDo(ctx, cs, claims, verb, group, resource, ns, name); !ok {
			return false, why
		}
		return scopedDataPlaneOnly(ctx, r, authz, claims, action, resType, resID)()
	}
}

// scopedDataPlaneThenCoarse is the legacy decision of a target check that ran the per-resource
// refinement first and then the coarse SubjectAccessReview (a Lambda integration target: lambda:Invoke
// on the function, then RBAC create on the kind: Function).
func scopedDataPlaneThenCoarse(ctx context.Context, r *http.Request, cs kubernetes.Interface, authz *dataplaneauthz.Checker,
	claims iam.Claims, action, resType, resID, verb, group, resource, ns, name string) func() (bool, string) {
	return func() (bool, string) {
		if ok, why := scopedDataPlaneOnly(ctx, r, authz, claims, action, resType, resID)(); !ok {
			return false, why
		}
		return iam.CanDo(ctx, cs, claims, verb, group, resource, ns, name)
	}
}

// enforcing reports whether IAM policy alone decides for the caller (its mode is enforce).
func enforcing(ctx context.Context, authz *dataplaneauthz.Checker, claims iam.Claims) bool {
	return authz.IAM().ModeFor(ctx, principalOf(claims)) == iamauthz.ModeEnforce
}

// coarseOnly is the legacy decision of a check that ran the coarse SubjectAccessReview alone.
func coarseOnly(ctx context.Context, cs kubernetes.Interface, claims iam.Claims, verb, group, resource, ns, name string) func() (bool, string) {
	return func() (bool, string) { return iam.CanDo(ctx, cs, claims, verb, group, resource, ns, name) }
}

// authzCheck is one (action, resource) an operation needs allowed.
type authzCheck struct{ action, resType, resID string }

// decideEach is decide for an operation that needs several checks allowed (DynamoDB's batch and
// transaction operations check every table they touch, a restore its source and its target): legacy runs
// the coarse check once and then each check's data-plane refinement, in order, as before; enforce asks
// IAM policy each check; the first denial answers, with the check it was. checks must not be empty.
func decideEach(ctx context.Context, r *http.Request, authz *dataplaneauthz.Checker, claims iam.Claims,
	coarse func() (bool, string), checks []authzCheck) (bool, string, authzCheck) {
	for i, c := range checks {
		c := c
		legacy := dataPlaneOnly(ctx, r, authz, claims, c.action, c.resType, c.resID)
		if i == 0 {
			legacy = func() (bool, string) {
				if ok, why := coarse(); !ok {
					return false, why
				}
				return dataPlaneOnly(ctx, r, authz, claims, c.action, c.resType, c.resID)()
			}
		}
		if ok, why := decide(ctx, r, authz, claims, c.action, c.resType, c.resID, legacy); !ok {
			return false, why, c
		}
	}
	return true, "", authzCheck{}
}

// scopedDataPlaneOnly is the legacy decision of a per-resource refinement (deniedByDataPlane), run where
// the resource is always named: a batch operation's per-name checks, a decrypt on its key.
func scopedDataPlaneOnly(ctx context.Context, r *http.Request, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string) func() (bool, string) {
	return func() (bool, string) {
		if denied, why := deniedByDataPlane(ctx, authz, claims, action, resType, resID, r); denied {
			return false, why
		}
		return true, ""
	}
}

// dataPlaneOnly is the legacy decision of a check that ran the data-plane refinement alone.
func dataPlaneOnly(ctx context.Context, r *http.Request, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string) func() (bool, string) {
	return func() (bool, string) {
		if denied, why := dataPlaneDenied(ctx, authz, claims, action, resType, resID, r); denied {
			return false, why
		}
		return true, ""
	}
}
