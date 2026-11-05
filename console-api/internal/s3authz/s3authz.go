// Package s3authz is the one object-storage authorization every front door onto MinIO uses: the
// aws-shim's S3 API and the console's bucket browser. Both reduce a request to an AWS action on a bucket,
// or on an object in it, and ask the same three questions in the same order, so a caller can do no more
// through one door than through the other:
//
//  1. The platform-bucket fence. Buckets the platform owns (backups, the audit trail, database
//     snapshots, the registry's blobs, the query warehouse) are reachable by admins only, whatever a
//     data-plane policy grants: a grant on "*" or Bucket::* never reaches them.
//  2. For a User, the coarse impersonated SubjectAccessReview (iam.CanDo) — read, write or delete on the
//     product resource that owns object storage — and then the data-plane policies (kind: Policy
//     dataPlane), which can only tighten it. For an assumed role, its data-plane policies alone,
//     default deny.
//  3. The resource the action acts on, as AWS evaluates it: a bucket action (ListBucket,
//     GetBucketVersioning …) on Bucket::<bucket>, an object action (GetObject, PutObject, DeleteObject,
//     tagging, multipart) on Bucket::<bucket>/<key>. A whole-bucket policy entry covers the bucket's
//     objects (policyengine's withBucketObjects), so existing grants keep their meaning, while an
//     object-prefix entry (Bucket::<bucket>/uploads/*, imported from arn:aws:s3:::<bucket>/uploads/*)
//     grants only the keys under it.
package s3authz

import (
	"context"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"k8s.io/client-go/kubernetes"
)

// PlatformBuckets are owned by the platform: no claim may take one, the S3 API never deletes one, and
// only an admin reaches one. Keep in step with PLATFORM_BUCKETS in platform/abstraction/provider-setup.yaml
// (TestPlatformBucketsMatchOwnership).
var PlatformBuckets = []string{"velero", "lakehouse", "query-data", "query-results", "db-snapshots", "openinfra-audit", "ecr-registry", "longhorn"}

// IsPlatformBucket reports whether bucket is one of PlatformBuckets.
func IsPlatformBucket(bucket string) bool { return slices.Contains(PlatformBuckets, bucket) }

// adminGroup is the impersonation group of the platform's administrators (iam.RoleGroups, a kind: User
// with spec.groups [admins]).
const adminGroup = "openinfra:admins"

// IsAdmin reports whether the caller is a platform administrator. An assumed role never is: its authority
// is its data-plane policies, and those never reach a platform bucket.
func IsAdmin(c iam.Claims) bool {
	if c.AssumedRole != "" {
		return false
	}
	_, groups, ok := iam.Identity(c)
	return ok && slices.Contains(groups, adminGroup)
}

// Request is one object-storage authorization question.
type Request struct {
	Action string // AWS's action name: s3:GetObject, s3:ListBucket …
	// Verb is the coarse RBAC verb the action needs: "get" to read, "create" to write, "delete" to delete.
	Verb   string
	Bucket string // "" for an action on no bucket (ListBuckets)
	// Key is the object an object action acts on. Object marks the action as an object action, checked on
	// Bucket::<bucket>/<key>; a bucket action is checked on Bucket::<bucket>.
	Key    string
	Object bool
}

// ResourceID is the data-plane resource id the request is checked on: <bucket>/<key> for an object
// action, <bucket> for a bucket action.
func (q Request) ResourceID() string {
	if q.Object && q.Bucket != "" {
		return q.Bucket + "/" + q.Key
	}
	return q.Bucket
}

// Gate is the authorization both front doors run.
type Gate struct {
	CS    kubernetes.Interface    // for the impersonated SubjectAccessReview (iam.CanDo)
	Authz *dataplaneauthz.Checker // the data-plane policy engine; nil = none (Users unaffected, roles denied)
	// NS is the namespace the coarse object-storage RBAC gate is evaluated in.
	NS string
}

// Allow answers whether the caller may make the request. reqCtx is the Cedar condition context
// (RequestContext). A denial carries its reason, for the caller's log.
func (g Gate) Allow(ctx context.Context, c iam.Claims, q Request, reqCtx map[string]any) (bool, string) {
	return g.allow(ctx, c, q, reqCtx, func(verb string) (bool, string) {
		return iam.CanDo(ctx, g.CS, c, verb, "openinfra.dev", "applications", g.NS, "")
	})
}

// Batch is Allow for many requests by one caller in one call (DeleteObjects names up to 1000 keys): each
// request gets the whole check on its own resource, while the coarse SubjectAccessReview, which depends
// only on the verb, is made once per verb.
type Batch struct {
	g      Gate
	coarse map[string]verdict
}

type verdict struct {
	ok     bool
	reason string
}

// Batch starts a batch of checks.
func (g Gate) Batch() *Batch { return &Batch{g: g, coarse: map[string]verdict{}} }

// Allow is Gate.Allow, sharing the batch's coarse reviews.
func (b *Batch) Allow(ctx context.Context, c iam.Claims, q Request, reqCtx map[string]any) (bool, string) {
	return b.g.allow(ctx, c, q, reqCtx, func(verb string) (bool, string) {
		v, seen := b.coarse[verb]
		if !seen {
			v.ok, v.reason = iam.CanDo(ctx, b.g.CS, c, verb, "openinfra.dev", "applications", b.g.NS, "")
			b.coarse[verb] = v
		}
		return v.ok, v.reason
	})
}

func (g Gate) allow(ctx context.Context, c iam.Claims, q Request, reqCtx map[string]any,
	coarse func(verb string) (bool, string)) (bool, string) {
	if IsPlatformBucket(q.Bucket) && !IsAdmin(c) {
		return false, "bucket " + q.Bucket + " is owned by the platform: only an administrator can reach it"
	}
	ev := g.Authz.IAM()
	if ev.Mode() == iamauthz.ModeLegacy {
		return g.legacy(ctx, c, q, reqCtx, coarse)
	}
	// Shadow or enforce (iamauthz.Evaluator.Decide): the request is evaluated as AWS evaluates it — the
	// caller's policies alone, default deny — on the resource it acts on.
	res := "Bucket::" + q.ResourceID()
	if q.Bucket == "" {
		res = "Bucket::*"
	}
	d := ev.Decide(ctx, iamauthz.PrincipalFromClaims(c, ""), q.Action, res, reqCtx, func() (bool, string) {
		return g.legacy(ctx, c, q, reqCtx, coarse)
	})
	return d.Allowed, d.Reason
}

// legacy is the decision before IAM policy became the one authorization plane: for an assumed role its
// data-plane policies alone; for a User the coarse SubjectAccessReview, tightened by its data-plane
// policies where one governs S3.
func (g Gate) legacy(ctx context.Context, c iam.Claims, q Request, reqCtx map[string]any,
	coarse func(verb string) (bool, string)) (bool, string) {
	res := q.ResourceID()
	if c.PrincipalType() == "Role" {
		// An assumed role's authority is exactly its data-plane policies, default deny (an ungoverned role is
		// denied). An action on no bucket is checked on Bucket::* (AWS's Resource "*").
		if res == "" {
			res = "*"
		}
		allowed, governed, reason := g.Authz.Authorize(ctx, "Role", c.PrincipalID(), c.Groups, q.Action, "Bucket", res, reqCtx)
		if !governed || !allowed {
			if reason == "" {
				reason = "assumed role has no data-plane policy allowing this action (default deny)"
			}
			return false, reason
		}
		return true, ""
	}
	if allowed, reason := coarse(q.Verb); !allowed {
		return false, reason
	}
	// The data-plane policies can only tighten a User's coarse grant: denied only when one governs S3 for
	// the User and does not allow this action on this resource.
	allowed, governed, reason := g.Authz.Authorize(ctx, c.PrincipalType(), c.PrincipalID(), c.Groups, q.Action, "Bucket", res, reqCtx)
	if governed && !allowed {
		return false, reason
	}
	return true, ""
}

// RequestContext is the Cedar condition context for a request: past authentication, the source IP, the
// calling principal's name (username) and the time it is evaluated (currentTime, for aws:CurrentTime
// conditions). The aws-shim's requestContext is this, so every front door feeds the engine the same
// attributes; each MUST stay in lockstep with policyengine's SupportedConditionKeys (the aws-shim's
// TestSupportedConditionKeysMatchRequestContext drift guard). currentTime is always set: an absent
// datetime would make a time-window Deny fail open.
func RequestContext(principalID string, r *http.Request) map[string]any {
	c := map[string]any{
		"authenticated": true,
		// RFC3339 UTC with a trailing Z, the form cedar-go's datetime() parses.
		"currentTime": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if r != nil {
		if ip := ClientIP(r); ip != "" {
			c["sourceIp"] = ip
		}
	}
	if principalID != "" {
		c["username"] = principalID
	}
	return c
}

// ClientIP is the request's source address: the first X-Forwarded-For hop, else the peer address.
func ClientIP(r *http.Request) string {
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
