package main

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// deniedByDataPlane runs the fine-grained data-plane policy check AFTER the coarse SubjectAccessReview
// has already allowed the request. It returns true only when a kind: Policy governs this principal
// and denies the (action, resource) — so it can only TIGHTEN a coarse grant, never widen it. It
// fails closed (a load/compile error denies), and a nil checker is a no-op.
func deniedByDataPlane(ctx context.Context, authz *dataplaneauthz.Checker, claims iam.Claims,
	action, resType, resID string, r *http.Request) (bool, string) {
	allowed, governed, reason := authz.Authorize(ctx, "User", claims.Sub, claims.Groups,
		action, resType, resID, requestContext(r))
	if governed && !allowed {
		return true, reason
	}
	return false, ""
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

// requestContext is the Cedar condition context: the request is past SigV4 auth, plus the source IP.
func requestContext(r *http.Request) map[string]any {
	c := map[string]any{"authenticated": true}
	if r != nil {
		if ip := clientIP(r); ip != "" {
			c["sourceIp"] = ip
		}
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
