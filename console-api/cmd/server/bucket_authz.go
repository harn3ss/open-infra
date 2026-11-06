package main

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/k8s"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// bucketAuthz authorizes the console's bucket browser as the signed-in user, with the aws-shim's own
// object-storage check (s3authz.Gate). The browser acts to MinIO with the console's ServiceAccount
// identity, which can reach every bucket, so without this a signed-in user could create, delete or read
// any bucket — including the platform's backups, snapshots and audit trail. With it, the console and the
// S3 API are one policy world: the same platform-bucket fence, the same coarse review, the same
// data-plane policies on the same resources (an object action on Bucket::<bucket>/<key>), and no second
// checker to drift from the first.
type bucketAuthz struct {
	gate   s3authz.Gate
	auth   *authStore
	logger *slog.Logger
}

// newBucketAuthz builds the console's gate. The data-plane policies are read from the cluster (the
// console's ServiceAccount already lists the IAM objects); if the dynamic client cannot be built the
// checker is nil, which leaves Users to the coarse review — as the aws-shim does without an engine.
func newBucketAuthz(client *k8s.Client, auth *authStore, logger *slog.Logger) *bucketAuthz {
	return newBucketAuthzWith(*client.Clientset, auth, newPolicyChecker(client, logger), logger)
}

// newBucketAuthzWith builds the gate over an existing policy checker, so the bucket browser and the
// console's route gate (iam_authz.go) read one cached policy world.
func newBucketAuthzWith(cs kubernetes.Interface, auth *authStore, checker *dataplaneauthz.Checker, logger *slog.Logger) *bucketAuthz {
	return &bucketAuthz{
		gate:   s3authz.Gate{CS: cs, Authz: checker, NS: getenv("AUTHZ_NAMESPACE", "default")},
		auth:   auth,
		logger: logger,
	}
}

// newPolicyChecker reads the IAM policy world (Policies, Users, Groups, Roles) from the cluster with the
// console's ServiceAccount, which already lists the IAM objects. When the dynamic client cannot be built
// the checker is nil: no IAM evaluator, so every decision stays legacy (the SubjectAccessReviews), as the
// aws-shim does without an engine.
func newPolicyChecker(client *k8s.Client, logger *slog.Logger) *dataplaneauthz.Checker {
	dyn, err := dynamic.NewForConfig(client.Config)
	if err != nil {
		logger.Warn("IAM policies not evaluated (no dynamic client); legacy authorization only", slog.String("error", err.Error()))
		return nil
	}
	home := getenv("USERS_NAMESPACE", dataplaneauthz.DefaultHomeNamespace)
	return dataplaneauthz.New(dataplaneauthz.K8sLoaderIn(dyn, home), 30*time.Second)
}

// allow reports whether the signed-in user may make the request, writing the refusal when not. With
// authentication off (AUTH_MODE=none, a development console) there is no user to authorize, exactly as
// for the console's other native endpoints.
func (b *bucketAuthz) allow(w http.ResponseWriter, r *http.Request, q s3authz.Request) bool {
	if b == nil || b.auth == nil || b.auth.mode == "none" {
		return true
	}
	c, ok := claimsFrom(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return false
	}
	allowed, reason := b.gate.Allow(r.Context(), c.Claims, q, s3authz.RequestContext(c.Claims, r))
	if !allowed {
		b.logger.Warn("bucket browser denied", "user", c.Sub, "role", c.Role, "action", q.Action,
			"bucket", q.Bucket, "key", q.Key, "reason", reason)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied: " + reason})
		return false
	}
	return true
}
