package main

import (
	"context"
	"log/slog"
	"net/http"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Per-user authorization for the BFF's OWN endpoints.
//
// Requests to /api/k8s/* are impersonated, so Kubernetes RBAC governs them directly. The BFF's
// native handlers (snapshots, restores, …) are different: they act with the console's
// ServiceAccount, which is far more privileged than any human. Without a check, a poweruser
// calling POST /api/databases/x/snapshot would execute with the ServiceAccount's rights —
// the authorization decision and the actual access would diverge.
//
// Fix: before doing the work, ask the API server whether the SIGNED-IN user could perform the
// equivalent action, via a SubjectAccessReview, and fail closed. This is the documented way to
// defer an authorization decision, and it means the check appears in the audit log against a
// person rather than being an invisible `if` in Go.
//
// Snapshot endpoints map onto the verb you'd need on the underlying resource:
//
//	take/delete a DB snapshot   -> update  applications      (mutating that database)
//	restore into a new database -> create  applications      (it creates one)
//	take/delete a VM snapshot   -> update  virtualmachines
//	restore into a new VM       -> create  virtualmachines

// canUserDo asks the API server whether the signed-in user may perform verb on
// group/resource in namespace. Fails CLOSED: any error means "no".
func canUserDo(ctx context.Context, cs kubernetes.Interface, c sessionClaims,
	verb, group, resource, namespace, name string) (bool, string) {
	sar := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   "openinfra:" + c.Sub,
			Groups: roleGroups(c.Role),
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:      verb,
				Group:     group,
				Resource:  resource,
				Namespace: namespace,
				Name:      name,
			},
		},
	}
	out, err := cs.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, "authorization check failed"
	}
	if !out.Status.Allowed || out.Status.Denied {
		reason := out.Status.Reason
		if reason == "" {
			reason = "your role does not allow " + verb + " on " + resource
		}
		return false, reason
	}
	return true, ""
}

// authorize guards a BFF-native handler. Returns false (and writes the response)
// when the signed-in user may not perform the equivalent action.
func authorize(w http.ResponseWriter, r *http.Request, cs kubernetes.Interface, a *authStore,
	logger *slog.Logger, verb, group, resource, namespace, name string) bool {
	if a.mode == "none" {
		return true
	}
	c, ok := claimsFrom(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
		return false
	}
	allowed, reason := canUserDo(r.Context(), cs, c, verb, group, resource, namespace, name)
	if !allowed {
		logger.Warn("denied BFF action",
			"user", c.Sub, "role", c.Role, "verb", verb, "resource", resource,
			"namespace", namespace, "name", name, "reason", reason)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return false
	}
	return true
}
