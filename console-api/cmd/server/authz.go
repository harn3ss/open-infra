package main

import (
	"log/slog"
	"net/http"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
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
// equivalent action, via a SubjectAccessReview, and fail closed. The check itself lives in the
// shared authorization core (internal/iam.CanDo) so the console and the AWS-shim enforce through
// exactly the same impersonated SubjectAccessReview — one policy world. It also means the check
// appears in the audit log against a person rather than being an invisible `if` in Go.
//
// Snapshot endpoints map onto the verb you'd need on the underlying resource:
//
//	take/delete a DB snapshot -> update applications (mutating that database)
//	restore into a new database -> create applications (it creates one)
//	take/delete a VM snapshot -> update virtualmachines
//	restore into a new VM -> create virtualmachines

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
	allowed, reason := iam.CanDo(r.Context(), cs, c.Claims, verb, group, resource, namespace, name)
	if !allowed {
		logger.Warn("denied BFF action",
			"user", c.Sub, "role", c.Role, "verb", verb, "resource", resource,
			"namespace", namespace, "name", name, "reason", reason)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": reason})
		return false
	}
	return true
}
