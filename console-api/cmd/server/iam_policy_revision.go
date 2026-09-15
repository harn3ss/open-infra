package main

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"k8s.io/client-go/kubernetes"
)

// Policy revision — the honest open-infra answer to AWS IAM's "Policy versions" tab.
//
// open-infra does NOT implement AWS's model of up-to-5 immutable, independently-rollback-able policy
// versions. A Policy is a Kubernetes custom resource: metadata.generation increments on each spec change,
// and the real version HISTORY (prior document contents and who changed them) lives in the DECLARATIVE
// SOURCE — git / ArgoCD — when the policy is GitOps-managed, not in the cluster. So rather than fabricate
// a version table the platform does not keep (which would be exactly the fake-widget this project
// refuses), this endpoint returns the genuine revision metadata and states plainly where real history
// does and does not exist.

type policyRevision struct {
	Generation       int64  `json:"generation"`
	ResourceVersion  string `json:"resourceVersion,omitempty"`
	CreatedAt        string `json:"createdAt,omitempty"`
	UID              string `json:"uid,omitempty"`
	GitOpsManaged    bool   `json:"gitOpsManaged"` // an ArgoCD tracking-id → git holds the version history
	GitOpsTrackingID string `json:"gitOpsTrackingId,omitempty"`
	Note             string `json:"note"`
}

func handleIAMPolicyRevision(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if !authorize(w, r, cs, auth, logger, "get", "iam.openinfra.dev", "policies", auth.ns, name) {
			return
		}
		rc := auth.rawREST()
		if rc == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "cluster client unavailable"})
			return
		}
		raw, err := rc.Get().AbsPath(policiesAbsPath(auth.ns) + "/" + name).DoRaw(r.Context())
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such policy"})
			return
		}
		var cr struct {
			Metadata struct {
				Generation        int64             `json:"generation"`
				ResourceVersion   string            `json:"resourceVersion"`
				CreationTimestamp string            `json:"creationTimestamp"`
				UID               string            `json:"uid"`
				Annotations       map[string]string `json:"annotations"`
			} `json:"metadata"`
		}
		if json.Unmarshal(raw, &cr) != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read policy metadata"})
			return
		}
		track := cr.Metadata.Annotations["argocd.argoproj.io/tracking-id"]
		rev := policyRevision{
			Generation:       cr.Metadata.Generation,
			ResourceVersion:  cr.Metadata.ResourceVersion,
			CreatedAt:        cr.Metadata.CreationTimestamp,
			UID:              cr.Metadata.UID,
			GitOpsManaged:    track != "",
			GitOpsTrackingID: track,
		}
		if rev.GitOpsManaged {
			rev.Note = "open-infra keeps only the CURRENT revision in the cluster (generation " +
				itoa64(rev.Generation) + "). This policy is GitOps-managed, so its true version history — " +
				"prior contents, who changed them, and rollback — lives in the declarative source (git / " +
				"ArgoCD), not in a per-policy version list as in AWS."
		} else {
			rev.Note = "open-infra keeps only the CURRENT revision in the cluster (generation " +
				itoa64(rev.Generation) + "); there is no prior-version history or rollback here as in AWS's " +
				"5-version model. This policy is console-managed. To retain reviewable, rollback-able version " +
				"history, manage it declaratively in git (the platform's version-control path)."
		}
		writeJSON(w, http.StatusOK, rev)
	}
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
