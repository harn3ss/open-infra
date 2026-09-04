package main

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/harn3ss/open-infra/console-api/internal/controlplaneauthz"
	"github.com/harn3ss/open-infra/policyengine"
	authzv1 "k8s.io/api/authorization/v1"
)

// Mode selects how a Cedar decision is turned into a SubjectAccessReview answer.
type Mode string

const (
	// Shadow always returns "no opinion" so the next authorizer (RBAC) still decides; the Cedar
	// decision is only logged, to measure divergence before anything is enforced.
	Shadow Mode = "shadow"
	// Enforce returns the Cedar decision as the authoritative answer (allow or explicit deny).
	Enforce Mode = "enforce"
)

// answer builds the SubjectAccessReviewStatus the API server reads. Shadow never expresses an
// opinion (allowed=false, denied=false → defer); enforce returns allow, or an explicit deny.
func answer(d policyengine.Decision, mode Mode) authzv1.SubjectAccessReviewStatus {
	if mode == Enforce {
		if d.Allowed {
			return authzv1.SubjectAccessReviewStatus{Allowed: true, Reason: d.Reason}
		}
		return authzv1.SubjectAccessReviewStatus{Allowed: false, Denied: true, Reason: d.Reason}
	}
	return authzv1.SubjectAccessReviewStatus{Allowed: false, Denied: false, Reason: "shadow (no opinion): would be " + verdict(d) + " — " + d.Reason}
}

func verdict(d policyengine.Decision) string {
	if d.Allowed {
		return "ALLOW"
	}
	return "DENY"
}

// webhookHandler serves the Kubernetes authorization-webhook contract: a SubjectAccessReview in, the
// same object with its Status filled, out.
type webhookHandler struct {
	checker *controlplaneauthz.Checker
	mode    Mode
	logger  *slog.Logger
}

func (h *webhookHandler) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var sar authzv1.SubjectAccessReview
	if err := json.NewDecoder(r.Body).Decode(&sar); err != nil {
		http.Error(w, "invalid SubjectAccessReview: "+err.Error(), http.StatusBadRequest)
		return
	}
	d := h.checker.Evaluate(r.Context(), sar.Spec)
	// Log every decision — the whole point of shadow mode is the divergence record.
	h.logger.Info("control-plane authz decision",
		"mode", h.mode, "user", sar.Spec.User, "verb", verbOf(sar.Spec),
		"resource", resourceOf(sar.Spec), "wouldAllow", d.Allowed, "reason", d.Reason)
	sar.Status = answer(d, h.mode)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&sar)
}

func verbOf(s authzv1.SubjectAccessReviewSpec) string {
	if s.ResourceAttributes != nil {
		return s.ResourceAttributes.Verb
	}
	if s.NonResourceAttributes != nil {
		return s.NonResourceAttributes.Verb
	}
	return ""
}

func resourceOf(s authzv1.SubjectAccessReviewSpec) string {
	if ra := s.ResourceAttributes; ra != nil {
		r := ra.Resource
		if ra.Group != "" {
			r += "." + ra.Group
		}
		if ra.Namespace != "" {
			r += " (" + ra.Namespace + "/" + ra.Name + ")"
		} else if ra.Name != "" {
			r += " (" + ra.Name + ")"
		}
		return r
	}
	if nra := s.NonResourceAttributes; nra != nil {
		return nra.Path
	}
	return ""
}
