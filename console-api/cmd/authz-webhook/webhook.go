package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

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
	checker         *controlplaneauthz.Checker
	mode            Mode
	logger          *slog.Logger
	breakGlass      map[string]bool // groups always allowed in enforce, independent of the corpus
	breakGlassUsers map[string]bool // users always allowed in enforce (the webhook's own SA, for bootstrap)
	// deferSANamespaces holds namespaces whose ServiceAccounts are governed by their own operator-authored
	// RBAC, not Cedar. Cedar ABSTAINS (NoOpinion → RBAC) for those SAs. This is for dynamically-created
	// infrastructure SAs the corpus cannot know in advance (e.g. a CloudNativePG cluster the RDS front door
	// provisions mints a new SA per instance). It is NOT allow — RBAC still decides, and it is scoped to
	// ServiceAccounts in these fenced namespaces only, never users/console/apps.
	deferSANamespaces map[string]bool
}

// isDeferredServiceAccount reports whether the identity is a ServiceAccount in a defer namespace. The
// Kubernetes username form is system:serviceaccount:<namespace>:<name>.
func (h *webhookHandler) isDeferredServiceAccount(user string) bool {
	const p = "system:serviceaccount:"
	if !strings.HasPrefix(user, p) {
		return false
	}
	ns, _, ok := strings.Cut(user[len(p):], ":")
	return ok && h.deferSANamespaces[ns]
}

// isBreakGlass reports whether the request's identity is in the break-glass floor — by exact user
// (the webhook's own ServiceAccount, so it can bootstrap its corpus) or by group (system:masters, for
// cluster-admin recovery through a broken/empty corpus).
func (h *webhookHandler) isBreakGlass(spec authzv1.SubjectAccessReviewSpec) bool {
	if h.breakGlassUsers[spec.User] {
		return true
	}
	for _, g := range spec.Groups {
		if h.breakGlass[g] {
			return true
		}
	}
	return false
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
	// Break-glass floor: in enforce, a break-glass group (default system:masters — the admin
	// kubeconfig) is ALWAYS allowed, decided BEFORE and INDEPENDENT of the Cedar corpus. So removing
	// RBAC can never lock out cluster-admin, even if the corpus fails to load or is empty — the
	// recovery path is always open. Not applied in shadow (shadow defers everything to RBAC).
	if h.mode == Enforce && h.isBreakGlass(sar.Spec) {
		h.logger.Info("control-plane authz decision", "mode", h.mode, "user", sar.Spec.User,
			"verb", verbOf(sar.Spec), "resource", resourceOf(sar.Spec), "wouldAllow", true, "reason", "break-glass floor")
		sar.Status = authzv1.SubjectAccessReviewStatus{Allowed: true, Reason: "break-glass floor (" + sar.Spec.User + ")"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&sar)
		return
	}
	// Enforce ONLY once Cedar actually has a corpus. With none loaded — a fresh cluster whose corpus
	// has not been applied yet, or a cold-start load blip — defer to RBAC (NoOpinion) instead of
	// denying everything, the same graceful degradation the apiserver's failurePolicy gives a webhook
	// that is down. Break-glass is already handled above; shadow defers unconditionally below anyway.
	if h.mode == Enforce && !h.checker.HasCorpus(r.Context()) {
		h.logger.Warn("no control-plane corpus loaded — deferring to RBAC (not enforcing)",
			"user", sar.Spec.User, "verb", verbOf(sar.Spec), "resource", resourceOf(sar.Spec))
		sar.Status = authzv1.SubjectAccessReviewStatus{Allowed: false, Denied: false,
			Reason: "control-plane authz: no corpus loaded — deferring to RBAC"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&sar)
		return
	}
	// Operator-managed infrastructure ServiceAccounts in fenced namespaces are governed by the operator's
	// own tight per-resource RBAC, not Cedar. A dynamically-provisioned resource (e.g. an RDS = a
	// CloudNativePG cluster) mints a new SA the corpus cannot know in advance, so Cedar ABSTAINS
	// (NoOpinion → RBAC decides) rather than denying it and dead-locking provisioning. This does NOT relax
	// Cedar over users, the console, or applications — only ServiceAccounts in these fenced namespaces.
	if h.mode == Enforce && h.isDeferredServiceAccount(sar.Spec.User) {
		h.logger.Info("control-plane authz decision", "mode", h.mode, "user", sar.Spec.User,
			"verb", verbOf(sar.Spec), "resource", resourceOf(sar.Spec), "wouldAllow", "defer",
			"reason", "operator-managed infra SA — deferring to RBAC")
		sar.Status = authzv1.SubjectAccessReviewStatus{Allowed: false, Denied: false,
			Reason: "control-plane authz: operator-managed infra ServiceAccount — deferring to RBAC"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&sar)
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
		if ra.Subresource != "" {
			r += "/" + ra.Subresource
		}
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
