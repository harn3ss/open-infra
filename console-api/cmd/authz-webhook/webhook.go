package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/controlplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iamcompile"
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
	// iamChecker evaluates the iam-corpus — compiled from IAM policy (iamcompile) — and is authoritative
	// for account-qualified principals ("openinfra:<account>:<principal>"). With none loaded, those
	// principals defer to RBAC, where the generated bindings decide. Nil = no iam-corpus configured.
	iamChecker      *controlplaneauthz.Checker
	mode            Mode
	logger          *slog.Logger
	breakGlass      map[string]bool // groups always allowed in enforce, independent of the corpus
	breakGlassUsers map[string]bool // users always allowed in enforce (the webhook's own SA, for bootstrap)
	// rootBreakGlass is the console's break-glass root, always allowed in enforce whatever either corpus
	// says, so a regenerated corpus that drops the admins grant can never lock root out (rootFloor).
	rootBreakGlass bool
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

// isServiceAccountUser reports whether the identity is a Kubernetes ServiceAccount
// (system:serviceaccount:<namespace>:<name>) — a machine identity, as opposed to a human user or a
// group. Corpus-miss defer-to-RBAC is scoped to these, so users/console/apps stay strictly enforced.
func isServiceAccountUser(user string) bool {
	return strings.HasPrefix(user, "system:serviceaccount:")
}

// isBreakGlass reports whether the request's identity is in the break-glass floor — by exact user
// (the webhook's own ServiceAccount, so it can bootstrap its corpus), by group (system:masters, for
// cluster-admin recovery through a broken/empty corpus), or as the console's break-glass root.
func (h *webhookHandler) isBreakGlass(spec authzv1.SubjectAccessReviewSpec) bool {
	if h.breakGlassUsers[spec.User] {
		return true
	}
	for _, g := range spec.Groups {
		if h.breakGlass[g] {
			return true
		}
	}
	return h.rootBreakGlass && isRootFloor(spec)
}

const (
	// legacyRootUser is the console's root as the legacy identity impersonates it (iam.Identity):
	// "openinfra:root" with the admins group.
	legacyRootUser = "openinfra:root"
	legacyAdmins   = "openinfra:admins"
	// accountRootUser is the management account's root as the account-qualified identity names it
	// (iam.AccountIdentity). Member accounts' roots are not break-glass: their power is their account's,
	// compiled like any principal's.
	accountRootUser = "openinfra:" + managementAccount + ":root"
	// managementAccount is the install's management account (iam.ManagementAccount).
	managementAccount = "000000000000"
)

// isRootFloor reports whether the request is the console's break-glass root. The legacy identity counts
// only WITH the admins group: the user name alone is not proof of root (a kind: User or directory user
// named "root" would be impersonated with the same name), so the floor never grants more than the
// principal's own admins tier already does — it makes that tier independent of the corpus, which is
// what keeps root from being locked out (a corpus regenerated without the admins grant). The
// management account's root is matched by its account-qualified name; the name "root" is reserved for
// it at every door that creates principals.
func isRootFloor(spec authzv1.SubjectAccessReviewSpec) bool {
	switch spec.User {
	case accountRootUser:
		return true
	case legacyRootUser:
		for _, g := range spec.Groups {
			if g == legacyAdmins {
				return true
			}
		}
	}
	return false
}

// checkerFor picks the corpus that decides the principal: the iam-corpus for an account-qualified
// principal, the RBAC-derived control-plane corpus for everyone else (platform ServiceAccounts, the
// legacy console identities).
func (h *webhookHandler) checkerFor(user string) (*controlplaneauthz.Checker, bool) {
	if h.iamChecker != nil && iamcompile.IsAccountIdentity(user) {
		return h.iamChecker, true
	}
	return h.checker, false
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
	// An account-qualified principal is decided by the iam-corpus, compiled from its IAM policies, and
	// never by the RBAC-derived corpus. With no iam-corpus loaded it defers to RBAC, where the bindings
	// generated from the same policies decide — never to the legacy tier grants.
	if chk, isIAM := h.checkerFor(sar.Spec.User); isIAM {
		if h.mode == Enforce && !chk.HasCorpus(r.Context()) {
			h.logger.Warn("no iam-corpus loaded — deferring to RBAC (generated bindings)",
				"user", sar.Spec.User, "verb", verbOf(sar.Spec), "resource", resourceOf(sar.Spec))
			sar.Status = authzv1.SubjectAccessReviewStatus{Allowed: false, Denied: false,
				Reason: "control-plane authz: no iam-corpus loaded — deferring to RBAC"}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(&sar)
			return
		}
		d := chk.Evaluate(r.Context(), sar.Spec)
		h.logger.Info("control-plane authz decision", "mode", h.mode, "corpus", "iam", "user", sar.Spec.User,
			"verb", verbOf(sar.Spec), "resource", resourceOf(sar.Spec), "wouldAllow", d.Allowed, "reason", d.Reason)
		sar.Status = answer(d, h.mode)
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
	// AWS-faithful corpus-miss handling for ServiceAccounts: a ServiceAccount the corpus names NOWHERE
	// is a freshly-minted machine identity the snapshot has not been regenerated for yet (a new
	// CloudNativePG cluster SA, an operator plugin SA, any new component). Defer it to RBAC — its
	// attached-at-creation policy — rather than default-denying and deadlocking provisioning. This
	// generalizes deferSANamespaces beyond a fixed namespace list: an allow-list snapshot can never
	// again deadlock a machine identity it simply has not been regenerated for (the "RBAC-fallback /
	// must not deadlock" intent). It is SCOPED TO ServiceAccounts on purpose — users, the console, and
	// applications stay under strict default-deny enforcement below (the AC-6 tightening is untouched),
	// and a ServiceAccount the corpus DOES name is also still fully enforced (named-but-tightened → the
	// ungranted action is denied).
	if h.mode == Enforce && isServiceAccountUser(sar.Spec.User) && !h.checker.PrincipalGoverned(r.Context(), sar.Spec) {
		h.logger.Info("control-plane authz decision", "mode", h.mode, "user", sar.Spec.User,
			"verb", verbOf(sar.Spec), "resource", resourceOf(sar.Spec), "wouldAllow", "defer",
			"reason", "ServiceAccount not in corpus — deferring to RBAC")
		sar.Status = authzv1.SubjectAccessReviewStatus{Allowed: false, Denied: false,
			Reason: "control-plane authz: ServiceAccount not in corpus — deferring to RBAC"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&sar)
		return
	}
	d := h.checker.Evaluate(r.Context(), sar.Spec)
	// A service-linked role (iamcompile/servicelinked.go): a platform ServiceAccount may act in a member
	// account's home as that account's service-linked role allows, even where the RBAC corpus does not
	// grant it. The compiler puts the role's grant in the iam-corpus each pass, so a new account needs no
	// corpus regeneration. This lifts only a default deny; an explicit forbid stands.
	if !d.Allowed && !d.ExplicitDeny && isServiceAccountUser(sar.Spec.User) && h.iamChecker != nil {
		if sl := h.iamChecker.Evaluate(r.Context(), sar.Spec); sl.Allowed {
			d = policyengine.Decision{Allowed: true, Reason: "service-linked role in a member account: " + sl.Reason}
		}
	}
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
