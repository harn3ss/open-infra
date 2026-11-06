package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/controlplaneauthz"
	"github.com/harn3ss/open-infra/policyengine"
	authzv1 "k8s.io/api/authorization/v1"
)

func checkerFor(appliesTo []string, stmts ...policyengine.Statement) *controlplaneauthz.Checker {
	return controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) {
		return []controlplaneauthz.PolicyDoc{{AppliesTo: appliesTo, Statements: stmts}}, nil
	}, time.Minute)
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// sar builds a SubjectAccessReview the API server would POST.
func sar(user string, groups []string, verb, group, resource, ns, name string) *authzv1.SubjectAccessReview {
	return &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: user, Groups: groups,
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: verb, Group: group, Resource: resource, Namespace: ns, Name: name},
		},
	}
}

func post(t *testing.T, h *webhookHandler, review *authzv1.SubjectAccessReview) authzv1.SubjectAccessReviewStatus {
	t.Helper()
	body, _ := json.Marshal(review)
	req := httptest.NewRequest("POST", "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.serve(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var out authzv1.SubjectAccessReview
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out.Status
}

// Shadow mode NEVER expresses an opinion — it always defers (allowed=false, denied=false) so RBAC
// still decides — regardless of what Cedar would have said.
func TestWebhook_ShadowAlwaysDefers(t *testing.T) {
	h := &webhookHandler{
		checker: checkerFor([]string{"Group::admins"},
			policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"*"}, Resources: []string{"*"}}),
		mode: Shadow, logger: discard(),
	}
	// Even a request Cedar would ALLOW is deferred in shadow.
	st := post(t, h, sar("alice", []string{"admins"}, "delete", "openinfra.dev", "databases", "prod", "db1"))
	if st.Allowed || st.Denied {
		t.Fatalf("shadow must express no opinion, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
	// And a request Cedar would DENY is also deferred (never an enforced deny in shadow).
	st = post(t, h, sar("nobody", []string{"interns"}, "get", "", "secrets", "kube-system", "root"))
	if st.Allowed || st.Denied {
		t.Fatalf("shadow must not deny, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
}

// Break-glass floor: system:masters is allowed in enforce even with an EMPTY or UNLOADABLE corpus —
// the recovery path so removing RBAC can never lock out cluster-admin. Non-break-glass is still
// default-denied, and shadow still defers.
func TestWebhook_BreakGlassFloor(t *testing.T) {
	empty := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) { return nil, nil }, time.Minute)
	h := &webhookHandler{checker: empty, mode: Enforce, logger: discard(), breakGlass: map[string]bool{"system:masters": true}}

	if st := post(t, h, sar("kubernetes-admin", []string{"system:masters"}, "delete", "", "secrets", "kube-system", "x")); !st.Allowed || st.Denied {
		t.Fatalf("break-glass must allow system:masters under an empty corpus, got %+v", st)
	}
	// With an empty/unusable corpus, a non-break-glass principal is NOT allowed (it is deferred to RBAC
	// by the corpus gate) — break-glass is the only identity that gets through a broken corpus.
	if st := post(t, h, sar("bob", []string{"devs"}, "get", "", "secrets", "default", "y")); st.Allowed {
		t.Fatalf("non-break-glass must not be allowed through an empty corpus, got %+v", st)
	}
	// A corpus LOAD ERROR must not lock out break-glass (it is decided before the corpus is consulted).
	h.checker = controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) {
		return nil, io.ErrUnexpectedEOF
	}, time.Minute)
	if st := post(t, h, sar("kubernetes-admin", []string{"system:masters"}, "get", "", "pods", "default", "z")); !st.Allowed {
		t.Fatalf("break-glass must survive a corpus load error, got %+v", st)
	}
	// Shadow never forces an opinion, even for break-glass.
	h.mode = Shadow
	if st := post(t, h, sar("kubernetes-admin", []string{"system:masters"}, "get", "", "pods", "default", "z")); st.Allowed || st.Denied {
		t.Fatalf("shadow must defer even for break-glass, got %+v", st)
	}
}

// With NO corpus loaded, enforce DEFERS to RBAC (no opinion) instead of denying everything — a fresh
// cluster whose corpus is not applied yet, or a cold-start load blip, degrades to RBAC, not a lockout.
// Once a non-empty corpus is present, an ungranted principal is default-denied (real enforce).
func TestWebhook_EnforceDefersWithoutCorpus(t *testing.T) {
	empty := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) { return nil, nil }, time.Minute)
	h := &webhookHandler{checker: empty, mode: Enforce, logger: discard(), breakGlass: map[string]bool{"system:masters": true}}
	// A normal (non-break-glass) principal with no corpus → defer (no opinion), NOT deny.
	if st := post(t, h, sar("bob", []string{"devs"}, "get", "", "pods", "default", "p")); st.Allowed || st.Denied {
		t.Fatalf("no corpus must defer to RBAC (no opinion), got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
	// With a non-empty corpus, an ungranted principal is default-denied (real enforce resumes).
	h.checker = checkerFor([]string{"Group::admins"},
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"get"}, Resources: []string{"pods::*"}})
	if st := post(t, h, sar("bob", []string{"devs"}, "get", "", "pods", "default", "p")); st.Allowed || !st.Denied {
		t.Fatalf("with a corpus loaded, an ungranted principal must be denied, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
	if st := post(t, h, sar("alice", []string{"admins"}, "get", "", "pods", "default", "p")); !st.Allowed {
		t.Fatalf("a granted principal should be allowed, got %+v", st)
	}
}

// Break-glass by exact USER: the webhook's own ServiceAccount is always allowed in enforce (so it can
// bootstrap its corpus), scoped to that one identity — NOT the whole namespace. A different SA in the
// same namespace is not break-glass and is governed by the corpus.
func TestWebhook_BreakGlassUser(t *testing.T) {
	empty := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) { return nil, nil }, time.Minute)
	h := &webhookHandler{checker: empty, mode: Enforce, logger: discard(),
		breakGlass:      map[string]bool{"system:masters": true},
		breakGlassUsers: map[string]bool{"system:serviceaccount:open-infra-authz:authz-webhook": true}}
	// The webhook's own SA is allowed even with an empty corpus (bootstrap).
	if st := post(t, h, sar("system:serviceaccount:open-infra-authz:authz-webhook", []string{"system:serviceaccounts:open-infra-authz"}, "list", "iam.openinfra.dev", "policies", "", "")); !st.Allowed {
		t.Fatalf("the webhook's own SA must be break-glass (bootstrap), got %+v", st)
	}
	// A DIFFERENT SA in the same namespace is NOT break-glass (the namespace is no longer a blanket
	// bypass) — with no corpus it defers to RBAC (not allowed, not denied).
	if st := post(t, h, sar("system:serviceaccount:open-infra-authz:corpus-auditor", []string{"system:serviceaccounts:open-infra-authz"}, "list", "iam.openinfra.dev", "policies", "", "")); st.Allowed {
		t.Fatalf("a different namespace SA must not be break-glass, got %+v", st)
	}
}

// A ServiceAccount in a defer namespace is governed by RBAC (NoOpinion), even with a corpus loaded that
// would otherwise default-deny it — so a dynamically-provisioned CNPG cluster's fresh SA is not
// dead-locked. A SA outside the defer set, and a regular user, are still enforced.
func TestWebhook_DeferServiceAccountNamespace(t *testing.T) {
	h := &webhookHandler{
		checker: checkerFor([]string{"Group::admins"},
			policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"get"}, Resources: []string{"clusters.postgresql.cnpg.io::*"}}),
		mode: Enforce, logger: discard(),
		breakGlass:        map[string]bool{"system:masters": true},
		deferSANamespaces: map[string]bool{"open-infra-rds": true},
	}
	// An (ungranted) CNPG cluster SA in the defer namespace → defer to RBAC (not allowed, not denied).
	if st := post(t, h, sar("system:serviceaccount:open-infra-rds:rds-smoke", []string{"system:serviceaccounts:open-infra-rds"}, "get", "postgresql.cnpg.io", "clusters", "open-infra-rds", "rds-smoke")); st.Allowed || st.Denied {
		t.Fatalf("a defer-namespace SA must defer to RBAC, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
	// A ServiceAccount the corpus names NOWHERE (even outside a defer namespace) DEFERS to RBAC — a new
	// machine identity the snapshot has not been regenerated for must not be dead-locked (corpus-miss fix).
	if st := post(t, h, sar("system:serviceaccount:default:other", []string{"system:serviceaccounts:default"}, "get", "postgresql.cnpg.io", "clusters", "default", "x")); st.Allowed || st.Denied {
		t.Fatalf("an unknown SA must defer to RBAC, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
	// A regular USER is never a deferred SA — still enforced.
	if st := post(t, h, sar("bob", []string{"devs"}, "get", "postgresql.cnpg.io", "clusters", "open-infra-rds", "x")); !st.Denied {
		t.Fatalf("a non-SA user must be enforced, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
}

// Corpus-miss fix: a ServiceAccount the corpus names NOWHERE defers to RBAC (so a new CNPG cluster SA
// or operator plugin SA is never dead-locked by a stale snapshot), while a ServiceAccount the corpus
// DOES name stays fully enforced (granted → allow, ungranted → deny, preserving the AC-6 tightening),
// and a human user absent from the corpus is NOT deferred — the defer is scoped to ServiceAccounts.
func TestWebhook_DeferUnknownServiceAccount(t *testing.T) {
	h := &webhookHandler{
		checker: checkerFor([]string{"ServiceAccount::cnpg-system/cloudnative-pg"},
			policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"get"}, Resources: []string{"clusters.postgresql.cnpg.io::*"}}),
		mode: Enforce, logger: discard(), breakGlass: map[string]bool{"system:masters": true},
	}
	// An absent SA (named nowhere) → defer to RBAC.
	if st := post(t, h, sar("system:serviceaccount:cnpg-system:plugin-barman-cloud", []string{"system:serviceaccounts:cnpg-system"}, "create", "coordination.k8s.io", "leases", "cnpg-system", "x")); st.Allowed || st.Denied {
		t.Fatalf("an unknown SA must defer to RBAC, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
	// A NAMED SA with a granted action → allowed (enforcement still works).
	if st := post(t, h, sar("system:serviceaccount:cnpg-system:cloudnative-pg", []string{"system:serviceaccounts:cnpg-system"}, "get", "postgresql.cnpg.io", "clusters", "x", "y")); !st.Allowed {
		t.Fatalf("a named+granted SA must be allowed, got %+v", st)
	}
	// A NAMED SA with an UNGRANTED action → denied (AC-6 tightening preserved for named SAs).
	if st := post(t, h, sar("system:serviceaccount:cnpg-system:cloudnative-pg", []string{"system:serviceaccounts:cnpg-system"}, "delete", "postgresql.cnpg.io", "clusters", "x", "y")); st.Allowed || !st.Denied {
		t.Fatalf("a named SA's ungranted action must be denied, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
	// A human USER absent from the corpus is NOT deferred (SA-scoped) — still default-denied.
	if st := post(t, h, sar("alice", []string{"devs"}, "get", "", "pods", "default", "p")); st.Allowed || !st.Denied {
		t.Fatalf("an absent human user must stay default-denied, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
}

// A ServiceAccount covered ONLY by the blanket Group::system:serviceaccounts baseline (which every SA
// matches) is NOT specifically governed — it still defers to RBAC, so the shared baseline cannot
// defeat the corpus-miss defer. A ServiceAccount named by its own (scoped) namespace group IS
// governed and stays enforced.
func TestWebhook_BlanketServiceAccountGroupStillDefers(t *testing.T) {
	checker := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) {
		return []controlplaneauthz.PolicyDoc{
			{AppliesTo: []string{"Group::system:serviceaccounts"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"get"}, Resources: []string{"NonResourceURL::/openid/v1/jwks"}}}},
			{AppliesTo: []string{"Group::system:serviceaccounts:curated-ns"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"get"}, Resources: []string{"clusters.postgresql.cnpg.io::*"}}}},
		}, nil
	}, time.Minute)
	h := &webhookHandler{checker: checker, mode: Enforce, logger: discard(), breakGlass: map[string]bool{"system:masters": true}}

	// An SA matching ONLY the blanket group → defer to RBAC for an action the baseline does not cover.
	if st := post(t, h, sar("system:serviceaccount:cnpg-system:plugin-barman-cloud",
		[]string{"system:serviceaccounts", "system:serviceaccounts:cnpg-system"}, "create", "coordination.k8s.io", "leases", "cnpg-system", "x")); st.Allowed || st.Denied {
		t.Fatalf("an SA matching only the blanket group must defer, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
	// An SA in a CURATED namespace group → specifically governed → enforced (ungranted action denied).
	if st := post(t, h, sar("system:serviceaccount:curated-ns:thing",
		[]string{"system:serviceaccounts", "system:serviceaccounts:curated-ns"}, "delete", "postgresql.cnpg.io", "clusters", "curated-ns", "x")); st.Allowed || !st.Denied {
		t.Fatalf("a curated-namespace SA must be enforced (denied), got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
}

// Enforce mode returns the real Cedar decision: an allow, and an explicit deny for the ungranted.
func TestWebhook_EnforceReturnsDecision(t *testing.T) {
	h := &webhookHandler{
		checker: checkerFor([]string{"Group::admins"},
			policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"get", "list"}, Resources: []string{"applications.openinfra.dev::*"}}),
		mode: Enforce, logger: discard(),
	}
	if st := post(t, h, sar("alice", []string{"admins"}, "get", "openinfra.dev", "applications", "team-a", "app")); !st.Allowed {
		t.Fatalf("enforce should allow a granted get, got %+v", st)
	}
	// An ungranted verb → explicit deny (default-deny allow-list).
	st := post(t, h, sar("alice", []string{"admins"}, "delete", "openinfra.dev", "applications", "team-a", "app"))
	if st.Allowed || !st.Denied {
		t.Fatalf("enforce should explicitly deny an ungranted verb, got allowed=%v denied=%v", st.Allowed, st.Denied)
	}
}

// The console's break-glass root stays allowed whatever the corpus says: a corpus regenerated
// WITHOUT Group::openinfra:admins (the grant root's tier rides on) must not lock root out, in either
// identity form — the legacy one with its admins group, and the management account's
// account-qualified root. The legacy user name alone is not root: a kind: User or directory user named
// "root" is impersonated with the same name but without the admins tier, and stays under the corpus.
func TestWebhook_RootFloorSurvivesACorpusWithoutAdmins(t *testing.T) {
	// A corpus that grants something to someone else, and nothing to admins.
	corpus := checkerFor([]string{"Group::openinfra:readers"},
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"get"}, Resources: []string{"*"}})
	h := &webhookHandler{checker: corpus, iamChecker: corpus, mode: Enforce, logger: discard(), rootBreakGlass: true}

	if st := post(t, h, sar("openinfra:root", []string{"openinfra:admins", "openinfra:users"}, "delete", "", "secrets", "kube-system", "x")); !st.Allowed {
		t.Fatalf("legacy root (admins tier) must pass a corpus without the admins grant, got %+v", st)
	}
	if st := post(t, h, sar("openinfra:000000000000:root", nil, "create", "rbac.authorization.k8s.io", "clusterrolebindings", "", "x")); !st.Allowed {
		t.Fatalf("the management account's root must pass a corpus without any grant for it, got %+v", st)
	}
	// The name without the tier is not root: a User named "root" with the readers tier stays a reader.
	if st := post(t, h, sar("openinfra:root", []string{"openinfra:readers", "openinfra:users"}, "delete", "", "secrets", "kube-system", "x")); st.Allowed || !st.Denied {
		t.Fatalf("a principal named root without the admins tier must not get the floor, got %+v", st)
	}
	// A member account's root is not break-glass.
	if st := post(t, h, sar("openinfra:912345678901:root", nil, "delete", "", "secrets", "kube-system", "x")); st.Allowed {
		t.Fatalf("a member account's root must not get the floor, got %+v", st)
	}
	// Off means off.
	h.rootBreakGlass = false
	if st := post(t, h, sar("openinfra:000000000000:root", nil, "create", "rbac.authorization.k8s.io", "clusterrolebindings", "", "x")); st.Allowed {
		t.Fatalf("with the root floor off, root is decided by the corpus, got %+v", st)
	}
}

// An account-qualified principal is decided by the iam-corpus alone: the RBAC-derived corpus's grants
// (here a blanket grant to everyone) never reach it, and with no iam-corpus loaded it defers to RBAC
// (the generated bindings) rather than being denied or decided by the legacy tiers.
func TestWebhook_AccountPrincipalsUseTheIAMCorpus(t *testing.T) {
	legacy := checkerFor([]string{"*"},
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"*"}, Resources: []string{"*"}})
	iamCorpus := checkerFor([]string{"User::openinfra:000000000000:alice"},
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"get", "list"}, Resources: []string{"buckets.openinfra.dev::open-infra-s3/*"}})
	h := &webhookHandler{checker: legacy, iamChecker: iamCorpus, mode: Enforce, logger: discard()}

	if st := post(t, h, sar("openinfra:000000000000:alice", nil, "get", "openinfra.dev", "buckets", "open-infra-s3", "b1")); !st.Allowed {
		t.Fatalf("alice's iam-corpus grant must allow, got %+v", st)
	}
	if st := post(t, h, sar("openinfra:000000000000:alice", nil, "delete", "openinfra.dev", "buckets", "open-infra-s3", "b1")); st.Allowed || !st.Denied {
		t.Fatalf("what alice's IAM policy does not grant is denied, even though the legacy corpus allows '*', got %+v", st)
	}
	if st := post(t, h, sar("openinfra:000000000000:bob", nil, "get", "openinfra.dev", "buckets", "open-infra-s3", "b1")); st.Allowed || !st.Denied {
		t.Fatalf("a principal with no IAM policy is denied (the legacy '*' does not reach it), got %+v", st)
	}
	// The legacy identity still uses the RBAC-derived corpus.
	if st := post(t, h, sar("openinfra:alice", []string{"openinfra:readers"}, "delete", "openinfra.dev", "buckets", "open-infra-s3", "b1")); !st.Allowed {
		t.Fatalf("a legacy identity is decided by the control-plane corpus, got %+v", st)
	}
	// No iam-corpus loaded: defer (no opinion), so the generated RBAC decides.
	h.iamChecker = controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) { return nil, nil }, time.Minute)
	if st := post(t, h, sar("openinfra:000000000000:alice", nil, "get", "openinfra.dev", "buckets", "open-infra-s3", "b1")); st.Allowed || st.Denied {
		t.Fatalf("with no iam-corpus an account principal defers to RBAC, got %+v", st)
	}
}

// A service-linked role: a platform ServiceAccount the RBAC corpus names (and so fully enforces) may
// act in a member account's home as the iam-corpus's service-linked grant allows, and nowhere else. An
// explicit forbid in the RBAC corpus stands, and the lift is for ServiceAccounts only.
func TestWebhook_ServiceLinkedRoleInMemberHome(t *testing.T) {
	const shim = "system:serviceaccount:open-infra-aws-shim:aws-shim"
	sa := []string{"system:serviceaccounts", "system:serviceaccounts:open-infra-aws-shim"}
	rbacCorpus := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) {
		return []controlplaneauthz.PolicyDoc{
			{AppliesTo: []string{"ServiceAccount::open-infra-aws-shim/aws-shim"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"get", "create"}, Resources: []string{"configmaps::open-infra-ecs/*"}},
				{Effect: policyengine.Deny, Actions: []string{"*"}, Resources: []string{"secrets::shop/locked"}},
			}},
			{AppliesTo: []string{"ServiceAccount::kube-system/other"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"get"}, Resources: []string{"pods::kube-system/*"}},
			}},
			{AppliesTo: []string{"User::bob"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"get"}, Resources: []string{"pods::default/*"}},
			}},
		}, nil
	}, time.Minute)
	iamCorpus := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) {
		return []controlplaneauthz.PolicyDoc{
			{AppliesTo: []string{"ServiceAccount::open-infra-aws-shim/aws-shim"}, Statements: []policyengine.Statement{
				{Effect: policyengine.Allow, Actions: []string{"get", "create"}, Resources: []string{"configmaps::shop/*", "secrets::shop/*"}},
			}},
		}, nil
	}, time.Minute)
	h := &webhookHandler{checker: rbacCorpus, iamChecker: iamCorpus, mode: Enforce, logger: discard()}

	if st := post(t, h, sar(shim, sa, "create", "", "configmaps", "open-infra-ecs", "")); !st.Allowed {
		t.Fatalf("the platform's own grant must still allow, got %+v", st)
	}
	if st := post(t, h, sar(shim, sa, "create", "", "configmaps", "shop", "")); !st.Allowed {
		t.Fatalf("the service-linked role must allow in the member home, got %+v", st)
	}
	if st := post(t, h, sar(shim, sa, "create", "", "configmaps", "elsewhere", "")); st.Allowed || !st.Denied {
		t.Fatalf("outside a member home the shim stays denied, got %+v", st)
	}
	if st := post(t, h, sar(shim, sa, "delete", "", "configmaps", "shop", "x")); st.Allowed || !st.Denied {
		t.Fatalf("a verb the service-linked role does not grant stays denied, got %+v", st)
	}
	if st := post(t, h, sar(shim, sa, "get", "", "secrets", "shop", "locked")); st.Allowed || !st.Denied {
		t.Fatalf("an explicit forbid must stand over a service-linked allow, got %+v", st)
	}
	if st := post(t, h, sar("system:serviceaccount:kube-system:other", []string{"system:serviceaccounts"}, "get", "", "configmaps", "shop", "x")); st.Allowed || !st.Denied {
		t.Fatalf("another ServiceAccount gets nothing from the shim's service-linked role, got %+v", st)
	}
	if st := post(t, h, sar("bob", nil, "get", "", "configmaps", "shop", "x")); st.Allowed || !st.Denied {
		t.Fatalf("a user is never lifted by a service-linked role, got %+v", st)
	}
}
