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
