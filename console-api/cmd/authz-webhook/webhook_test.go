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
