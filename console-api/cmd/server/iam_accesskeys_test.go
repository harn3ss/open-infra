package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes/fake"
)

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestAccessKeyStatusLabel(t *testing.T) {
	if accessKeyStatusLabel(false) != "Active" {
		t.Error("an enabled key must read as Active")
	}
	if accessKeyStatusLabel(true) != "Inactive" {
		t.Error("a revoked key must read as Inactive")
	}
}

// viewFromMeta must never carry secret material and must map status/created faithfully. A JSON
// round-trip of the view proves there is no secret field an accidental future edit could populate.
func TestViewFromMeta_NoSecret(t *testing.T) {
	created := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	v := viewFromMeta(awskeys.Meta{
		AccessKeyID: "OIAKVIEW000000000001",
		Owner:       "alice",
		Disabled:    true,
		Created:     created,
	})
	if v.Status != "Inactive" {
		t.Fatalf("status = %q, want Inactive", v.Status)
	}
	if v.Created != "2026-09-07T12:00:00Z" {
		t.Fatalf("created = %q, want RFC3339 UTC", v.Created)
	}
	if v.LastUsed != nil {
		t.Fatal("lastUsed must be null — per-key last-used is not tracked yet")
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret", "Secret", "secretKey", "secretAccessKey"} {
		if containsField(b, forbidden) {
			t.Fatalf("the list/get view leaked a secret-shaped field %q: %s", forbidden, b)
		}
	}
}

func containsField(jsonBytes []byte, needle string) bool {
	var m map[string]any
	if err := json.Unmarshal(jsonBytes, &m); err != nil {
		return false
	}
	for k := range m {
		if k == needle {
			return true
		}
	}
	return false
}

func reqWithClaims(sub string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	claims := sessionClaims{Claims: iam.Claims{Sub: sub, Groups: []string{"openinfra:users"}}}
	return r.WithContext(context.WithValue(r.Context(), ctxUser{}, claims))
}

// authorizeAccessKey is the self-or-admin gate. AUTH_MODE=none lets anything through; a signed-in
// user may act on their OWN keys without an admin SAR; acting on someone else's falls to the SAR,
// which the fake apiserver denies (no RBAC) — so a non-admin acting on another user is refused.
func TestAuthorizeAccessKey(t *testing.T) {
	cs := fake.NewSimpleClientset()
	logger := testLogger()

	// mode none → allowed, no claims required.
	none := &authStore{cs: cs, ns: "open-infra-console", mode: "none"}
	if !authorizeAccessKey(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), cs, none, logger, "get", "alice") {
		t.Fatal("mode=none must allow")
	}

	local := &authStore{cs: cs, ns: "open-infra-console", mode: "local"}

	// Self-service: alice acting on alice's keys → allowed with no SAR.
	if !authorizeAccessKey(httptest.NewRecorder(), reqWithClaims("alice"), cs, local, logger, "update", "alice") {
		t.Fatal("a user must be allowed to manage their own keys")
	}

	// Not signed in → 401.
	rr := httptest.NewRecorder()
	if authorizeAccessKey(rr, httptest.NewRequest(http.MethodGet, "/", nil), cs, local, logger, "get", "alice") {
		t.Fatal("an unauthenticated request must be refused")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", rr.Code)
	}

	// bob (non-admin) acting on alice's keys → SAR path → denied by the fake apiserver.
	rr = httptest.NewRecorder()
	if authorizeAccessKey(rr, reqWithClaims("bob"), cs, local, logger, "update", "alice") {
		t.Fatal("a non-admin must not manage another user's keys")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-user status = %d, want 403", rr.Code)
	}
}
