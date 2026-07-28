package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// requireSignedIn is the gate in front of the Grafana reverse proxy. It must (a) block
// callers with no/invalid session so an internet-exposed console doesn't leak Grafana's
// anonymous-Viewer dashboards, and (b) — unlike requireAuth — let a POST through without
// the CSRF header, because Grafana's own panels POST /api/ds/query without it and would
// otherwise break.
func TestRequireSignedIn(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	newReq := func(method string, withCookie bool, a *authStore) *http.Request {
		r := httptest.NewRequest(method, "/grafana/api/ds/query", nil)
		if withCookie {
			tok, err := a.issue("alice", "admin", []string{"openinfra:admins"})
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
		}
		return r
	}
	do := func(a *authStore, r *http.Request) int {
		rec := httptest.NewRecorder()
		a.requireSignedIn(next).ServeHTTP(rec, r)
		return rec.Code
	}

	local := &authStore{mode: "local", sessionKey: []byte("test-signing-key")}

	// No session → 401, whichever method.
	if got := do(local, newReq(http.MethodGet, false, local)); got != http.StatusUnauthorized {
		t.Errorf("GET without session = %d, want 401", got)
	}

	// Valid session → passes.
	if got := do(local, newReq(http.MethodGet, true, local)); got != http.StatusOK {
		t.Errorf("GET with valid session = %d, want 200", got)
	}

	// The whole point vs requireAuth: a POST with a valid session but NO CSRF header
	// still passes (Grafana's panel queries are POSTs and lack our header).
	if got := do(local, newReq(http.MethodPost, true, local)); got != http.StatusOK {
		t.Errorf("POST with valid session, no CSRF header = %d, want 200", got)
	}

	// Garbage cookie → 401 (not signed by our key).
	rGarbage := httptest.NewRequest(http.MethodGet, "/grafana/", nil)
	rGarbage.AddCookie(&http.Cookie{Name: sessionCookie, Value: "not.a.real.token"})
	if got := do(local, rGarbage); got != http.StatusUnauthorized {
		t.Errorf("garbage cookie = %d, want 401", got)
	}

	// AUTH_MODE=none → open (the SPA shows a standing banner instead).
	none := &authStore{mode: "none", sessionKey: []byte("test-signing-key")}
	if got := do(none, newReq(http.MethodGet, false, none)); got != http.StatusOK {
		t.Errorf("mode=none without session = %d, want 200 (open)", got)
	}
}
