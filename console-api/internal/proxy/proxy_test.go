package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestProxyStripsPrefixAndForwards verifies that the /api/k8s prefix is removed,
// query params survive, the method is preserved, and client-supplied auth headers
// are dropped (only the transport may authenticate).
func TestProxyStripsPrefixAndForwards(t *testing.T) {
	var gotPath, gotQuery, gotMethod, gotAuth string

	// Stand in for the API server; record what the proxy forwarded.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	host, _ := url.Parse(upstream.URL)
	h := New(host, http.DefaultTransport, "/api/k8s", slog.New(slog.DiscardHandler), nil)

	req := httptest.NewRequest(http.MethodDelete,
		"/api/k8s/apis/openinfra.dev/v1/namespaces/default/applications/foo?propagationPolicy=Foreground", nil)
	req.Header.Set("Authorization", "Bearer browser-supplied-should-be-dropped")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if want := "/apis/openinfra.dev/v1/namespaces/default/applications/foo"; gotPath != want {
		t.Errorf("forwarded path = %q, want %q", gotPath, want)
	}
	if want := "propagationPolicy=Foreground"; gotQuery != want {
		t.Errorf("forwarded query = %q, want %q", gotQuery, want)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("forwarded method = %q, want DELETE", gotMethod)
	}
	if gotAuth != "" {
		t.Errorf("Authorization header leaked to upstream: %q", gotAuth)
	}
}

// TestProxyRootPath ensures stripping the prefix from a bare "/api/k8s" yields "/".
func TestProxyRootPath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host, _ := url.Parse(upstream.URL)
	h := New(host, http.DefaultTransport, "/api/k8s", slog.New(slog.DiscardHandler), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/k8s", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotPath != "/" {
		t.Errorf("forwarded path = %q, want %q", gotPath, "/")
	}
}

// The proxy must impersonate the signed-in console user so Kubernetes RBAC —
// not the console — decides what they may do.
func TestProxyImpersonatesIdentity(t *testing.T) {
	var gotUser string
	var gotGroups []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("Impersonate-User")
		gotGroups = r.Header.Values("Impersonate-Group")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host, _ := url.Parse(upstream.URL)
	h := New(host, http.DefaultTransport, "/api/k8s", slog.New(slog.DiscardHandler),
		func(*http.Request) (Identity, bool) {
			return Identity{User: "openinfra:alice", Groups: []string{"openinfra:readers", "openinfra:users"}}, true
		})

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/k8s/api/v1/pods", nil))

	if gotUser != "openinfra:alice" {
		t.Errorf("Impersonate-User = %q, want %q", gotUser, "openinfra:alice")
	}
	if len(gotGroups) != 2 || gotGroups[0] != "openinfra:readers" {
		t.Errorf("Impersonate-Group = %v, want [openinfra:readers openinfra:users]", gotGroups)
	}
}

// A browser must never be able to choose who it is impersonating: client-supplied
// Impersonate-* headers are stripped before ours are applied.
func TestProxyStripsClientImpersonationHeaders(t *testing.T) {
	var gotUser string
	var gotGroups []string
	var gotExtra string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("Impersonate-User")
		gotGroups = r.Header.Values("Impersonate-Group")
		gotExtra = r.Header.Get("Impersonate-Extra-Scopes")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host, _ := url.Parse(upstream.URL)

	// No identity resolved (e.g. unauthenticated path): nothing may be impersonated.
	h := New(host, http.DefaultTransport, "/api/k8s", slog.New(slog.DiscardHandler), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/k8s/api/v1/secrets", nil)
	req.Header.Set("Impersonate-User", "system:admin")
	req.Header.Set("Impersonate-Group", "system:masters")
	req.Header.Set("Impersonate-Extra-Scopes", "everything")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotUser != "" || len(gotGroups) != 0 || gotExtra != "" {
		t.Errorf("client impersonation leaked: user=%q groups=%v extra=%q", gotUser, gotGroups, gotExtra)
	}

	// With an identity, ours replaces theirs — they cannot escalate to system:masters.
	h2 := New(host, http.DefaultTransport, "/api/k8s", slog.New(slog.DiscardHandler),
		func(*http.Request) (Identity, bool) {
			return Identity{User: "openinfra:alice", Groups: []string{"openinfra:readers"}}, true
		})
	req2 := httptest.NewRequest(http.MethodGet, "/api/k8s/api/v1/secrets", nil)
	req2.Header.Set("Impersonate-User", "system:admin")
	req2.Header.Set("Impersonate-Group", "system:masters")
	h2.ServeHTTP(httptest.NewRecorder(), req2)

	if gotUser != "openinfra:alice" {
		t.Errorf("Impersonate-User = %q, want openinfra:alice", gotUser)
	}
	for _, g := range gotGroups {
		if g == "system:masters" {
			t.Fatal("client-supplied system:masters group reached the API server")
		}
	}
}
