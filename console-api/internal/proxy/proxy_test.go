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
	h := New(host, http.DefaultTransport, "/api/k8s", slog.New(slog.DiscardHandler))

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
	h := New(host, http.DefaultTransport, "/api/k8s", slog.New(slog.DiscardHandler))

	req := httptest.NewRequest(http.MethodGet, "/api/k8s", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotPath != "/" {
		t.Errorf("forwarded path = %q, want %q", gotPath, "/")
	}
}
