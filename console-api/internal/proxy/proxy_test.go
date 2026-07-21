package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
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

// The impersonation-denial rewrite must fire for exactly one shape of 403 and be
// invisible for every other response — including ordinary RBAC denials, which the
// console relies on passing through verbatim.
func TestExplainImpersonationDenial(t *testing.T) {
	mk := func(code int, body string) *http.Response {
		return &http.Response{
			StatusCode: code,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(body)),
		}
	}
	read := func(r *http.Response) string {
		b, _ := io.ReadAll(r.Body)
		return string(b)
	}

	impersonate := `{"kind":"Status","code":403,"message":"groups \"openinfra:devs\" is forbidden: User \"system:serviceaccount:open-infra-console:console\" cannot impersonate resource \"groups\" in API group \"\" at the cluster scope","details":{"name":"openinfra:devs","kind":"groups"}}`
	resp := mk(403, impersonate)
	if err := explainImpersonationDenial(resp); err != nil {
		t.Fatal(err)
	}
	got := read(resp)
	if !strings.Contains(got, "open-infra-console-impersonator") || !strings.Contains(got, "openinfra:devs") {
		t.Fatalf("message not rewritten: %s", got)
	}
	if !strings.Contains(got, `"kind":"Status"`) {
		t.Fatalf("rewrite dropped the Status envelope, breaking client error handling: %s", got)
	}
	if resp.Header.Get("Content-Length") != strconv.Itoa(len(got)) {
		t.Fatalf("Content-Length %q does not match body length %d", resp.Header.Get("Content-Length"), len(got))
	}

	// An ordinary RBAC denial must survive byte-for-byte.
	rbac := `{"kind":"Status","code":403,"message":"virtualmachines.openinfra.dev is forbidden: User \"openinfra:alice\" cannot list resource","details":{"kind":"virtualmachines"}}`
	resp = mk(403, rbac)
	if err := explainImpersonationDenial(resp); err != nil {
		t.Fatal(err)
	}
	if read(resp) != rbac {
		t.Fatal("an ordinary RBAC 403 was modified")
	}

	// Non-403s are not even parsed.
	ok := `{"items":[]}`
	resp = mk(200, ok)
	if err := explainImpersonationDenial(resp); err != nil {
		t.Fatal(err)
	}
	if read(resp) != ok {
		t.Fatal("a 200 response was modified")
	}

	// Malformed bodies must pass through rather than blank the response.
	junk := `not json`
	resp = mk(403, junk)
	if err := explainImpersonationDenial(resp); err != nil {
		t.Fatal(err)
	}
	if read(resp) != junk {
		t.Fatal("a malformed 403 body was not preserved")
	}
}
