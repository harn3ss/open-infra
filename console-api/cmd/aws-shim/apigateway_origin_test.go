package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// An HTTP integration's URI may name public and LAN origins only: a cluster Service name, a cluster
// address, loopback, link-local (the instance-metadata address) or a URI carrying credentials is refused
// when the integration is made.
func TestAPIGWOrigin_RefusesPlatformTargets(t *testing.T) {
	g := newOriginGuard()
	for _, u := range []string{
		"http://open-appsync.open-infra-appsync.svc:8080/graphql",
		"http://trino.query.svc.cluster.local:8080/v1/statement",
		"http://minio/",
		"http://localhost:9000/",
		"http://127.0.0.1:4566/",
		"http://10.43.0.10/",
		"http://10.16.0.25:8080/",
		"http://100.64.0.2/",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/",
		"http://[fe80::1]/",
		"http://[::ffff:10.43.0.1]/",
		"http://0.0.0.0/",
		"http://user:pass@example.com/",
		"ftp://example.com/",
		"http://ip-10-16-0-5.ec2.internal/",
	} {
		if err := g.checkURI(u); err == nil {
			t.Errorf("checkURI(%q) = nil, want a refusal", u)
		}
	}
	for _, u := range []string{"https://example.com/api", "http://192.0.2.10:8080/", "http://172.20.5.5/", "https://api.example.org"} {
		if err := g.checkURI(u); err != nil {
			t.Errorf("checkURI(%q) = %v, want allowed", u, err)
		}
	}
}

// The check is made again when a connection is dialled — a name that resolves to a cluster address is
// refused there, so a public name cannot be pointed at the platform after the integration is made.
func TestAPIGWOrigin_DialRefusesClusterAddresses(t *testing.T) {
	g := newOriginGuard()
	for _, addr := range []string{"127.0.0.1:80", "10.43.0.1:443", "169.254.169.254:80", "[::1]:80", "minio:9000", "foo.bar.svc:80"} {
		if c, err := g.dialContext(context.Background(), "tcp", addr); err == nil {
			c.Close()
			t.Errorf("dialContext(%q) connected, want refused", addr)
		}
	}
}

func newOriginTestHandler() *apigwV1Handler {
	return newAPIGWV1Handler(nil, "ns", "fn", "svc", "", nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// A caller's platform identity headers are never forwarded to an integration's origin: open-appsync and
// Trino trust them only because the platform sets them.
func TestAPIGWProxy_DoesNotForwardIdentityHeaders(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer origin.Close()
	h := newOriginTestHandler()
	h.origins.allowLoopback = true // httptest listens on loopback
	for name, call := range map[string]func(w http.ResponseWriter, r *http.Request){
		"HTTP_PROXY": func(w http.ResponseWriter, r *http.Request) {
			h.proxyHTTP(w, r, restIntegration{Type: "HTTP_PROXY", URI: origin.URL}, "/", nil, "req")
		},
		"HTTP": func(w http.ResponseWriter, r *http.Request) {
			h.invokeHTTPIntegration(w, r, restIntegration{Type: "HTTP", URI: origin.URL}, "api", "prod", "/", "req", nil, nil, []byte("{}"))
		},
	} {
		r := httptest.NewRequest("POST", "http://apigw/prod/", strings.NewReader("{}"))
		r.Header.Set("X-OpenInfra-User", "admin")
		r.Header.Set("X-OpenInfra-Groups", "admins")
		r.Header.Set("X-Trino-User", "admin")
		r.Header.Set("Impersonate-User", "system:admin")
		r.Header.Set("X-App-Header", "kept")
		w := httptest.NewRecorder()
		call(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: status %d, want 200 (%s)", name, w.Code, w.Body.String())
		}
		mu.Lock()
		for _, k := range []string{"X-Openinfra-User", "X-Openinfra-Groups", "X-Trino-User", "Impersonate-User"} {
			if got.Get(k) != "" {
				t.Errorf("%s: the origin received %s=%q", name, k, got.Get(k))
			}
		}
		if got.Get("X-App-Header") != "kept" {
			t.Errorf("%s: an ordinary header was not forwarded", name)
		}
		mu.Unlock()
	}
}

// By default an integration cannot reach a loopback (or any cluster) origin even when one was stored
// before this check existed: the connection is refused when dialled, and nothing reaches the origin.
func TestAPIGWProxy_RefusesLoopbackOriginWhenDialled(t *testing.T) {
	hit := false
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer origin.Close()
	h := newOriginTestHandler()
	r := httptest.NewRequest("GET", "http://apigw/prod/", nil)
	w := httptest.NewRecorder()
	h.proxyHTTP(w, r, restIntegration{Type: "HTTP_PROXY", URI: origin.URL}, "/", nil, "req")
	if hit || w.Code != http.StatusBadGateway {
		t.Fatalf("a loopback origin was reached (hit=%v, status %d)", hit, w.Code)
	}
	if ip := net.ParseIP("::ffff:127.0.0.1"); !h.origins.deniedIP(ip) {
		t.Errorf("an IPv4-mapped loopback address must be refused")
	}
}
