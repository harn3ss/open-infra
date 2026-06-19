// Package proxy exposes the Kubernetes API server to the browser as a same-origin
// reverse proxy. The browser never sees cluster credentials: this handler injects
// the ServiceAccount's TLS + bearer token (via the authenticated transport from
// package k8s) onto every forwarded request.
//
// All HTTP methods (GET/POST/PUT/PATCH/DELETE) and query parameters pass through
// unchanged, so this single handler covers the full CRUD surface. Authorization
// is delegated entirely to the ServiceAccount's RBAC — if the SA can't do it, the
// API server returns 403 and we faithfully relay that.
package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// New returns an http.Handler that reverse-proxies requests to the API server at
// host, using transport for authentication. stripPrefix (e.g. "/api/k8s") is
// removed from the inbound path before forwarding, so that
//
//	/api/k8s/apis/openinfra.dev/v1/...  ->  <host>/apis/openinfra.dev/v1/...
//
// The handler is mounted in the router under the same prefix it strips.
func New(host *url.URL, transport http.RoundTripper, stripPrefix string, logger *slog.Logger) http.Handler {
	rp := &httputil.ReverseProxy{
		// Rewrite is the modern (Go 1.20+) replacement for Director: it sets the
		// outbound target and preserves inbound query params automatically.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(host) // scheme + host of the API server

			// Strip the BFF-local prefix so the remaining path is a genuine
			// Kubernetes API path. SetURL joins host with pr.Out.URL.Path, so we
			// mutate the outbound path here.
			trimmed := strings.TrimPrefix(pr.In.URL.Path, stripPrefix)
			if trimmed == "" {
				trimmed = "/"
			} else if !strings.HasPrefix(trimmed, "/") {
				trimmed = "/" + trimmed
			}
			pr.Out.URL.Path = trimmed
			// RawPath must stay consistent with Path for any escaped segments.
			pr.Out.URL.RawPath = ""

			// Query is already carried over from the inbound request by SetURL;
			// nothing to do for params.

			// Host header should match the upstream so TLS SNI / virtual hosting
			// behave. The Authorization header and TLS are added by transport.
			pr.Out.Host = host.Host

			// Drop any client-supplied auth/forwarding headers so the browser
			// can never smuggle credentials or spoof its origin to the API
			// server; the transport is the sole source of authentication.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Upstream/transport failure (DNS, TLS, connection reset). The API
			// server's own 4xx/5xx responses are NOT errors and flow through the
			// normal response path; this only fires for proxy-level failures.
			logger.Error("k8s reverse proxy error",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("error", err.Error()),
			)
			http.Error(w, "upstream Kubernetes API error", http.StatusBadGateway)
		},
	}
	return rp
}
