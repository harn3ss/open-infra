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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
)

// New returns an http.Handler that reverse-proxies requests to the API server at
// host, using transport for authentication. stripPrefix (e.g. "/api/k8s") is
// removed from the inbound path before forwarding, so that
//
//	/api/k8s/apis/openinfra.dev/v1/...  ->  <host>/apis/openinfra.dev/v1/...
//
// The handler is mounted in the router under the same prefix it strips.
// Identity is the console user a proxied request should act as. When supplied,
// the request is sent to the API server with Impersonate-* headers so Kubernetes
// RBAC — not the console — decides what the user may do.
type Identity struct {
	User   string
	Groups []string
}

// IdentityFunc resolves the signed-in user from an inbound request. Return
// ok=false to forward with the ServiceAccount's own rights (no impersonation).
type IdentityFunc func(*http.Request) (Identity, bool)

func New(host *url.URL, transport http.RoundTripper, stripPrefix string, logger *slog.Logger, identity IdentityFunc) http.Handler {
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

			// Impersonation is set by US, never by the caller: strip any
			// client-supplied Impersonate-* headers first, or a browser could ask
			// the API server to act as any user it likes.
			pr.Out.Header.Del("Impersonate-User")
			pr.Out.Header.Del("Impersonate-Uid")
			pr.Out.Header.Del("Impersonate-Group")
			for k := range pr.Out.Header {
				if strings.HasPrefix(http.CanonicalHeaderKey(k), "Impersonate-") {
					pr.Out.Header.Del(k)
				}
			}

			// Act as the signed-in console user so Kubernetes RBAC applies to them
			// rather than to the console's ServiceAccount.
			if identity != nil {
				if id, ok := identity(pr.In); ok && id.User != "" {
					pr.Out.Header.Set("Impersonate-User", id.User)
					for _, g := range id.Groups {
						pr.Out.Header.Add("Impersonate-Group", g)
					}
				}
			}
		},
		Transport: transport,
		// A group the console isn't allowed to impersonate produces a 403 that blames
		// the ServiceAccount ("system:serviceaccount:... cannot impersonate resource
		// groups"), which reads like a console bug and says nothing about what to do.
		// It actually means a kind: Group used a name outside the impersonator
		// ClusterRole's resourceNames — a deliberate privilege ceiling. Rewrite the
		// message so the person hitting it can act on it.
		ModifyResponse: explainImpersonationDenial,
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

// explainImpersonationDenial rewrites the API server's impersonation 403 into an
// actionable message. It only touches responses that are unambiguously this case —
// a 403 naming an impersonate denial on "groups" — and leaves every other status,
// including ordinary RBAC denials, exactly as the API server sent them.
func explainImpersonationDenial(resp *http.Response) error {
	if resp.StatusCode != http.StatusForbidden {
		return nil
	}
	// Bounded read: a Status object is small, and we must not buffer a large body.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	restore := func() {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	var st struct {
		Message string `json:"message"`
		Details struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
		} `json:"details"`
	}
	if json.Unmarshal(body, &st) != nil ||
		!strings.Contains(st.Message, "cannot impersonate") ||
		st.Details.Kind != "groups" {
		restore()
		return nil
	}

	var out map[string]any
	if json.Unmarshal(body, &out) != nil {
		restore()
		return nil
	}
	out["message"] = fmt.Sprintf(
		"the console is not permitted to impersonate the group %q. A kind: Group only takes "+
			"effect if its name is listed in the open-infra-console-impersonator ClusterRole — "+
			"an intentional ceiling on what any Group can grant. Either use a built-in group "+
			"(admins, powerusers, readers) or have an operator add %q to that ClusterRole.",
		st.Details.Name, st.Details.Name)
	nb, err := json.Marshal(out)
	if err != nil {
		restore()
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(nb))
	resp.ContentLength = int64(len(nb))
	resp.Header.Set("Content-Length", strconv.Itoa(len(nb)))
	return nil
}
