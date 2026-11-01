package main

import (
	"net/http"
)

// Some endpoints on the shim's main port are for in-cluster callers only — today the VM credentials
// endpoint, which trades a VM's ServiceAccount token for role credentials. The shim's main port is also
// exposed to the LAN through an Ingress (the S3 virtual-host and path-style addresses), and that Ingress
// forwards every path. A request that came through the Ingress carries the proxy's forwarding headers
// (Traefik always sets X-Forwarded-For), so those headers mark it as external: an internal-only endpoint
// answers it 404, as if the path did not exist. An in-cluster caller has no reason to send these headers;
// one that does only locks itself out.
//
// The other non-AWS paths stay reachable from the LAN on purpose: /healthz (no data), /v1/ca-bundle
// (the public CA certificate), /ecr/token (docker login from a workstation), the API Gateway data plane,
// Cognito's JWKS/discovery and anonymous user ops, and STS AssumeRoleWithWebIdentity (external OIDC
// tokens) — each is public on AWS too, or authenticates its own credential.

// proxyHeaders are the headers an HTTP reverse proxy adds to a forwarded request.
var proxyHeaders = []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Real-Ip", "Forwarded"}

// cameThroughProxy reports whether a request carries any proxy forwarding header, even an empty one.
func cameThroughProxy(r *http.Request) bool {
	for _, h := range proxyHeaders {
		if _, ok := r.Header[http.CanonicalHeaderKey(h)]; ok {
			return true
		}
	}
	return false
}

// refuseIfProxied answers 404 to a request that came through a proxy, and reports whether it did. An
// internal-only endpoint calls it first.
func refuseIfProxied(w http.ResponseWriter, r *http.Request) bool {
	if !cameThroughProxy(r) {
		return false
	}
	http.NotFound(w, r)
	return true
}
