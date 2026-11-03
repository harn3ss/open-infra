package main

// Which origins an API Gateway HTTP / HTTP_PROXY integration may reach, and what it may send them.
//
// An HTTP integration forwards a caller's request to a URI its API's owner chose. Inside the cluster
// that URI could name a platform service — one that trusts identity headers set by the platform
// (open-appsync's X-OpenInfra-User, Trino's X-Trino-User), or one with no authentication at all — and
// the request would arrive from the shim, carrying whatever headers the caller sent. On AWS an API's
// HTTP integration reaches the internet; a VPC's private addresses only through a VPC link.
//
// So, here: an HTTP integration reaches public and LAN origins only, never a cluster address. Its URI
// is refused when it is made if its host is a cluster name (*.svc, *.cluster.local, a single label)
// or a cluster, loopback, link-local or unspecified address; and every connection is checked again
// when it is dialled — after DNS resolution, and for each redirect — so a public name that resolves
// to a cluster address, or redirects to one, is refused too. The platform's identity headers are never
// forwarded, whatever the caller sent: they mean something only when the platform sets them.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// defaultClusterCIDRs are the install's pod network, Service network and kube-ovn join subnet (install.sh),
// and the k3s default pod CIDR. APIGW_ORIGIN_DENY_CIDRS (comma-separated) adds more, e.g. tenant subnets.
var defaultClusterCIDRs = []string{"10.16.0.0/16", "10.43.0.0/16", "100.64.0.0/16", "10.42.0.0/16"}

type originGuard struct {
	deny []*net.IPNet
	// allowLoopback lets tests reach an httptest origin; never set outside tests.
	allowLoopback bool
	resolver      *net.Resolver
}

func newOriginGuard() *originGuard {
	g := &originGuard{resolver: net.DefaultResolver}
	cidrs := append([]string(nil), defaultClusterCIDRs...)
	if extra := os.Getenv("APIGW_ORIGIN_DENY_CIDRS"); extra != "" {
		cidrs = append(cidrs, strings.Split(extra, ",")...)
	}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			g.deny = append(g.deny, n)
		}
	}
	return g
}

var errOriginInsidePlatform = errors.New("the integration's origin is inside the platform (a cluster name or address); an HTTP integration reaches public and LAN origins only")

// deniedIP reports whether an integration may not connect to ip.
func (g *originGuard) deniedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() {
		return !g.allowLoopback
	}
	if ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, n := range g.deny {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clusterHostname reports whether host is a name the cluster's DNS answers (a Service name, the cluster
// domain, a bare label resolved through the search domains), or localhost.
func clusterHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	switch {
	case h == "" || h == "localhost" || strings.HasSuffix(h, ".localhost"):
		return true
	case strings.HasSuffix(h, ".svc") || strings.Contains(h, ".svc.") || strings.HasSuffix(h, ".cluster.local") || strings.HasSuffix(h, ".internal"):
		return true
	case !strings.Contains(h, "."):
		return true
	}
	return false
}

// checkURI refuses, when an integration is made, a URI that is not http(s) or whose host is inside the
// platform. A name is resolved again when the request is sent (dialContext), so this is the early refusal.
func (g *originGuard) checkURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("an HTTP integration requires an http(s) uri with a host")
	}
	if u.User != nil {
		return errors.New("an HTTP integration's uri may not carry credentials")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if g.deniedIP(ip) {
			return errOriginInsidePlatform
		}
		return nil
	}
	if clusterHostname(host) {
		return errOriginInsidePlatform
	}
	return nil
}

// dialContext connects only to an address the guard allows: the host is resolved here, and the
// connection made to an allowed address it resolved to (so a lookup cannot be swapped in between).
func (g *originGuard) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		if clusterHostname(host) {
			return nil, errOriginInsidePlatform
		}
		addrs, err := g.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	var lastErr error = errOriginInsidePlatform
	for _, ip := range ips {
		if g.deniedIP(ip) {
			continue
		}
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// client is the HTTP client HTTP integrations use: every connection guarded, redirects re-checked, no proxy
// from the environment (a proxy would dial on the integration's behalf).
func (g *originGuard) client(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           g.dialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if err := g.checkURI(req.URL.String()); err != nil {
				return fmt.Errorf("redirect refused: %w", err)
			}
			return nil
		},
	}
}

// platformIdentityHeader reports whether a header carries an identity the platform's own services trust
// when the platform sets it — never forwarded from a caller to an integration's origin.
func platformIdentityHeader(name string) bool {
	k := strings.ToLower(name)
	for _, p := range []string{"x-openinfra-", "x-trino-", "x-presto-", "impersonate-", "x-remote-", "x-forwarded-user", "x-forwarded-groups", "x-forwarded-email", "x-auth-request-"} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}
