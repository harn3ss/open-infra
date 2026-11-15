// Package clientip is a request's source address as AWS's aws:SourceIp means it: the address the request
// came from, which the caller cannot choose.
//
// The platform's ingress (Traefik, on the nodes' host network) forwards LAN clients: it connects from its
// node's own address and puts the client's address in X-Forwarded-For, replacing any the client sent. So
// X-Forwarded-For is believed only from a node's address (or a CIDR the operator adds for a proxy in front
// of the cluster), and then only its last entry, the one that proxy added. Every other caller — a pod, a
// VM, a function, which reaches the service directly — is its peer address, whatever headers it sends:
// otherwise anything inside the cluster could claim any address and satisfy an aws:SourceIp condition.
package clientip

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type trustSet struct {
	ips  map[string]bool
	nets []*net.IPNet
}

var trusted atomic.Pointer[trustSet]

// Trust replaces the trusted proxy addresses: ips exactly, and any address in cidrs.
func Trust(ips []string, cidrs []*net.IPNet) {
	s := &trustSet{ips: map[string]bool{}, nets: cidrs}
	for _, ip := range ips {
		if p := net.ParseIP(strings.TrimSpace(ip)); p != nil {
			s.ips[p.String()] = true
		}
	}
	trusted.Store(s)
}

func isTrusted(ip net.IP) bool {
	s := trusted.Load()
	if s == nil || ip == nil {
		return false
	}
	if s.ips[ip.String()] {
		return true
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func peer(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// Of is r's source address: from a trusted proxy, the address it put last in X-Forwarded-For; from
// anyone else, the peer.
func Of(r *http.Request) string {
	p := peer(r)
	if !isTrusted(net.ParseIP(p)) {
		return p
	}
	vals := r.Header.Values("X-Forwarded-For")
	if len(vals) == 0 {
		return p
	}
	hops := strings.Split(strings.Join(vals, ","), ",")
	last := strings.TrimSpace(hops[len(hops)-1])
	if ip := net.ParseIP(last); ip != nil {
		return ip.String()
	}
	return p
}

// ParseCIDRs parses a comma-separated CIDR list (TRUSTED_PROXY_CIDRS), skipping and logging what doesn't
// parse.
func ParseCIDRs(s string, logger *slog.Logger) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range strings.Split(s, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			if logger != nil {
				logger.Warn("clientip: a trusted proxy CIDR does not parse; ignored", "cidr", c)
			}
			continue
		}
		out = append(out, n)
	}
	return out
}

// nodeAddresses is every node's InternalIP and ExternalIP.
func nodeAddresses(ctx context.Context, cs kubernetes.Interface) ([]string, error) {
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range nodes.Items {
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP || a.Type == corev1.NodeExternalIP {
				out = append(out, a.Address)
			}
		}
	}
	return out, nil
}

// WatchNodes trusts the cluster's node addresses (where the host-network ingress runs) and extra, loading
// them now and again every interval until ctx ends. Until a load succeeds nothing is trusted, so every
// request is its peer address: a refusal of a LAN client's IP condition, never a forged address.
func WatchNodes(ctx context.Context, cs kubernetes.Interface, extra []*net.IPNet, every time.Duration, logger *slog.Logger) {
	load := func() {
		lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		ips, err := nodeAddresses(lctx, cs)
		if err != nil {
			if logger != nil {
				logger.Warn("clientip: could not list the nodes; keeping the trusted proxies as they were", "err", err)
			}
			if trusted.Load() == nil {
				Trust(nil, extra)
			}
			return
		}
		Trust(ips, extra)
	}
	load()
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				load()
			}
		}
	}()
}
