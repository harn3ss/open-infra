package clientip

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func req(remote string, xff ...string) string {
	r := httptest.NewRequest("GET", "http://shim/", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return Of(r)
}

// A caller that isn't a trusted proxy is its peer address, whatever X-Forwarded-For it sends: a pod can't
// claim a LAN address to satisfy an aws:SourceIp condition.
func TestUntrustedPeerCannotClaimAnAddress(t *testing.T) {
	Trust([]string{"192.0.2.10"}, nil)
	if got := req("10.16.5.9:4000", "198.51.100.7"); got != "10.16.5.9" {
		t.Fatalf("a pod's forged X-Forwarded-For was believed: %s", got)
	}
	if got := req("10.16.5.9:4000"); got != "10.16.5.9" {
		t.Fatalf("peer: %s", got)
	}
}

// From the ingress's node, the address the ingress put last is the client's; an earlier entry (the
// client's own claim, had the proxy kept it) is not.
func TestTrustedProxyGivesItsLastEntry(t *testing.T) {
	Trust([]string{"192.0.2.10"}, nil)
	if got := req("192.0.2.10:5555", "198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("the ingress's client: %s", got)
	}
	if got := req("192.0.2.10:5555", "203.0.113.1, 198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("last hop: %s", got)
	}
	if got := req("192.0.2.10:5555", "203.0.113.1", "198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("last hop across header lines: %s", got)
	}
	if got := req("192.0.2.10:5555", "not-an-ip"); got != "192.0.2.10" {
		t.Fatalf("an unparseable entry: %s", got)
	}
	if got := req("192.0.2.10:5555"); got != "192.0.2.10" {
		t.Fatalf("no header: %s", got)
	}
}

// Nothing is trusted until the trusted set is loaded; CIDRs the operator adds are trusted.
func TestTrustCIDRsAndDefault(t *testing.T) {
	trusted.Store(nil)
	if got := req("192.0.2.10:1", "198.51.100.7"); got != "192.0.2.10" {
		t.Fatalf("trusted before any load: %s", got)
	}
	Trust(nil, ParseCIDRs("203.0.113.0/24, bogus", nil))
	if got := req("203.0.113.9:1", "198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("a CIDR proxy: %s", got)
	}
}

// The nodes' addresses become the trusted proxies.
func TestWatchNodes(t *testing.T) {
	trusted.Store(nil)
	cs := fake.NewClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"},
		Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.21"}, {Type: corev1.NodeHostName, Address: "n1"}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	WatchNodes(ctx, cs, nil, time.Hour, nil)
	if got := req("192.0.2.21:1", "198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("a node's forward: %s", got)
	}
	if got := req("192.0.2.22:1", "198.51.100.7"); got != "192.0.2.22" {
		t.Fatalf("a non-node: %s", got)
	}
}
