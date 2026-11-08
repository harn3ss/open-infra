package render

import (
	"strings"
	"testing"
)

// A connection a cluster node makes itself (an operator working on a node, or a host-network pod)
// reaches a pod from the node's join-subnet address: kube-proxy masquerades it, and the node enters
// the pod network through its join port. So a SecurityGroup ingress cidr that names a node's LAN
// address must also admit that node's join address, or the rule never matches the node it names.
// These tests pin that mapping: the named node only, never another node, never when the cidr
// already covers the join address, and the node fetch is requested only when a cidr needs it.

const sgCompositionPath = "../../platform/abstraction/securitygroup-composition.yaml"

// sgNode is one fetched Node as the go-templating function exposes it under .extraResources.
func sgNode(name, joinIP string, addrs ...string) map[string]any {
	ann := map[string]any{}
	if joinIP != "" {
		ann["ovn.kubernetes.io/ip_address"] = joinIP
	}
	var as []any
	for i, a := range addrs {
		typ := "InternalIP"
		if i > 0 {
			typ = "ExternalIP"
		}
		as = append(as, map[string]any{"type": typ, "address": a})
	}
	as = append(as, map[string]any{"type": "Hostname", "address": name})
	return map[string]any{"resource": map[string]any{
		"metadata": map[string]any{"name": name, "annotations": ann},
		"status":   map[string]any{"addresses": as},
	}}
}

// sgNodes is a small cluster on documentation addresses (RFC 5737), with kube-ovn's default join
// subnet: two joined nodes, one not yet joined (no join annotation), one IPv6-only node.
func sgNodes() map[string]any {
	return map[string]any{"nodes": map[string]any{"items": []any{
		sgNode("node-a", "100.64.0.6", "192.0.2.10"),
		sgNode("node-b", "100.64.0.7", "192.0.2.20"),
		sgNode("node-c", "", "192.0.2.30"),
		sgNode("node-d", "fd00:100:64::8", "2001:db8::12"),
	}}}
}

// sgIngressCtx is a SecurityGroup with one ingress rule on port 22 from the given cidrs.
func sgIngressCtx(extra map[string]any, cidrs ...string) map[string]any {
	var from []any
	for _, c := range cidrs {
		from = append(from, map[string]any{"cidr": c})
	}
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": map[string]any{"ingress": []any{map[string]any{"ports": []any{22}, "from": from}}},
		"metadata": map[string]any{"labels": map[string]any{
			"crossplane.io/claim-name": "ssh-admin", "crossplane.io/claim-namespace": "team-a",
		}},
	}}}}
	if extra != nil {
		ctx["extraResources"] = extra
	}
	return ctx
}

func TestSecurityGroup_CidrNamingANodeAdmitsItsJoinAddress(t *testing.T) {
	tmpl := extractInlineTemplate(t, sgCompositionPath)
	cases := []struct {
		name     string
		cidrs    []string
		want     []string // cidrs the rule must admit
		wantNot  []string // cidrs it must not admit
		wantOnce string   // a join cidr that must appear exactly once
	}{
		{name: "a node's /32 admits that node's join address only",
			cidrs: []string{"192.0.2.10/32"}, want: []string{"192.0.2.10/32", "100.64.0.6/32"}, wantNot: []string{"100.64.0.7/32"}},
		{name: "a LAN range admits every joined node inside it",
			cidrs: []string{"192.0.2.0/24"}, want: []string{"192.0.2.0/24", "100.64.0.6/32", "100.64.0.7/32"}},
		{name: "a cidr naming no node adds nothing",
			cidrs: []string{"198.51.100.0/24"}, want: []string{"198.51.100.0/24"}, wantNot: []string{"100.64.0.6/32", "100.64.0.7/32"}},
		{name: "0.0.0.0/0 already covers join addresses",
			cidrs: []string{"0.0.0.0/0"}, want: []string{"0.0.0.0/0"}, wantNot: []string{"100.64.0.6/32", "100.64.0.7/32"}},
		{name: "two cidrs naming one node admit its join address once",
			cidrs: []string{"192.0.2.10/32", "192.0.2.8/29"}, want: []string{"192.0.2.10/32", "192.0.2.8/29", "100.64.0.6/32"}, wantNot: []string{"100.64.0.7/32"}, wantOnce: "100.64.0.6/32"},
		{name: "IPv6 and non-canonical cidrs are kept but never mapped",
			cidrs: []string{"2001:db8::/64", "192.0.002.10/32"}, want: []string{"2001:db8::/64", "192.0.002.10/32"}, wantNot: []string{"100.64.0.6/32", "fd00:100:64::8"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := render(t, tmpl, sgIngressCtx(sgNodes(), c.cidrs...))
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("rule from %v must admit %s; got:\n%s", c.cidrs, w, grepCtx(out, "ingress:"))
				}
			}
			for _, w := range c.wantNot {
				if strings.Contains(out, w) {
					t.Errorf("rule from %v must not admit %s; got:\n%s", c.cidrs, w, grepCtx(out, w))
				}
			}
			if c.wantOnce != "" {
				if n := strings.Count(out, "cidr: "+c.wantOnce+"\n"); n != 1 {
					t.Errorf("%s must appear once, appeared %d times; got:\n%s", c.wantOnce, n, out)
				}
			}
			// Every rule keeps its port: the join address is admitted on the rule's ports only.
			if !strings.Contains(out, "port: 22") {
				t.Errorf("the rule must keep port 22; got:\n%s", grepCtx(out, "ports"))
			}
		})
	}
}

// The node fetch is requested only by a group with a cidr narrower than 0.0.0.0/0, so a group
// without one never depends on Crossplane's read access to nodes. Before the nodes are observed
// (the first reconcile), the declared cidrs still render, unchanged.
func TestSecurityGroup_NodeFetchOnlyWhenACidrNeedsIt(t *testing.T) {
	tmpl := extractInlineTemplate(t, sgCompositionPath)
	const fetch = "kind: ExtraResources"

	first := render(t, tmpl, sgIngressCtx(nil, "192.0.2.10/32"))
	if !strings.Contains(first, fetch) || !strings.Contains(first, "kind: Node") {
		t.Errorf("a narrow cidr must request the nodes; got:\n%s", grepCtx(first, "ExtraResources"))
	}
	if !strings.Contains(first, "cidr: 192.0.2.10/32\n") || strings.Contains(first, "100.64.") {
		t.Errorf("before the nodes are observed only the declared cidr renders; got:\n%s", grepCtx(first, "ingress:"))
	}

	for name, ctx := range map[string]map[string]any{
		"0.0.0.0/0 only":   sgIngressCtx(sgNodes(), "0.0.0.0/0"),
		"IPv6 only":        sgIngressCtx(sgNodes(), "2001:db8::/64"),
		"security groups":  {"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{"spec": map[string]any{"ingress": []any{map[string]any{"from": []any{map[string]any{"securityGroup": "web"}}}}}, "metadata": map[string]any{}}}}},
		"no ingress rules": sgCtx(false),
	} {
		if out := render(t, tmpl, ctx); strings.Contains(out, fetch) {
			t.Errorf("%s: no cidr needs the nodes, so none may be requested; got:\n%s", name, grepCtx(out, "ExtraResources"))
		}
	}
}

// Egress cidrs name destinations as the pod sees them, so they are never mapped.
func TestSecurityGroup_EgressCidrIsNotMapped(t *testing.T) {
	tmpl := extractInlineTemplate(t, sgCompositionPath)
	ctx := map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec":     map[string]any{"egress": []any{map[string]any{"ports": []any{443}, "to": []any{map[string]any{"cidr": "192.0.2.10/32"}}}}},
		"metadata": map[string]any{},
	}}}, "extraResources": sgNodes()}
	out := render(t, tmpl, ctx)
	if !strings.Contains(out, "cidr: 192.0.2.10/32\n") || strings.Contains(out, "100.64.0.6") {
		t.Errorf("egress must render the declared cidr only; got:\n%s", grepCtx(out, "egress:"))
	}
}

// A group with an empty ingress — what CloudFormation emits for an AWS group with no inbound rules (#374) —
// restricts inbound: its NetworkPolicy selects Ingress and allows only the console, never "everything". A
// rule of protocol ALL (AWS IpProtocol -1) renders with no ports: every protocol, every port.
func TestSecurityGroup_EmptyIngressDeniesInbound(t *testing.T) {
	tmpl := extractInlineTemplate(t, sgCompositionPath)
	ctx := sgCtx(false)
	spec := ctx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["spec"].(map[string]any)
	spec["ingress"] = []any{}
	spec["egress"] = []any{map[string]any{"protocol": "ALL", "to": []any{map[string]any{"cidr": "0.0.0.0/0"}}}}
	out := render(t, tmpl, ctx)
	if !strings.Contains(out, "- Ingress") {
		t.Fatalf("an empty ingress must restrict inbound (policyTypes Ingress):\n%s", out)
	}
	if !strings.Contains(out, "open-infra-console") {
		t.Errorf("only the console is admitted:\n%s", out)
	}
	np := out[strings.Index(out, "kind: NetworkPolicy"):]
	egress := np[strings.Index(np, "egress:"):]
	if strings.Contains(egress, "protocol: ALL") {
		t.Errorf("protocol ALL must not reach the NetworkPolicy (it is every protocol: no ports):\n%s", egress)
	}
	if !strings.Contains(egress, "cidr: 0.0.0.0/0") {
		t.Errorf("the ALL rule's destination must render:\n%s", egress)
	}
}

// A rule with no ports is every port of its protocol, as an AWS rule is (tcp 0-65535 is TCP only): it renders
// a NetworkPolicy port of that protocol and no number. Rendered with no ports at all it would allow every
// protocol. Only protocol ALL (AWS -1) is every protocol.
func TestSecurityGroup_PortlessRuleKeepsItsProtocol(t *testing.T) {
	tmpl := extractInlineTemplate(t, sgCompositionPath)
	ctx := sgCtx(false)
	spec := ctx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["spec"].(map[string]any)
	spec["ingress"] = []any{map[string]any{"protocol": "UDP", "from": []any{map[string]any{"cidr": "10.0.0.0/8"}}}}
	spec["egress"] = []any{map[string]any{"to": []any{map[string]any{"cidr": "10.0.0.0/8"}}}} // protocol defaults to TCP
	out := render(t, tmpl, ctx)
	np := out[strings.Index(out, "kind: NetworkPolicy"):]
	ing := np[strings.Index(np, "ingress:"):strings.Index(np, "egress:")]
	if !strings.Contains(ing, "protocol: UDP") {
		t.Errorf("a port-less UDP rule must stay UDP:\n%s", ing)
	}
	eg := np[strings.Index(np, "egress:"):]
	if !strings.Contains(eg, "protocol: TCP") {
		t.Errorf("a port-less rule with the default protocol must stay TCP:\n%s", eg)
	}
}
