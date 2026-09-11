// Pure helpers for the lan-expose controller: EIP allocation out of a configured
// range, and the merge that keeps the default VPC's policyRoutes list in sync with
// the set of exposed pods. Kept dependency-free and side-effect-free so they can be
// unit-tested without a cluster.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
)

// ipRange is an inclusive [start,end] IPv4 range (e.g. .241–.249) that EIPs are
// auto-allocated from.
type ipRange struct {
	start uint32
	end   uint32
}

// parseIPRange parses "192.0.2.241-192.0.2.249" (or a single "…241").
func parseIPRange(s string) (ipRange, error) {
	s = strings.TrimSpace(s)
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		hi = lo
	}
	a := net.ParseIP(strings.TrimSpace(lo)).To4()
	b := net.ParseIP(strings.TrimSpace(hi)).To4()
	if a == nil || b == nil {
		return ipRange{}, fmt.Errorf("invalid IP range %q", s)
	}
	r := ipRange{start: binary.BigEndian.Uint32(a), end: binary.BigEndian.Uint32(b)}
	if r.start > r.end {
		return ipRange{}, fmt.Errorf("range start after end: %q", s)
	}
	return r, nil
}

func u32ToIP(u uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return net.IP(b[:]).String()
}

// contains reports whether ip (dotted quad) falls inside the range.
func (r ipRange) contains(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip)).To4()
	if p == nil {
		return false
	}
	u := binary.BigEndian.Uint32(p)
	return u >= r.start && u <= r.end
}

// allocate returns the lowest IP in the range not present in `used`. Deterministic
// (ascending) so repeated reconciles are stable. Returns "" if the range is full.
func (r ipRange) allocate(used map[string]bool) string {
	for u := r.start; u <= r.end; u++ {
		ip := u32ToIP(u)
		if !used[ip] {
			return ip
		}
	}
	return ""
}

// PolicyRoute mirrors one entry of vpc.spec.policyRoutes.
type PolicyRoute struct {
	Priority  int    `json:"priority"`
	Match     string `json:"match"`
	Action    string `json:"action"`
	NextHopIP string `json:"nextHopIP,omitempty"`
}

// ownedPolicyMatch is the exact match string this controller writes so a FIP pod's
// reply to the LAN egresses the external gateway (skipping the subnet's natOutgoing
// reroute) — see memory kube-ovn-lan-exposure. It is also the fingerprint used to
// recognise our own entries in the shared policyRoutes list.
func ownedPolicyMatch(podIP, lanCIDR string) string {
	return fmt.Sprintf("ip4.src == %s && ip4.dst == %s", podIP, lanCIDR)
}

// isOwnedPolicy reports whether a policyRoute was written by this controller: our
// priority, an "allow" action, and a match that targets the LAN CIDR from a single
// /32 pod source. This lets us reconcile only our own entries and never touch
// policyRoutes some other component added.
func isOwnedPolicy(p PolicyRoute, priority int, lanCIDR string) bool {
	return p.Priority == priority &&
		p.Action == "allow" &&
		strings.HasSuffix(strings.TrimSpace(p.Match), "&& ip4.dst == "+lanCIDR) &&
		strings.HasPrefix(strings.TrimSpace(p.Match), "ip4.src == ")
}

// mergePolicyRoutes returns the desired full policyRoutes list: every entry that is
// NOT ours is preserved verbatim, and our entries are replaced by exactly one
// per wanted pod IP. The result is sorted (by priority, then match) so the patch is
// stable and doesn't churn the VPC object on every poll.
func mergePolicyRoutes(existing []PolicyRoute, wantPodIPs []string, priority int, lanCIDR string) []PolicyRoute {
	out := make([]PolicyRoute, 0, len(existing)+len(wantPodIPs))
	for _, p := range existing {
		if !isOwnedPolicy(p, priority, lanCIDR) {
			out = append(out, p)
		}
	}
	seen := map[string]bool{}
	for _, ip := range wantPodIPs {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, PolicyRoute{
			Priority: priority,
			Match:    ownedPolicyMatch(ip, lanCIDR),
			Action:   "allow",
		})
	}
	return sortRoutes(out)
}

// sortRoutes returns a stable, canonically ordered copy (priority desc, then match).
// Used both to canonicalise the desired list and to compare against the live list so
// reconcile only patches the VPC when something actually changed.
func sortRoutes(routes []PolicyRoute) []PolicyRoute {
	out := append([]PolicyRoute(nil), routes...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Match < out[j].Match
	})
	return out
}

// policyRoutesEqual compares two lists order-insensitively (both are canonicalised
// by mergePolicyRoutes before comparison, so a plain elementwise compare suffices).
func policyRoutesEqual(a, b []PolicyRoute) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// resourceName builds the deterministic name for the OvnEip/OvnFip backing a given
// Service, e.g. lanexpose-default-otf-phoneformat. Kept DNS-label-safe and stable so
// reconcile is idempotent.
func resourceName(ns, svc string) string {
	return fmt.Sprintf("lanexpose-%s-%s", ns, svc)
}
