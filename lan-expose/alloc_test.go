package main

import "testing"

// Tests use RFC5737 TEST-NET-1 (192.0.2.0/24) example addresses — never a real site
// range (this repo is public).

func TestParseIPRangeAndAllocate(t *testing.T) {
	r, err := parseIPRange("192.0.2.241-192.0.2.243")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := r.allocate(map[string]bool{}); got != "192.0.2.241" {
		t.Fatalf("first alloc = %q, want .241", got)
	}
	used := map[string]bool{"192.0.2.241": true, "192.0.2.242": true}
	if got := r.allocate(used); got != "192.0.2.243" {
		t.Fatalf("alloc with two used = %q, want .243", got)
	}
	full := map[string]bool{"192.0.2.241": true, "192.0.2.242": true, "192.0.2.243": true}
	if got := r.allocate(full); got != "" {
		t.Fatalf("alloc when full = %q, want empty", got)
	}
}

func TestParseIPRangeSingleAndErrors(t *testing.T) {
	if r, err := parseIPRange("192.0.2.241"); err != nil || r.start != r.end {
		t.Fatalf("single ip range: %v (start==end? %v)", err, r.start == r.end)
	}
	if _, err := parseIPRange("192.0.2.9-192.0.2.1"); err == nil {
		t.Fatalf("reversed range should error")
	}
	if _, err := parseIPRange("not-an-ip"); err == nil {
		t.Fatalf("garbage should error")
	}
}

func TestRangeContains(t *testing.T) {
	r, _ := parseIPRange("192.0.2.241-192.0.2.249")
	if !r.contains("192.0.2.245") {
		t.Fatal(".245 should be in range")
	}
	if r.contains("192.0.2.250") {
		t.Fatal(".250 (LRP) must be out of range")
	}
	if r.contains("192.0.2.240") {
		t.Fatal(".240 (MetalLB) must be out of range")
	}
}

func TestMergePolicyRoutesPreservesForeignAndReplacesOwn(t *testing.T) {
	cidrs := []string{"192.0.2.0/24"}
	const prio = 29500
	existing := []PolicyRoute{
		{Priority: 31000, Match: "ip4.dst == 100.64.0.0/16", Action: "allow"},                      // foreign, keep
		{Priority: prio, Match: ownedPolicyMatch("10.16.0.5", "192.0.2.0/24"), Action: "allow"},    // ours, stale — drop
		{Priority: prio, Match: ownedPolicyMatch("10.16.0.5", "198.51.100.0/24"), Action: "allow"}, // ours, stale for a now-removed CIDR — still dropped (shape-recognised)
	}
	got := mergePolicyRoutes(existing, []string{"10.16.112.153", "10.16.112.153", ""}, prio, cidrs)
	var foreign, ours int
	for _, p := range got {
		if p.Priority == 31000 {
			foreign++
		}
		if isOwnedPolicy(p, prio) {
			ours++
		}
	}
	if foreign != 1 {
		t.Fatalf("foreign policy not preserved: %+v", got)
	}
	if ours != 1 { // deduped pod IP × 1 CIDR, both stale ours removed (incl. the removed-CIDR one)
		t.Fatalf("want exactly 1 owned policy, got %d: %+v", ours, got)
	}
	for _, p := range got {
		if isOwnedPolicy(p, prio) && p.Match != ownedPolicyMatch("10.16.112.153", "192.0.2.0/24") {
			t.Fatalf("owned policy has wrong match: %q", p.Match)
		}
	}
}

// Two return-path CIDRs → one owned allow route per (pod IP × CIDR), so a reply to
// either VLAN takes the allow path (polyhedron #126 residual 2).
func TestMergePolicyRoutesMultiCIDR(t *testing.T) {
	cidrs := []string{"10.0.10.0/24", "10.0.20.0/24"}
	const prio = 29500
	got := mergePolicyRoutes(nil, []string{"10.16.1.7"}, prio, cidrs)
	want := map[string]bool{
		ownedPolicyMatch("10.16.1.7", "10.0.10.0/24"): false,
		ownedPolicyMatch("10.16.1.7", "10.0.20.0/24"): false,
	}
	if len(got) != 2 {
		t.Fatalf("want 2 routes (1 pod × 2 CIDRs), got %d: %+v", len(got), got)
	}
	for _, p := range got {
		if !isOwnedPolicy(p, prio) {
			t.Fatalf("route not recognised as owned: %+v", p)
		}
		if _, ok := want[p.Match]; !ok {
			t.Fatalf("unexpected match %q", p.Match)
		}
		want[p.Match] = true
	}
	for m, seen := range want {
		if !seen {
			t.Fatalf("missing expected route %q", m)
		}
	}
}

func TestMergePolicyRoutesStableAndEqual(t *testing.T) {
	cidrs := []string{"192.0.2.0/24"}
	const prio = 29500
	a := mergePolicyRoutes(nil, []string{"10.16.0.9", "10.16.0.3"}, prio, cidrs)
	b := mergePolicyRoutes(nil, []string{"10.16.0.3", "10.16.0.9"}, prio, cidrs)
	if !policyRoutesEqual(a, b) {
		t.Fatalf("merge not order-stable:\n a=%+v\n b=%+v", a, b)
	}
	// removing all wanted IPs clears our entries but keeps foreign ones
	foreign := []PolicyRoute{{Priority: 10, Match: "x", Action: "reroute", NextHopIP: "1.2.3.4"}}
	cleared := mergePolicyRoutes(append(foreign, a...), nil, prio, cidrs)
	if len(cleared) != 1 || cleared[0].Priority != 10 {
		t.Fatalf("clearing should leave only the foreign route, got %+v", cleared)
	}
}

func TestSameCIDRSet(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{[]string{"10.0.10.0/24", "10.0.20.0/24"}, []string{"10.0.20.0/24", "10.0.10.0/24"}, true}, // order-insensitive
		{[]string{"10.0.10.0/24"}, []string{"10.0.10.0/24", "10.0.20.0/24"}, false},                // drift: CIDR added
		{[]string{"10.0.10.0/24", "10.0.20.0/24"}, []string{"10.0.10.0/24"}, false},                // drift: CIDR removed
		{[]string{"10.0.10.0/24", "", "10.0.10.0/24"}, []string{"10.0.10.0/24"}, true},             // blanks + dups ignored
		{nil, nil, true},
	}
	for i, c := range cases {
		if got := sameCIDRSet(c.a, c.b); got != c.want {
			t.Errorf("case %d: sameCIDRSet(%v,%v)=%v want %v", i, c.a, c.b, got, c.want)
		}
	}
}

func TestResourceName(t *testing.T) {
	if got := resourceName("default", "otf-phoneformat"); got != "lanexpose-default-otf-phoneformat" {
		t.Fatalf("resourceName = %q", got)
	}
}
