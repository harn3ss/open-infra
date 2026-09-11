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
	const cidr = "192.0.2.0/24"
	const prio = 29500
	existing := []PolicyRoute{
		{Priority: 31000, Match: "ip4.dst == 100.64.0.0/16", Action: "allow"},         // foreign, keep
		{Priority: prio, Match: ownedPolicyMatch("10.16.0.5", cidr), Action: "allow"}, // ours, stale — drop
	}
	got := mergePolicyRoutes(existing, []string{"10.16.112.153", "10.16.112.153", ""}, prio, cidr)
	// foreign preserved
	var foreign, ours int
	for _, p := range got {
		if p.Priority == 31000 {
			foreign++
		}
		if isOwnedPolicy(p, prio, cidr) {
			ours++
		}
	}
	if foreign != 1 {
		t.Fatalf("foreign policy not preserved: %+v", got)
	}
	if ours != 1 {
		t.Fatalf("want exactly 1 owned policy (deduped, no empty), got %d: %+v", ours, got)
	}
	for _, p := range got {
		if isOwnedPolicy(p, prio, cidr) && p.Match != ownedPolicyMatch("10.16.112.153", cidr) {
			t.Fatalf("owned policy has wrong match: %q", p.Match)
		}
	}
}

func TestMergePolicyRoutesStableAndEqual(t *testing.T) {
	const cidr = "192.0.2.0/24"
	const prio = 29500
	a := mergePolicyRoutes(nil, []string{"10.16.0.9", "10.16.0.3"}, prio, cidr)
	b := mergePolicyRoutes(nil, []string{"10.16.0.3", "10.16.0.9"}, prio, cidr)
	if !policyRoutesEqual(a, b) {
		t.Fatalf("merge not order-stable:\n a=%+v\n b=%+v", a, b)
	}
	// removing all wanted IPs clears our entries but keeps foreign ones
	foreign := []PolicyRoute{{Priority: 10, Match: "x", Action: "reroute", NextHopIP: "1.2.3.4"}}
	cleared := mergePolicyRoutes(append(foreign, a...), nil, prio, cidr)
	if len(cleared) != 1 || cleared[0].Priority != 10 {
		t.Fatalf("clearing should leave only the foreign route, got %+v", cleared)
	}
}

func TestResourceName(t *testing.T) {
	if got := resourceName("default", "otf-phoneformat"); got != "lanexpose-default-otf-phoneformat" {
		t.Fatalf("resourceName = %q", got)
	}
}
