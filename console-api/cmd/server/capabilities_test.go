package main

import (
	"strings"
	"testing"
)

func TestResolveKind(t *testing.T) {
	vm := archEntry{Amd64: "supported", Arm64: "unsupported"} // VirtualMachine
	noImage := archEntry{Amd64: "supported", Arm64: "untested"}
	multiArch := archEntry{Amd64: "supported", Arm64: "supported"} // image-backed post-#42
	armOnlyKind := archEntry{Amd64: "unsupported", Arm64: "supported"}

	tests := []struct {
		name        string
		entry       archEntry
		nodeArches  []string
		gate        bool
		wantVerdict string
		reasonHas   string // substring the reason must contain ("" = reason must be empty)
	}{
		{"mixed cluster, VM -> available (amd64 present)", vm, []string{"amd64", "arm64"}, true, "available", ""},
		{"arm64-only cluster, VM -> unavailable", vm, []string{"arm64"}, true, "unavailable", "requires amd64"},
		{"arm64-only cluster, no-image kind -> untested", noImage, []string{"arm64"}, true, "untested", "untested on this cluster"},
		{"arm64-only cluster, multi-arch kind -> available", multiArch, []string{"arm64"}, true, "available", ""},
		{"amd64-only cluster, no-image kind -> available", noImage, []string{"amd64"}, true, "available", ""},
		{"amd64-only cluster, arm64-only kind -> unavailable", armOnlyKind, []string{"amd64"}, true, "unavailable", "requires arm64"},
		{"gate off (degraded) -> available regardless", vm, []string{"arm64"}, false, "available", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveKind("K", tc.entry, tc.nodeArches, tc.gate)
			if got.Verdict != tc.wantVerdict {
				t.Fatalf("verdict = %q, want %q", got.Verdict, tc.wantVerdict)
			}
			if tc.reasonHas == "" {
				if got.Reason != "" {
					t.Fatalf("reason = %q, want empty", got.Reason)
				}
			} else if !strings.Contains(got.Reason, tc.reasonHas) {
				t.Fatalf("reason = %q, want to contain %q", got.Reason, tc.reasonHas)
			}
		})
	}
}

func TestJoinOr(t *testing.T) {
	cases := map[string]struct {
		in   []string
		want string
	}{
		"none": {nil, "none"},
		"one":  {[]string{"amd64"}, "amd64"},
		"two":  {[]string{"amd64", "arm64"}, "amd64 or arm64"},
		"three": {[]string{"a", "b", "c"}, "a, b, or c"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := joinOr(c.in); got != c.want {
				t.Fatalf("joinOr(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
