package main

import "testing"

// sanitize must keep "cp-"+result within the 63-byte object-name limit, and two distinct principals
// that share a long prefix must NOT collide to the same name (a plain 253-cap truncation dropped
// principals from the corpus — the #155 bug).
func TestSanitize_LengthAndUniqueness(t *testing.T) {
	long1 := "ServiceAccount::crossplane-system/crossplane-contrib-provider-kubernetes-101d5a6d80d3"
	long2 := "ServiceAccount::crossplane-system/crossplane-contrib-provider-kubernetes-999999999999"
	s1, s2 := sanitize(long1), sanitize(long2)

	for _, s := range []string{s1, s2} {
		if n := len("cp-" + s); n > 63 {
			t.Errorf("name too long: cp-%s is %d bytes (>63)", s, n)
		}
	}
	if s1 == s2 {
		t.Errorf("distinct principals collided to the same sanitized name: %q", s1)
	}
	if sanitize(long1) != s1 {
		t.Errorf("sanitize must be deterministic")
	}
	// Short principals pass through unchanged (readable, no hash suffix).
	if got := sanitize("ServiceAccount::cnpg-system/cloudnative-pg"); got != "sa-cnpg-system-cloudnative-pg" {
		t.Errorf("short name should pass through cleanly, got %q", got)
	}
}
