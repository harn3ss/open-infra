package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The operator's validated domains (ACM's domain validation, done once) are a mounted ConfigMap key, read
// live into the CloudFormation front door's capabilities: one per line or comma-separated, normalized;
// missing or empty is none, so sites keep the self-signed issuer.
func TestFileDomains(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "validatedDomains")
	if err := os.WriteFile(list, []byte("Sites.Example.test.\n*.apps.example.test, other.example.test\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []string{"sites.example.test", "apps.example.test", "other.example.test"}
	if got := fileDomains(list); !reflect.DeepEqual(got, want) {
		t.Errorf("fileDomains = %v, want %v", got, want)
	}
	for _, p := range []string{filepath.Join(dir, "missing"), ""} {
		if got := fileDomains(p); got != nil {
			t.Errorf("fileDomains(%q) = %v, want none", p, got)
		}
	}
	h := &cfnDoorway{validatedDomainsFile: list}
	if got := h.caps(context.Background()).ValidatedDomains; !reflect.DeepEqual(got, want) {
		t.Errorf("caps().ValidatedDomains = %v, want %v", got, want)
	}
}
