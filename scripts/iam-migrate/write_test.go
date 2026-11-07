package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A removal is written to the claim's composite first: Crossplane keeps a claim's spec in step with its
// composite's, so a field removed from the claim alone comes back on the next sync. A patch that only
// adds touches the claim alone.
func TestWrite_RemovalReachesTheComposite(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "kubectl")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\ncase \"$*\" in *jsonpath*) printf 'iam.openinfra.dev/v1 XGroup readers-x7k2p' ;; esac\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := write(fake, Change{Kind: "Group", Namespace: "open-infra-console", Name: "readers",
		Patch: map[string]any{"clusterRole": nil, "policies": []any{"aws-readonlyaccess"}}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	calls := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(calls) != 3 || !strings.Contains(calls[1], "patch xgroups.iam.openinfra.dev readers-x7k2p") ||
		!strings.Contains(calls[2], "-n open-infra-console patch groups.iam.openinfra.dev readers") {
		t.Fatalf("calls = %q, want the composite patched before the claim", calls)
	}

	_ = os.Remove(log)
	if err := write(fake, Change{Kind: "Group", Namespace: "open-infra-console", Name: "readers",
		Patch: map[string]any{"policies": []any{"aws-readonlyaccess"}}}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(log)
	if calls := strings.Split(strings.TrimSpace(string(b)), "\n"); len(calls) != 1 {
		t.Fatalf("an additive patch made %d calls (%q), want the claim's alone", len(calls), calls)
	}
}
