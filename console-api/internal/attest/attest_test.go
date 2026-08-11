package attest

import (
	"context"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// With an empty cluster (fake clientset: no CRs, no ConfigMaps), Assemble must not panic and must
// still enumerate every control family — each simply "not present" with zero-count evidence. This
// guards the shape of the attestation (a control silently dropping out would understate coverage).
func TestAssemble_EmptyClusterEnumeratesAllControls(t *testing.T) {
	cs := fake.NewSimpleClientset()
	a := Assemble(context.Background(), cs, "open-infra-console", "monitoring")

	if a.ConsoleNS != "open-infra-console" {
		t.Fatalf("console ns not carried: %q", a.ConsoleNS)
	}
	if len(a.Controls) != 6 {
		t.Fatalf("expected 6 control families, got %d", len(a.Controls))
	}
	// The audit family is absent on an empty cluster (no anchor ConfigMap).
	var sawAudit bool
	for _, c := range a.Controls {
		if c.Control == "" || c.Feature == "" || c.Evidence == "" {
			t.Errorf("control has an empty field: %+v", c)
		}
		if c.Feature == "audit off-siting (WORM hash chain)" {
			sawAudit = true
			if c.Present {
				t.Errorf("audit off-siting should be absent on an empty cluster")
			}
		}
	}
	if !sawAudit {
		t.Error("audit off-siting control family missing")
	}
	// Evidence map present and zeroed.
	if a.Evidence["encryptionKeys"] != 0 || a.Evidence["grants"] != 0 {
		t.Errorf("expected zero evidence on empty cluster: %+v", a.Evidence)
	}
	// GeneratedAt is stamped by the caller, not Assemble — must be empty here (deterministic).
	if a.GeneratedAt != "" {
		t.Errorf("Assemble must not stamp GeneratedAt (caller does): %q", a.GeneratedAt)
	}
}

func TestMarkdown_RendersControls(t *testing.T) {
	cs := fake.NewSimpleClientset()
	a := Assemble(context.Background(), cs, "open-infra-console", "monitoring")
	a.GeneratedAt = "2026-08-11T00:00:00Z"
	md := Markdown(a)
	for _, want := range []string{"compliance attestation", "2026-08-11T00:00:00Z", "AC-2(2)", "MP-6 / SP 800-88"} {
		if !contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
