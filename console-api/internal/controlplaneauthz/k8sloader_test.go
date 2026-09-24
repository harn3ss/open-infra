package controlplaneauthz

import "testing"

func TestParseBundle(t *testing.T) {
	raw := `
- appliesTo: ["ServiceAccount::cnpg-system/cloudnative-pg"]
  statements:
    - effect: Allow
      actions: ["bind", "escalate"]
      resources: ["roles.rbac.authorization.k8s.io::*"]
  caveats: ["grants create on rolebindings — add an explicit bind grant"]
- appliesTo: ["Group::system:nodes"]
  statements:
    - effect: Allow
      actions: ["get", "list", "watch"]
      resources: ["pods::*"]
`
	docs, err := parseBundle([]byte(raw))
	if err != nil {
		t.Fatalf("parseBundle: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("want 2 docs, got %d", len(docs))
	}
	cnpg := docs[0]
	if len(cnpg.AppliesTo) != 1 || cnpg.AppliesTo[0] != "ServiceAccount::cnpg-system/cloudnative-pg" {
		t.Errorf("appliesTo not parsed: %#v", cnpg.AppliesTo)
	}
	s := cnpg.Statements
	if len(s) != 1 || string(s[0].Effect) != "Allow" || len(s[0].Actions) != 2 ||
		len(s[0].Resources) != 1 || s[0].Resources[0] != "roles.rbac.authorization.k8s.io::*" {
		t.Errorf("statement not parsed (caveats must be ignored, not treated as a statement): %#v", s)
	}

	// A grant with no statements is dropped (nothing to enforce).
	if d, _ := parseBundle([]byte(`- appliesTo: ["User::x"]`)); len(d) != 0 {
		t.Errorf("grant with no statements should be dropped, got %#v", d)
	}

	// A malformed bundle must ERROR — the Checker then serves its last-good snapshot rather than
	// silently under-granting (which would deny live traffic).
	if _, err := parseBundle([]byte("- appliesTo: [unterminated")); err == nil {
		t.Errorf("malformed bundle should error")
	}
}
