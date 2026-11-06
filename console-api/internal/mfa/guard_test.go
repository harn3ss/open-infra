package mfa

import (
	"os"
	"strings"
	"testing"
)

// The admission guard (platform/aws-shim/mfa-device-guard.yaml) holds a device's name prefix and labels
// together; it names them as literals. Renaming one here without the guard would leave every new device
// refused (or, worse, an old name unguarded), so the two are pinned to each other.
func TestGuardNamesTheStoresPrefixAndLabels(t *testing.T) {
	raw, err := os.ReadFile("../../../platform/aws-shim/mfa-device-guard.yaml")
	if err != nil {
		t.Fatal(err)
	}
	guard := string(raw)
	for _, s := range []string{
		"startsWith('" + SecretPrefix + "')",
		"'" + LabelDevice + "'", "'" + LabelAccount + "'", "'" + LabelUser + "'", "'" + LabelUserNamespace + "'",
	} {
		if !strings.Contains(guard, s) {
			t.Errorf("the MFA device guard does not name %s", s)
		}
	}
	if n := SecretName("000000000000", "Alice@Phone"); !strings.HasPrefix(n, SecretPrefix) {
		t.Errorf("SecretName %q lacks the guarded prefix %q", n, SecretPrefix)
	}
}
