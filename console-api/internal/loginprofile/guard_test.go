package loginprofile

import (
	"os"
	"strings"
	"testing"
)

// The admission guard (platform/aws-shim/login-profile-guard.yaml) holds a profile's name prefix and
// labels together; it names them as literals. Renaming one here without the guard would leave every
// new profile refused (or, worse, an old name unguarded), so the two are pinned to each other.
func TestGuardNamesTheStoresPrefixesAndLabels(t *testing.T) {
	raw, err := os.ReadFile("../../../platform/aws-shim/login-profile-guard.yaml")
	if err != nil {
		t.Fatal(err)
	}
	guard := string(raw)
	for _, s := range []string{
		"startsWith('" + SecretPrefix + "')",
		"startsWith('" + PolicyPrefix + "')",
		"'" + PolicyPrefix + "' + variables.account",
		"'" + LabelProfile + "'", "'" + LabelUser + "'", "'" + LabelUserNamespace + "'",
		"'" + LabelPolicy + "'", "'" + LabelAccount + "'",
	} {
		if !strings.Contains(guard, s) {
			t.Errorf("the login-profile guard does not name %s", s)
		}
	}
	// Every Secret the store writes passes the guard's shape: the prefix with the label, never apart.
	if n := SecretName("open-infra-console", "alice"); !strings.HasPrefix(n, SecretPrefix) {
		t.Errorf("SecretName %q lacks the guarded prefix %q", n, SecretPrefix)
	}
	if n := PolicySecretName("123456789012"); n != PolicyPrefix+"123456789012" {
		t.Errorf("PolicySecretName = %q, want the guarded %q+account", n, PolicyPrefix)
	}
}
