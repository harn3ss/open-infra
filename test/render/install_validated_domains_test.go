package render

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// install.sh's certificates.validatedDomains: the list is read as the example config writes it (comma
// separated, or a flow list), normalized (case, a leading "*.", a trailing dot, duplicates) and checked
// to be DNS domains; anything else stops the install rather than constrain the CA to a typo.
func TestInstall_ValidatedDomainsParsing(t *testing.T) {
	b, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	a := strings.Index(s, "VD_LIST=\"\"\nfor d in $(yget certificates.validatedDomains")
	z := strings.Index(s, "if [ -n \"$VD_LIST\" ]; then")
	if a < 0 || z < a {
		t.Fatal("install.sh has no certificates.validatedDomains parsing step")
	}
	step := s[a:z]
	run := func(val string) (string, bool) {
		script := "yget() { printf '%s' \"$VAL\"; }\nDIE() { echo \"DIE: $*\"; exit 3; }\n" + step + "printf '%s' \"$VD_LIST\"\n"
		cmd := exec.Command("sh", "-c", script)
		cmd.Env = append(os.Environ(), "VAL="+val)
		out, err := cmd.CombinedOutput()
		return string(out), err == nil
	}
	for in, want := range map[string]string{
		"":                                 "",
		"Sites.Example.test.":              "sites.example.test",
		"b.example.test, *.a.example.test": "a.example.test b.example.test",
		"[a.example.test, a.example.test]": "a.example.test",
		`"sites.192-0-2-232.sslip.io"`:     "sites.192-0-2-232.sslip.io",
		"x.example.test,y.example.test":    "x.example.test y.example.test",
	} {
		got, ok := run(in)
		if !ok || got != want {
			t.Errorf("validatedDomains %q -> %q (ok=%v), want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"localhost", "exa mple..test", "-bad.example.test", "under_score.example.test"} {
		if got, ok := run(bad); ok {
			t.Errorf("validatedDomains %q must stop the install, got %q", bad, got)
		}
	}
	for _, want := range []string{"nameConstraints:", "critical: true", "name: openinfra-acm }", "issuerRef: { name: openinfra-ca, kind: ClusterIssuer", "kind: EnvironmentConfig\nmetadata: { name: openinfra-certificates }", "create configmap openinfra-certificates"} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh's validated-domain CA is missing %q", want)
		}
	}
}
