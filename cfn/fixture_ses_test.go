package cfn

import (
	"os"
	"strings"
	"testing"
)

// The lift-and-shift fixture's instance role sends email through SES as one identity: its companion
// data-plane Policy grants ses:SendEmail and ses:SendRawEmail on Identity::<SesSenderAddress> and on no
// other identity, so the instance can mail as that sender only (the shim's SES door authorizes the From
// address).
func TestFixture_InstanceRoleSendsEmailAsItsSender(t *testing.T) {
	data, err := os.ReadFile("testdata/lift-and-shift/template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]string{"SiteDomain": "site.example.test", "AppRepositoryName": "fixture-app",
		"SesSenderAddress": "app@example.test"}
	built, err := buildManifests(data, DeployOptions{StackName: "fixture", Namespace: "app", Params: params,
		Caps: Capabilities{ObjectEncryption: true}})
	if err != nil {
		t.Fatalf("buildManifests: %v", err)
	}
	var policy string
	for _, b := range built {
		if b.res.Kind == "Policy" && strings.Contains(string(b.yml), "ses:") {
			policy = string(b.yml)
		}
	}
	if policy == "" {
		t.Fatal("no companion Policy grants the instance role SES")
	}
	for _, want := range []string{"ses:SendEmail", "ses:SendRawEmail", "Identity::app@example.test"} {
		if !strings.Contains(policy, want) {
			t.Errorf("the role's policy is missing %q:\n%s", want, policy)
		}
	}
	if strings.Contains(policy, "Identity::*") || strings.Contains(policy, "fixture-sender@example.test") {
		t.Errorf("the SES grant must name the sender parameter's identity only:\n%s", policy)
	}
}
