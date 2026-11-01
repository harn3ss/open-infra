package render

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const awsIdentityYAML = "../../platform/aws-shim/aws-identity.yaml"

// The install's AWS identity lives in one file: a ConfigMap the aws-shim reads (ACCOUNT_ID, AWS_REGION)
// and an EnvironmentConfig the VM composition reads (awsAccountId, awsRegion). They must agree, the
// account must be a 12-digit AWS account id, and the shim must take both values from the ConfigMap.
func TestAWSIdentity_OneSource(t *testing.T) {
	cm := yamlDoc(t, awsIdentityYAML, "ConfigMap", "openinfra-aws-identity")
	ec := yamlDoc(t, awsIdentityYAML, "EnvironmentConfig", "openinfra-aws-identity")
	val := func(doc, key string) string {
		m := regexp.MustCompile(`(?m)^\s+` + key + `:\s+"([^"]*)"`).FindStringSubmatch(doc)
		if m == nil {
			t.Fatalf("aws-identity.yaml: no %s in\n%s", key, doc)
		}
		return m[1]
	}
	acct, region := val(cm, "ACCOUNT_ID"), val(cm, "AWS_REGION")
	if got := val(ec, "awsAccountId"); got != acct {
		t.Errorf("EnvironmentConfig awsAccountId %q != ConfigMap ACCOUNT_ID %q", got, acct)
	}
	if got := val(ec, "awsRegion"); got != region {
		t.Errorf("EnvironmentConfig awsRegion %q != ConfigMap AWS_REGION %q", got, region)
	}
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(acct) {
		t.Errorf("ACCOUNT_ID %q is not a 12-digit AWS account id", acct)
	}

	shim, err := os.ReadFile("../../platform/aws-shim/aws-shim.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"name: ACCOUNT_ID, valueFrom: { configMapKeyRef: { name: openinfra-aws-identity, key: ACCOUNT_ID } }",
		"name: AWS_REGION, valueFrom: { configMapKeyRef: { name: openinfra-aws-identity, key: AWS_REGION } }",
	} {
		if !strings.Contains(string(shim), want) {
			t.Errorf("aws-shim.yaml must read the identity from the ConfigMap (missing %q)", want)
		}
	}
	if regexp.MustCompile(`name: (ACCOUNT_ID|AWS_REGION), value:`).Match(shim) {
		t.Errorf("aws-shim.yaml sets ACCOUNT_ID or AWS_REGION literally; take them from openinfra-aws-identity")
	}
}

// The guest's instance metadata reports the install's identity: the account and region from the
// EnvironmentConfig, and AWS's default identity when there is none.
func TestVM_IMDSIdentityIsTheInstall(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmComposition)
	ctx := vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"})
	ctx["context"] = map[string]any{"apiextensions.crossplane.io/environment": map[string]any{
		"awsAccountId": "123456789012", "awsRegion": "eu-west-1",
	}}
	cfg := vmAgentConfig(t, render(t, tmpl, ctx))
	if cfg["accountId"] != "123456789012" || cfg["region"] != "eu-west-1" || cfg["availabilityZone"] != "eu-west-1a" {
		t.Errorf("agent identity = account %v region %v az %v, want the EnvironmentConfig's", cfg["accountId"], cfg["region"], cfg["availabilityZone"])
	}

	cfg = vmAgentConfig(t, render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"})))
	if cfg["accountId"] != "000000000000" || cfg["region"] != "us-east-1" {
		t.Errorf("without the EnvironmentConfig the agent identity = %v / %v, want the default 000000000000 / us-east-1", cfg["accountId"], cfg["region"])
	}

	raw, err := os.ReadFile(vmComposition)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "name: openinfra-aws-identity") {
		t.Errorf("vm-composition.yaml must read the openinfra-aws-identity EnvironmentConfig")
	}
}

// No manifest presents the old "open-infra" account any more.
func TestAWSIdentity_NoLegacyAccountLiteral(t *testing.T) {
	legacy := regexp.MustCompile(`("accountId" "open-infra"|name: ACCOUNT_ID, value: "open-infra")`)
	for _, f := range []string{vmComposition, "../../platform/aws-shim/aws-shim.yaml"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if legacy.Match(b) {
			t.Errorf("%s still presents the legacy account \"open-infra\"", f)
		}
	}
}
