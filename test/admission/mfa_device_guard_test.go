package admission

import (
	"strings"
	"testing"
)

const (
	mfaGuardPath = "../../platform/aws-shim/mfa-device-guard.yaml"
	mfaGuardName = "openinfra-mfa-device-guard"
)

// device is a virtual MFA device Secret as mfa.Store writes it; user "" is unassigned.
func device(account, user, userNS string) map[string]any {
	labels := map[string]string{
		"app.kubernetes.io/managed-by": "open-infra-iam",
		"openinfra.dev/mfa-device":     "true",
		"openinfra.dev/account-id":     account,
	}
	if user != "" {
		labels["openinfra.dev/iam-user"] = user
	}
	if userNS != "" {
		labels["openinfra.dev/iam-user-namespace"] = userNS
	}
	return secret("iam-mfa-alice-phone-0123456789ab", labels)
}

func mfaGuard(t *testing.T) *Policy {
	t.Helper()
	p, err := Load(mfaGuardPath, mfaGuardName)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mfaGuardCases() []guardCase {
	const acct = "000000000000"
	masters := create(storeNS, "kubernetes-admin", secret("iam-mfa-repair", nil))
	masters.Groups = []string{"system:masters", "system:authenticated"}
	return []guardCase{
		// 1. The device prefix and label come together or not at all.
		{"shim creates a device", create(storeNS, shimSA, device(acct, "", "")), true, ""},
		{"console creates a device", create(storeNS, consoleSA, device(acct, "", "")), true, ""},
		{"an unlabelled iam-mfa- Secret", create(storeNS, shimSA, secret("iam-mfa-x-0123456789ab", nil)), false, "both or neither"},
		{"a device label off the prefix", create(storeNS, shimSA, secret("iam-ak-0123", map[string]string{
			"openinfra.dev/mfa-device": "true", "openinfra.dev/account-id": acct})), false, "both or neither"},
		{"a device label not \"true\"", create(storeNS, shimSA, secret("iam-mfa-x-0123456789ab", map[string]string{
			"openinfra.dev/mfa-device": "yes", "openinfra.dev/account-id": acct})), false, "both or neither"},
		{"an access key is no device", create(storeNS, shimSA, secret("iam-ak-0123456789abcdef", map[string]string{"openinfra.dev/access-key": "true"})), true, ""},
		{"a Secret with no labels", create(storeNS, shimSA, secret("aws-shim-minio-creds", nil)), true, ""},

		// 2. A device names its account and keeps it.
		{"a device with no account", create(storeNS, shimSA, secret("iam-mfa-x-0123456789ab", map[string]string{"openinfra.dev/mfa-device": "true"})), false, "names its account"},
		{"a device moved to another account", update(storeNS, shimSA, device(acct, "", ""), device("999999999999", "", "")), false, "another account"},

		// 3. An assigned device names its user, both labels or neither, and is never handed to another user.
		{"enable assigns a user", update(storeNS, shimSA, device(acct, "", ""), device(acct, "alice", consoleNS)), true, ""},
		{"deactivate unassigns it", update(storeNS, consoleSA, device(acct, "alice", consoleNS), device(acct, "", "")), true, ""},
		{"a new code recorded", update(storeNS, shimSA, device(acct, "alice", consoleNS), device(acct, "alice", consoleNS)), true, ""},
		{"a user with no namespace", create(storeNS, shimSA, device(acct, "alice", "")), false, "both or neither"},
		{"a namespace with no user", update(storeNS, shimSA, device(acct, "", ""), device(acct, "", consoleNS)), false, "both or neither"},
		{"handed to another user", update(storeNS, shimSA, device(acct, "alice", consoleNS), device(acct, "bob", consoleNS)), false, "deactivate it first"},
		{"handed to another account's user", update(storeNS, shimSA, device(acct, "alice", consoleNS), device(acct, "alice", "team-a")), false, "deactivate it first"},
		{"the device label stripped", update(storeNS, shimSA, device(acct, "", ""), secret("iam-mfa-alice-phone-0123456789ab", nil)), false, "both or neither"},
		{"delete a device", del(storeNS, shimSA, device(acct, "", "")), true, ""},

		// Out of scope: a cluster administrator, and every other namespace.
		{"system:masters repairs a device", masters, true, ""},
		{"another namespace", create(consoleNS, consoleSA, secret("iam-mfa-x", nil)), true, ""},
	}
}

func TestMFADeviceGuard(t *testing.T) {
	p := mfaGuard(t)
	for _, c := range mfaGuardCases() {
		t.Run(c.name, func(t *testing.T) {
			v, err := p.Admit(c.req)
			if err != nil {
				t.Fatalf("policy failed to evaluate (failurePolicy: Fail would refuse every such write): %v", err)
			}
			if v.Allowed() != c.allow {
				t.Fatalf("allowed=%v, want %v (refusal: %q)", v.Allowed(), c.allow, v.Denied)
			}
			if !c.allow && !strings.Contains(v.Denied, c.why) {
				t.Fatalf("refused for %q, want a refusal mentioning %q", v.Denied, c.why)
			}
		})
	}
}

// Every rule is load-bearing: without any one of them, some write the cases refuse gets through.
func TestMFADeviceGuard_EveryRuleIsTested(t *testing.T) {
	full := mfaGuard(t)
	for i, val := range full.Spec.Validations {
		cut := *full
		cut.Spec.Validations = append(append([]struct {
			Expression string `yaml:"expression"`
			Message    string `yaml:"message"`
			Reason     string `yaml:"reason"`
		}{}, full.Spec.Validations[:i]...), full.Spec.Validations[i+1:]...)
		let := 0
		for _, c := range mfaGuardCases() {
			v, err := cut.Admit(c.req)
			if err != nil {
				t.Fatal(err)
			}
			if !c.allow && v.Allowed() {
				let++
			}
		}
		if let == 0 {
			t.Errorf("validation %d (%s) refuses nothing the others would allow", i, val.Message)
		}
	}
}

func TestMFADeviceGuard_Scope(t *testing.T) {
	p := mfaGuard(t)
	if p.Spec.FailurePolicy != "Fail" {
		t.Errorf("failurePolicy = %q, want Fail", p.Spec.FailurePolicy)
	}
	if len(p.Spec.MatchConstraints.ResourceRules) != 1 {
		t.Fatalf("want one resource rule, got %d", len(p.Spec.MatchConstraints.ResourceRules))
	}
	r := p.Spec.MatchConstraints.ResourceRules[0]
	if strings.Join(r.APIGroups, ",") != "" || strings.Join(r.Resources, ",") != "secrets" ||
		strings.Join(r.Operations, ",") != "CREATE,UPDATE,DELETE" {
		t.Errorf("rule matches %v/%v %v, want core secrets on every write", r.APIGroups, r.Resources, r.Operations)
	}
}
