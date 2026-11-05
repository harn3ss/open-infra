package admission

import (
	"strings"
	"testing"
)

const (
	guardPath = "../../platform/aws-shim/login-profile-guard.yaml"
	guardName = "openinfra-login-profile-guard"

	consoleNS = "open-infra-console"
	storeNS   = "open-infra-aws-shim"
	shimSA    = "system:serviceaccount:open-infra-aws-shim:aws-shim"
	consoleSA = "system:serviceaccount:open-infra-console:console"
)

func secret(name string, labels map[string]string) map[string]any {
	meta := map[string]any{"name": name}
	if labels != nil {
		l := map[string]any{}
		for k, v := range labels {
			l[k] = v
		}
		meta["labels"] = l
	}
	return map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": meta, "data": map[string]any{"hash": "eA=="}}
}

// profile is a login-profile Secret as loginprofile.Store writes it.
func profile(user, userNS string) map[string]any {
	return secret("iam-login-"+user+"-0123456789", map[string]string{
		"app.kubernetes.io/managed-by":     "open-infra-iam",
		"openinfra.dev/login-profile":      "true",
		"openinfra.dev/iam-user":           user,
		"openinfra.dev/iam-user-namespace": userNS,
	})
}

func policySecret(name, account string) map[string]any {
	return secret(name, map[string]string{"openinfra.dev/password-policy": "true", "openinfra.dev/account-id": account})
}

func guard(t *testing.T) *Policy {
	t.Helper()
	p, err := Load(guardPath, guardName)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func create(ns, who string, obj map[string]any) Request {
	return Request{Operation: "CREATE", Namespace: ns, Username: who, Groups: []string{"system:serviceaccounts", "system:authenticated"}, Object: obj}
}

func update(ns, who string, old, obj map[string]any) Request {
	r := create(ns, who, obj)
	r.Operation, r.OldObject = "UPDATE", old
	return r
}

func del(ns, who string, old map[string]any) Request {
	r := create(ns, who, nil)
	r.Operation, r.OldObject = "DELETE", old
	return r
}

type guardCase struct {
	name  string
	req   Request
	allow bool
	why   string // a fragment of the refusal message
}

func guardCases() []guardCase {
	consoleAuth := secret("console-auth", nil)
	masters := create(consoleNS, "kubernetes-admin", consoleAuth)
	masters.Groups = []string{"system:masters", "system:authenticated"}
	mastersUnlabelled := create(storeNS, "kubernetes-admin", secret("iam-login-repair", nil))
	mastersUnlabelled.Groups = masters.Groups

	return []guardCase{
		// 1. The shim writes nothing in the console namespace — root's console-auth above all.
		{"shim creates console-auth", create(consoleNS, shimSA, consoleAuth), false, "writes no Secret in the console namespace"},
		{"shim updates console-auth", update(consoleNS, shimSA, consoleAuth, secret("console-auth", map[string]string{"x": "y"})), false, "console namespace"},
		{"shim deletes console-auth", del(consoleNS, shimSA, consoleAuth), false, "console namespace"},
		{"shim writes a labelled profile in the console namespace", create(consoleNS, shimSA, profile("alice", consoleNS)), false, "console namespace"},
		{"shim writes an unlabelled Secret in the console namespace", create(consoleNS, shimSA, secret("iam-pw-alice", nil)), false, "console namespace"},
		{"the console still manages its own namespace", update(consoleNS, consoleSA, secret("iam-pw-alice", nil), secret("iam-pw-alice", nil)), true, ""},

		// 2. In the store, the profile prefix and label come together or not at all, and name a user.
		{"shim creates a profile", create(storeNS, shimSA, profile("alice", consoleNS)), true, ""},
		{"console creates a profile", create(storeNS, consoleSA, profile("alice", consoleNS)), true, ""},
		{"an unlabelled iam-login- Secret", create(storeNS, shimSA, secret("iam-login-alice-0123456789", nil)), false, "both or neither"},
		{"a profile label off the prefix", create(storeNS, shimSA, secret("iam-ak-0123", map[string]string{
			"openinfra.dev/login-profile": "true", "openinfra.dev/iam-user": "alice", "openinfra.dev/iam-user-namespace": consoleNS})), false, "both or neither"},
		{"a profile label not \"true\"", create(storeNS, shimSA, secret("iam-login-alice-0123456789", map[string]string{
			"openinfra.dev/login-profile": "yes", "openinfra.dev/iam-user": "alice", "openinfra.dev/iam-user-namespace": consoleNS})), false, "both or neither"},
		{"a profile naming no user", create(storeNS, shimSA, secret("iam-login-alice-0123456789", map[string]string{
			"openinfra.dev/login-profile": "true", "openinfra.dev/iam-user-namespace": consoleNS})), false, "names its user"},
		{"a profile naming no user namespace", create(storeNS, shimSA, secret("iam-login-alice-0123456789", map[string]string{
			"openinfra.dev/login-profile": "true", "openinfra.dev/iam-user": "alice"})), false, "names its user"},
		{"an access key is not a profile", create(storeNS, shimSA, secret("iam-ak-0123456789abcdef", map[string]string{"openinfra.dev/access-key": "true"})), true, ""},
		{"a Secret with no labels at all", create(storeNS, shimSA, secret("aws-shim-minio-creds", nil)), true, ""},

		// 3. An update keeps a profile's user; a delete sees the Secret as it was.
		{"a new hash for the same user", update(storeNS, shimSA, profile("alice", consoleNS), profile("alice", consoleNS)), true, ""},
		{"a profile moved to another user", update(storeNS, shimSA, profile("alice", consoleNS), func() map[string]any {
			s := profile("alice", consoleNS)
			s["metadata"].(map[string]any)["labels"].(map[string]any)["openinfra.dev/iam-user"] = "bob"
			return s
		}()), false, "cannot be moved"},
		{"a profile moved to another namespace's user", update(storeNS, shimSA, profile("alice", consoleNS), func() map[string]any {
			s := profile("alice", consoleNS)
			s["metadata"].(map[string]any)["labels"].(map[string]any)["openinfra.dev/iam-user-namespace"] = "other"
			return s
		}()), false, "cannot be moved"},
		{"a profile's label stripped on update", update(storeNS, shimSA, profile("alice", consoleNS), secret("iam-login-alice-0123456789", nil)), false, "both or neither"},
		{"delete a profile", del(storeNS, shimSA, profile("alice", consoleNS)), true, ""},
		{"delete an access key", del(storeNS, shimSA, secret("iam-ak-0123", nil)), true, ""},

		// The account password policy: iam-password-policy-<account>, labelled for that account.
		{"an account password policy", create(storeNS, shimSA, policySecret("iam-password-policy-123456789012", "123456789012")), true, ""},
		{"a policy named for another account", create(storeNS, shimSA, policySecret("iam-password-policy-123456789012", "999999999999")), false, "named for its account"},
		{"a policy with no account", create(storeNS, shimSA, secret("iam-password-policy-123456789012", map[string]string{"openinfra.dev/password-policy": "true"})), false, "named for its account"},
		{"an unlabelled policy", create(storeNS, shimSA, secret("iam-password-policy-123456789012", nil)), false, "both or neither"},
		{"a policy label off the prefix", create(storeNS, shimSA, policySecret("aws-shim-config", "123456789012")), false, "both or neither"},
		{"delete a policy", del(storeNS, shimSA, policySecret("iam-password-policy-123456789012", "123456789012")), true, ""},

		// Out of scope: a cluster administrator, and every other namespace.
		{"system:masters writes console-auth", masters, true, ""},
		{"system:masters repairs an unlabelled profile", mastersUnlabelled, true, ""},
		{"the shim in its other namespaces", create("open-infra-dynamodb", shimSA, secret("iam-login-x", nil)), true, ""},
	}
}

func TestLoginProfileGuard(t *testing.T) {
	p := guard(t)
	for _, c := range guardCases() {
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

// Every rule is load-bearing: without any one of them, some write the cases refuse gets through. A rule
// no case depends on is either dead or untested.
func TestLoginProfileGuard_EveryRuleIsTested(t *testing.T) {
	full := guard(t)
	for i, val := range full.Spec.Validations {
		cut := *full
		cut.Spec.Validations = append(append([]struct {
			Expression string `yaml:"expression"`
			Message    string `yaml:"message"`
			Reason     string `yaml:"reason"`
		}{}, full.Spec.Validations[:i]...), full.Spec.Validations[i+1:]...)
		let := 0
		for _, c := range guardCases() {
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

// The policy's scope: every Secret write (DELETE included, or a profile could be removed without the
// guard seeing it), failing closed.
func TestLoginProfileGuard_Scope(t *testing.T) {
	p := guard(t)
	if p.Spec.FailurePolicy != "Fail" {
		t.Errorf("failurePolicy = %q, want Fail", p.Spec.FailurePolicy)
	}
	if len(p.Spec.MatchConstraints.ResourceRules) != 1 {
		t.Fatalf("want one resource rule, got %d", len(p.Spec.MatchConstraints.ResourceRules))
	}
	r := p.Spec.MatchConstraints.ResourceRules[0]
	if strings.Join(r.APIGroups, ",") != "" || strings.Join(r.Resources, ",") != "secrets" {
		t.Errorf("rule matches %v/%v, want core secrets", r.APIGroups, r.Resources)
	}
	if strings.Join(r.Operations, ",") != "CREATE,UPDATE,DELETE" {
		t.Errorf("operations = %v, want CREATE, UPDATE, DELETE", r.Operations)
	}
}
