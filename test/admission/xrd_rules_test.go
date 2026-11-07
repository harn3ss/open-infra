package admission

import (
	"strings"
	"testing"
)

const (
	groupXRD = "../../platform/abstraction/group-xrd.yaml"
	grantXRD = "../../platform/abstraction/grant-xrd.yaml"
)

type ruleCase struct {
	name string
	spec map[string]any
	why  string // "" = admitted; else a fragment of the refusal
}

func runRules(t *testing.T, path string, cases []ruleCase) {
	t.Helper()
	rules, err := LoadXRDSpecRules(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		msg, err := Validate(rules, c.spec)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		switch {
		case c.why == "" && msg != "":
			t.Errorf("%s: refused: %s", c.name, msg)
		case c.why != "" && !strings.Contains(msg, c.why):
			t.Errorf("%s: want a refusal saying %q, got %q", c.name, c.why, msg)
		}
	}
}

// A Group is a container of policies: one naming a clusterRole (the old permission tier) is refused, with
// the managed policy to attach instead.
func TestGroupXRD_ClusterRoleIsRefused(t *testing.T) {
	runRules(t, groupXRD, []ruleCase{
		{"a group of policies", map[string]any{"policies": []any{"aws-poweruseraccess"}}, ""},
		{"an empty group", map[string]any{}, ""},
		{"a group with inline policies", map[string]any{"inlinePolicies": []any{map[string]any{"name": "x", "document": map[string]any{"Statement": []any{}}}}}, ""},
		{"a permission tier", map[string]any{"clusterRole": "open-infra-poweruser"},
			"spec.clusterRole is not supported: a Group is a container of policies"},
		{"a tier beside policies", map[string]any{"clusterRole": "open-infra-console", "policies": []any{"aws-administratoraccess"}},
			"Attach a managed policy in spec.policies instead, such as aws-poweruseraccess"},
		{"an empty tier", map[string]any{"clusterRole": ""}, "not supported"},
	})
}

func grant(policies []any, duration string) map[string]any {
	spec := map[string]any{"subject": map[string]any{"kind": "User", "name": "alice"}, "duration": duration}
	if policies != nil {
		spec["policies"] = policies
	}
	return spec
}

// A Grant names policies and a duration of at most 24h; one naming a clusterRole (the old ClusterRole
// elevation) is refused, with the policies to name instead.
func TestGrantXRD_ClusterRoleAndDurationAreRefused(t *testing.T) {
	ro := []any{"aws-readonlyaccess"}
	withRole := grant(ro, "4h")
	withRole["clusterRole"] = "open-infra-poweruser"
	roleOnly := grant(nil, "4h")
	roleOnly["clusterRole"] = "open-infra-readonly"
	runRules(t, grantXRD, []ruleCase{
		{"policies for 4h", grant(ro, "4h"), ""},
		{"policies for 30m", grant(ro, "30m"), ""},
		{"policies for 1h30m", grant(ro, "1h30m"), ""},
		{"policies for 24h", grant(ro, "24h"), ""},
		{"policies for 90s", grant(ro, "90s"), ""},
		{"a ClusterRole beside policies", withRole, "spec.clusterRole is not supported: a Grant attaches IAM policies"},
		{"the old form: a ClusterRole alone", roleOnly, "Name them in spec.policies instead, such as aws-readonlyaccess"},
		{"25h", grant(ro, "25h"), "at most 24h"},
		{"24h1s", grant(ro, "24h1s"), "at most 24h"},
		{"1440m1s", grant(ro, "1440m1s"), "at most 24h"},
		{"zero", grant(ro, "0s"), "at most 24h"},
		{"empty", grant(ro, ""), "at most 24h"},
		{"fractional", grant(ro, "0.5h"), "at most 24h"},
		{"days", grant(ro, "1d"), "at most 24h"},
		{"negative", grant(ro, "-1h"), "at most 24h"},
		{"overflowing", grant(ro, "99999999999999h"), "at most 24h"},
	})
}
