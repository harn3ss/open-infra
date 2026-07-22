package main

import (
	"strings"
	"testing"
)

// validateStatements is the user-facing half of the permission boundary: it turns a bad
// action into a clear message instead of the composition silently dropping the rule. The
// composition is the real safety net, but if these two drift a user gets a confusing
// "policy saved but grants nothing".
func TestValidateStatements(t *testing.T) {
	ok := func(sts []policyStatement) {
		t.Helper()
		if msg := validateStatements(sts); msg != "" {
			t.Errorf("expected valid, got %q for %+v", msg, sts)
		}
	}
	bad := func(want string, sts []policyStatement) {
		t.Helper()
		msg := validateStatements(sts)
		if msg == "" {
			t.Errorf("expected an error mentioning %q, got none for %+v", want, sts)
			return
		}
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}

	ok([]policyStatement{{Effect: "Allow", Actions: []string{"virtualmachines:*", "volumes:Get"}}})
	ok([]policyStatement{{Actions: []string{"*:List"}}})         // effect defaults to Allow
	ok([]policyStatement{{Actions: []string{"queries:Create"}}}) // last resource in the list
	ok([]policyStatement{{Actions: []string{"volumes:get"}}})    // lowercase verb accepted

	bad("at least one statement", nil)
	bad("at least one action", []policyStatement{{Effect: "Allow"}})
	bad("Deny", []policyStatement{{Effect: "Deny", Actions: []string{"volumes:Get"}}})
	bad("<resource>:<verb>", []policyStatement{{Actions: []string{"volumesGet"}}})
	bad("<resource>:<verb>", []policyStatement{{Actions: []string{"volumes:"}}})
	// The one that matters: a resource outside the boundary must be refused here, not
	// silently dropped by the composition.
	bad("unknown resource", []policyStatement{{Actions: []string{"secrets:Get"}}})
	bad("unknown resource", []policyStatement{{Actions: []string{"clusterroles:*"}}})
	bad("unknown verb", []policyStatement{{Actions: []string{"volumes:Frobnicate"}}})
}

// The BFF whitelist MUST equal the composition's whitelist and the provider's grant, or an
// action valid here would be dropped there (or vice versa). This test can't read the YAML,
// but it pins the exact set so a change to policyResources is a conscious, reviewed diff
// that has to be mirrored in platform/abstraction/policy-composition.yaml AND
// provider-setup.yaml. Keep this list and those two in lockstep.
func TestPolicyResourcesMatchBoundary(t *testing.T) {
	want := []string{
		"applications", "functions", "models", "virtualmachines", "vmimages", "volumes",
		"fileshares", "directories", "migrations", "replications", "dataflows", "streams",
		"securitygroups", "faultinjections", "queries",
	}
	if len(policyResources) != len(want) {
		t.Fatalf("policyResources has %d entries, want %d — mirror the change in "+
			"policy-composition.yaml and provider-setup.yaml", len(policyResources), len(want))
	}
	set := map[string]bool{}
	for _, r := range policyResources {
		set[r] = true
	}
	for _, r := range want {
		if !set[r] {
			t.Errorf("policyResources is missing %q", r)
		}
	}
}

func TestNormStatementsDefaults(t *testing.T) {
	out := normStatements([]policyStatement{{Actions: []string{" volumes:Get ", ""}}})
	if len(out) != 1 {
		t.Fatalf("got %d statements", len(out))
	}
	m := out[0].(map[string]any)
	if m["effect"] != "Allow" {
		t.Errorf("effect not defaulted to Allow: %v", m["effect"])
	}
	if res, _ := m["resources"].([]string); len(res) != 1 || res[0] != "*" {
		t.Errorf("resources not defaulted to [*]: %v", m["resources"])
	}
	if acts, _ := m["actions"].([]string); len(acts) != 1 || acts[0] != "volumes:Get" {
		t.Errorf("actions not trimmed/cleaned: %v", m["actions"])
	}
}

func TestRolesUsingPolicyAndGroupsUsingClusterRole(t *testing.T) {
	roles := []crdRole{
		{Metadata: struct {
			Name string `json:"name"`
		}{Name: "ops"}, Spec: struct {
			Description string   `json:"description"`
			Policies    []string `json:"policies"`
		}{Policies: []string{"vmfull", "volread"}}},
	}
	if got := rolesUsingPolicy(roles, "vmfull"); len(got) != 1 || got[0] != "ops" {
		t.Errorf("rolesUsingPolicy = %v", got)
	}
	if got := rolesUsingPolicy(roles, "nope"); len(got) != 0 {
		t.Errorf("rolesUsingPolicy(nope) = %v", got)
	}

	groups := []crdGroup{
		{Metadata: struct {
			Name string `json:"name"`
		}{Name: "operators"}, Spec: crdGroupSpec{ClusterRole: "openinfra-role-ops"}},
	}
	if got := groupsUsingClusterRole(groups, "openinfra-role-ops"); len(got) != 1 || got[0] != "operators" {
		t.Errorf("groupsUsingClusterRole = %v", got)
	}
}
