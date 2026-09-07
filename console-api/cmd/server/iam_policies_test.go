package main

import (
	"encoding/json"
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
		"securitygroups", "faultinjections", "queries", "httpapis", "graphqlapis",
		"databaseproxies", "statemachines", "trainingjobs", "modelpackages", "batchtransforms", "processingjobs", "modelmonitors", "featuregroups",
		"staticsites", "parameters", "emailsenders",
		"tables", "buckets", "queues",
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
			Name        string            `json:"name"`
			Annotations map[string]string `json:"annotations,omitempty"`
		}{Name: "ops"}, Spec: struct {
			Description string   `json:"description"`
			Policies    []string `json:"policies"`
			Trust       []string `json:"trust"`
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

// validateCedar guards the data-plane / control-plane blocks: it permits Deny + conditions (the
// whole reason Cedar exists) but still rejects a malformed effect, empty actions, or a bad resource.
func TestValidateCedar(t *testing.T) {
	if msg := validateCedar("dataPlane", nil); msg != "" {
		t.Errorf("nil block should be valid, got %q", msg)
	}
	// Deny + a condition is valid (unlike control-plane statements).
	ok := &cedarBlock{
		AppliesTo: []string{"User::alice", "*"},
		Statements: []cedarStatement{
			{Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::assets"}},
			{Effect: "Deny", Actions: []string{"s3:*"}, Resources: []string{"Bucket::secret"}, Condition: map[string]string{"authenticated": "true"}},
			{Effect: "allow", Actions: []string{"dynamodb:Query"}, Resources: []string{"Table::*"}}, // case-insensitive effect
		},
	}
	if msg := validateCedar("dataPlane", ok); msg != "" {
		t.Errorf("expected valid, got %q", msg)
	}

	bad := func(want string, b *cedarBlock) {
		t.Helper()
		msg := validateCedar("dataPlane", b)
		if msg == "" || !strings.Contains(msg, want) {
			t.Errorf("expected error mentioning %q, got %q", want, msg)
		}
	}
	bad("effect", &cedarBlock{Statements: []cedarStatement{{Actions: []string{"s3:GetObject"}}}})
	bad("not supported", &cedarBlock{Statements: []cedarStatement{{Effect: "Audit", Actions: []string{"s3:GetObject"}}}})
	bad("at least one action", &cedarBlock{Statements: []cedarStatement{{Effect: "Allow"}}})
	bad("Type::id", &cedarBlock{Statements: []cedarStatement{{Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"assets"}}}})
}

// validatePolicyReq: a control-plane-only policy stays valid, a data-plane-only policy is now valid
// (statements may be omitted), and an empty policy is rejected.
func TestValidatePolicyReq(t *testing.T) {
	ctrlOnly := policyReq{Statements: []policyStatement{{Actions: []string{"volumes:Get"}}}}
	if msg := validatePolicyReq(ctrlOnly); msg != "" {
		t.Errorf("control-plane-only should be valid, got %q", msg)
	}
	dataOnly := policyReq{DataPlane: &cedarBlock{Statements: []cedarStatement{{Effect: "Deny", Actions: []string{"s3:*"}}}}}
	if msg := validatePolicyReq(dataOnly); msg != "" {
		t.Errorf("data-plane-only should be valid, got %q", msg)
	}
	if msg := validatePolicyReq(policyReq{}); !strings.Contains(msg, "at least one statement") {
		t.Errorf("empty policy should be rejected, got %q", msg)
	}
	// A bad control-plane statement is still caught.
	if msg := validatePolicyReq(policyReq{Statements: []policyStatement{{Actions: []string{"secrets:Get"}}}}); !strings.Contains(msg, "unknown resource") {
		t.Errorf("out-of-boundary statement should be rejected, got %q", msg)
	}
	// A bad data-plane block is caught too.
	if msg := validatePolicyReq(policyReq{DataPlane: &cedarBlock{Statements: []cedarStatement{{Effect: "Deny"}}}}); !strings.Contains(msg, "at least one action") {
		t.Errorf("bad data-plane block should be rejected, got %q", msg)
	}
}

// normCedar canonicalises the block the API server stores.
func TestNormCedar(t *testing.T) {
	m := normCedar(&cedarBlock{
		AppliesTo: []string{"User::alice", "", "  Group::eng  "},
		Statements: []cedarStatement{
			{Effect: "deny", Actions: []string{" s3:GetObject ", ""}, Resources: []string{"Bucket::assets"}, Condition: map[string]string{"authenticated": "true"}},
			{Effect: "Allow", Actions: []string{"s3:*"}},
		},
	})
	if at, _ := m["appliesTo"].([]string); len(at) != 2 || at[0] != "User::alice" || at[1] != "Group::eng" {
		t.Errorf("appliesTo not cleaned: %v", m["appliesTo"])
	}
	stmts, _ := m["statements"].([]any)
	if len(stmts) != 2 {
		t.Fatalf("got %d statements", len(stmts))
	}
	s0 := stmts[0].(map[string]any)
	if s0["effect"] != "Deny" { // canonicalised
		t.Errorf("effect not canonicalised: %v", s0["effect"])
	}
	if acts, _ := s0["actions"].([]string); len(acts) != 1 || acts[0] != "s3:GetObject" {
		t.Errorf("actions not trimmed: %v", s0["actions"])
	}
	if _, ok := s0["condition"]; !ok {
		t.Errorf("condition dropped")
	}
	s1 := stmts[1].(map[string]any)
	if _, ok := s1["resources"]; ok {
		t.Errorf("empty resources should be omitted, got %v", s1["resources"])
	}
}

// The views must carry the new fields so the UI can round-trip them, without dropping the old ones.
func TestPolicyAndRoleViewRoundTrip(t *testing.T) {
	var p crdPolicy
	p.Metadata.Name = "s3ro"
	p.Spec.Description = "read assets"
	p.Spec.Statements = []policyStatement{{Effect: "Allow", Actions: []string{"buckets:Get"}}}
	p.Spec.DataPlane = &cedarBlock{AppliesTo: []string{"User::alice"}, Statements: []cedarStatement{{Effect: "Allow", Actions: []string{"s3:GetObject"}}}}
	pv := policyView(p)
	if pv.DataPlane == nil || len(pv.DataPlane.Statements) != 1 {
		t.Errorf("policyView dropped dataPlane: %+v", pv.DataPlane)
	}
	if len(pv.Statements) != 1 || pv.Statements[0].Actions[0] != "buckets:Get" {
		t.Errorf("policyView regressed statements: %+v", pv.Statements)
	}

	// A policy with no cedar blocks omits them entirely (backward-compatible shape).
	var plain crdPolicy
	plain.Metadata.Name = "plain"
	plain.Spec.Statements = []policyStatement{{Actions: []string{"volumes:Get"}}}
	if b, _ := json.Marshal(policyView(plain)); strings.Contains(string(b), "dataPlane") {
		t.Errorf("plain policy view should omit dataPlane: %s", b)
	}

	var r crdRole
	r.Metadata.Name = "dep"
	r.Spec.Policies = []string{"p1"}
	r.Spec.Trust = []string{"User::alice", "*"}
	if rv := roleView(r); len(rv.Trust) != 2 || rv.Trust[0] != "User::alice" {
		t.Errorf("roleView dropped trust: %+v", rv.Trust)
	}
	// Trust is always a non-nil array (never JSON null) even when empty.
	var noTrust crdRole
	noTrust.Metadata.Name = "x"
	if b, _ := json.Marshal(roleView(noTrust)); !strings.Contains(string(b), `"trust":[]`) {
		t.Errorf("empty trust should serialise as [], got %s", b)
	}
}

// Managed policies are the out-of-the-box library set (openinfra.dev/managed-policy: "true").
// The console must recognise them so it renders them read-only and the update/delete handlers
// refuse to mutate them. The label value is an exact "true"; anything else is customer-managed.
func TestIsManagedPolicyAndView(t *testing.T) {
	if isManagedPolicy(nil) {
		t.Error("nil labels must not be managed")
	}
	if isManagedPolicy(map[string]string{managedPolicyLabel: "false"}) {
		t.Error(`a "false" label must not be managed`)
	}
	if isManagedPolicy(map[string]string{managedPolicyLabel: "yes"}) {
		t.Error(`only exactly "true" is managed`)
	}
	if !isManagedPolicy(map[string]string{managedPolicyLabel: "true"}) {
		t.Error(`a "true" label must be managed`)
	}

	// A managed policy's view carries managed=true and its category.
	var m crdPolicy
	m.Metadata.Name = "AdministratorAccess"
	m.Metadata.Labels = map[string]string{managedPolicyLabel: "true", policyCategoryLabel: "job-function"}
	m.Spec.Statements = []policyStatement{{Actions: []string{"virtualmachines:*"}}}
	mv := policyView(m)
	if !mv.Managed {
		t.Error("policyView did not mark a labelled policy managed")
	}
	if mv.Category != "job-function" {
		t.Errorf("policyView dropped category: %q", mv.Category)
	}

	// A customer policy is not managed and omits the category field from the JSON, while `managed`
	// is always present (not omitempty) so the SPA can rely on it being a boolean.
	var c crdPolicy
	c.Metadata.Name = "custom"
	c.Spec.Statements = []policyStatement{{Actions: []string{"volumes:Get"}}}
	cv := policyView(c)
	if cv.Managed {
		t.Error("a customer policy must not be managed")
	}
	b, _ := json.Marshal(cv)
	if strings.Contains(string(b), "category") {
		t.Errorf("a customer policy view should omit category: %s", b)
	}
	if !strings.Contains(string(b), `"managed":false`) {
		t.Errorf("managed must be present even when false: %s", b)
	}
}

// A user's attached policies must serialise as an array (never JSON null) — the SPA calls
// .includes()/.map() on it. This guards the spec.policies attach surface the User detail page uses.
func TestUserViewPoliciesAlwaysArray(t *testing.T) {
	v := iamUserView{Name: "alice", Groups: groupList(nil), Policies: groupList(nil)}
	if b, _ := json.Marshal(v); !strings.Contains(string(b), `"policies":[]`) {
		t.Errorf("empty policies should serialise as [], got %s", b)
	}
	v2 := iamUserView{Name: "bob", Policies: groupList([]string{"read-only", "s3-access"})}
	if b, _ := json.Marshal(v2); !strings.Contains(string(b), `"policies":["read-only","s3-access"]`) {
		t.Errorf("policies not carried through: %s", b)
	}
}
