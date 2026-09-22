package main

import (
	"context"
	"testing"
)

func TestClassifyAction(t *testing.T) {
	cases := []struct {
		action             string
		plane, left, right string
		ok                 bool
	}{
		{"virtualmachines:Get", "control", "virtualmachines", "get", true},
		{"volumes:*", "control", "volumes", "*", true},
		{"*:List", "control", "*", "list", true},
		{"s3:GetObject", "data", "s3", "GetObject", true},
		{"s3:*", "data", "s3", "*", true},
		{"dynamodb:Query", "data", "dynamodb", "Query", true},
		{"lambda:InvokeFunction", "data", "lambda", "InvokeFunction", true},
		{"volumes:Frobnicate", "", "volumes", "Frobnicate", false}, // known resource, unknown verb, not a service
		{"unknownsvc:Foo", "", "unknownsvc", "Foo", false},
		{"noColon", "", "", "", false},
		{"trailing:", "", "", "", false},
		{":leading", "", "", "", false},
	}
	for _, c := range cases {
		plane, left, right, ok := classifyAction(c.action)
		if ok != c.ok || plane != c.plane {
			t.Errorf("classifyAction(%q) = (%q,%q,%q,%v), want (%q,_,_,%v)", c.action, plane, left, right, ok, c.plane, c.ok)
			continue
		}
		if ok && (left != c.left || right != c.right) {
			t.Errorf("classifyAction(%q) split = (%q,%q), want (%q,%q)", c.action, left, right, c.left, c.right)
		}
	}
}

func TestCoarseVerbAndKind(t *testing.T) {
	verbs := map[string]string{
		"GetObject": "get", "ListBucket": "get", "Query": "get", "InvokeFunction": "get",
		"PutObject": "create", "CreateTable": "create", "UpdateItem": "create", "BatchWriteItem": "create",
		"DeleteObject": "delete", "DeleteItem": "delete",
	}
	for op, want := range verbs {
		if got := coarseVerb(op); got != want {
			t.Errorf("coarseVerb(%q) = %q, want %q", op, got, want)
		}
	}
	kinds := map[string]string{"s3": "buckets", "dynamodb": "tables", "lambda": "functions", "nope": ""}
	for svc, want := range kinds {
		if got := dataServiceKind(svc); got != want {
			t.Errorf("dataServiceKind(%q) = %q, want %q", svc, got, want)
		}
	}
}

func TestParsePrincipalAndSplitTyped(t *testing.T) {
	pcases := []struct{ in, pType, name string }{
		{"User::alice", "User", "alice"},
		{"Group::eng", "Group", "eng"},
		{"Role::dep", "Role", "dep"},
		{"bob", "User", "bob"},
		{"  Role::x  ", "Role", "x"},
	}
	for _, c := range pcases {
		pt, n := parsePrincipal(c.in)
		if pt != c.pType || n != c.name {
			t.Errorf("parsePrincipal(%q) = (%q,%q), want (%q,%q)", c.in, pt, n, c.pType, c.name)
		}
	}
	scases := []struct{ in, typ, id string }{
		{"Bucket::assets", "Bucket", "assets"},
		{"assets", "", "assets"},
		{"", "", ""},
		{"*", "", ""},
	}
	for _, c := range scases {
		typ, id := splitTyped(c.in)
		if typ != c.typ || id != c.id {
			t.Errorf("splitTyped(%q) = (%q,%q), want (%q,%q)", c.in, typ, id, c.typ, c.id)
		}
	}
}

func TestSimContext(t *testing.T) {
	if c := simContext(nil); c["authenticated"] != true {
		t.Errorf("default authenticated should be true, got %v", c["authenticated"])
	}
	c := simContext(map[string]any{"sourceIp": "1.2.3.4", "authenticated": "false"})
	if c["sourceIp"] != "1.2.3.4" {
		t.Errorf("sourceIp not passed through: %v", c["sourceIp"])
	}
	if c["authenticated"] != false { // "false" string coerced to bool
		t.Errorf("authenticated string not coerced to bool: %v (%T)", c["authenticated"], c["authenticated"])
	}
}

func TestCombineDecision(t *testing.T) {
	allow := planeResult{Decision: "allow"}
	deny := planeResult{Decision: "deny", Reason: "explicit forbid"}
	notGov := planeResult{Decision: "not-governed"}
	indet := planeResult{Decision: "indeterminate", Reason: "role unbound"}

	cases := []struct {
		name     string
		cp, dp   planeResult
		decision string
	}{
		{"allow+notgoverned", allow, notGov, "allow"},
		{"allow+allow", allow, planeResult{Decision: "allow"}, "allow"},
		{"allow+deny", allow, deny, "deny"},
		{"deny+anything", deny, allow, "deny"},
		{"indeterminate+deny", indet, deny, "deny"},
		{"indeterminate+notgoverned", indet, notGov, "indeterminate"},
	}
	for _, c := range cases {
		got, reason := combineDecision(c.cp, c.dp)
		if got != c.decision {
			t.Errorf("%s: combineDecision = %q (%q), want %q", c.name, got, reason, c.decision)
		}
	}
}

// dataPlaneCheckerFor + the real Cedar engine: an end-to-end data-plane evaluation with no cluster.
// This exercises exactly the enforcement path the aws-shim uses, so the simulator's data-plane
// answer matches production.
func TestDataPlaneCheckerForEndToEnd(t *testing.T) {
	var p crdPolicy
	p.Metadata.Name = "s3ro"
	p.Spec.DataPlane = &cedarBlock{
		AppliesTo: []string{"User::alice"},
		Statements: []cedarStatement{
			{Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::assets"}},
			{Effect: "Deny", Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::secret"}},
		},
	}
	// A policy with no dataPlane must be ignored by the loader.
	var plain crdPolicy
	plain.Metadata.Name = "plain"
	plain.Spec.Statements = []policyStatement{{Actions: []string{"volumes:Get"}}}

	checker := dataPlaneCheckerFor([]crdPolicy{p, plain})
	ctx := context.Background()
	rc := map[string]any{"authenticated": true}

	// Allowed resource.
	if allowed, governed, _ := checker.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "assets", rc); !governed || !allowed {
		t.Errorf("alice on Bucket::assets: governed=%v allowed=%v, want true/true", governed, allowed)
	}
	// Explicit Deny wins.
	if allowed, governed, _ := checker.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "secret", rc); !governed || allowed {
		t.Errorf("alice on Bucket::secret: governed=%v allowed=%v, want true/false", governed, allowed)
	}
	// Default deny for an un-allowed resource within a governed service.
	if allowed, governed, _ := checker.Authorize(ctx, "User", "alice", nil, "s3:GetObject", "Bucket", "other", rc); !governed || allowed {
		t.Errorf("alice on Bucket::other: governed=%v allowed=%v, want true/false", governed, allowed)
	}
	// A service the principal has no statement for is not governed → coarse decision stands.
	if _, governed, _ := checker.Authorize(ctx, "User", "alice", nil, "dynamodb:Query", "Table", "orders", rc); governed {
		t.Errorf("alice on dynamodb: governed=%v, want false", governed)
	}
	// A principal no policy names is not governed.
	if _, governed, _ := checker.Authorize(ctx, "User", "bob", nil, "s3:GetObject", "Bucket", "assets", rc); governed {
		t.Errorf("bob on s3: governed=%v, want false", governed)
	}
}

func TestSimulateCustom(t *testing.T) {
	ctx := context.Background()
	draft := &draftPolicyInput{
		AppliesTo: []string{"*"},
		Statements: []draftStatement{
			{Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::assets"}},
			{Effect: "Deny", Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::secret"}},
		},
	}
	run := func(resource string, actions ...string) simulateResp {
		return simulateCustom(ctx, simulateReq{Draft: draft, Resource: resource, Actions: actions}, nonEmpty(actions))
	}

	r := run("Bucket::assets", "s3:GetObject")
	if r.Mode != "custom" {
		t.Fatalf("mode=%q, want custom", r.Mode)
	}
	if r.Results[0].Decision != "allow" {
		t.Errorf("assets: decision=%q, want allow", r.Results[0].Decision)
	}
	if r.Results[0].Enforced {
		t.Error("a custom-mode (unattached draft) result must not be marked enforced")
	}
	if got := run("Bucket::secret", "s3:GetObject").Results[0].Decision; got != "deny" {
		t.Errorf("secret: %q, want deny", got)
	}
	if got := run("Bucket::other", "s3:GetObject").Results[0].Decision; got != "deny" {
		t.Errorf("other (governed default-deny): %q, want deny", got)
	}
	if got := run("Table::orders", "dynamodb:Query").Results[0].Decision; got != "not-governed" {
		t.Errorf("dynamodb not in draft: %q, want not-governed", got)
	}
	if got := run("", "volumes:Get").Results[0].Decision; got != "not-evaluable" {
		t.Errorf("control action in custom mode: %q, want not-evaluable", got)
	}
	if got := run("", "bogus").Results[0].Decision; got != "unknown" {
		t.Errorf("malformed action: %q, want unknown", got)
	}

	// Empty draft: warns and reports not-governed for a data action.
	empty := simulateCustom(ctx, simulateReq{Draft: &draftPolicyInput{}, Actions: []string{"s3:GetObject"}}, []string{"s3:GetObject"})
	if len(empty.Warnings) == 0 {
		t.Error("an empty draft should warn")
	}
	if empty.Results[0].Decision != "not-governed" {
		t.Errorf("empty draft: %q, want not-governed", empty.Results[0].Decision)
	}

	// IP condition flows through custom mode: an Allow gated on sourceIp ∈ 10.0.0.0/8.
	ipDraft := &draftPolicyInput{
		AppliesTo: []string{"*"},
		Statements: []draftStatement{{
			Effect: "Allow", Actions: []string{"s3:GetObject"}, Resources: []string{"Bucket::assets"},
			IPConditions: []draftIPCondition{{Key: "sourceIp", CIDR: "10.0.0.0/8"}},
		}},
	}
	ipRun := func(ip string) string {
		return simulateCustom(ctx, simulateReq{
			Draft: ipDraft, Resource: "Bucket::assets", Actions: []string{"s3:GetObject"},
			Context: map[string]any{"sourceIp": ip},
		}, []string{"s3:GetObject"}).Results[0].Decision
	}
	if got := ipRun("10.0.0.5"); got != "allow" {
		t.Errorf("in-CIDR: %q, want allow", got)
	}
	if got := ipRun("192.168.1.1"); got != "deny" {
		t.Errorf("out-of-CIDR (allow shouldn't fire → governed default-deny): %q, want deny", got)
	}
}
