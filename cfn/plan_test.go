package main

import (
	"os"
	"strings"
	"testing"
)

func mustPlan(t *testing.T, data []byte, params map[string]string, stack string) *Plan {
	t.Helper()
	p, err := BuildPlan(data, params, stack)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	return p
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func idx(order []string, id string) int {
	for i, v := range order {
		if v == id {
			return i
		}
	}
	return -1
}

func blockersJoined(p *Plan) string { return strings.Join(p.Blockers, "\n") }

// The realistic template: supported + one partial (S3) => PROVISIONABLE_WITH_CAVEATS, a
// condition-excluded resource, and a real dependency order.
func TestPlan_Webapp_DevCaveats(t *testing.T) {
	p := mustPlan(t, readFixture(t, "webapp.yaml"), map[string]string{"Stage": "dev"}, "web")

	if p.Verdict != ProvisionableWithCaveats {
		t.Fatalf("verdict = %s, want PROVISIONABLE_WITH_CAVEATS; blockers:\n%s", p.Verdict, blockersJoined(p))
	}
	if len(p.Blockers) != 0 {
		t.Fatalf("expected no blockers, got:\n%s", blockersJoined(p))
	}

	// ProdAlarms is gated on IsProd, which is false at Stage=dev.
	var prod *PlannedResource
	for i := range p.Resources {
		if p.Resources[i].LogicalID == "ProdAlarms" {
			prod = &p.Resources[i]
		}
	}
	if prod == nil || prod.Included {
		t.Fatalf("ProdAlarms should be excluded at Stage=dev, got %+v", prod)
	}
	if idx(p.Order, "ProdAlarms") != -1 {
		t.Fatalf("excluded ProdAlarms must not be in provisioning order: %v", p.Order)
	}

	// Dependency order: keys/roles before the things that reference them; Workflow last.
	for _, pair := range [][2]string{
		{"AppKey", "Assets"}, {"AppKey", "Api"}, {"AppRole", "Api"},
		{"Assets", "Api"}, {"Api", "Workflow"},
	} {
		if a, b := idx(p.Order, pair[0]), idx(p.Order, pair[1]); a == -1 || b == -1 || a > b {
			t.Errorf("order violated %s before %s: %v", pair[0], pair[1], p.Order)
		}
	}

	// The S3 caveat must be surfaced, not swallowed.
	var assets *PlannedResource
	for i := range p.Resources {
		if p.Resources[i].LogicalID == "Assets" {
			assets = &p.Resources[i]
		}
	}
	if assets == nil || assets.Status != Partial || !strings.Contains(assets.Note, "Application") {
		t.Fatalf("Assets should map partial via Application, got %+v", assets)
	}
}

func TestPlan_Webapp_ProdIncludesConditional(t *testing.T) {
	p := mustPlan(t, readFixture(t, "webapp.yaml"), map[string]string{"Stage": "prod"}, "web")
	if p.Verdict != ProvisionableWithCaveats {
		t.Fatalf("verdict = %s, want caveats; blockers:\n%s", p.Verdict, blockersJoined(p))
	}
	if idx(p.Order, "ProdAlarms") == -1 {
		t.Fatalf("ProdAlarms should be included at Stage=prod: %v", p.Order)
	}
}

// The cardinal rule: an unsupported/gated type or an unsupported intrinsic => REJECTED, with
// the exact reasons, and NOTHING is claimed provisionable.
func TestPlan_Unsupported_Rejected(t *testing.T) {
	p := mustPlan(t, readFixture(t, "unsupported.yaml"), nil, "x")
	if p.Verdict != Rejected {
		t.Fatalf("verdict = %s, want REJECTED", p.Verdict)
	}
	b := blockersJoined(p)
	for _, want := range []string{"DynamoDB", "CustomResource", "ImportValue"} {
		if !strings.Contains(b, want) {
			t.Errorf("blockers missing %q:\n%s", want, b)
		}
	}
	// gated type must be flagged gated, not silently dropped or treated as supported.
	for _, r := range p.Resources {
		if r.LogicalID == "Table" && r.Status != Gated {
			t.Errorf("Table should be gated, got %s", r.Status)
		}
		if r.LogicalID == "Users" && r.Status != Unsupported {
			t.Errorf("Users should be unsupported, got %s", r.Status)
		}
	}
}

func TestPlan_JSON(t *testing.T) {
	data := []byte(`{"Resources":{"K":{"Type":"AWS::KMS::Key","Properties":{"Description":"k"}}}}`)
	p := mustPlan(t, data, nil, "")
	if p.Verdict != Provisionable {
		t.Fatalf("verdict = %s, want PROVISIONABLE; blockers:\n%s", p.Verdict, blockersJoined(p))
	}
	if len(p.Order) != 1 || p.Order[0] != "K" {
		t.Fatalf("order = %v, want [K]", p.Order)
	}
}

func TestPlan_Cycle_Rejected(t *testing.T) {
	data := []byte(`
Resources:
  A:
    Type: AWS::IAM::Role
    Properties: { Path: !Ref B }
  B:
    Type: AWS::IAM::Role
    Properties: { Path: !Ref A }
`)
	p := mustPlan(t, data, nil, "")
	if p.Verdict != Rejected {
		t.Fatalf("verdict = %s, want REJECTED for a cycle", p.Verdict)
	}
	if !strings.Contains(blockersJoined(p), "circular") {
		t.Fatalf("expected a circular-dependency blocker:\n%s", blockersJoined(p))
	}
}

func TestPlan_MissingParam_Rejected(t *testing.T) {
	data := []byte(`
Parameters:
  Name: { Type: String }
Resources:
  R:
    Type: AWS::IAM::Role
    Properties: { RoleName: !Ref Name }
`)
	p := mustPlan(t, data, nil, "")
	if p.Verdict != Rejected {
		t.Fatalf("verdict = %s, want REJECTED when a required param is missing", p.Verdict)
	}
	n := 0
	for _, b := range p.Blockers {
		if strings.Contains(b, "Name") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one blocker mentioning Name, got %d:\n%s", n, blockersJoined(p))
	}
	// Supplying it clears the blocker.
	if p2 := mustPlan(t, data, map[string]string{"Name": "r"}, ""); p2.Verdict != Provisionable {
		t.Fatalf("with param supplied, verdict = %s, want PROVISIONABLE; blockers:\n%s", p2.Verdict, blockersJoined(p2))
	}
}

func TestPlan_Transform_Rejected(t *testing.T) {
	data := []byte(`
Transform: AWS::Serverless-2016-10-31
Resources:
  K: { Type: AWS::KMS::Key, Properties: { Description: k } }
`)
	p := mustPlan(t, data, nil, "")
	if p.Verdict != Rejected || !strings.Contains(blockersJoined(p), "Transform") {
		t.Fatalf("SAM/macro Transform should be REJECTED with a Transform blocker; got %s:\n%s", p.Verdict, blockersJoined(p))
	}
}

func TestLookup_UnknownAndCustomUnsupported(t *testing.T) {
	for _, ty := range []string{"AWS::Nonexistent::Thing", "Custom::MyResource"} {
		if e := Lookup(ty); e.Status != Unsupported || e.mappable() {
			t.Errorf("Lookup(%q) = %+v, want unsupported/not-mappable", ty, e)
		}
	}
	if !Lookup("AWS::Lambda::Function").mappable() {
		t.Error("Lambda should be mappable")
	}
}
