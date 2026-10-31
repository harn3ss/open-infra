package cfn

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

// The realistic template exercises mapping, intrinsics, a condition, and dependency ordering — and
// now that plan runs the TRANSLATE GATE (the same gate deploy runs), it is honestly REJECTED: its
// shapes are faithful-AWS but open-infra refuses them at deploy (a KMS-SSE bucket, a lambda-trust role,
// a zip/Runtime Lambda, an ASL that references a sibling's ARN). plan surfaces each refusal per-resource
// instead of letting deploy discover them — this is the "a PROVISIONABLE* verdict means deploy won't
// refuse" guarantee. The mapping/ordering/condition logic is still asserted.
func TestPlan_Webapp_Dev_TranslateGateSurfacesRefusals(t *testing.T) {
	p := mustPlan(t, readFixture(t, "webapp.yaml"), map[string]string{"Stage": "dev"}, "web")

	if p.Verdict != Rejected {
		t.Fatalf("verdict = %s, want REJECTED (the translate gate refuses several faithful-AWS shapes); blockers:\n%s", p.Verdict, blockersJoined(p))
	}
	// Each deploy-refusal is surfaced at PLAN now, not at deploy.
	b := blockersJoined(p)
	for _, want := range []string{
		"ec2.amazonaws.com",                        // AppRole trusts lambda, not the ec2 service principal
		"BucketEncryption",                         // Assets per-bucket SSE needs the opt-in objectEncryption stack
		"PackageType: Image",                       // Api is a zip/Runtime Lambda
		"ASL definition references cross-resource", // Workflow Task Resource is a sibling ARN
	} {
		if !strings.Contains(b, want) {
			t.Errorf("plan must surface the deploy-refusal %q:\n%s", want, b)
		}
	}

	// ProdAlarms is gated on IsProd, which is false at Stage=dev.
	var prod, assets *PlannedResource
	for i := range p.Resources {
		switch p.Resources[i].LogicalID {
		case "ProdAlarms":
			prod = &p.Resources[i]
		case "Assets":
			assets = &p.Resources[i]
		}
	}
	if prod == nil || prod.Included {
		t.Fatalf("ProdAlarms should be excluded at Stage=dev, got %+v", prod)
	}
	if idx(p.Order, "ProdAlarms") != -1 {
		t.Fatalf("excluded ProdAlarms must not be in provisioning order: %v", p.Order)
	}

	// Dependency order is still computed (keys/roles before dependents; Workflow last), even when rejected.
	for _, pair := range [][2]string{
		{"AppKey", "Assets"}, {"AppKey", "Api"}, {"AppRole", "Api"},
		{"Assets", "Api"}, {"Api", "Workflow"},
	} {
		if a, b := idx(p.Order, pair[0]), idx(p.Order, pair[1]); a == -1 || b == -1 || a > b {
			t.Errorf("order violated %s before %s: %v", pair[0], pair[1], p.Order)
		}
	}

	// Assets still MAPS (partial, kind: Bucket) and carries the per-resource translate refusal.
	if assets == nil || assets.Status != Partial || assets.Kind != "Bucket" {
		t.Fatalf("Assets should map partial to kind: Bucket, got %+v", assets)
	}
	if len(assets.TranslateRefusals) == 0 || !strings.Contains(strings.Join(assets.TranslateRefusals, " "), "BucketEncryption") {
		t.Fatalf("Assets must carry its translate refusal (BucketEncryption), got %+v", assets.TranslateRefusals)
	}
}

func TestPlan_Webapp_ProdIncludesConditional(t *testing.T) {
	p := mustPlan(t, readFixture(t, "webapp.yaml"), map[string]string{"Stage": "prod"}, "web")
	// Still rejected by the translate gate (the conditional only adds ProdAlarms), but ProdAlarms is now
	// included in the order — the condition-inclusion logic is independent of the verdict.
	if p.Verdict != Rejected {
		t.Fatalf("verdict = %s, want REJECTED; blockers:\n%s", p.Verdict, blockersJoined(p))
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
	for _, want := range []string{"GuardDuty", "ImportValue"} {
		if !strings.Contains(b, want) {
			t.Errorf("blockers missing %q:\n%s", want, b)
		}
	}
	// an unsupported type must be flagged unsupported, not silently dropped or treated as supported.
	for _, r := range p.Resources {
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
	// A Supported + deployable type (KMS::Key: create translator, no partial caveats), so with the
	// param supplied the plan is cleanly PROVISIONABLE — isolating the missing-param behaviour.
	data := []byte(`
Parameters:
  Name: { Type: String }
Resources:
  R:
    Type: AWS::KMS::Key
    Properties: { Description: !Ref Name }
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

func TestLookup_UnknownUnsupported_CustomSupported(t *testing.T) {
	// A genuinely-unknown type stays unsupported — the engine never guesses.
	for _, ty := range []string{"AWS::Nonexistent::Thing", "AWS::GuardDuty::Detector"} {
		if e := Lookup(ty); e.Status != Unsupported || e.mappable() {
			t.Errorf("Lookup(%q) = %+v, want unsupported/not-mappable", ty, e)
		}
	}
	// A Lambda-backed custom resource IS supported now (#269): invoke-at-deploy with a create translator.
	for _, ty := range []string{"AWS::CloudFormation::CustomResource", "Custom::MyResource"} {
		if e := Lookup(ty); !e.mappable() || !hasTranslator(ty) {
			t.Errorf("Lookup(%q) = %+v, want supported/mappable with a translator", ty, e)
		}
	}
	if !Lookup("AWS::Lambda::Function").mappable() {
		t.Error("Lambda should be mappable")
	}
}

// A type that maps at plan but has no create translator (an IAM Group) is flagged Deployable=false,
// and a stack containing one is never cleanly PROVISIONABLE — the map-vs-deploy gap is surfaced at
// plan time, not discovered at deploy. A translator-backed type is Deployable=true.
func TestPlan_DeployabilitySurfaced(t *testing.T) {
	data := []byte(`
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: k }
  Group:
    Type: AWS::IAM::Group
    Properties: { Path: / }
`)
	p := mustPlan(t, data, nil, "")
	// The Group maps to a kind but has no create translator → deploy refuses it, so plan REJECTS (parity),
	// and the blocker says exactly why — it still MAPS, it just can't be created.
	if p.Verdict != Rejected {
		t.Fatalf("verdict = %s, want REJECTED (a mapped-but-undeployable Group); blockers:\n%s", p.Verdict, blockersJoined(p))
	}
	if b := blockersJoined(p); !strings.Contains(b, "Group") || !strings.Contains(b, "no create translator") {
		t.Fatalf("the blocker must name the Group + 'no create translator', got:\n%s", b)
	}
	byID := map[string]PlannedResource{}
	for _, r := range p.Resources {
		byID[r.LogicalID] = r
	}
	if !byID["Key"].Deployable {
		t.Errorf("KMS::Key has a create translator — want Deployable=true")
	}
	if byID["Group"].Deployable {
		t.Errorf("IAM::Group has no create translator — want Deployable=false")
	}
	if byID["Group"].Kind != "Group" {
		t.Errorf("IAM::Group should still MAP to kind: Group at plan, got %q", byID["Group"].Kind)
	}
}

// API Gateway REST v1 (#295): a REST-v1 stack maps (Partial — faithful-subset caveats) and is
// create-deployable via the in-cluster doorway (the whole API collates into one provisioning plan on
// its RestApi; the CLI refuses with no hook). Every AWS::ApiGateway::* type is translator-backed, so
// Deployable=true; the stack is PROVISIONABLE_WITH_CAVEATS (Partial).
func TestPlan_ApiGatewayRestV1(t *testing.T) {
	data := []byte(`
Resources:
  Api:
    Type: AWS::ApiGateway::RestApi
    Properties: { Name: orders }
  Res:
    Type: AWS::ApiGateway::Resource
    Properties: { RestApiId: !Ref Api, ParentId: root, PathPart: items }
  Method:
    Type: AWS::ApiGateway::Method
    Properties: { RestApiId: !Ref Api, ResourceId: !Ref Res, HttpMethod: POST, AuthorizationType: NONE }
  Model:
    Type: AWS::ApiGateway::Model
    Properties: { RestApiId: !Ref Api, ContentType: application/json, Name: Item, Schema: {} }
  Validator:
    Type: AWS::ApiGateway::RequestValidator
    Properties: { RestApiId: !Ref Api, ValidateRequestBody: true }
  Deployment:
    Type: AWS::ApiGateway::Deployment
    Properties: { RestApiId: !Ref Api }
  Stage:
    Type: AWS::ApiGateway::Stage
    Properties: { RestApiId: !Ref Api, DeploymentId: !Ref Deployment, StageName: prod }
  Key:
    Type: AWS::ApiGateway::ApiKey
    Properties: { Enabled: true }
  Plan:
    Type: AWS::ApiGateway::UsagePlan
    Properties: { ApiStages: [ { ApiId: !Ref Api, Stage: prod } ] }
`)
	p := mustPlan(t, data, nil, "")
	byID := map[string]PlannedResource{}
	for _, r := range p.Resources {
		byID[r.LogicalID] = r
	}
	for _, id := range []string{"Api", "Res", "Method", "Model", "Validator", "Deployment", "Stage", "Key", "Plan"} {
		if byID[id].Kind == "" || byID[id].Status != Partial {
			t.Errorf("%s should MAP at plan (Partial), got kind=%q status=%q", id, byID[id].Kind, byID[id].Status)
		}
		if !byID[id].Deployable {
			t.Errorf("%s is translator-backed — want Deployable=true (collates into the RestApi plan, provisioned via the in-cluster doorway)", id)
		}
	}
	// Partial (faithful-subset) → caveated, never cleanly provisionable.
	if p.Verdict != ProvisionableWithCaveats {
		t.Fatalf("verdict = %s, want PROVISIONABLE_WITH_CAVEATS (REST v1 is a faithful subset); blockers:\n%s", p.Verdict, blockersJoined(p))
	}
}

// Lambda versions/aliases (#257): a published Version is a Knative revision (assigned at apply) and an
// Alias is a weighted traffic tag on a kind: Function — both are recognized at plan but neither is
// create-deployable (Deployable=false), because the alias->revision binding isn't template-derivable.
// Traffic is declared natively via kind: Function spec.aliases (render-tested + the shim Invoke doorway
// routes a Qualifier to it). This keeps a migrating stack HONEST: it maps, but deploy refuses rather
// than fabricating a revision pin.
func TestPlan_LambdaVersionAliasPlanOnly(t *testing.T) {
	data := []byte(`
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/fn:latest } }
  Ver:
    Type: AWS::Lambda::Version
    Properties: { FunctionName: !Ref Fn }
  Prod:
    Type: AWS::Lambda::Alias
    Properties: { FunctionName: !Ref Fn, FunctionVersion: !GetAtt Ver.Version, Name: prod }
`)
	p := mustPlan(t, data, nil, "")
	byID := map[string]PlannedResource{}
	for _, r := range p.Resources {
		byID[r.LogicalID] = r
	}
	// Both map at plan (no backing-kind blocker) ...
	for _, id := range []string{"Ver", "Prod"} {
		if byID[id].Kind == "" || byID[id].Status != Partial {
			t.Errorf("%s should MAP at plan (Partial), got kind=%q status=%q", id, byID[id].Kind, byID[id].Status)
		}
		// ... but neither is create-deployable (no translator).
		if byID[id].Deployable {
			t.Errorf("%s has no create translator — want Deployable=false (Knative revisions aren't template-derivable)", id)
		}
	}
	// They map but have no create translator, so deploy refuses them — plan REJECTS (parity), naming the
	// structural reason. Traffic is declared natively via kind: Function spec.aliases instead.
	if p.Verdict != Rejected {
		t.Fatalf("verdict = %s, want REJECTED (version/alias map but deploy refuses them); blockers:\n%s", p.Verdict, blockersJoined(p))
	}
	if !strings.Contains(blockersJoined(p), "no create translator") {
		t.Fatalf("the blocker must say 'no create translator', got:\n%s", blockersJoined(p))
	}
}
