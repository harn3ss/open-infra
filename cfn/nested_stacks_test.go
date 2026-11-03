package cfn

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// fakeNested is a NestedStacks driver that deploys each child through the real engine, onto a fakeApplier
// of its own (a fakeApplier holds one stack record), reading child templates from a map by URL.
type fakeNested struct {
	templates map[string]string
	children  map[string]*fakeApplier // child name -> its "cluster"
	reqs      []NestedStackRequest
	deleted   []string
	failChild string // a child template resource (Kind/name) whose apply fails
}

func newFakeNested(templates map[string]string) *fakeNested {
	return &fakeNested{templates: templates, children: map[string]*fakeApplier{}}
}

func (f *fakeNested) CreateNested(ctx context.Context, req NestedStackRequest) (NestedStackResult, error) {
	f.reqs = append(f.reqs, req)
	body, ok := f.templates[req.TemplateURL]
	if !ok {
		return NestedStackResult{}, fmt.Errorf("TemplateURL %s: no such object", req.TemplateURL)
	}
	ap := &fakeApplier{}
	if f.failChild != "" {
		ap.failOn = f.failChild
	}
	f.children[req.Name] = ap
	id := awsidentity.Current().NewStackID(req.Name)
	opts := DeployOptions{StackName: req.Name, Namespace: "ns", Params: req.Parameters, StackID: id, ParentID: req.ParentID, RootID: req.RootID}
	rec, err := Deploy(ctx, []byte(body), opts, ap)
	res := NestedStackResult{StackID: id, Outputs: map[string]string{}}
	if rec != nil {
		for _, o := range rec.Outputs {
			res.Outputs[o.OutputKey] = o.OutputValue
		}
	}
	return res, err
}

func (f *fakeNested) DeleteNested(ctx context.Context, name string) error {
	f.deleted = append(f.deleted, name)
	ap, ok := f.children[name]
	if !ok || ap.stored == nil {
		return nil
	}
	_, err := Destroy(ctx, DeployOptions{StackName: name, Namespace: "ns"}, ap)
	return err
}

func (f *fakeNested) NestedOutputs(_ context.Context, name string) (NestedStackResult, bool, error) {
	ap, ok := f.children[name]
	if !ok || ap.stored == nil {
		return NestedStackResult{}, false, nil
	}
	res := NestedStackResult{StackID: ap.stored.StackID, Outputs: map[string]string{}}
	for _, o := range ap.stored.Outputs {
		res.Outputs[o.OutputKey] = o.OutputValue
	}
	return res, true, nil
}

func (f *fakeNested) NestedUnchanged(_ context.Context, req NestedStackRequest) (bool, string, error) {
	ap, ok := f.children[req.Name]
	if !ok || ap.stored == nil {
		return false, "it no longer exists", nil
	}
	if f.templates[req.TemplateURL] != ap.stored.Template {
		return false, "its template changed", nil
	}
	if !reflect.DeepEqual(req.Parameters, ap.stored.Parameters) && !(len(req.Parameters) == 0 && len(ap.stored.Parameters) == 0) {
		return false, "its parameters changed", nil
	}
	return true, "", nil
}

const childTmpl = `
Parameters:
  Env: { Type: String }
Resources:
  Inner:
    Type: AWS::KMS::Key
    Properties: { Description: !Sub "inner-${Env}" }
Outputs:
  KeyName: { Value: !Sub "child-${Env}" }
`

const parentTmpl = `
Parameters:
  Env: { Type: String, Default: prod }
Resources:
  Network:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub "https://s3.amazonaws.com/templates/${Env}/child.yaml"
      Parameters: { Env: !Ref Env }
      TimeoutInMinutes: 5
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: !GetAtt Network.Outputs.KeyName }
Outputs:
  FromChild: { Value: !GetAtt Network.Outputs.KeyName }
  ChildId:   { Value: !Ref Network }
`

func nestedOpts(drv NestedStacks) DeployOptions {
	o := deployOpts()
	o.StackID = awsidentity.Current().NewStackID(o.StackName)
	o.Caps.NestedStacks = true
	o.NestedStacks = drv
	return o
}

func nestedFixture() map[string]string {
	return map[string]string{"https://s3.amazonaws.com/templates/prod/child.yaml": childTmpl}
}

// A nested stack is a stack of its own: created from its TemplateURL (a Fn::Sub) with its parameters, its
// StackId is the resource's physical id and Ref, and its Outputs feed the parent's resources and Outputs.
func TestNested_CreatesAChildStack(t *testing.T) {
	drv := newFakeNested(nestedFixture())
	f := &fakeApplier{}
	opts := nestedOpts(drv)
	rec, err := Deploy(context.Background(), []byte(parentTmpl), opts, f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" || len(drv.reqs) != 1 {
		t.Fatalf("status %s, %d nested creates", rec.Status, len(drv.reqs))
	}
	req := drv.reqs[0]
	if req.TemplateURL != "https://s3.amazonaws.com/templates/prod/child.yaml" || req.Parameters["Env"] != "prod" ||
		req.Parent != "s" || req.ParentID != opts.StackID || req.RootID != opts.StackID || req.LogicalID != "Network" || req.Timeout.Minutes() != 5 {
		t.Fatalf("nested request = %+v", req)
	}
	if !regexp.MustCompile(`^s-network-[a-z0-9]{12}$`).MatchString(req.Name) {
		t.Fatalf("child stack name %q is not <parent>-<logical id>-<suffix>", req.Name)
	}
	child := drv.children[req.Name].stored
	if child == nil || child.Status != "CREATE_COMPLETE" || child.ParentID != opts.StackID || child.RootID != opts.StackID {
		t.Fatalf("child record = %+v", child)
	}
	var nested *StackResource
	for i := range rec.Resources {
		if rec.Resources[i].LogicalID == "Network" {
			nested = &rec.Resources[i]
		}
	}
	if nested == nil || !IsNestedStack(*nested) || nested.PhysicalID != child.StackID || nested.Name != req.Name || nested.Type != StackTypeName {
		t.Fatalf("the parent's Network resource = %+v", nested)
	}
	if got := outputValue(rec, "FromChild"); got != "child-prod" {
		t.Fatalf("Output FromChild = %q, want the child's Output", got)
	}
	if got := outputValue(rec, "ChildId"); got != child.StackID {
		t.Fatalf("Output ChildId (Ref) = %q, want the child's StackId %s", got, child.StackID)
	}
	if d, _ := f.liveSpecs["EncryptionKey/s-key"]["description"].(string); d != "child-prod" {
		t.Fatalf("a parent resource reading the child's Output got %q", d)
	}
	for _, a := range f.applied {
		if strings.Contains(a, "NestedStack") {
			t.Fatalf("the nested-stack sentinel was applied as an object: %v", f.applied)
		}
	}

	// Deleting the parent deletes the child, as a stack.
	if _, err := Destroy(context.Background(), opts, f); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if len(drv.deleted) != 1 || drv.deleted[0] != req.Name || drv.children[req.Name].stored != nil {
		t.Fatalf("the child was not deleted with its parent: deleted %v", drv.deleted)
	}
}

// A child that fails is rolled back as a stack, and the parent's rollback deletes it.
func TestNested_ChildFailureRollsBackTheParent(t *testing.T) {
	drv := newFakeNested(nestedFixture())
	f := &fakeApplier{}
	// The child's template is one the engine refuses: its create fails before it creates anything.
	tmpl := strings.Replace(parentTmpl, "${Env}/child.yaml", "bad/child.yaml", 1)
	drv.templates["https://s3.amazonaws.com/templates/bad/child.yaml"] = "Resources:\n  Gone: { Type: AWS::Nope::Thing }\n"
	rec, err := Deploy(context.Background(), []byte(tmpl), nestedOpts(drv), f)
	if err == nil {
		t.Fatal("a parent whose nested stack failed must fail")
	}
	if rec.Status != "ROLLBACK_COMPLETE" {
		t.Fatalf("parent status = %s, want ROLLBACK_COMPLETE", rec.Status)
	}
	if !strings.Contains(err.Error(), "Embedded stack") {
		t.Fatalf("the failure should name the embedded stack: %v", err)
	}
	if len(drv.reqs) != 1 || len(drv.deleted) != 1 || drv.deleted[0] != drv.reqs[0].Name {
		t.Fatalf("the failed child must be deleted by the rollback: created %v, deleted %v", drv.reqs, drv.deleted)
	}
	for _, a := range f.applied {
		if a == "EncryptionKey/s-key" {
			t.Fatal("the parent's resource that reads the child's Output must not be created after the child failed")
		}
	}
}

// An update that leaves the nested stack as it is runs, its resources reading the child's current Outputs;
// one that would change the nested stack is refused with nothing changed.
func TestNested_UpdateLeavesTheChildOrIsRefused(t *testing.T) {
	drv := newFakeNested(nestedFixture())
	f := &fakeApplier{}
	opts := nestedOpts(drv)
	if _, err := Deploy(context.Background(), []byte(parentTmpl), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	childName := drv.reqs[0].Name
	childID := drv.children[childName].stored.StackID

	upd := parentTmpl + `  Extra: { Value: !GetAtt Network.Outputs.KeyName }
`
	upd = strings.Replace(upd, "Resources:\n", "Resources:\n  Key2:\n    Type: AWS::KMS::Key\n    Properties: { Description: !GetAtt Network.Outputs.KeyName }\n", 1)
	uopts := nestedOpts(drv)
	uopts.StackID = ""
	out, err := Update(context.Background(), []byte(upd), uopts, f)
	if err != nil {
		t.Fatalf("an update leaving the nested stack as it is: %v", err)
	}
	if out.Status != "UPDATE_COMPLETE" || outputValue(out, "Extra") != "child-prod" || outputValue(out, "ChildId") != childID {
		t.Fatalf("after the update: %s, Extra=%q ChildId=%q", out.Status, outputValue(out, "Extra"), outputValue(out, "ChildId"))
	}
	if d, _ := f.liveSpecs["EncryptionKey/s-key2"]["description"].(string); d != "child-prod" {
		t.Fatalf("a new resource reading the child's current Output got %q", d)
	}
	if len(drv.reqs) != 1 || len(drv.deleted) != 0 {
		t.Fatalf("the update touched the nested stack: creates %d, deletes %v", len(drv.reqs), drv.deleted)
	}
	for _, r := range out.Resources {
		if r.LogicalID == "Network" && (r.Name != childName || r.PhysicalID != childID) {
			t.Fatalf("the nested stack resource lost its stack: %+v", r)
		}
	}

	before := *f.stored
	changed := strings.Replace(upd, "Parameters: { Env: !Ref Env }", "Parameters: { Env: other }", 1)
	if _, err := Update(context.Background(), []byte(changed), uopts, f); err == nil || !strings.Contains(err.Error(), "Network (its parameters changed)") {
		t.Fatalf("an update changing the nested stack's parameters must be refused: %v", err)
	}
	removed := "Resources:\n  Key:\n    Type: AWS::KMS::Key\n    Properties: { Description: k }\n"
	if _, err := Update(context.Background(), []byte(removed), uopts, f); err == nil || !strings.Contains(err.Error(), "Network (removed)") {
		t.Fatalf("an update removing the nested stack must be refused: %v", err)
	}
	if !reflect.DeepEqual(f.stored.Resources, before.Resources) || f.stored.Status != before.Status {
		t.Fatal("a refused update changed the stack")
	}
}

// What a nested stack's resource asks for that open-infra does not do is refused, not approximated; and on
// a path that cannot create stacks (the CLI flattens instead) the type refuses.
func TestNested_TranslatorRefusals(t *testing.T) {
	ctx := &stackCtx{caps: Capabilities{NestedStacks: true}, template: &Template{Resources: map[string]Resource{}}}
	for name, tc := range map[string]struct {
		props map[string]any
		want  string
	}{
		"notifications": {map[string]any{"TemplateURL": "https://s3.amazonaws.com/b/k", "NotificationARNs": []any{"arn:aws:sns:us-east-1:1:t"}}, "NotificationARNs"},
		"list value":    {map[string]any{"TemplateURL": "https://s3.amazonaws.com/b/k", "Parameters": map[string]any{"Subnets": []any{"a", "b"}}}, "Parameters.Subnets"},
		"no url":        {map[string]any{}, "TemplateURL is required"},
		"bad timeout":   {map[string]any{"TemplateURL": "https://s3.amazonaws.com/b/k", "TimeoutInMinutes": 0}, "TimeoutInMinutes"},
		"unknown prop":  {map[string]any{"TemplateURL": "https://s3.amazonaws.com/b/k", "StackPolicyURL": "x"}, "StackPolicyURL"},
	} {
		if _, fs := translateNestedStack("Child", tc.props, ctx); len(fs) == 0 || !strings.Contains(joinFindings(fs), tc.want) {
			t.Errorf("%s: findings %v, want one naming %s", name, fs, tc.want)
		}
	}
	if _, fs := translateNestedStack("Child", map[string]any{"TemplateURL": "https://s3.amazonaws.com/b/k"}, &stackCtx{}); len(fs) == 0 {
		t.Error("without a front door that creates stacks, a nested stack must refuse")
	}
	m, fs := translateNestedStack("Child", map[string]any{"TemplateURL": "https://s3.amazonaws.com/b/k", "Parameters": map[string]any{"N": float64(3), "B": true}, "Tags": []any{}}, ctx)
	if len(fs) > 0 || m.Spec["parameters"].(map[string]any)["N"] != "3" || m.Spec["parameters"].(map[string]any)["B"] != "true" || len(m.Caveats) != 1 {
		t.Fatalf("scalar parameters and a Tags caveat: %+v %v", m, fs)
	}
}

// Every property a nested stack's resource accepts changes the child it asks for, or is refused.
func TestFidelityGuard_NestedStack(t *testing.T) {
	old := guardCaps
	guardCaps = Capabilities{NestedStacks: true}
	t.Cleanup(func() { guardCaps = old })
	guardCheck(t, []guardBaseline{
		yamlBaseline("AWS::CloudFormation::Stack", `{ TemplateURL: "https://s3.amazonaws.com/templates/child.yaml" }`, ""),
	})
}

// A stack with a nested stack plans PROVISIONABLE where stacks can be created, and its Outputs reading the
// child's Outputs are not refused.
func TestNested_PlansWhereStacksCanBeCreated(t *testing.T) {
	p, err := BuildPlanWithCaps([]byte(parentTmpl), nil, nil, "s", Capabilities{NestedStacks: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Verdict == Rejected {
		t.Fatalf("plan rejected: %v", p.Blockers)
	}
	p, err = BuildPlanWithCaps([]byte(parentTmpl), nil, nil, "s", Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Verdict != Rejected {
		t.Fatal("without nested-stack support the plan must refuse")
	}
}
