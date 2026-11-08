package cfn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A custom resource whose ServiceToken !GetAtt's an in-stack AWS::Lambda::Function translates to the
// invoke sentinel: the backing Function's k8s name, the CFN resource type, and the ResourceProperties
// (minus ServiceToken, which AWS does not pass to the handler).
func TestTranslateCustomResource_InStackFunction(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/h:latest } }
  CR:
    Type: Custom::Thing
    Properties: { ServiceToken: !GetAtt Fn.Arn, Foo: bar }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateCustomResource("CR", ecsResolvedService(t, ctx, "CR"), ctx)
	if len(fs) != 0 {
		t.Fatalf("a faithful custom resource must translate: %s", findingsText(fs))
	}
	if m.APIVersion != customResourceAPIVersion || m.Kind != customResourceKind {
		t.Fatalf("bad sentinel head: %+v", m)
	}
	if m.Spec["function"] != k8sName("Fn") {
		t.Errorf("function should be the in-stack Function's k8s name %q, got %v", k8sName("Fn"), m.Spec["function"])
	}
	if m.Spec["resourceType"] != "Custom::Thing" {
		t.Errorf("resourceType = %v, want Custom::Thing", m.Spec["resourceType"])
	}
	props, _ := m.Spec["properties"].(map[string]any)
	if _, has := props["ServiceToken"]; has {
		t.Error("ServiceToken must be stripped from the ResourceProperties the handler receives")
	}
	if props["Foo"] != "bar" {
		t.Errorf("ResourceProperties missing Foo: %#v", props)
	}
}

// Also accepts the AWS::CloudFormation::CustomResource spelling with a !Ref ServiceToken.
func TestTranslateCustomResource_RefServiceToken(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/h:latest } }
  CR:
    Type: AWS::CloudFormation::CustomResource
    Properties: { ServiceToken: !Ref Fn }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateCustomResource("CR", ecsResolvedService(t, ctx, "CR"), ctx)
	if len(fs) != 0 || m == nil {
		t.Fatalf("a !Ref ServiceToken to an in-stack Function must translate: %s", findingsText(fs))
	}
	if m.Spec["function"] != k8sName("Fn") {
		t.Errorf("function = %v", m.Spec["function"])
	}
}

// FAIL-CLOSED: a ServiceToken that is not a !Ref/!GetAtt to an in-stack AWS::Lambda::Function refuses.
func TestTranslateCustomResource_FailClosed(t *testing.T) {
	cases := map[string]string{
		"out-of-stack ARN": `
Resources:
  CR:
    Type: Custom::X
    Properties: { ServiceToken: "arn:aws:lambda:us-east-1:111111111111:function:external" }`,
		"ref to a non-function": `
Resources:
  B:
    Type: AWS::S3::Bucket
    Properties: {}
  CR:
    Type: Custom::X
    Properties: { ServiceToken: !GetAtt B.Arn }`,
		"missing ServiceToken": `
Resources:
  CR:
    Type: Custom::X
    Properties: { Foo: bar }`,
	}
	for name, tmpl := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := ecsCtx(t, tmpl)
			m, fs := translateCustomResource("CR", ecsResolvedService(t, ctx, "CR"), ctx)
			if len(fs) == 0 {
				t.Fatalf("expected a fail-closed finding, got manifest %+v", m)
			}
			if !strings.Contains(findingsText(fs), "ServiceToken") {
				t.Errorf("refusal should mention ServiceToken: %s", findingsText(fs))
			}
		})
	}
}

// The interleaved deploy: a custom resource's Function is invoked at its point in dependency order and
// its returned Data flows into a LATER dependent's Fn::GetAtt — the faithful AWS behavior (#269).
func TestDeploy_CustomResource_DataFlowsToGetAtt(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/handler:latest } }
  Setup:
    Type: Custom::Setup
    Properties: { ServiceToken: !GetAtt Fn.Arn, Foo: bar }
  Consumer:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: Image
      Code: { ImageUri: ghcr.io/x/consumer:latest }
      Environment: { Variables: { ENDPOINT: !GetAtt Setup.Endpoint } }
`
	f := &fakeApplier{}
	var invokedFn string
	var invokedEvent map[string]any
	opts := deployOpts()
	opts.Invoke = func(_ context.Context, _, fn string, event []byte) (map[string]any, error) {
		invokedFn = fn
		_ = json.Unmarshal(event, &invokedEvent)
		return map[string]any{"Status": "SUCCESS", "Data": map[string]any{"Endpoint": "https://computed.example"}}, nil
	}
	rec, err := Deploy(context.Background(), []byte(tmpl), opts, f)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("status = %s, want CREATE_COMPLETE", rec.Status)
	}
	if invokedFn != stackQualifiedName("s", "Fn") {
		t.Errorf("invoked function = %q, want %q", invokedFn, stackQualifiedName("s", "Fn"))
	}
	if invokedEvent["RequestType"] != "Create" || invokedEvent["LogicalResourceId"] != "Setup" {
		t.Errorf("custom-resource event wrong: %#v", invokedEvent)
	}
	// The returned Data resolved the Consumer's Fn::GetAtt.
	consumer := f.liveSpecs["Function/"+stackQualifiedName("s", "Consumer")]
	if consumer == nil {
		t.Fatalf("Consumer not applied; liveSpecs keys=%v", keysOf(f.liveSpecs))
	}
	js, _ := json.Marshal(consumer)
	if !strings.Contains(string(js), "https://computed.example") {
		t.Errorf("custom-resource Data did not flow into Consumer via GetAtt: %s", js)
	}
	// The sentinel is NEVER applied as a k8s object.
	for _, a := range f.applied {
		if strings.Contains(a, "CustomResourceInvoke") {
			t.Errorf("custom resource must not be applied as an object: %v", f.applied)
		}
	}
}

// A custom resource that returns FAILED rolls the whole deploy back (fail-closed, no orphans).
func TestDeploy_CustomResource_FailedStatus_RollsBack(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/handler:latest } }
  Setup:
    Type: Custom::Setup
    Properties: { ServiceToken: !GetAtt Fn.Arn }
`
	f := &fakeApplier{}
	opts := deployOpts()
	opts.Invoke = func(_ context.Context, _, _ string, _ []byte) (map[string]any, error) {
		return map[string]any{"Status": "FAILED", "Reason": "boom"}, nil
	}
	rec, err := Deploy(context.Background(), []byte(tmpl), opts, f)
	if err == nil {
		t.Fatal("a FAILED custom resource must fail the deploy")
	}
	if rec != nil && rec.Status != "ROLLBACK_COMPLETE" {
		t.Errorf("status = %s, want ROLLBACK_COMPLETE", rec.Status)
	}
	// The Function applied before the failing custom resource must have been rolled back (deleted).
	var fnDeleted bool
	for _, d := range f.deleted {
		if strings.HasPrefix(d, "Function/") {
			fnDeleted = true
		}
	}
	if !fnDeleted {
		t.Errorf("rollback should delete the applied Function; deleted=%v", f.deleted)
	}
}

// Without an invoker (the CLI deploy path, not in-cluster), a custom-resource stack refuses rather than
// guessing — fail-closed.
func TestDeploy_CustomResource_NoInvoker_Refused(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/handler:latest } }
  Setup:
    Type: Custom::Setup
    Properties: { ServiceToken: !GetAtt Fn.Arn }
`
	f := &fakeApplier{}
	opts := deployOpts() // Invoke is nil
	_, err := Deploy(context.Background(), []byte(tmpl), opts, f)
	if err == nil || !strings.Contains(err.Error(), "in-cluster") {
		t.Fatalf("a custom-resource stack with no invoker must refuse with an in-cluster hint, got: %v", err)
	}
}

// #348: a custom resource a rolled-back create had already created gets its Function's Delete event (as
// AWS sends it), before its Function is deleted; one whose Delete fails leaves the stack ROLLBACK_FAILED.
func TestDeploy_CustomResource_RollbackSendsDelete(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/handler:latest } }
  Setup:
    Type: Custom::Setup
    Properties: { ServiceToken: !GetAtt Fn.Arn, Seed: x }
  Last:
    Type: AWS::KMS::Key
    DependsOn: Setup
`
	for deleteStatus, want := range map[string][2]string{"SUCCESS": {"ROLLBACK_COMPLETE", "DELETE_COMPLETE"}, "FAILED": {"ROLLBACK_FAILED", "DELETE_FAILED"}} {
		f := &fakeApplier{notReady: "s-last"}
		opts := deployOpts()
		var requests []string
		opts.Invoke = func(_ context.Context, _, _ string, event []byte) (map[string]any, error) {
			var ev map[string]any
			_ = json.Unmarshal(event, &ev)
			rt, _ := ev["RequestType"].(string)
			requests = append(requests, rt)
			if rt == "Delete" {
				for _, d := range f.deleted {
					if strings.HasPrefix(d, "Function/") {
						t.Errorf("the Delete event must come before the Function is deleted: %v", f.deleted)
					}
				}
				return map[string]any{"Status": deleteStatus, "Reason": "cleanup"}, nil
			}
			return map[string]any{"Status": "SUCCESS"}, nil
		}
		rec, err := Deploy(context.Background(), []byte(tmpl), opts, f)
		if err == nil {
			t.Fatal("test premise: the create fails at Last")
		}
		if strings.Join(requests, ",") != "Create,Delete" {
			t.Fatalf("want the custom resource's Create then Delete on rollback, got %v", requests)
		}
		if rec.Status != want[0] || !hasEvent(rec, "Setup", want[1]) {
			t.Fatalf("Delete answered %s: status %s, events %+v", deleteStatus, rec.Status, rec.Events)
		}
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A change set for a new stack with a custom resource whose Data a later resource reads (the shape `aws
// cloudformation deploy` sends) lists the stack's resources as Adds, as AWS's change set lists such values as
// known after apply, instead of refusing them as unresolved; executing it creates the stack resource by
// resource, as CreateStack does. It is validated as CreateStack validates such a stack, by its plan: a plan
// that refuses the stack refuses its change set.
func TestChangeSet_CustomResourceDataIsKnownAfterApply(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/handler:latest } }
  Setup:
    Type: Custom::Setup
    Properties: { ServiceToken: !GetAtt Fn.Arn }
  Consumer:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: Image
      Code: { ImageUri: ghcr.io/x/consumer:latest }
      Environment: { Variables: { ENDPOINT: !GetAtt Setup.Endpoint } }
`
	cs, _, _, err := BuildChangeSet(context.Background(), []byte(tmpl), deployOpts(), &fakeApplier{})
	if err != nil {
		t.Fatalf("a custom-resource stack's change set must not refuse a value known after apply: %v", err)
	}
	got := map[string]ChangeAction{}
	for _, c := range cs.Changes {
		got[c.LogicalID] = c.Action
	}
	for _, id := range []string{"Fn", "Setup", "Consumer"} {
		if got[id] != Add {
			t.Errorf("%s: %q, want Add (%v)", id, got[id], cs.Changes)
		}
	}
	// A plan refusal (here an out-of-stack ServiceToken) refuses the change set, as it refuses CreateStack.
	out := strings.Replace(tmpl, "ServiceToken: !GetAtt Fn.Arn", "ServiceToken: arn:aws:lambda:us-east-1:123456789012:function:elsewhere", 1)
	if _, _, _, err := BuildChangeSet(context.Background(), []byte(out), deployOpts(), &fakeApplier{}); err == nil {
		t.Error("a stack its plan refuses must not get a change set")
	}
}
