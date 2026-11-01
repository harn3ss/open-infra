package cfn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A stack with a custom resource and a REST v1 API, as a front door records it.
func outOfBandStack(f *fakeApplier) {
	f.stored = &StackRecord{Name: "s", Namespace: "cfn-test", Status: "CREATE_COMPLETE", Resources: []StackResource{
		{LogicalID: "Key", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: "s-key"},
		{LogicalID: "Api", APIVersion: apigwRestV1APIVersion, Kind: apigwRestV1Kind, Name: "api", ProvisionedID: "api123"},
		{LogicalID: "Custom", APIVersion: customResourceAPIVersion, Kind: customResourceKind, Name: "custom",
			Spec: map[string]any{"function": "handler"}},
	}}
}

// A hook that fails is skipped, so a broken Function can't wedge a delete; a hook that refuses because
// the caller may not do that step fails the teardown, and the stack never reports DELETE_COMPLETE.
func TestDestroy_UnauthorizedHookFailsTheDelete(t *testing.T) {
	for name, tc := range map[string]struct {
		invokeErr, deprovisionErr error
		wantStatus                string
		wantLeft                  []string // logical ids still recorded
	}{
		"hooks fail":                 {errors.New("Function crashed"), errors.New("store down"), "DELETE_COMPLETE", nil},
		"invoke not authorized":      {fmt.Errorf("wrapped: %w", Unauthorized("may not invoke handler")), nil, "DELETE_FAILED", []string{"Key", "Api", "Custom"}},
		"deprovision not authorized": {nil, Unauthorized("may not delete api123"), "DELETE_FAILED", []string{"Key", "Api"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeApplier{}
			outOfBandStack(f)
			opts := deployOpts()
			opts.Invoke = func(context.Context, string, string, []byte) (map[string]any, error) { return nil, tc.invokeErr }
			opts.DeprovisionRestAPI = func(context.Context, string) error { return tc.deprovisionErr }
			rec, err := Destroy(context.Background(), opts, f)
			if rec == nil || rec.Status != tc.wantStatus {
				t.Fatalf("status = %+v (err %v), want %s", rec, err, tc.wantStatus)
			}
			if tc.wantStatus == "DELETE_FAILED" {
				if err == nil || !strings.Contains(err.Error(), "may not") {
					t.Fatalf("the refusal must be the reason: %v", err)
				}
				var left []string
				for _, r := range rec.Resources {
					left = append(left, r.LogicalID)
				}
				if strings.Join(left, ",") != strings.Join(tc.wantLeft, ",") {
					t.Fatalf("resources left = %v, want %v", left, tc.wantLeft)
				}
				if contains(f.deleted, "EncryptionKey/s-key") {
					t.Fatal("teardown must stop at the refusal (newest first: the key comes after it)")
				}
				if _, found, _ := f.GetStack(context.Background(), "s"); !found {
					t.Fatal("a refused delete keeps the stack record")
				}
			} else if err != nil {
				t.Fatalf("a failing hook is best-effort: %v", err)
			}
		})
	}
}

// ctxApplier fails a write whose context has ended, as the API server would never see it.
type ctxApplier struct{ *fakeApplier }

func (c ctxApplier) Apply(ctx context.Context, y []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.fakeApplier.Apply(ctx, y)
}

// A completing stack waits for a post-deploy attribute only until shortly before the operation's
// deadline, so the CREATE_COMPLETE record is still written in time; waiting to the deadline itself would
// leave the stack in progress for the next front door to roll back.
func TestOutputs_WaitLeavesTimeForTheRecord(t *testing.T) {
	fastOutputs(t)
	prev := outputRecordReserve
	outputRecordReserve = 300 * time.Millisecond
	t.Cleanup(func() { outputRecordReserve = prev })
	tmpl := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref TestSG ] }
  TestSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: test }
  WebEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Web }
Outputs:
  Address: { Value: !Ref WebEip }
`
	f := &fakeApplier{statusFn: func(string) (map[string]any, bool) { return map[string]any{}, true }} // never assigned
	opts := deployOpts()
	opts.Timeout = time.Minute // the output wait alone would outlast the operation
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	start := time.Now()
	rec, err := Deploy(ctx, []byte(tmpl), opts, ctxApplier{f})
	if err != nil {
		t.Fatalf("the stack must complete with its record written: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" || f.stored == nil || f.stored.Status != "CREATE_COMPLETE" {
		t.Fatalf("want a stored CREATE_COMPLETE record: %+v / %+v", rec, f.stored)
	}
	if !strings.Contains(omissionMap(f.stored)["Address"], "LAN IP was not assigned") {
		t.Fatalf("the unassigned address is omitted saying so: %v", f.stored.OutputsOmitted)
	}
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Fatalf("the wait ran into the record's reserve (%s)", el)
	}
}
