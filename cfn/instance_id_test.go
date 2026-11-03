package cfn

import (
	"context"
	"testing"
)

// #347 item 23: an instance's Ref and InstanceId are the i- id its guest's instance metadata reports (the
// VM's status.instanceId), not its Kubernetes name, and the stack records it as the instance's physical id.
// While the VM has not reported it, the Outputs wait for it, as for any status attribute.
func TestInstance_RefIsTheGuestsInstanceID(t *testing.T) {
	fastOutputs(t)
	tmpl := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref TestSG ] }
  TestSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: test }
Outputs:
  Ref:  { Value: !Ref Web }
  Id:   { Value: !GetAtt Web.InstanceId }
  Both: { Value: !Sub "${Web}/${Web.InstanceId}" }
`
	const id = "i-0123456789abcdef0"
	reads := 0
	f := &fakeApplier{statusFn: func(key string) (map[string]any, bool) {
		if key != "VirtualMachine/s-web" {
			return map[string]any{}, true
		}
		reads++
		if reads < 2 {
			return map[string]any{"ip": "10.16.0.21"}, true // not reported yet
		}
		return map[string]any{"ip": "10.16.0.21", "instanceId": id}, true
	}}
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	out := outputMap(rec)
	for k, want := range map[string]string{"Ref": id, "Id": id, "Both": id + "/" + id} {
		if got := out[k].OutputValue; got != want {
			t.Errorf("Output %s = %q, want %q", k, got, want)
		}
	}
	if reads < 2 {
		t.Errorf("an instance id not reported yet must be waited for (reads=%d)", reads)
	}
	for _, r := range rec.Resources {
		if r.LogicalID == "Web" && r.PhysicalID != id {
			t.Errorf("the instance's physical id = %q, want %q", r.PhysicalID, id)
		}
	}
}

// A deploy path that cannot read live status (the CLI) still gets a value: the VM's name.
func TestInstance_RefWithoutStatusIsTheName(t *testing.T) {
	e := &attrEnv{id: "Web", typ: "AWS::EC2::Instance"}
	if v, ok := instanceID(e); !ok || v == "" {
		t.Fatalf("without live status the Ref must still resolve (to the name); got %q %v", v, ok)
	}
}
