package cfn

import (
	"context"
	"strings"
	"testing"
)

// #347 item 8: an Elastic IP allocated in one stack, associated with an instance in another by its
// AllocationId (a parameter or an export).

var eipCaps = Capabilities{EC2AddressAPI: true}

const eipStackTmpl = `
Resources:
  Address:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc, Tags: [ { Key: team, Value: web } ] }
Outputs:
  AllocationId: { Value: !GetAtt Address.AllocationId, Export: { Name: shared-address } }
  PublicIp:     { Value: !Ref Address }
`

const appStackTmpl = `
Parameters:
  AddressAllocationId: { Type: String }
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress: [ { IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 0.0.0.0/0 } ]
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref WebSG ] }
  Assoc:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !Ref AddressAllocationId, InstanceId: !Ref Web }
Outputs:
  Address: { Value: !GetAtt Web.PublicIp }
`

func buildEIP(t *testing.T, tmpl, stack string, params map[string]string, caps Capabilities) (map[string]builtResource, error) {
	t.Helper()
	order, err := buildManifests([]byte(tmpl), DeployOptions{StackName: stack, Namespace: "open-infra-cfn", Caps: caps, Params: params})
	if err != nil {
		return nil, err
	}
	out := map[string]builtResource{}
	for _, b := range order {
		out[b.res.LogicalID] = b
	}
	return out, nil
}

// An EIP associated with nothing in its stack is an allocation of its own where the platform keeps them,
// named by the same AllocationId its GetAtt reports; without them it still refuses.
func TestEIP_UnassociatedIsAnAllocation(t *testing.T) {
	got, err := buildEIP(t, eipStackTmpl, "net", nil, eipCaps)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	a := got["Address"]
	want := eipAllocationID("net", "Address")
	if a.res.APIVersion != ServiceAPIVersion || a.res.Kind != KindEC2Address || a.res.Name != want {
		t.Fatalf("the allocation = %s/%s %s, want %s/%s %s", a.res.APIVersion, a.res.Kind, a.res.Name, ServiceAPIVersion, KindEC2Address, want)
	}
	if !strings.Contains(strings.Join(a.cav, " "), "Tags dropped") || !strings.Contains(strings.Join(a.cav, " "), "InvalidIPAddress.InUse") {
		t.Fatalf("caveats = %v", a.cav)
	}
	if _, err := buildEIP(t, eipStackTmpl, "net", nil, Capabilities{}); err == nil || !strings.Contains(err.Error(), "keeps no allocations") {
		t.Fatalf("without allocations an unassociated EIP must refuse: %v", err)
	}
}

// An EIPAssociation naming another stack's allocation (by parameter) puts that address on the instance's VM:
// spec.expose plus spec.elasticIp, so the VM's LAN Service carries the allocation's address.
func TestEIPAssociation_AllocationFromAnotherStack(t *testing.T) {
	alloc := eipAllocationID("net", "Address")
	got, err := buildEIP(t, appStackTmpl, "app", map[string]string{"AddressAllocationId": alloc}, eipCaps)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	web := got["Web"].res
	if exp, _ := web.Spec["expose"].(bool); !exp {
		t.Fatalf("the VM must be exposed: %v", web.Spec)
	}
	eip, _ := web.Spec["elasticIp"].(map[string]any)
	if eip["allocationId"] != alloc {
		t.Fatalf("spec.elasticIp = %v, want allocationId %s", web.Spec["elasticIp"], alloc)
	}
	if !strings.Contains(strings.Join(got["Web"].cav, " "), "follows the instance") {
		t.Fatalf("caveats = %v", got["Web"].cav)
	}
	if _, assoc := got["Assoc"]; assoc {
		t.Fatal("the association provisions nothing of its own")
	}
	// The allocation must exist when the VM is applied: an id of the right shape that names nothing here
	// (an AWS account's, say) is refused before anything is created.
	req := false
	for _, r := range got["Web"].requires {
		req = req || (r.APIVersion == ServiceAPIVersion && r.Kind == KindEC2Address && r.Name == alloc)
	}
	if !req {
		t.Fatalf("the VM must require the allocation: %+v", got["Web"].requires)
	}

	for name, c := range map[string]struct {
		params map[string]string
		caps   Capabilities
		want   string
	}{
		"not an allocation id": {map[string]string{"AddressAllocationId": "eipalloc-0abc"}, eipCaps, "is not an Elastic IP allocation open-infra holds"},
		"offline":              {map[string]string{"AddressAllocationId": alloc}, Capabilities{}, "keeps no allocations"},
	} {
		if _, err := buildEIP(t, appStackTmpl, "app", c.params, c.caps); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want a refusal mentioning %q, got %v", name, c.want, err)
		}
	}
}

// One instance carries one address: an in-stack EIP and another stack's allocation on it refuses, as do
// two associations of one allocation, and a published port the holder reserves.
func TestEIPAssociation_AllocationConflicts(t *testing.T) {
	alloc := eipAllocationID("net", "Address")
	both := appStackTmpl + `
  Local:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Web }
`
	both = strings.Replace(both, "Outputs:\n  Address: { Value: !GetAtt Web.PublicIp }\n", "", 1)
	if _, err := buildEIP(t, both, "app", map[string]string{"AddressAllocationId": alloc}, eipCaps); err == nil || !strings.Contains(err.Error(), "would carry 2 Elastic IPs") {
		t.Fatalf("two addresses on one instance must refuse: %v", err)
	}
	twice := strings.Replace(appStackTmpl, "Outputs:", `  Web2:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref WebSG ] }
  Assoc2:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !Ref AddressAllocationId, InstanceId: !Ref Web2 }
Outputs:`, 1)
	if _, err := buildEIP(t, twice, "app", map[string]string{"AddressAllocationId": alloc}, eipCaps); err == nil || !strings.Contains(err.Error(), "associated with more than one instance") {
		t.Fatalf("one allocation on two instances must refuse: %v", err)
	}
	udp9 := strings.Replace(appStackTmpl, "{ IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 0.0.0.0/0 }", "{ IpProtocol: udp, FromPort: 9, ToPort: 9, CidrIp: 0.0.0.0/0 }", 1)
	if _, err := buildEIP(t, udp9, "app", map[string]string{"AddressAllocationId": alloc}, eipCaps); err == nil || !strings.Contains(err.Error(), "reserves on its address") {
		t.Fatalf("publishing the holder's port must refuse: %v", err)
	}
}

// The allocation stack's Outputs: its AllocationId, and its address once the platform reports it.
func TestEIP_AllocationOutputs(t *testing.T) {
	fastOutputs(t)
	alloc := eipAllocationID("s", "Address")
	f := &fakeApplier{statusFn: func(key string) (map[string]any, bool) {
		if key == KindEC2Address+"/"+alloc {
			return map[string]any{"ready": true, "publicIp": "192.0.2.77"}, true
		}
		return nil, false
	}}
	opts := deployOpts()
	opts.Caps = eipCaps
	rec, err := Deploy(context.Background(), []byte(eipStackTmpl), opts, f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	out := outputMap(rec)
	if out["AllocationId"].OutputValue != alloc || out["PublicIp"].OutputValue != "192.0.2.77" {
		t.Fatalf("outputs = %+v", out)
	}
}
