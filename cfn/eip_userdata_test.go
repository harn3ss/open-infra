package cfn

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// #348: an instance's UserData may embed its Elastic IP's address, as on AWS: the EIP (associated by an
// EIPAssociation) is an allocation of its own, created first, and the instance is created once that
// allocation holds its address, which the UserData then carries.
const eipUserDataTmpl = `
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress: [ { IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 0.0.0.0/0 } ]
  Eip:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc }
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      SecurityGroupIds: [ !Ref WebSG ]
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          echo "public=${Eip} also=${Eip.PublicIp}" > /etc/eip
  Assoc:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !GetAtt Eip.AllocationId, InstanceId: !Ref Web }
Outputs:
  Address: { Value: !Ref Eip }
`

const eipTestAddress = "10.0.254.77"

// eipStatus answers an allocation's address once it is applied, and a running VM carrying it.
func eipStatus(f *fakeApplier) func(key string) (map[string]any, bool) {
	return func(key string) (map[string]any, bool) {
		if _, applied := f.liveSpecs[key]; !applied {
			return nil, false
		}
		switch {
		case strings.HasPrefix(key, KindEC2Address+"/"):
			return map[string]any{"ready": true, "publicIp": eipTestAddress}, true
		case strings.HasPrefix(key, "VirtualMachine/"):
			return map[string]any{"ip": "10.16.0.21", "lanIp": eipTestAddress, "instanceId": "i-0123456789abcdef0"}, true
		}
		return map[string]any{}, true
	}
}

func TestEIP_UserDataEmbedsTheAddressAtCreate(t *testing.T) {
	fastOutputs(t)
	f := &fakeApplier{}
	f.statusFn = eipStatus(f)
	opts := deployOpts()
	opts.Caps = eipCaps
	rec, err := Deploy(context.Background(), []byte(eipUserDataTmpl), opts, f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	alloc := eipAllocationID("s", "Eip")
	vm := f.liveSpecs["VirtualMachine/s-web"]
	if vm == nil {
		t.Fatalf("no VM applied: %v", f.applied)
	}
	ud, _ := vm["userData"].(string)
	if !strings.Contains(ud, "public="+eipTestAddress+" also="+eipTestAddress) {
		t.Fatalf("the VM's user data = %q, want the Elastic IP's address embedded twice", ud)
	}
	if eip, _ := vm["elasticIp"].(map[string]any); eip == nil || eip["allocationId"] != alloc || vm["expose"] != true {
		t.Fatalf("the VM must carry the stack's allocation (spec.elasticIp %s, expose): %v", alloc, vm)
	}
	// The allocation is created before the instance that embeds its address.
	ai, vi := -1, -1
	for i, a := range f.applied {
		switch a {
		case KindEC2Address + "/" + alloc:
			ai = i
		case "VirtualMachine/s-web":
			vi = i
		}
	}
	if ai < 0 || vi < 0 || ai > vi {
		t.Fatalf("apply order %v: the allocation must be created before the instance", f.applied)
	}
	if len(rec.Outputs) != 1 || rec.Outputs[0].OutputValue != eipTestAddress {
		t.Errorf("Outputs = %+v, want the address", rec.Outputs)
	}
}

// Without allocations (the CLI) nothing changes: the EIP folds onto the VM, and a UserData that embeds its
// address is reported as not applied (the address is assigned after the instance), as before.
func TestEIP_UserDataWithoutAllocationsIsUnchanged(t *testing.T) {
	got, err := buildEIP(t, eipUserDataTmpl, "s", nil, Capabilities{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, has := got["Eip"]; has {
		t.Fatal("without allocations the EIP must fold onto the VM, not become an allocation")
	}
	web := got["Web"]
	if _, has := web.res.Spec["userData"]; has || !strings.Contains(strings.Join(web.cav, " "), "UserData could not be statically resolved") {
		t.Fatalf("spec %v, caveats %v", web.res.Spec, web.cav)
	}
}

// An update of a stack that holds the allocation resolves the address from it; an update that adds the EIP
// and embeds it in the same operation refuses rather than boot the instance without its script.
func TestEIP_UpdateEmbedsAHeldAddressAndRefusesANewOne(t *testing.T) {
	fastOutputs(t)
	f := &fakeApplier{}
	f.statusFn = eipStatus(f)
	opts := deployOpts()
	opts.Caps = eipCaps
	if _, err := Deploy(context.Background(), []byte(eipUserDataTmpl), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	// The update re-translates the instance (its UserData embeds the address, read from the held allocation,
	// so it is unchanged and needs no restart) while it changes the security group.
	changed := strings.Replace(eipUserDataTmpl, "FromPort: 80, ToPort: 80", "FromPort: 8080, ToPort: 8080", 1)
	if _, err := Update(context.Background(), []byte(changed), opts, f); err != nil {
		t.Fatalf("update: %v", err)
	}
	if ud, _ := f.liveSpecs["VirtualMachine/s-web"]["userData"].(string); !strings.Contains(ud, "public="+eipTestAddress) {
		t.Fatalf("after the update the user data = %q, want the held address", ud)
	}

	// A stack without the EIP, then an update that adds it and embeds it in the instance's UserData.
	g := &fakeApplier{}
	g.statusFn = eipStatus(g)
	plain := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, UserData: ` + base64.StdEncoding.EncodeToString([]byte("#!/bin/bash\ntrue\n")) + ` }
`
	if _, err := Deploy(context.Background(), []byte(plain), opts, g); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	_, err := Update(context.Background(), []byte(eipUserDataTmpl), opts, g)
	if err == nil || !strings.Contains(err.Error(), "UserData embeds Elastic IP Eip's address") {
		t.Fatalf("an update that adds an EIP and embeds it must refuse, got %v", err)
	}
}

func TestRefsEIPAddress(t *testing.T) {
	for _, c := range []struct {
		v    any
		want bool
	}{
		{map[string]any{"Ref": "Eip"}, true},
		{map[string]any{"Fn::GetAtt": []any{"Eip", "PublicIp"}}, true},
		{map[string]any{"Fn::GetAtt": "Eip.PublicIp"}, true},
		{map[string]any{"Fn::GetAtt": []any{"Eip", "AllocationId"}}, false},
		{map[string]any{"Fn::Sub": "ip=${Eip}"}, true},
		{map[string]any{"Fn::Sub": "ip=${!Eip}"}, false},
		{map[string]any{"Fn::Sub": []any{"ip=${Eip}", map[string]any{"Eip": "x"}}}, false},
		{map[string]any{"Fn::Base64": map[string]any{"Fn::Sub": "a ${Eip.PublicIp} b"}}, true},
		{map[string]any{"Ref": "Other"}, false},
	} {
		if got := refsEIPAddress(c.v, "Eip"); got != c.want {
			t.Errorf("refsEIPAddress(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}
