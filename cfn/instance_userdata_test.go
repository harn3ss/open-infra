package cfn

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// An instance's UserData may embed another in-stack instance's address (Fn::GetAtt Server.PrivateIp), as on
// AWS: the stack is created interleaved, Server first, and Client is translated once Server is complete,
// with Server's address filled in. Until then a plan says so; a deploy that cannot read it refuses rather
// than boot Client without its script.
const instanceUserDataTmpl = `
Resources:
  Server:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, InstanceType: t3.micro }
  Client:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      InstanceType: t3.micro
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          echo "server=${Server.PrivateIp} id=${Server}" > /etc/server
`

const instanceTestIP = "10.16.0.21"

// instanceStatus answers a VM's address and id once it is applied.
func instanceStatus(f *fakeApplier) func(key string) (map[string]any, bool) {
	return func(key string) (map[string]any, bool) {
		if _, applied := f.liveSpecs[key]; !applied {
			return nil, false
		}
		if strings.HasPrefix(key, "VirtualMachine/") {
			return map[string]any{"ready": true, "ip": instanceTestIP, "instanceId": "i-0123456789abcdef0", "powerState": "Running"}, true
		}
		return map[string]any{}, true
	}
}

func TestInstance_UserDataEmbedsAnotherInstanceAtCreate(t *testing.T) {
	pt, err := Parse([]byte(instanceUserDataTmpl))
	if err != nil {
		t.Fatal(err)
	}
	if !embedsInstanceAttr(pt) {
		t.Fatal("Client's UserData embeds Server's address: the stack must be created interleaved")
	}
	fastOutputs(t)
	f := &fakeApplier{}
	f.statusFn = instanceStatus(f)
	if _, err := Deploy(context.Background(), []byte(instanceUserDataTmpl), deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	ud, _ := f.liveSpecs["VirtualMachine/s-client"]["userData"].(string)
	if !strings.Contains(ud, "server="+instanceTestIP+" id=i-0123456789abcdef0") {
		t.Fatalf("Client's user data = %q, want Server's address and id embedded", ud)
	}
	si, ci := -1, -1
	for i, a := range f.applied {
		switch a {
		case "VirtualMachine/s-server":
			si = i
		case "VirtualMachine/s-client":
			ci = i
		}
	}
	if si < 0 || ci < 0 || si > ci {
		t.Fatalf("apply order %v: Server must be created before Client", f.applied)
	}
}

// A plan (no instance to read) says the address is filled in at create; a stack whose instances embed
// nothing of each other's is not interleaved for it.
func TestInstance_UserDataEmbeddingAnotherInPlan(t *testing.T) {
	got, err := buildEIP(t, instanceUserDataTmpl, "s", nil, Capabilities{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	c := got["Client"]
	if _, has := c.res.Spec["userData"]; has || !strings.Contains(strings.Join(c.cav, " "), "UserData embeds instance Server's address") {
		t.Fatalf("spec %v, caveats %v", c.res.Spec, c.cav)
	}
	plain := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, UserData: ` + base64.StdEncoding.EncodeToString([]byte("#!/bin/bash\ntrue\n")) + ` }
`
	if pt, _ := Parse([]byte(plain)); embedsInstanceAttr(pt) {
		t.Error("an instance with literal user data embeds no other instance")
	}
}

// An update that adds Server and embeds it in Client in the same operation refuses rather than boot Client
// without its script; one that holds Server embeds its address.
func TestInstance_UpdateEmbedsAHeldInstanceAndRefusesANewOne(t *testing.T) {
	fastOutputs(t)
	g := &fakeApplier{}
	g.statusFn = instanceStatus(g)
	opts := deployOpts()
	plain := `
Resources:
  Client:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, InstanceType: t3.micro, UserData: ` + base64.StdEncoding.EncodeToString([]byte("#!/bin/bash\ntrue\n")) + ` }
`
	if _, err := Deploy(context.Background(), []byte(plain), opts, g); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	_, err := Update(context.Background(), []byte(instanceUserDataTmpl), opts, g)
	if err == nil || !strings.Contains(err.Error(), "UserData embeds instance Server's address") {
		t.Fatalf("an update that adds Server and embeds it must refuse, got %v", err)
	}

	f := &fakeApplier{}
	f.statusFn = instanceStatus(f)
	if _, err := Deploy(context.Background(), []byte(instanceUserDataTmpl), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	// The update re-translates Client, whose UserData embeds the held Server's address (unchanged, so no
	// restart), while it adds a security group; an address it could not read would refuse the update.
	changed := instanceUserDataTmpl + `  Extra:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: extra }
`
	if _, err := Update(context.Background(), []byte(changed), opts, f); err != nil {
		t.Fatalf("update: %v", err)
	}
	if ud, _ := f.liveSpecs["VirtualMachine/s-client"]["userData"].(string); !strings.Contains(ud, "server="+instanceTestIP) {
		t.Fatalf("after the update Client's user data = %q, want the held Server's address", ud)
	}
}
