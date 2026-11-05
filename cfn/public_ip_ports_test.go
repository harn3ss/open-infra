package cfn

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// publishedPorts lists a VM manifest's spec.ports as "<port>/<proto>", sorted.
func publishedPorts(m *Manifest) []string {
	ps, _ := m.Spec["ports"].([]any)
	var out []string
	for _, p := range ps {
		pm, _ := p.(map[string]any)
		out = append(out, fmt.Sprintf("%v/%v", pm["port"], pm["protocol"]))
	}
	sort.Strings(out)
	return out
}

const publicIPTemplate = `
Parameters:
  Mode: { Type: String, Default: nic }
Conditions:
  ByNic: !Equals [ !Ref Mode, nic ]
  BySubnet: !Equals [ !Ref Mode, subnet ]
  SubnetButNicOff: !Equals [ !Ref Mode, subnet-nic-off ]
  PublicSubnet: !Or [ !Condition BySubnet, !Condition SubnetButNicOff ]
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.40.0.0/16 }
  Subnet:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Vpc, CidrBlock: 10.40.1.0/24, MapPublicIpOnLaunch: !If [PublicSubnet, true, false] }
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      VpcId: !Ref Vpc
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 0.0.0.0/0 }
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0 }
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      NetworkInterfaces:
        - !If
          - ByNic
          - { DeviceIndex: "0", AssociatePublicIpAddress: true, SubnetId: !Ref Subnet, GroupSet: [ !Ref WebSG ] }
          - !If
            - SubnetButNicOff
            - { DeviceIndex: "0", AssociatePublicIpAddress: false, SubnetId: !Ref Subnet, GroupSet: [ !Ref WebSG ] }
            - { DeviceIndex: "0", SubnetId: !Ref Subnet, GroupSet: [ !Ref WebSG ] }
`

// A public IP reaches every port the instance's security groups allow, as on AWS (and as an Elastic IP
// does here): AssociatePublicIpAddress, or an instance launched into a subnet with MapPublicIpOnLaunch,
// publishes the groups' CIDR-sourced ports on the VM's LAN address, not the access port alone.
func TestTranslate_EC2Instance_PublicIPPublishesSecurityGroupPorts(t *testing.T) {
	for _, mode := range []string{"nic", "subnet"} {
		ctx := ctxWithParams(t, publicIPTemplate, map[string]string{"Mode": mode})
		m, fs := translateEC2Instance("Web", ecsResolvedService(t, ctx, "Web"), ctx)
		if len(fs) != 0 || m == nil {
			t.Fatalf("mode %s: %s", mode, findingsText(fs))
		}
		if exp, _ := m.Spec["expose"].(bool); !exp {
			t.Fatalf("mode %s: the instance must have a public address (expose), spec=%v", mode, m.Spec)
		}
		if got := strings.Join(publishedPorts(m), ","); got != "443/TCP,80/TCP" {
			t.Fatalf("mode %s: a public IP must publish the security group's ports 80 and 443, got %q", mode, got)
		}
	}
}

// AssociatePublicIpAddress: false on the interface overrides the subnet's MapPublicIpOnLaunch, as on AWS:
// no public address, nothing published.
func TestTranslate_EC2Instance_InterfaceTurnsOffSubnetPublicIP(t *testing.T) {
	ctx := ctxWithParams(t, publicIPTemplate, map[string]string{"Mode": "subnet-nic-off"})
	m, fs := translateEC2Instance("Web", ecsResolvedService(t, ctx, "Web"), ctx)
	if len(fs) != 0 || m == nil {
		t.Fatal(findingsText(fs))
	}
	if exp, _ := m.Spec["expose"].(bool); exp {
		t.Fatalf("AssociatePublicIpAddress false must keep the instance off the LAN, spec=%v", m.Spec)
	}
	if ps := publishedPorts(m); len(ps) != 0 {
		t.Fatalf("an instance with no public address publishes nothing, got %v", ps)
	}
}
