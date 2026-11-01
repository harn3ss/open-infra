package cfn

import (
	"strings"
	"testing"
)

// An instance's SecurityGroupIds entry that is not a direct in-stack SG !Ref is RESOLVED rather than
// silently dropped (the VM would otherwise launch without a firewall attachment the template declared —
// fail-open, and with an Elastic IP publishing ports on its LAN IP, an exposure): a parameter naming a
// cross-stack kind: SecurityGroup attaches it, an !If-wrapped in-stack ref attaches the group (NoValue
// drops it), a parameter carrying a raw sg- id refuses (opaque), and an entry naming no group refuses.
func TestTranslate_EC2Instance_SGListResolvesOrRefuses(t *testing.T) {
	tmpl := `
Parameters:
  SharedSg: { Type: String, Default: shared-web }
  UseAdmin: { Type: String, Default: "true" }
Conditions:
  Admin: !Equals [ !Ref UseAdmin, "true" ]
Resources:
  AdminSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: admin }
  Vol:
    Type: AWS::EC2::Volume
    Properties: { Size: 10 }
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      SecurityGroupIds:
        - !Ref SharedSg
        - !If [ Admin, !Ref AdminSG, !Ref "AWS::NoValue" ]
`
	sgsOf := func(params map[string]string) ([]string, []Finding) {
		ctx := ctxWithParams(t, tmpl, params)
		m, fs := translateEC2Instance("Web", ecsResolvedService(t, ctx, "Web"), ctx)
		if m == nil {
			return nil, fs
		}
		sgs, _ := m.Spec["securityGroups"].([]string)
		return sgs, fs
	}

	sgs, fs := sgsOf(nil)
	if len(fs) != 0 || strings.Join(sgs, ",") != "shared-web,adminsg" {
		t.Fatalf("a parameter-named SG and an !If-wrapped in-stack SG must both attach: sgs=%v findings=%s", sgs, findingsText(fs))
	}
	sgs, fs = sgsOf(map[string]string{"UseAdmin": "false"})
	if len(fs) != 0 || strings.Join(sgs, ",") != "shared-web" {
		t.Fatalf("an !If resolving to AWS::NoValue drops only that entry: sgs=%v findings=%s", sgs, findingsText(fs))
	}
	if _, fs = sgsOf(map[string]string{"SharedSg": "sg-0123456789abcdef0"}); !strings.Contains(findingsText(fs), "raw AWS security-group id") {
		t.Fatalf("a parameter carrying a raw sg- id must refuse (opaque): %s", findingsText(fs))
	}

	notSG := strings.Replace(tmpl, "- !Ref SharedSg", "- !Ref Vol", 1)
	ctx := ecsCtx(t, notSG)
	if _, fs := translateEC2Instance("Web", ecsResolvedService(t, ctx, "Web"), ctx); !strings.Contains(findingsText(fs), "resolves to no kind: SecurityGroup") {
		t.Fatalf("an entry naming no SecurityGroup must refuse, not be dropped: %s", findingsText(fs))
	}
}

// A NetworkInterfaces entry wrapped in Fn::If is the interface its condition picks — its GroupSet
// attaches — never an interface with no security groups. An existing interface attached by
// NetworkInterfaceId (its groups are not in the template) and an unknown interface property refuse.
func TestTranslate_EC2Instance_NICEntriesResolveOrRefuse(t *testing.T) {
	tmpl := `
Parameters:
  Public: { Type: String, Default: "true" }
Conditions:
  IsPublic: !Equals [ !Ref Public, "true" ]
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: web }
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      NetworkInterfaces:
        - !If
          - IsPublic
          - { DeviceIndex: "0", AssociatePublicIpAddress: !Ref Public, GroupSet: [ !Ref WebSG ] }
          - { DeviceIndex: "0", GroupSet: [ !Ref WebSG ] }
`
	for _, public := range []string{"true", "false"} {
		ctx := ctxWithParams(t, tmpl, map[string]string{"Public": public})
		m, fs := translateEC2Instance("Web", ecsResolvedService(t, ctx, "Web"), ctx)
		if len(fs) != 0 || m == nil {
			t.Fatalf("Public=%s: %s", public, findingsText(fs))
		}
		if sgs, _ := m.Spec["securityGroups"].([]string); strings.Join(sgs, ",") != "websg" {
			t.Fatalf("Public=%s: the picked interface's GroupSet must attach, got %v", public, m.Spec["securityGroups"])
		}
		if exp, _ := m.Spec["expose"].(bool); exp != (public == "true") {
			t.Fatalf("Public=%s: AssociatePublicIpAddress from a parameter must be read as a boolean, expose=%v", public, m.Spec["expose"])
		}
	}

	for name, c := range map[string]struct{ nic, want string }{
		"existing interface": {`{ DeviceIndex: "0", NetworkInterfaceId: eni-0123456789abcdef0 }`, "NetworkInterfaceId attaches an existing network interface"},
		"unknown property":   {`{ DeviceIndex: "0", GroupSet: [ !Ref WebSG ], InterfaceType: efa }`, "property InterfaceType is not translatable"},
		"not an interface":   {`!GetAtt WebSG.GroupId`, "does not resolve to an interface"},
		"not a boolean":      {`{ DeviceIndex: "0", GroupSet: [ !Ref WebSG ], AssociatePublicIpAddress: "yes" }`, "AssociatePublicIpAddress must be true or false"},
	} {
		src := `
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: web }
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      NetworkInterfaces: [ ` + c.nic + ` ]
`
		ctx := ecsCtx(t, src)
		if _, fs := translateEC2Instance("Web", ecsResolvedService(t, ctx, "Web"), ctx); !strings.Contains(findingsText(fs), c.want) {
			t.Errorf("%s: want a refusal containing %q, got %s", name, c.want, findingsText(fs))
		}
	}
}
