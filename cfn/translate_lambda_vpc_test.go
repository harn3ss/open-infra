package cfn

import (
	"strings"
	"testing"
)

const lambdaVPCTemplate = `
Resources:
  Network:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.20.0.0/16 }
  Other:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.30.0.0/16 }
  AppA:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Network, CidrBlock: 10.20.1.0/24 }
  AppB:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Network, CidrBlock: 10.20.2.0/24 }
  OtherA:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Other, CidrBlock: 10.30.1.0/24 }
  FnSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: the function's outbound allow-list
      VpcId: !Ref Network
      SecurityGroupEgress:
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 192.0.2.0/24 }
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Code: { ZipFile: "def handler(e, c): return 1" }
      VpcConfig:
        SubnetIds: [ !Ref AppA, !Ref AppB ]
        SecurityGroupIds: [ !Ref FnSG ]
`

// A security group's VpcId is its spec.vpc; a Lambda's VpcConfig is its spec.vpcConfig, the VPC read from
// its in-stack subnets.
func TestTranslate_LambdaVpcConfig(t *testing.T) {
	ctx := ecsCtx(t, lambdaVPCTemplate)
	sg, fs := translateEC2SecurityGroup("FnSG", ecsResolvedService(t, ctx, "FnSG"), ctx)
	if len(fs) != 0 {
		t.Fatalf("security group: %s", findingsText(fs))
	}
	if sg.Spec["vpc"] != "network" {
		t.Fatalf("the group's VpcId is its spec.vpc: %#v", sg.Spec["vpc"])
	}
	for _, c := range sg.Caveats {
		if strings.Contains(c, "VpcId") {
			t.Errorf("a VpcId that maps carries no caveat: %s", c)
		}
	}

	m, fs := translateLambdaFunction("Fn", ecsResolvedService(t, ctx, "Fn"), ctx)
	if len(fs) != 0 {
		t.Fatalf("function: %s", findingsText(fs))
	}
	vc, _ := m.Spec["vpcConfig"].(map[string]any)
	if vc == nil || vc["vpcId"] != "network" {
		t.Fatalf("spec.vpcConfig = %#v", m.Spec["vpcConfig"])
	}
	if s := vc["subnetIds"].([]any); len(s) != 2 || s[0] != "appa" || s[1] != "appb" {
		t.Errorf("subnetIds %#v", s)
	}
	if g := vc["securityGroupIds"].([]any); len(g) != 1 || g[0] != "fnsg" {
		t.Errorf("securityGroupIds %#v", g)
	}
}

func TestTranslate_LambdaVpcConfigRefusals(t *testing.T) {
	for name, c := range map[string]struct{ vpc, want string }{
		"subnets of two VPCs":    {"{ SubnetIds: [ !Ref AppA, !Ref OtherA ], SecurityGroupIds: [ !Ref FnSG ] }", "subnets of one VPC"},
		"an out-of-stack subnet": {"{ SubnetIds: [ subnet-0abc ], SecurityGroupIds: [ !Ref FnSG ] }", "subnets this stack creates"},
		"no security groups":     {"{ SubnetIds: [ !Ref AppA ] }", "needs both SubnetIds and SecurityGroupIds"},
		"IPv6":                   {"{ SubnetIds: [ !Ref AppA ], SecurityGroupIds: [ !Ref FnSG ], Ipv6AllowedForDualStack: true }", "IPv4 only"},
		"an unknown property":    {"{ SubnetIds: [ !Ref AppA ], SecurityGroupIds: [ !Ref FnSG ], Frobnicate: 1 }", "VpcConfig.Frobnicate"},
	} {
		t.Run(name, func(t *testing.T) {
			tmpl := strings.Replace(lambdaVPCTemplate, `VpcConfig:
        SubnetIds: [ !Ref AppA, !Ref AppB ]
        SecurityGroupIds: [ !Ref FnSG ]`, "VpcConfig: "+c.vpc, 1)
			ctx := ecsCtx(t, tmpl)
			_, fs := translateLambdaFunction("Fn", ecsResolvedService(t, ctx, "Fn"), ctx)
			if !strings.Contains(findingsText(fs), c.want) {
				t.Fatalf("want a finding %q, got %s", c.want, findingsText(fs))
			}
		})
	}
	// No VpcConfig at all, or an empty one: no VPC.
	tmpl := strings.Replace(lambdaVPCTemplate, `VpcConfig:
        SubnetIds: [ !Ref AppA, !Ref AppB ]
        SecurityGroupIds: [ !Ref FnSG ]`, "VpcConfig: { SubnetIds: [], SecurityGroupIds: [] }", 1)
	ctx := ecsCtx(t, tmpl)
	m, fs := translateLambdaFunction("Fn", ecsResolvedService(t, ctx, "Fn"), ctx)
	if len(fs) != 0 || m.Spec["vpcConfig"] != nil {
		t.Fatalf("an empty VpcConfig is no VPC: %v %#v", findingsText(fs), m.Spec["vpcConfig"])
	}
}
