package main

import (
	"strings"
	"testing"
)

// #120 Phase 3: AWS::EC2::VPC -> kind: Vpc; the VPC-level CidrBlock is an informational caveat.
func TestTranslate_EC2VPC(t *testing.T) {
	m, fs := translateEC2VPC("MyVpc", map[string]any{
		"CidrBlock": "10.0.0.0/16", "EnableDnsSupport": true,
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("a VPC must translate cleanly: %s", findingsText(fs))
	}
	if m.Kind != "Vpc" || m.Name != "myvpc" {
		t.Fatalf("bad head: %+v", m)
	}
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "CidrBlock is informational") {
		t.Fatalf("VPC CidrBlock should be an informational caveat: %v", m.Caveats)
	}
}

// #120 Phase 3: AWS::EC2::Subnet -> kind: Subnet — CidrBlock->cidr, VpcId !Ref->vpc,
// MapPublicIpOnLaunch->private (public => not private).
func TestTranslate_EC2Subnet_Faithful(t *testing.T) {
	tmpl := `
Resources:
  MyVpc:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.0.0.0/16 }
  AppSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      CidrBlock: 10.0.1.0/24
      VpcId: !Ref MyVpc
      MapPublicIpOnLaunch: false
`
	ctx := ecsCtx(t, tmpl)
	props := ecsResolvedService(t, ctx, "AppSubnet")
	m, fs := translateEC2Subnet("AppSubnet", props, ctx)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Spec["cidr"] != "10.0.1.0/24" {
		t.Fatalf("CidrBlock should map to cidr: %#v", m.Spec["cidr"])
	}
	if m.Spec["vpc"] != "myvpc" {
		t.Fatalf("VpcId !Ref should map to vpc=myvpc: %#v", m.Spec["vpc"])
	}
	if m.Spec["private"] != true {
		t.Fatalf("MapPublicIpOnLaunch:false should map to private:true: %#v", m.Spec["private"])
	}
}

// A public subnet (MapPublicIpOnLaunch:true) maps to private:false.
func TestTranslate_EC2Subnet_Public(t *testing.T) {
	m, _ := translateEC2Subnet("Pub", map[string]any{
		"CidrBlock": "10.0.2.0/24", "MapPublicIpOnLaunch": true,
	}, nil)
	if m.Spec["private"] != false {
		t.Fatalf("a public subnet should be private:false, got %#v", m.Spec["private"])
	}
}

// Missing CidrBlock blocks (required).
func TestTranslate_EC2Subnet_RequiresCidr(t *testing.T) {
	_, fs := translateEC2Subnet("S", map[string]any{"AvailabilityZone": "us-east-1a"}, nil)
	if !strings.Contains(findingsText(fs), "CidrBlock is required") {
		t.Fatalf("missing CidrBlock must block, got: %s", findingsText(fs))
	}
}

// End-to-end #120: an EC2::Instance whose SubnetId !Refs an in-stack AWS::EC2::Subnet resolves to
// that subnet's kind: Subnet name — the full CFN subnet path.
func TestTranslate_EC2Instance_SubnetRefEndToEnd(t *testing.T) {
	tmpl := `
Resources:
  MyVpc:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.0.0.0/16 }
  AppSubnet:
    Type: AWS::EC2::Subnet
    Properties: { CidrBlock: 10.0.1.0/24, VpcId: !Ref MyVpc }
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      InstanceType: t3.small
      SubnetId: !Ref AppSubnet
`
	ctx := ecsCtx(t, tmpl)
	props := ecsResolvedService(t, ctx, "Web")
	m, fs := translateEC2Instance("Web", props, ctx)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Spec["subnet"] != "appsubnet" {
		t.Fatalf("SubnetId !Ref AppSubnet should place the VM in subnet 'appsubnet', got %#v", m.Spec["subnet"])
	}
}
