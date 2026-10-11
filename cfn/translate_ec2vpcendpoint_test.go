package cfn

import (
	"strings"
	"testing"
)

func TestTranslate_EC2VPCEndpoint_Faithful(t *testing.T) {
	tmpl := `
Resources:
  MyVpc:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.0.0.0/16 }
  S3Endpoint:
    Type: AWS::EC2::VPCEndpoint
    Properties:
      ServiceName: com.amazonaws.us-east-1.s3
      VpcId: !Ref MyVpc
      VpcEndpointType: Gateway
`
	ctx := ecsCtx(t, tmpl)
	props := ecsResolvedService(t, ctx, "S3Endpoint")
	m, fs := translateEC2VPCEndpoint("S3Endpoint", props, ctx)
	if len(fs) != 0 {
		t.Fatalf("a VPCEndpoint must translate cleanly: %s", findingsText(fs))
	}
	if m.Kind != "VpcEndpoint" || m.APIVersion != "openinfra.dev/v1" {
		t.Fatalf("bad head: %+v", m)
	}
	if m.Spec["service"] != "s3" {
		t.Fatalf("ServiceName should map to service=s3: %#v", m.Spec["service"])
	}
	if m.Spec["vpcEndpointType"] != "Gateway" {
		t.Fatalf("VpcEndpointType should be carried: %#v", m.Spec["vpcEndpointType"])
	}
	if m.Spec["vpc"] != "myvpc" {
		t.Fatalf("VpcId !Ref should map to vpc=myvpc: %#v", m.Spec["vpc"])
	}
}

// Default VpcEndpointType is Gateway (AWS default) when unset; PolicyDocument is a caveat, not a finding.
func TestTranslate_EC2VPCEndpoint_DefaultsAndPolicyCaveat(t *testing.T) {
	m, fs := translateEC2VPCEndpoint("E", map[string]any{
		"ServiceName":    "com.amazonaws.us-east-1.dynamodb",
		"PolicyDocument": map[string]any{"Version": "2012-10-17"},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Spec["service"] != "dynamodb" {
		t.Fatalf("service=dynamodb expected: %#v", m.Spec["service"])
	}
	if m.Spec["vpcEndpointType"] != "Gateway" {
		t.Fatalf("default VpcEndpointType should be Gateway: %#v", m.Spec["vpcEndpointType"])
	}
	if !strings.Contains(strings.Join(m.Caveats, " "), "PolicyDocument") {
		t.Fatalf("PolicyDocument should be a caveat: %v", m.Caveats)
	}
}

// Missing ServiceName blocks (required).
func TestTranslate_EC2VPCEndpoint_RequiresServiceName(t *testing.T) {
	_, fs := translateEC2VPCEndpoint("E", map[string]any{"VpcEndpointType": "Interface"}, nil)
	if !strings.Contains(findingsText(fs), "ServiceName is required") {
		t.Fatalf("missing ServiceName must block, got: %s", findingsText(fs))
	}
}

func TestServiceFromServiceName(t *testing.T) {
	cases := map[string]string{
		"com.amazonaws.us-east-1.s3":       "s3",
		"com.amazonaws.us-west-2.dynamodb": "dynamodb",
		"com.amazonaws.eu-west-1.ecr.dkr":  "ecr.dkr",
		"weird":                            "weird",
	}
	for in, want := range cases {
		if got := serviceFromServiceName(in); got != want {
			t.Errorf("serviceFromServiceName(%q)=%q want %q", in, got, want)
		}
	}
}
