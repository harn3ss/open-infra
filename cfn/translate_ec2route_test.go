package cfn

import (
	"strings"
	"testing"
)

// routeCtx parses a small networking template and returns the stack context the Route translator
// needs to follow a GatewayId !Ref to its in-stack target type.
const routeTmpl = `
Resources:
  Igw:
    Type: AWS::EC2::InternetGateway
  Nat:
    Type: AWS::EC2::NatGateway
    Properties: { SubnetId: dummy }
  RT:
    Type: AWS::EC2::RouteTable
    Properties: { VpcId: dummy }
  DefaultRoute:
    Type: AWS::EC2::Route
    Properties: { RouteTableId: { Ref: RT }, DestinationCidrBlock: 0.0.0.0/0, GatewayId: { Ref: Igw } }
  PrivateRoute:
    Type: AWS::EC2::Route
    Properties: { RouteTableId: { Ref: RT }, DestinationCidrBlock: 10.0.0.0/8, GatewayId: { Ref: Igw } }
  NatDefaultRoute:
    Type: AWS::EC2::Route
    Properties: { RouteTableId: { Ref: RT }, DestinationCidrBlock: 0.0.0.0/0, NatGatewayId: { Ref: Nat } }
`

func rawProps(ctx *stackCtx, id string) map[string]any {
	return ctx.template.Resources[id].Properties
}

// A RouteTable is a pure container — it provisions nothing (routes are VPC-scoped in kube-ovn), so it
// translates to a clean no-op rather than blocking the stack.
func TestTranslate_EC2RouteTable_Implicit(t *testing.T) {
	m, fs := translateEC2RouteTable("RT", map[string]any{"VpcId": map[string]any{"Ref": "Vpc"}, "Tags": []any{}}, nil)
	if m != nil {
		t.Fatalf("a RouteTable must provision nothing (implicit), got manifest: %+v", m)
	}
	if len(fs) != 0 {
		t.Fatalf("a VpcId/Tags-only RouteTable must translate cleanly: %s", findingsText(fs))
	}
}

// A RouteTable carrying a property we cannot honor refuses fail-closed, never a silent drop.
func TestTranslate_EC2RouteTable_UnknownPropRefuses(t *testing.T) {
	_, fs := translateEC2RouteTable("RT", map[string]any{"PropagatingVgws": []any{"vgw-1"}}, nil)
	if !strings.Contains(findingsText(fs), "PropagatingVgws") {
		t.Fatalf("an unhandled RouteTable property must refuse, got: %s", findingsText(fs))
	}
}

// The one faithful Route shape: the default route 0.0.0.0/0 -> an in-stack InternetGateway. It is
// implicit (egress is a property of the kind: NatGateway border device) — no manifest, no finding.
func TestTranslate_EC2Route_DefaultToIgwImplicit(t *testing.T) {
	ctx := ecsCtx(t, routeTmpl)
	m, fs := translateEC2Route("DefaultRoute", rawProps(ctx, "DefaultRoute"), ctx)
	if m != nil {
		t.Fatalf("a default route to an in-stack IGW must be implicit (no manifest), got: %+v", m)
	}
	if len(fs) != 0 {
		t.Fatalf("a default route to an in-stack IGW must translate cleanly: %s", findingsText(fs))
	}
}

// A non-default CIDR carries real next-hop intent we cannot derive — refuse, never fabricate a route.
func TestTranslate_EC2Route_NonDefaultCidrRefuses(t *testing.T) {
	ctx := ecsCtx(t, routeTmpl)
	_, fs := translateEC2Route("PrivateRoute", rawProps(ctx, "PrivateRoute"), ctx)
	if !strings.Contains(findingsText(fs), "default route 0.0.0.0/0") {
		t.Fatalf("a non-default-CIDR route must refuse with help, got: %s", findingsText(fs))
	}
}

// A default route to something other than an in-stack InternetGateway (here a NatGateway) refuses:
// its next-hop IP is not template-derivable.
func TestTranslate_EC2Route_NonIgwTargetRefuses(t *testing.T) {
	ctx := ecsCtx(t, routeTmpl)
	_, fs := translateEC2Route("NatDefaultRoute", rawProps(ctx, "NatDefaultRoute"), ctx)
	if !strings.Contains(findingsText(fs), "InternetGateway") {
		t.Fatalf("a default route to a non-IGW target must refuse with help, got: %s", findingsText(fs))
	}
}

// A Route with an untranslatable property refuses before the target analysis (fail-closed on props).
func TestTranslate_EC2Route_UnknownPropRefuses(t *testing.T) {
	_, fs := translateEC2Route("R", map[string]any{"DestinationPrefixListId": "pl-123"}, nil)
	if !strings.Contains(findingsText(fs), "DestinationPrefixListId") {
		t.Fatalf("an unhandled Route property must refuse, got: %s", findingsText(fs))
	}
}

// Plan-level: an instance profile + an EIP association used to be hard blockers (no backing kind),
// which made a whole lift-and-shift stack REJECTED. They now map at plan (gated, not create-faithful),
// so a stack carrying them is understood — PROVISIONABLE_WITH_CAVEATS — and the blockers name neither.
func TestPlan_InstanceProfileAndEipAssociationMapNotBlock(t *testing.T) {
	tmpl := `
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [] }
  Profile:
    Type: AWS::IAM::InstanceProfile
    Properties: { Roles: [ { Ref: Role } ] }
  Eip:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc }
  App:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
  Assoc:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: { Fn::GetAtt: [ Eip, AllocationId ] }, InstanceId: { Ref: App } }
`
	p := mustPlan(t, []byte(tmpl), nil, "s")
	if p.Verdict == Rejected {
		t.Fatalf("stack must not be REJECTED now that InstanceProfile/EIPAssociation map; blockers:\n%s", blockersJoined(p))
	}
	if strings.Contains(blockersJoined(p), "InstanceProfile") || strings.Contains(blockersJoined(p), "EIPAssociation") {
		t.Fatalf("InstanceProfile/EIPAssociation must not be blockers, got:\n%s", blockersJoined(p))
	}
	// Neither is a hard blocker any more (both map). InstanceProfile is now create-deployable (an
	// implicit no-op — the role binding lives on the VM); EIPAssociation still maps-but-gated.
	for _, r := range p.Resources {
		if r.CFNType == "AWS::IAM::InstanceProfile" && (r.Kind == "" || !r.Deployable) {
			t.Fatalf("InstanceProfile should map and be create-deployable (implicit): kind=%q deployable=%v", r.Kind, r.Deployable)
		}
		if r.CFNType == "AWS::EC2::EIPAssociation" && (r.Kind == "" || r.Deployable) {
			t.Fatalf("EIPAssociation should map (Kind set) and be gated (not Deployable): kind=%q deployable=%v", r.Kind, r.Deployable)
		}
	}
}

// The common lift-and-shift refusals (ELB/ASG/LaunchTemplate/CloudFront) are unsupported, but each
// refuses with a pointer to the open-infra path rather than the bare "no backing kind" default — so
// an assessment reads as guidance. None maps (Kind stays empty) and none is a silent approximation.
func TestMapping_LiftAndShiftRefusalsGuide(t *testing.T) {
	for _, tc := range []struct {
		cfnType, mustMention string
	}{
		{"AWS::ElasticLoadBalancingV2::LoadBalancer", "ingress"},
		{"AWS::ElasticLoadBalancing::LoadBalancer", "ingress"},
		{"AWS::AutoScaling::AutoScalingGroup", "autoscaling"},
		{"AWS::EC2::LaunchTemplate", "VirtualMachine"},
		{"AWS::CloudFront::Distribution", "CDN"},
	} {
		e := Lookup(tc.cfnType)
		if e.Status != Unsupported || e.Kind != "" {
			t.Errorf("%s: want unsupported/no-kind, got {%q,%q}", tc.cfnType, e.Status, e.Kind)
		}
		if !strings.Contains(e.Note, tc.mustMention) {
			t.Errorf("%s: note should mention %q as the open-infra path, got: %s", tc.cfnType, tc.mustMention, e.Note)
		}
	}
}

// Plan-level: a default route to an in-stack IGW and its route table are now create-deployable
// (implicit), so they no longer sit in the gated "maps at plan only" set.
func TestPlan_DefaultRouteAndTableDeployable(t *testing.T) {
	p := mustPlan(t, []byte(routeTmpl), nil, "s")
	for _, r := range p.Resources {
		if r.CFNType == "AWS::EC2::RouteTable" && !r.Deployable {
			t.Fatalf("RouteTable should be create-deployable (implicit no-op)")
		}
		if r.LogicalID == "DefaultRoute" && !r.Deployable {
			t.Fatalf("a default Route should be create-deployable (implicit)")
		}
	}
}
