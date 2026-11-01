package cfn

import "testing"

// #120: the EIP + NAT/Internet-Gateway family. The NatGateway backing kind is dataplane-verified, but
// AWS's property set doesn't carry the gateway binding / lanIp our model needs — so NatGateway is
// plan-recognized, NOT create-deployable (author natively), and the structural IGW /
// VPCGatewayAttachment are no-ops. An EIP / EIPAssociation on an in-stack INSTANCE is create-deployable
// (#347 1.6: folded onto the VM's LAN IP — see translate_ec2eip_test.go); an EIP used as a NatGateway's
// address still refuses there. This locks that contract.
func TestMapping_EIPNatGatewayFamily(t *testing.T) {
	// NatGateway: recognized (Partial, mappable) but plan-only — no create translator.
	e := Lookup("AWS::EC2::NatGateway")
	if e.Status != Partial || e.Kind != "NatGateway" || !e.mappable() {
		t.Errorf("AWS::EC2::NatGateway: got {%q,%q}, want {partial,NatGateway} and mappable", e.Status, e.Kind)
	}
	if hasTranslator("AWS::EC2::NatGateway") {
		t.Errorf("AWS::EC2::NatGateway: must be plan-only (no create translator) — AWS props don't carry the gateway binding/lanIp")
	}
	// EIP + EIPAssociation: Partial, folded onto the VM (spec.expose), and create-deployable.
	for _, cfnType := range []string{"AWS::EC2::EIP", "AWS::EC2::EIPAssociation"} {
		e := Lookup(cfnType)
		if e.Status != Partial || e.Kind != "VirtualMachine(spec.expose)" {
			t.Errorf("%s: got {%q,%q}, want {partial,VirtualMachine(spec.expose)}", cfnType, e.Status, e.Kind)
		}
		if !hasTranslator(cfnType) {
			t.Errorf("%s: must have a create translator (folds onto the associated VM's LAN IP)", cfnType)
		}
	}

	// Structural no-ops (recognized, deployable, provision nothing) — like an ECS Cluster.
	for _, cfnType := range []string{
		"AWS::EC2::InternetGateway", "AWS::EC2::VPCGatewayAttachment",
		"AWS::EC2::SubnetNetworkAclAssociation", "AWS::EC2::SubnetRouteTableAssociation",
	} {
		if !hasTranslator(cfnType) {
			t.Errorf("%s: should have a no-op translator so a template carrying it doesn't block", cfnType)
		}
		m, fs := translateEC2ImplicitGateway(cfnType, map[string]any{"Tags": []any{}}, nil)
		if m != nil || len(fs) != 0 {
			t.Errorf("%s: should be a no-op (nil manifest, no findings), got m=%v fs=%v", cfnType, m, fs)
		}
	}
}

// The rest of the networking surface — NetworkAcl, VPCPeeringConnection, TransitGateway, FlowLog — is
// recognized at plan but NOT create-deployable, for the same reason as NatGateway: the kube-ovn
// model needs IPs / links / rule collation AWS auto-assigns or splits across resources, so a faithful
// create translator can't be derived and the honest move is author-natively. (RouteTable and the
// default Route graduated to create-deployable as implicit no-ops — see the Route translator tests.)
func TestMapping_NetworkingPlanOnly(t *testing.T) {
	for _, tc := range []struct {
		cfnType, kind string
	}{
		{"AWS::EC2::NetworkAcl", "Subnet(acls)"},
		{"AWS::EC2::VPCPeeringConnection", "Vpc(peerings)"},
		{"AWS::EC2::TransitGateway", "TransitGateway"},
		{"AWS::EC2::FlowLog", "FlowLog"},
	} {
		e := Lookup(tc.cfnType)
		if e.Status != Partial || e.Kind != tc.kind {
			t.Errorf("%s: got {%q,%q}, want {partial,%q}", tc.cfnType, e.Status, e.Kind, tc.kind)
		}
		if hasTranslator(tc.cfnType) {
			t.Errorf("%s: must be plan-only (no create translator)", tc.cfnType)
		}
	}
}
