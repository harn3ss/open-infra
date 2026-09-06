package main

import "testing"

// #120: the EIP + NAT/Internet-Gateway family. The backing kinds (ElasticIp, NatGateway) are
// dataplane-verified, but AWS's property sets don't carry the gateway binding / lanIp / association
// our model needs — so EIP and NatGateway are plan-recognized, NOT create-deployable (author
// natively), and the structural IGW / VPCGatewayAttachment are no-ops. This locks that contract.
func TestMapping_EIPNatGatewayFamily(t *testing.T) {
	// EIP + NatGateway: recognized (Partial, mappable) but plan-only — no create translator.
	for _, tc := range []struct {
		cfnType, kind string
	}{
		{"AWS::EC2::EIP", "ElasticIp"},
		{"AWS::EC2::NatGateway", "NatGateway"},
	} {
		e := Lookup(tc.cfnType)
		if e.Status != Partial {
			t.Errorf("%s: status = %q, want partial", tc.cfnType, e.Status)
		}
		if e.Kind != tc.kind {
			t.Errorf("%s: kind = %q, want %q", tc.cfnType, e.Kind, tc.kind)
		}
		if !e.mappable() {
			t.Errorf("%s: should map at plan", tc.cfnType)
		}
		if hasTranslator(tc.cfnType) {
			t.Errorf("%s: must be plan-only (no create translator) — AWS props don't carry the gateway binding/lanIp", tc.cfnType)
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

// The rest of the networking surface — NetworkAcl, VPCPeeringConnection, TransitGateway, RouteTable,
// Route — is recognized at plan but NOT create-deployable, for the same reason as EIP/NatGateway:
// the kube-ovn model needs IPs / links / rule collation AWS auto-assigns or splits across resources,
// so a faithful create translator can't be derived and the honest move is author-natively.
func TestMapping_NetworkingPlanOnly(t *testing.T) {
	for _, tc := range []struct {
		cfnType, kind string
	}{
		{"AWS::EC2::NetworkAcl", "Subnet(acls)"},
		{"AWS::EC2::VPCPeeringConnection", "Vpc(peerings)"},
		{"AWS::EC2::TransitGateway", "TransitGateway"},
		{"AWS::EC2::RouteTable", "Vpc(routes)"},
		{"AWS::EC2::Route", "Vpc(routes)"},
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
