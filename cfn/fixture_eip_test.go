package cfn

import (
	"os"
	"strings"
	"testing"
)

// The lift-and-shift fixture keeps its address either in-stack (AppAddressAllocationId empty: the EIP folds
// onto the instance's VM, through the Fn::If) or in eip.yaml's stack (the parameter set: the VM carries that
// allocation's address), and plans both ways; eip.yaml plans as an allocation of its own.
func TestFixture_AddressInStackOrFromItsOwnStack(t *testing.T) {
	app, err := os.ReadFile("testdata/lift-and-shift/template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	eip, err := os.ReadFile("testdata/lift-and-shift/eip.yaml")
	if err != nil {
		t.Fatal(err)
	}
	caps := Capabilities{ObjectEncryption: true, EC2AddressAPI: true}
	params := map[string]string{"SiteDomain": "site.example.test", "AppRepositoryName": "fixture-app"}

	// In-stack: the Fn::If picks the stack's own EIP, which folds onto the VM (no allocation of its own).
	own, err := buildManifests(app, DeployOptions{StackName: "fx", Namespace: "open-infra-cfn", Caps: caps, Params: params})
	if err != nil {
		t.Fatalf("in-stack address: %v", err)
	}
	for _, b := range own {
		if b.res.Kind == KindEC2Address {
			t.Fatalf("the stack's own EIP must fold onto its instance, not become an allocation: %+v", b.res)
		}
		if b.res.LogicalID == "AppInstance" {
			if exp, _ := b.res.Spec["expose"].(bool); !exp || b.res.Spec["elasticIp"] != nil {
				t.Fatalf("in-stack: the VM is exposed with its own address: %v", b.res.Spec)
			}
		}
	}

	// From eip.yaml: an allocation of its own, whose id the app stack takes as a parameter.
	ep, err := BuildPlanWithCaps(eip, nil, nil, "fx-address", caps)
	if err != nil || ep.Verdict == Rejected {
		t.Fatalf("eip.yaml must plan where allocations are kept: %v %v", err, ep.Blockers)
	}
	alloc := eipAllocationID("fx-address", "Address")
	params["AppAddressAllocationId"] = alloc
	ext, err := buildManifests(app, DeployOptions{StackName: "fx", Namespace: "open-infra-cfn", Caps: caps, Params: params})
	if err != nil {
		t.Fatalf("address from eip.yaml: %v", err)
	}
	found := false
	for _, b := range ext {
		if b.res.LogicalID == "AppAddress" {
			t.Fatal("with an address from eip.yaml the app stack allocates none")
		}
		if b.res.LogicalID == "AppInstance" {
			found = true
			e, _ := b.res.Spec["elasticIp"].(map[string]any)
			if e["allocationId"] != alloc {
				t.Fatalf("the VM must carry eip.yaml's allocation: %v", b.res.Spec)
			}
			if !strings.Contains(strings.Join(b.cav, " "), "PublicDnsName") {
				t.Errorf("the plan must say what PublicDnsName is: %v", b.cav)
			}
		}
	}
	if !found {
		t.Fatal("no AppInstance built")
	}
}
