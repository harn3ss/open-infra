package render

import (
	"strings"
	"testing"
)

// An instance in a default VPC's private subnet runs on the NAT gateway node, the one its traffic leaves
// through, with or without high availability. Any other subnet's instance has no such constraint.
func TestVirtualMachine_PrivateSubnetRunsOnTheNATGatewayNode(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	const nat = `{ key: openinfra.dev/nat-gateway, operator: In, values: ["true"] }`
	for _, ha := range []bool{false, true} {
		out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"subnet": "default-vpc-912345678901-private", "highAvailability": ha}))
		if !strings.Contains(out, nat) {
			t.Errorf("highAvailability %v: the instance is not placed on the NAT gateway node", ha)
		}
		if !strings.Contains(out, `ovn.kubernetes.io/logical_switch: "default-vpc-912345678901-private"`) {
			t.Errorf("highAvailability %v: the instance is not in its subnet", ha)
		}
	}
	// A Windows instance (its root a clone its launcher places) is placed there too.
	if out := render(t, tmpl, vmCtxFW("windows-server-2022", map[string]any{"subnet": "default-vpc-912345678901-private"})); !strings.Contains(out, nat) {
		t.Error("a Windows instance in the private subnet is not placed on the NAT gateway node")
	}
	for _, subnet := range []string{"default-vpc-912345678901", "private-a", ""} {
		extra := map[string]any{}
		if subnet != "" {
			extra["subnet"] = subnet
		}
		if out := render(t, tmpl, vmCtxFW("ubuntu-24.04", extra)); strings.Contains(out, nat) {
			t.Errorf("an instance in subnet %q is placed on the NAT gateway node", subnet)
		}
	}
}
