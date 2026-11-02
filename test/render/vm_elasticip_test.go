package render

import (
	"strings"
	"testing"
)

const testAlloc = "eipalloc-0123456789abcdef0"

// holderObserved adds the observed holder Service of an Elastic IP allocation (labels + its address).
func holderObserved(ctx map[string]any, labels map[string]any, ingress []any) map[string]any {
	obs, _ := ctx["observed"].(map[string]any)["resources"].(map[string]any)
	if obs == nil {
		obs = map[string]any{}
		ctx["observed"].(map[string]any)["resources"] = obs
	}
	obs["vm-eip-holder"] = map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{
		"manifest": map[string]any{
			"metadata": map[string]any{"labels": labels},
			"status":   map[string]any{"loadBalancer": map[string]any{"ingress": ingress}},
		},
	}}}}
	return ctx
}

// docWith returns the rendered document that contains needle ("" if none).
func docWith(out, needle string) string {
	for _, d := range strings.Split(out, "\n---\n") {
		if strings.Contains(d, needle) {
			return d
		}
	}
	return ""
}

// spec.elasticIp (#347 item 8): the VM's LAN Service carries the address an Elastic IP allocation holds,
// shared with the allocation's holder Service (same MetalLB sharing key, same selector); the VM's pod
// carries that selector's label; the holder is observed only, in the VM's own namespace.
func TestVM_ElasticIPSharesTheAllocationsAddress(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	spec := map[string]any{"expose": true, "elasticIp": map[string]any{"allocationId": testAlloc}}
	holderLabels := map[string]any{"openinfra.dev/eip-holder": "true"}
	out := render(t, tmpl, holderObserved(vmCtxFW("ubuntu-24.04", spec), holderLabels, []any{map[string]any{"ip": "192.0.2.60"}}))

	holder := docWith(out, "composition-resource-name: vm-eip-holder")
	if holder == "" || !strings.Contains(holder, `managementPolicies: ["Observe"]`) ||
		!strings.Contains(holder, `metadata: { name: "`+testAlloc+`", namespace: "default" }`) {
		t.Fatalf("the holder must be observed (only) by name in the VM's namespace:\n%s", holder)
	}
	lan := docWith(out, "composition-resource-name: vm-lan")
	for _, want := range []string{
		`metallb.universe.tf/loadBalancerIPs: "192.0.2.60"`,
		`metallb.universe.tf/allow-shared-ip: "` + testAlloc + `"`,
		`selector: { openinfra.dev/eip-allocation: "` + testAlloc + `" }`,
		"externalTrafficPolicy: Local",
	} {
		if !strings.Contains(lan, want) {
			t.Errorf("the LAN Service is missing %q:\n%s", want, lan)
		}
	}
	if !strings.Contains(out, `openinfra.dev/eip-allocation: "`+testAlloc+`"`+"\n") {
		t.Errorf("the VM's pod must carry the shared selector's label:\n%s", grepCtx(out, "eip-allocation"))
	}
	if !strings.Contains(docWith(out, "kind: XVirtualMachine"), "lanIp:") {
		t.Error("the composite status must still render")
	}

	// Until the holder reports an address (or if what is observed is not a holder), no LAN Service: the
	// VM never takes an address of its own that it would lose when the allocation's arrives.
	for name, ctx := range map[string]map[string]any{
		"holder not observed yet": vmCtxFW("ubuntu-24.04", spec),
		"no address yet":          holderObserved(vmCtxFW("ubuntu-24.04", spec), holderLabels, []any{}),
		"not a holder":            holderObserved(vmCtxFW("ubuntu-24.04", spec), map[string]any{"app": "x"}, []any{map[string]any{"ip": "192.0.2.61"}}),
	} {
		got := render(t, tmpl, ctx)
		if docWith(got, "composition-resource-name: vm-lan") != "" {
			t.Errorf("%s: no LAN Service may render:\n%s", name, grepCtx(got, "vm-lan"))
		}
		if docWith(got, "composition-resource-name: vm-eip-holder") == "" {
			t.Errorf("%s: the holder must still be observed", name)
		}
	}
}

// A VM without spec.elasticIp renders exactly as before: its own LAN Service and selector, no holder,
// no sharing annotations, no allocation label.
func TestVM_NoElasticIPUnchanged(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"expose": true}))
	for _, not := range []string{"vm-eip-holder", "eip-allocation", "allow-shared-ip", "loadBalancerIPs"} {
		if strings.Contains(out, not) {
			t.Errorf("a VM without spec.elasticIp must not render %q:\n%s", not, grepCtx(out, not))
		}
	}
	if !strings.Contains(docWith(out, "composition-resource-name: vm-lan"), "selector: { kubevirt.io/domain: myvm }") {
		t.Errorf("the LAN Service must select the VM itself:\n%s", docWith(out, "composition-resource-name: vm-lan"))
	}
}
