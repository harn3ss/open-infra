package render

import (
	"strings"
	"testing"
)

const asgCompositionPath = "../../platform/abstraction/autoscalinggroup-composition.yaml"

func asgCtx(spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{
			"uid":    "00000000-0000-0000-0000-00000000asg",
			"labels": map[string]any{"crossplane.io/claim-name": "web-fleet", "crossplane.io/claim-namespace": "team-a"},
		},
	}}}}
}

// A Linux AutoScalingGroup renders a VirtualMachinePool with the 3-way selector/label match, a
// per-member root DataVolume from the OS image, and the capacity as replicas.
func TestAutoScalingGroup_LinuxPool(t *testing.T) {
	tmpl := extractInlineTemplate(t, asgCompositionPath)
	out := render(t, tmpl, asgCtx(map[string]any{
		"minSize": int64(1), "maxSize": int64(5), "desiredCapacity": int64(3),
		"launchTemplate": map[string]any{"os": "ubuntu-24.04", "cpu": int64(2), "memory": "4Gi"},
	}))
	for _, want := range []string{
		"kind: VirtualMachinePool", "apiVersion: pool.kubevirt.io/v1beta1",
		"name: web-fleet", "namespace: team-a",
		"replicas: 3",
		"openinfra.dev/autoscalinggroup: web-fleet", // selector + both label spots
		"name: web-fleet-root",                      // per-member DV base name (pool appends ordinal)
		"docker://quay.io/containerdisks/ubuntu:24.04",
		"poolName: web-fleet", "desiredCapacity: 3", // status
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Linux ASG render missing %q; got:\n%s", want, grepCtx(out, "VirtualMachinePool"))
		}
	}
	// The pool selector label must appear at least 3× (pool selector + VM template + VMI template).
	if n := strings.Count(out, "openinfra.dev/autoscalinggroup: web-fleet"); n < 3 {
		t.Errorf("selector label must be on the pool selector + VM template + VMI template (>=3); got %d", n)
	}
	// A Linux (non-Windows) pool must clone no golden PVC and mint no OOBE ConfigMap.
	if strings.Contains(out, "-golden") || strings.Contains(out, "-oobe") {
		t.Errorf("Linux ASG must not reference a Windows golden/oobe; got:\n%s", grepCtx(out, "golden"))
	}
	// maxUnavailable default "1" must render as an INTEGER (a quoted "1" is read as a percent and
	// rejected by the pool webhook: "must end with %").
	if !strings.Contains(out, "maxUnavailable: 1") || strings.Contains(out, `maxUnavailable: "1"`) {
		t.Errorf("default maxUnavailable must render as integer 1 (not quoted); got:\n%s", grepCtx(out, "maxUnavailable"))
	}
}

// A percentage maxUnavailable renders as a quoted string (the int-or-string other branch).
func TestAutoScalingGroup_MaxUnavailablePercent(t *testing.T) {
	tmpl := extractInlineTemplate(t, asgCompositionPath)
	out := render(t, tmpl, asgCtx(map[string]any{
		"desiredCapacity": int64(4),
		"launchTemplate":  map[string]any{"os": "ubuntu-24.04"},
		"instanceRefresh": map[string]any{"maxUnavailable": "25%"},
	}))
	if !strings.Contains(out, `maxUnavailable: "25%"`) {
		t.Errorf("percentage maxUnavailable must render as a quoted string; got:\n%s", grepCtx(out, "maxUnavailable"))
	}
}

// The capacity-clamp fix: desiredCapacity WITHOUT maxSize must be honored as-is (no silent clamp to a
// default max); when maxSize IS set below desired, replicas clamp to it; below minSize, floor to min.
func TestAutoScalingGroup_CapacityClamp(t *testing.T) {
	tmpl := extractInlineTemplate(t, asgCompositionPath)
	lt := map[string]any{"os": "ubuntu-24.04"}

	noMax := render(t, tmpl, asgCtx(map[string]any{"desiredCapacity": int64(3), "launchTemplate": lt}))
	if !strings.Contains(noMax, "replicas: 3") {
		t.Errorf("desiredCapacity:3 with no maxSize must give replicas:3 (the footgun fix); got:\n%s", grepCtx(noMax, "replicas"))
	}
	capped := render(t, tmpl, asgCtx(map[string]any{"desiredCapacity": int64(10), "maxSize": int64(5), "launchTemplate": lt}))
	if !strings.Contains(capped, "replicas: 5") {
		t.Errorf("desiredCapacity:10 maxSize:5 must clamp to replicas:5; got:\n%s", grepCtx(capped, "replicas"))
	}
	floored := render(t, tmpl, asgCtx(map[string]any{"minSize": int64(2), "desiredCapacity": int64(0), "launchTemplate": lt}))
	if !strings.Contains(floored, "replicas: 2") {
		t.Errorf("desiredCapacity:0 minSize:2 must floor to replicas:2; got:\n%s", grepCtx(floored, "replicas"))
	}
}

// A Windows AutoScalingGroup clones the per-version golden PVC per member, pins amd64, and mints the
// (shared) OOBE ConfigMap — rendered honestly with its documented limits.
func TestAutoScalingGroup_WindowsPool(t *testing.T) {
	tmpl := extractInlineTemplate(t, asgCompositionPath)
	out := render(t, tmpl, asgCtx(map[string]any{
		"desiredCapacity": int64(2),
		"launchTemplate":  map[string]any{"os": "windows-server-2022", "cpu": int64(4), "memory": "8Gi"},
	}))
	for _, want := range []string{
		"name: windows-server-2022-golden", // per-member golden clone
		"architecture: amd64", "kubernetes.io/arch: amd64",
		"name: web-fleet-oobe", // shared OOBE ConfigMap
		"kind: ConfigMap", "unattend.xml",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Windows ASG render missing %q; got:\n%s", want, grepCtx(out, "windows"))
		}
	}
}

// highAvailability puts each member's root on longhorn-migratable + sets LiveMigrate; replaceUnhealthy:false
// omits autohealing entirely (nil disables it in the pool controller).
func TestAutoScalingGroup_HAAndHealthToggle(t *testing.T) {
	tmpl := extractInlineTemplate(t, asgCompositionPath)
	ha := render(t, tmpl, asgCtx(map[string]any{
		"desiredCapacity": int64(2),
		"launchTemplate":  map[string]any{"os": "ubuntu-24.04", "highAvailability": true},
	}))
	for _, want := range []string{"storageClassName: longhorn-migratable", "evictionStrategy: LiveMigrate", "volumeMode: Block"} {
		if !strings.Contains(ha, want) {
			t.Errorf("HA ASG missing %q; got:\n%s", want, grepCtx(ha, "storage"))
		}
	}
	// Default (replaceUnhealthy defaults true) → autohealing present; explicit false → absent.
	def := render(t, tmpl, asgCtx(map[string]any{"launchTemplate": map[string]any{"os": "ubuntu-24.04"}}))
	if !strings.Contains(def, "autohealing:") {
		t.Errorf("default ASG must enable autohealing; got:\n%s", grepCtx(def, "autohealing"))
	}
	off := render(t, tmpl, asgCtx(map[string]any{
		"launchTemplate": map[string]any{"os": "ubuntu-24.04"},
		"healthCheck":    map[string]any{"replaceUnhealthy": false},
	}))
	if strings.Contains(off, "autohealing:") {
		t.Errorf("replaceUnhealthy:false must omit autohealing; got:\n%s", grepCtx(off, "autohealing"))
	}
}
