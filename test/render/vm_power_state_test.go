package render

import (
	"strings"
	"testing"
)

// status.powerState and status.restartRequired come from the KubeVirt VirtualMachine (its printableStatus
// and RestartRequired condition), so a CloudFormation update that resizes an instance can stop and start it
// and know when it runs at the new size. Before KubeVirt reports anything they are "" and false.
func TestVM_StatusPowerState(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	observedVM := func(status map[string]any) map[string]any {
		ctx := vmCtx("ubuntu-24.04", "")
		ctx["observed"].(map[string]any)["resources"] = map[string]any{
			"virtualmachine": map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{
				"manifest": map[string]any{"status": status},
			}}}},
		}
		return ctx
	}
	statusDoc := func(out string) string {
		i := strings.Index(out, "kind: XVirtualMachine")
		if i < 0 {
			t.Fatalf("the composite status document must always render")
		}
		return out[i:]
	}
	cases := []struct {
		name   string
		ctx    map[string]any
		power  string
		needed string
	}{
		{"not observed yet", vmCtx("ubuntu-24.04", ""), `powerState: ""`, "restartRequired: false"},
		{"running", observedVM(map[string]any{"printableStatus": "Running",
			"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}), `powerState: "Running"`, "restartRequired: false"},
		{"running an earlier spec", observedVM(map[string]any{"printableStatus": "Running",
			"conditions": []any{map[string]any{"type": "Ready", "status": "True"}, map[string]any{"type": "RestartRequired", "status": "True"}}}),
			`powerState: "Running"`, "restartRequired: true"},
		{"a cleared condition", observedVM(map[string]any{"printableStatus": "Running",
			"conditions": []any{map[string]any{"type": "RestartRequired", "status": "False"}}}), `powerState: "Running"`, "restartRequired: false"},
		{"stopped", observedVM(map[string]any{"printableStatus": "Stopped"}), `powerState: "Stopped"`, "restartRequired: false"},
		{"stopped, its instance gone", observedVM(map[string]any{"printableStatus": "Stopped", "created": false}), `powerState: "Stopped"`, "restartRequired: false"},
		// The guest is down but its VirtualMachineInstance is still being deleted: a start asked for now
		// would be lost, so the instance is still stopping.
		{"stopped, its instance not yet gone", observedVM(map[string]any{"printableStatus": "Stopped", "created": true}), `powerState: "Stopping"`, "restartRequired: false"},
	}
	for _, c := range cases {
		got := statusDoc(render(t, tmpl, c.ctx))
		if !strings.Contains(got, c.power) || !strings.Contains(got, c.needed) {
			t.Errorf("%s: want %s and %s in the composite status; got:\n%s", c.name, c.power, c.needed, got)
		}
	}
	// The VM is watched, so a change of its state reaches the composite promptly.
	out := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	i := strings.Index(out, "composition-resource-name: virtualmachine\n")
	if i < 0 || !strings.Contains(out[i:i+200], "watch: true") {
		t.Errorf("the virtualmachine Object must be watched")
	}
}

// status.launchRefused is the EC2 error a VM's launch is refused with, from the conditions KubeVirt reports
// (their text as KubeVirt writes it): the account's capacity refusing its launcher pod or its root disk, or no
// node with room for it. Anything else refuses nothing.
func TestVM_StatusLaunchRefused(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	withConds := func(printable string, conds ...map[string]any) map[string]any {
		cs := make([]any, len(conds))
		for i, c := range conds {
			cs[i] = c
		}
		ctx := vmCtx("ubuntu-24.04", "")
		ctx["observed"].(map[string]any)["resources"] = map[string]any{
			"virtualmachine": map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{
				"manifest": map[string]any{"status": map[string]any{"printableStatus": printable, "conditions": cs}},
			}}}},
		}
		return ctx
	}
	podRefused := func(quota string) map[string]any {
		return map[string]any{"type": "Synchronized", "status": "False", "reason": "FailedCreate",
			"message": `failed to create virtual machine pod: pods "virt-launcher-myvm-mx885" is forbidden: exceeded quota: ` + quota +
				`, requested: requests.memory=17515223040, used: requests.memory=17515223040, limited: requests.memory=17Gi`}
	}
	cases := []struct {
		name, want string
		ctx        map[string]any
	}{
		{"memory capacity", "VcpuLimitExceeded", withConds("Starting", podRefused("account-capacity-memory"))},
		{"cpu capacity", "VcpuLimitExceeded", withConds("Starting", podRefused("account-capacity-cpu"))},
		{"gpu capacity", "VcpuLimitExceeded", withConds("Starting", podRefused("account-capacity-gpu"))},
		{"pod budget", "InstanceLimitExceeded", withConds("Starting", podRefused("account-capacity-pods"))},
		{"storage capacity", "VolumeLimitExceeded", withConds("Provisioning", map[string]any{"type": "Failure", "status": "True", "reason": "FailedCreate",
			"message": `Error encountered while creating DataVolumes: DataVolume myvm-root importer is not running due to an error: persistentvolumeclaims "myvm-root" is forbidden: exceeded quota: account-capacity-storage, requested: requests.storage=120Gi, used: requests.storage=127474629346, limited: requests.storage=200Gi`})},
		{"no node with room", "InsufficientInstanceCapacity", withConds("ErrorUnschedulable", map[string]any{"type": "PodScheduled", "status": "False", "reason": "Unschedulable",
			"message": "0/7 nodes are available: 1 node(s) had untolerated taint, 6 Insufficient memory. preemption: 0/7 nodes are available"})},
		{"unschedulable for another reason", "", withConds("ErrorUnschedulable", map[string]any{"type": "PodScheduled", "status": "False", "reason": "Unschedulable",
			"message": "0/7 nodes are available: 7 node(s) didn't match PersistentVolume's node affinity."})},
		{"a quota that is not the account's capacity", "", withConds("Starting", podRefused("someone-elses-quota"))},
		{"a refusal that has cleared", "", withConds("Running", map[string]any{"type": "Synchronized", "status": "True", "reason": "FailedCreate",
			"message": "exceeded quota: account-capacity-memory"})},
		{"running", "", withConds("Running", map[string]any{"type": "Ready", "status": "True"})},
	}
	for _, c := range cases {
		out := render(t, tmpl, c.ctx)
		doc := out[strings.Index(out, "kind: XVirtualMachine"):]
		if want := `launchRefused: "` + c.want + `"`; !strings.Contains(doc, want) {
			t.Errorf("%s: want %s in the composite status; got:\n%s", c.name, want, grepCtx(doc, "launchRefused"))
		}
	}
}

// A running VM restarts after a crash but stays stopped when the guest shuts itself down (RerunOnFailure), as
// EC2's instance-initiated shutdown stops an instance; a stopped one is Halted.
func TestVM_RunStrategy_InstanceInitiatedShutdownStops(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	if out := render(t, tmpl, vmCtx("ubuntu-24.04", "")); !strings.Contains(out, "runStrategy: RerunOnFailure") {
		t.Errorf("a running VM must be RerunOnFailure:\n%s", grepCtx(out, "runStrategy"))
	}
	if out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"running": false})); !strings.Contains(out, "runStrategy: Halted") {
		t.Errorf("a stopped VM must be Halted:\n%s", grepCtx(out, "runStrategy"))
	}
}
