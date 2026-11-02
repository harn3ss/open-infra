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
