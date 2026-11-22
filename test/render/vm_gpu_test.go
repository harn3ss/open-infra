package render

import (
	"strings"
	"testing"
)

// A GPU instance (spec.gpus, a g4dn.xlarge's one) is given each GPU whole: a passed-through card KubeVirt
// offers as openinfra.dev/instance-gpu. An instance without GPUs asks for none, and a GPU instance cannot be
// highAvailability (the card cannot live-migrate).
func TestVM_GPUInstance(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmCompositionPath)
	if out := render(t, tmpl, vmCtx("ubuntu-24.04", "")); strings.Contains(out, "openinfra.dev/instance-gpu") {
		t.Errorf("an instance without GPUs must ask for none:\n%s", grepCtx(out, "instance-gpu"))
	}
	for _, n := range []int64{1, 2} {
		out := render(t, tmpl, vmCtxFW("windows-server-2022", map[string]any{"cpu": int64(4), "memory": "16Gi", "gpus": n}))
		docs, err := parseYAMLDocs(out)
		if err != nil {
			t.Fatal(err)
		}
		var gpus []any
		for _, d := range docs {
			if m := digMap(d, "spec", "forProvider", "manifest"); m != nil && m["kind"] == "VirtualMachine" {
				if l, ok := mget(m, "spec", "template", "spec", "domain", "devices", "gpus").([]any); ok {
					gpus = l
				}
			}
		}
		if int64(len(gpus)) != n {
			t.Fatalf("gpus %d: want %d passed-through GPUs, got %v", n, n, gpus)
		}
		for i, g := range gpus {
			gm, _ := g.(map[string]any)
			if gm["deviceName"] != "openinfra.dev/instance-gpu" || gm["name"] != "gpu"+string(rune('1'+i)) {
				t.Errorf("gpus %d: GPU %d = %v", n, i, gm)
			}
		}
	}
	err := renderErr(tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"gpus": int64(1), "highAvailability": true}))
	if err == nil || !strings.Contains(err.Error(), "GPU instance") {
		t.Errorf("a highAvailability GPU instance must be refused, got %v", err)
	}
}
