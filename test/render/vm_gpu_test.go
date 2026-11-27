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

// Each GPU instance family is its own pool of cards: a g5 instance (spec.gpuFamily g5) asks for the g5 pool's
// card, and g4dn (or no family) for the pool every GPU instance used before families existed.
func TestVM_GPUInstanceFamily(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmCompositionPath)
	for family, want := range map[string]string{
		"":     "openinfra.dev/instance-gpu",
		"g4dn": "openinfra.dev/instance-gpu",
		"g5":   "openinfra.dev/instance-gpu-g5",
	} {
		spec := map[string]any{"cpu": int64(4), "memory": "16Gi", "gpus": int64(1)}
		if family != "" {
			spec["gpuFamily"] = family
		}
		docs, err := parseYAMLDocs(render(t, tmpl, vmCtxFW("windows-server-2022", spec)))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, d := range docs {
			if m := digMap(d, "spec", "forProvider", "manifest"); m != nil && m["kind"] == "VirtualMachine" {
				l, _ := mget(m, "spec", "template", "spec", "domain", "devices", "gpus").([]any)
				for _, g := range l {
					gm, _ := g.(map[string]any)
					got = append(got, gm["deviceName"].(string))
				}
			}
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("gpuFamily %q: want one GPU from %s, got %v", family, want, got)
		}
	}
	// A family alone gives no GPU: spec.gpus counts them.
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"gpuFamily": "g5"}))
	if strings.Contains(out, "instance-gpu") {
		t.Errorf("gpuFamily without gpus must ask for no GPU:\n%s", grepCtx(out, "instance-gpu"))
	}
}
