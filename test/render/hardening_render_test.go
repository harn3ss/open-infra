package render

import (
	"strings"
	"testing"
)

// A spec number reaches the template as a float64 (JSON), and Go templates refuse to compare a float
// with an int literal: a ScheduledJob or ProcessingJob that set gpu used to fail to render at all.
// With gpu as Crossplane delivers it, the job now runs on a GPU node with the GPUs it asked for.
func TestJobs_GPUCountFromJSONRenders(t *testing.T) {
	for _, c := range []struct{ name, path string }{
		{"scheduledjob", "../../platform/abstraction/scheduledjob-composition.yaml"},
		{"processingjob", "../../platform/abstraction/processingjob-composition.yaml"},
	} {
		tmpl := extractInlineTemplate(t, c.path)
		spec := map[string]any{"image": "x", "schedule": "0 * * * *", "cpu": "1", "memory": "1Gi", "gpu": float64(1)}
		if err := renderErr(tmpl, compositeCtx(spec)); err != nil {
			t.Fatalf("%s with gpu: 1 (a JSON number) must render: %v", c.name, err)
		}
		out := render(t, tmpl, compositeCtx(spec))
		if !strings.Contains(out, "runtimeClassName: nvidia") || !strings.Contains(out, "nvidia.com/gpu: 1") {
			t.Errorf("%s with gpu: 1 must request one GPU on a GPU node:\n%s", c.name, grepCtx(out, "gpu"))
		}
		cpu := render(t, tmpl, compositeCtx(map[string]any{"image": "x", "schedule": "0 * * * *", "cpu": "1", "memory": "1Gi", "gpu": float64(0)}))
		if strings.Contains(cpu, "nvidia.com/gpu") || strings.Contains(cpu, "runtimeClassName: nvidia") {
			t.Errorf("%s with gpu: 0 stays CPU-only", c.name)
		}
	}
}

func faultCtx(spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{"name": "kill-1-xyz", "labels": map[string]any{
			"crossplane.io/claim-name": "kill-1", "crossplane.io/claim-namespace": "team-a",
		}},
	}}}}
}

// A fault's blast radius is its own namespace: a target in another namespace (another tenant's pods)
// is refused; naming the claim's own namespace, or none, targets it.
func TestFaultInjection_TargetStaysInItsNamespace(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/faultinjection-composition.yaml")
	sel := map[string]any{"app": "pg"}
	err := renderErr(tmpl, faultCtx(map[string]any{"type": "pod-kill", "target": map[string]any{"namespace": "team-b", "labelSelector": sel}}))
	if err == nil || !strings.Contains(err.Error(), "own namespace") {
		t.Fatalf("a target in another namespace must be refused, got %v", err)
	}
	for name, target := range map[string]map[string]any{
		"own namespace named": {"namespace": "team-a", "labelSelector": sel},
		"namespace omitted":   {"labelSelector": sel},
	} {
		out := render(t, tmpl, faultCtx(map[string]any{"type": "pod-kill", "target": target}))
		if !strings.Contains(out, `namespace: "team-a"`) || strings.Contains(out, "team-b") {
			t.Errorf("%s: the experiment runs in the claim's namespace:\n%s", name, grepCtx(out, "namespace"))
		}
	}
}
