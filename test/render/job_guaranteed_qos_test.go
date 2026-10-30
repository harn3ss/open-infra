package render

import (
	"regexp"
	"testing"
)

// compositeCtx wraps a spec as the function-go-templating observed-composite context.
func compositeCtx(spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{"labels": map[string]any{
			"crossplane.io/claim-name":      "sz",
			"crossplane.io/claim-namespace": "team",
		}},
	}}}}
}

// Every one-shot/scheduled job kind sets the container request == limit (Guaranteed QoS). The bug
// this guards: those kinds used to hardcode a fixed request floor (e.g. 512Mi) while taking the
// limit from the user's cpu/memory, so a job sized BELOW the floor rendered request > limit — an
// invalid pod the API server refuses at Job/Deployment creation, leaving it NotReady with no cause
// on the claim (the same class of defect as the Function memoryRequest>memory finding, found while
// checking the other request/limit kinds). A one-shot job has no warm-idle fleet, so Guaranteed QoS
// carries no reservation trap; request==limit makes the inversion unrepresentable by construction.
//
// We render each kind with a memory smaller than every old floor and assert the rendered memory
// request equals the limit (the user's value), not a larger floor.
func TestJobKinds_RequestEqualsLimit_NoInversion(t *testing.T) {
	const tiny = "64Mi" // below all old floors (512Mi / 1Gi / 128Mi)
	cases := []struct {
		name string
		path string
		spec map[string]any
	}{
		{"scheduledjob", "../../platform/abstraction/scheduledjob-composition.yaml",
			map[string]any{"schedule": "0 2 * * *", "image": "x", "cpu": "50m", "memory": tiny, "gpu": int64(0)}},
		{"batchtransform", "../../platform/abstraction/batchtransform-composition.yaml",
			map[string]any{"image": "x", "cpu": "50m", "memory": tiny, "gpu": int64(0),
				"input":  map[string]any{"bucket": "in"},
				"output": map[string]any{"bucket": "out"}}},
		{"processingjob", "../../platform/abstraction/processingjob-composition.yaml",
			map[string]any{"image": "x", "cpu": "50m", "memory": tiny, "gpu": int64(0)}},
		{"trainingjob", "../../platform/abstraction/trainingjob-composition.yaml",
			map[string]any{"image": "x", "cpu": "50m", "memory": tiny, "gpu": int64(0)}},
	}
	reqMemRe := regexp.MustCompile(`requests:\s*\{[^}]*memory:\s*"?([0-9A-Za-z]+)"?`)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmpl := extractInlineTemplate(t, c.path)
			out := render(t, tmpl, compositeCtx(c.spec))
			m := reqMemRe.FindStringSubmatch(out)
			if m == nil {
				t.Fatalf("%s: no requests.memory in render:\n%s", c.name, grepCtx(out, "resources"))
			}
			if m[1] != tiny {
				t.Errorf("%s: requests.memory = %q, want %q (== limit). A fixed request floor above the "+
					"user's limit renders request > limit — an invalid pod refused at creation.", c.name, m[1], tiny)
			}
		})
	}
}
