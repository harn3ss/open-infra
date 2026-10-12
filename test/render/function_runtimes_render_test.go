package render

import (
	"strings"
	"testing"
)

// kind: Function spec.code.runtime maps each managed runtime to its runtime base image. This locks
// the full set — including nodejs22 and python3.13 — so otf can bring functions on those runtimes.
func TestFunction_RuntimeImages(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/function-composition.yaml")
	ctx := func(runtime string) map[string]any {
		return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": map[string]any{"code": map[string]any{"runtime": runtime, "handler": "app.handler",
				"source": map[string]any{"configMap": "fn-code"}}},
			"metadata": map[string]any{"labels": map[string]any{
				"crossplane.io/claim-name": "fn", "crossplane.io/claim-namespace": "team-a"}},
		}}}}
	}
	for runtime, image := range map[string]string{
		"python3.12": "ghcr.io/harn3ss/open-infra-lambda-python:latest",
		"python3.13": "ghcr.io/harn3ss/open-infra-lambda-python313:latest",
		"nodejs20":   "ghcr.io/harn3ss/open-infra-lambda-nodejs:latest",
		"nodejs22":   "ghcr.io/harn3ss/open-infra-lambda-nodejs22:latest",
		"dotnet8":    "ghcr.io/harn3ss/open-infra-lambda-dotnet:latest",
	} {
		out := render(t, tmpl, ctx(runtime))
		if !strings.Contains(out, "image: "+image) {
			t.Errorf("runtime %s must render base image %q; got:\n%s", runtime, image, grepCtx(out, "image:"))
		}
	}
}
