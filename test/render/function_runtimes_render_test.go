package render

import (
	"strings"
	"testing"
)

// kind: Function spec.code.runtime maps each managed runtime to its runtime base image. This locks
// the full set — including nodejs22, nodejs24 and python3.13 — so functions on those runtimes run.
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
		"nodejs24":   "ghcr.io/harn3ss/open-infra-lambda-nodejs24:latest",
		"nodejs16":   "ghcr.io/harn3ss/open-infra-lambda-nodejs16:latest",
		"nodejs18":   "ghcr.io/harn3ss/open-infra-lambda-nodejs18:latest",
		"python3.8":  "ghcr.io/harn3ss/open-infra-lambda-python38:latest",
		"python3.9":  "ghcr.io/harn3ss/open-infra-lambda-python39:latest",
		"python3.10": "ghcr.io/harn3ss/open-infra-lambda-python310:latest",
		"python3.11": "ghcr.io/harn3ss/open-infra-lambda-python311:latest",
		"python3.14": "ghcr.io/harn3ss/open-infra-lambda-python314:latest",
		"dotnet8":    "ghcr.io/harn3ss/open-infra-lambda-dotnet:latest",
		"dotnet10":   "ghcr.io/harn3ss/open-infra-lambda-dotnet10:latest",
	} {
		out := render(t, tmpl, ctx(runtime))
		if !strings.Contains(out, `image: "`+image) {
			t.Errorf("runtime %s must render base image %q; got:\n%s", runtime, image, grepCtx(out, "image:"))
		}
	}
}
