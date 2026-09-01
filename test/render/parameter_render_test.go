package render

import (
	"strings"
	"testing"
)

const parameterCompositionPath = "../../platform/abstraction/parameter-composition.yaml"

func parameterCtx(spec map[string]any) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"labels": map[string]any{
					"crossplane.io/claim-name":      "dbhost",
					"crossplane.io/claim-namespace": "shop",
				},
			},
		}}},
	}
}

// The spec-mirror ConfigMap carries the path/type/tier metadata for the console but
// must NEVER carry the value (the value lives in the CR and, materialized, in the
// namespace Secret — the reconciler, not this ConfigMap, moves it).
func TestParameter_SpecMirrorOmitsValue(t *testing.T) {
	tmpl := extractInlineTemplate(t, parameterCompositionPath)
	out := render(t, tmpl, parameterCtx(map[string]any{
		"path": "/app/db/host", "value": "supersecret-hostname", "type": "SecureString",
	}))

	if strings.Contains(out, "supersecret-hostname") {
		t.Errorf("the value must NEVER appear in the spec-mirror ConfigMap; got:\n%s", out)
	}
	if !strings.Contains(out, `path: "/app/db/host"`) {
		t.Errorf("the spec mirror should carry the path; got:\n%s", grepCtx(out, "path"))
	}
	if !strings.Contains(out, `type: "SecureString"`) {
		t.Errorf("the spec mirror should carry the type; got:\n%s", grepCtx(out, "type"))
	}
	if !strings.Contains(out, "ready: true") {
		t.Errorf("the composite should report ready; got:\n%s", grepCtx(out, "ready"))
	}
}
