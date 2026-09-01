package render

import (
	"strings"
	"testing"
)

const httpapiCompositionPath = "../../platform/abstraction/httpapi-composition.yaml"

func httpapiCtx(spec map[string]any) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{
				"labels": map[string]any{
					"crossplane.io/claim-name":      "api",
					"crossplane.io/claim-namespace": "default",
				},
			},
		}}},
	}
}

func baseHttpApiSpec() map[string]any {
	return map[string]any{
		"domain": "api.example.com",
		"routes": []any{
			map[string]any{"path": "/", "backend": map[string]any{"name": "fn"}},
		},
	}
}

// waf defaults off: no Coraza middleware, no router.middlewares annotation — existing
// HttpApis are untouched.
func TestHttpApi_WafOffByDefault(t *testing.T) {
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(baseHttpApiSpec()))
	if strings.Contains(out, "kind: Middleware") || strings.Contains(out, "router.middlewares") {
		t.Errorf("waf off must render no middleware; got:\n%s", grepCtx(out, "middleware"))
	}
}

// waf on: a per-namespace Coraza middleware plus the Ingress annotation referencing it.
func TestHttpApi_WafOnRendersCorazaMiddleware(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["waf"] = true
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))

	if !strings.Contains(out, "kind: Middleware") || !strings.Contains(out, "name: httpapi-api-waf") {
		t.Errorf("waf on should render a per-API Middleware; got:\n%s", grepCtx(out, "Middleware"))
	}
	if !strings.Contains(out, "traefik.ingress.kubernetes.io/router.middlewares: default-httpapi-api-waf@kubernetescrd") {
		t.Errorf("waf on should annotate the Ingress with the middleware ref; got:\n%s", grepCtx(out, "middlewares"))
	}
	if !strings.Contains(out, "SecRuleEngine On") || !strings.Contains(out, "@owasp_crs/*.conf") {
		t.Errorf("the middleware should load the OWASP CRS via the coraza plugin; got:\n%s", grepCtx(out, "coraza"))
	}
}
