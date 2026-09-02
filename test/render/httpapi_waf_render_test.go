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

// CORS renders a Traefik headers middleware carrying the configured policy, and joins the
// router.middlewares chain.
func TestHttpApi_CORS(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["cors"] = map[string]any{"allowOrigins": []any{"https://app.example.com"}, "allowCredentials": true}
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))
	if !strings.Contains(out, "name: httpapi-api-cors") || !strings.Contains(out, "accessControlAllowOriginList") {
		t.Errorf("cors should render a headers middleware; got:\n%s", grepCtx(out, "cors"))
	}
	if !strings.Contains(out, `"https://app.example.com"`) || !strings.Contains(out, "accessControlAllowCredentials: true") {
		t.Errorf("cors should carry the configured origins + credentials; got:\n%s", grepCtx(out, "accessControl"))
	}
	if !strings.Contains(out, "router.middlewares: default-httpapi-api-cors@kubernetescrd") {
		t.Errorf("cors should be in the router.middlewares annotation; got:\n%s", grepCtx(out, "middlewares"))
	}
}

// Rate limit renders a Traefik rateLimit middleware with the configured average/burst.
func TestHttpApi_RateLimit(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["rateLimit"] = map[string]any{"average": 50, "burst": 20}
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))
	if !strings.Contains(out, "name: httpapi-api-ratelimit") || !strings.Contains(out, "average: 50") || !strings.Contains(out, "burst: 20") {
		t.Errorf("rateLimit should render a rateLimit middleware; got:\n%s", grepCtx(out, "rateLimit"))
	}
	if !strings.Contains(out, "router.middlewares: default-httpapi-api-ratelimit@kubernetescrd") {
		t.Errorf("rateLimit should be in the annotation; got:\n%s", grepCtx(out, "middlewares"))
	}
}

// All three middlewares compose into one ordered router.middlewares chain (cors, ratelimit, waf).
func TestHttpApi_MiddlewareChainComposes(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["cors"] = map[string]any{}
	spec["rateLimit"] = map[string]any{}
	spec["waf"] = true
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))
	want := "router.middlewares: default-httpapi-api-cors@kubernetescrd,default-httpapi-api-ratelimit@kubernetescrd,default-httpapi-api-waf@kubernetescrd"
	if !strings.Contains(out, want) {
		t.Errorf("middleware chain should compose cors,ratelimit,waf in order; got:\n%s", grepCtx(out, "middlewares"))
	}
}
