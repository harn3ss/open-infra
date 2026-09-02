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

// Base: a Traefik IngressRoute (not a plain Ingress — that can't match methods) with a
// Host+PathPrefix match onto the backend Service, plus a cert-manager Certificate for the TLS
// secret the route references (tls defaults on).
func TestHttpApi_BaseIngressRoute(t *testing.T) {
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(baseHttpApiSpec()))
	if !strings.Contains(out, "kind: IngressRoute") {
		t.Errorf("should render a Traefik IngressRoute; got:\n%s", grepCtx(out, "kind:"))
	}
	if strings.Contains(out, "kind: Ingress\n") {
		t.Errorf("should NOT render a plain networking Ingress; got:\n%s", grepCtx(out, "kind: Ingress"))
	}
	if !strings.Contains(out, "Host(`api.example.com`) && PathPrefix(`/`)") {
		t.Errorf("route match should be Host + PathPrefix; got:\n%s", grepCtx(out, "match"))
	}
	if !strings.Contains(out, "name: fn") {
		t.Errorf("route should target the backend service; got:\n%s", grepCtx(out, "services"))
	}
	if !strings.Contains(out, "kind: Certificate") || !strings.Contains(out, "secretName: httpapi-api-tls") {
		t.Errorf("tls (default) should render a cert-manager Certificate into httpapi-api-tls; got:\n%s", grepCtx(out, "Certificate"))
	}
}

// tls:false → no Certificate, the web entrypoint, and no tls block.
func TestHttpApi_TLSOff(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["tls"] = false
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))
	if strings.Contains(out, "kind: Certificate") {
		t.Errorf("tls:false must not render a Certificate; got:\n%s", grepCtx(out, "Certificate"))
	}
	if !strings.Contains(out, "entryPoints: [ web ]") {
		t.Errorf("tls:false should use the web entrypoint; got:\n%s", grepCtx(out, "entryPoints"))
	}
}

// Per-route HTTP methods: the match gains an OR-group of Method() clauses. This is the gap a
// plain Ingress cannot express.
func TestHttpApi_PerRouteMethods(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["routes"] = []any{
		map[string]any{"path": "/users", "methods": []any{"GET", "POST"}, "backend": map[string]any{"name": "fn"}},
	}
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))
	if !strings.Contains(out, "PathPrefix(`/users`) && (Method(`GET`) || Method(`POST`))") {
		t.Errorf("route should match the listed methods; got:\n%s", grepCtx(out, "match"))
	}
}

// pathType Exact → Path() (whole-path), not PathPrefix.
func TestHttpApi_ExactPath(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["routes"] = []any{
		map[string]any{"path": "/health", "pathType": "Exact", "backend": map[string]any{"name": "fn"}},
	}
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))
	if !strings.Contains(out, "Path(`/health`)") || strings.Contains(out, "PathPrefix(`/health`)") {
		t.Errorf("Exact should render Path(), not PathPrefix(); got:\n%s", grepCtx(out, "match"))
	}
}

// waf defaults off: no Coraza middleware and no middleware refs on the route.
func TestHttpApi_WafOffByDefault(t *testing.T) {
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(baseHttpApiSpec()))
	if strings.Contains(out, "httpapi-api-waf") || strings.Contains(out, "middlewares:") {
		t.Errorf("waf off (and no other middleware) must render no middleware refs; got:\n%s", grepCtx(out, "middleware"))
	}
}

// waf on: a per-API Coraza middleware plus a route middleware ref to it.
func TestHttpApi_WafOnRendersCorazaMiddleware(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["waf"] = true
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))
	if !strings.Contains(out, "kind: Middleware") || !strings.Contains(out, "name: httpapi-api-waf") {
		t.Errorf("waf on should render a per-API Middleware; got:\n%s", grepCtx(out, "Middleware"))
	}
	if !strings.Contains(out, "middlewares:") {
		t.Errorf("waf on should attach a middleware ref to the route; got:\n%s", grepCtx(out, "middlewares"))
	}
	if !strings.Contains(out, "SecRuleEngine On") || !strings.Contains(out, "@owasp_crs/*.conf") {
		t.Errorf("the middleware should load the OWASP CRS via the coraza plugin; got:\n%s", grepCtx(out, "coraza"))
	}
}

// CORS renders a Traefik headers middleware carrying the configured policy, referenced by the route.
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
}

// JWT authorizer: a per-API JWT middleware whose keys/issuer come from the configured issuer,
// referenced by the route.
func TestHttpApi_Authorizer(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["authorizer"] = map[string]any{"jwt": map[string]any{
		"issuer":   "https://pool.example/realms/app",
		"audience": []any{"my-api"},
	}}
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))
	if !strings.Contains(out, "name: httpapi-api-authorizer") {
		t.Errorf("authorizer should render a JWT middleware; got:\n%s", grepCtx(out, "authorizer"))
	}
	if !strings.Contains(out, `"https://pool.example/realms/app/.well-known/jwks.json"`) {
		t.Errorf("authorizer should fetch keys from the issuer's JWKS; got:\n%s", grepCtx(out, "jwks"))
	}
	if !strings.Contains(out, `"my-api"`) {
		t.Errorf("authorizer should carry the configured audience; got:\n%s", grepCtx(out, "Audiences"))
	}
	// referenced by the route (name appears both in the ref list and the middleware def → >=2)
	if strings.Count(out, "name: httpapi-api-authorizer") < 2 {
		t.Errorf("authorizer middleware should be referenced by the route; got:\n%s", grepCtx(out, "authorizer"))
	}
}

// All four middlewares compose in order: cors, authorizer, ratelimit, waf.
func TestHttpApi_MiddlewareChainOrder(t *testing.T) {
	spec := baseHttpApiSpec()
	spec["cors"] = map[string]any{}
	spec["authorizer"] = map[string]any{"jwt": map[string]any{"issuer": "https://i"}}
	spec["rateLimit"] = map[string]any{}
	spec["waf"] = true
	tmpl := extractInlineTemplate(t, httpapiCompositionPath)
	out := render(t, tmpl, httpapiCtx(spec))
	iCors := strings.Index(out, "name: httpapi-api-cors")
	iAuth := strings.Index(out, "name: httpapi-api-authorizer")
	iRate := strings.Index(out, "name: httpapi-api-ratelimit")
	iWaf := strings.Index(out, "name: httpapi-api-waf")
	if !(iCors >= 0 && iCors < iAuth && iAuth < iRate && iRate < iWaf) {
		t.Errorf("route middleware chain should be cors, authorizer, ratelimit, waf; got positions cors=%d auth=%d rate=%d waf=%d\n%s",
			iCors, iAuth, iRate, iWaf, grepCtx(out, "middlewares"))
	}
}
