package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAgwOpFromRequest(t *testing.T) {
	cases := []struct {
		method, path string
		op, apiID    string
		ok           bool
	}{
		{"POST", "/v2/apis", "CreateApi", "", true},
		{"GET", "/v2/apis", "GetApis", "", true},
		{"GET", "/v2/apis/abc123", "GetApi", "abc123", true},
		{"DELETE", "/v2/apis/abc123", "DeleteApi", "abc123", true},
		{"POST", "/v2/apis/abc123/routes", "CreateRoute", "abc123", true},
		{"GET", "/v2/apis/abc123/routes", "GetRoutes", "abc123", true},
		{"POST", "/v2/apis/abc123/integrations", "CreateIntegration", "abc123", true},
		{"POST", "/v2/apis/abc123/stages", "CreateStage", "abc123", true},
		{"GET", "/v2/apis/abc123/stages", "GetStages", "abc123", true},
		{"POST", "/v2/apis/abc123/deployments", "CreateDeployment", "abc123", true},
		{"POST", "/v2/apis/abc123/authorizers", "CreateAuthorizer", "abc123", true},
		{"GET", "/v1/apis", "", "", false},
		{"PUT", "/v2/apis/abc123/routes", "", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		op, apiID, ok := agwOpFromRequest(r)
		if op != c.op || apiID != c.apiID || ok != c.ok {
			t.Errorf("%s %s => (%q,%q,%v), want (%q,%q,%v)", c.method, c.path, op, apiID, ok, c.op, c.apiID, c.ok)
		}
	}
}

func TestMatchRoutePrecedence(t *testing.T) {
	routes := []agwRoute{
		{ID: "r1", RouteKey: "POST /items/{id}"},
		{ID: "r2", RouteKey: "ANY /{proxy+}"},
		{ID: "r3", RouteKey: "GET /items/list"},
		{ID: "r4", RouteKey: "$default"},
	}
	// exact static beats variable
	if m, _, ok := matchRoute(routes, "GET", "/items/list"); !ok || m.ID != "r3" {
		t.Errorf("GET /items/list should match r3 (static), got %v ok=%v", m.ID, ok)
	}
	// path variable
	m, params, ok := matchRoute(routes, "POST", "/items/42")
	if !ok || m.ID != "r1" {
		t.Fatalf("POST /items/42 should match r1, got %v ok=%v", m.ID, ok)
	}
	if params["id"] != "42" {
		t.Errorf("pathParameters id = %q, want 42", params["id"])
	}
	// greedy proxy for something no static/var route covers
	m, params, ok = matchRoute(routes, "DELETE", "/other/deep/path")
	if !ok || m.ID != "r2" {
		t.Fatalf("DELETE /other/deep/path should match r2 (greedy ANY), got %v ok=%v", m.ID, ok)
	}
	if params["proxy"] != "other/deep/path" {
		t.Errorf("proxy param = %q, want other/deep/path", params["proxy"])
	}
	// $default fallback when nothing else matches (no greedy present)
	routes2 := []agwRoute{{ID: "s1", RouteKey: "GET /a"}, {ID: "d", RouteKey: "$default"}}
	if m, _, ok := matchRoute(routes2, "POST", "/z"); !ok || m.ID != "d" {
		t.Errorf("unmatched should fall to $default, got %v ok=%v", m.ID, ok)
	}
	// no match at all
	routes3 := []agwRoute{{ID: "s1", RouteKey: "GET /a"}}
	if _, _, ok := matchRoute(routes3, "POST", "/z"); ok {
		t.Error("POST /z should not match GET /a with no default")
	}
}

func TestMatchRouteMethodExactBeatsAny(t *testing.T) {
	routes := []agwRoute{
		{ID: "any", RouteKey: "ANY /items/{id}"},
		{ID: "post", RouteKey: "POST /items/{id}"},
	}
	if m, _, ok := matchRoute(routes, "POST", "/items/9"); !ok || m.ID != "post" {
		t.Errorf("POST should prefer the exact-method route, got %v", m.ID)
	}
	if m, _, ok := matchRoute(routes, "GET", "/items/9"); !ok || m.ID != "any" {
		t.Errorf("GET should fall to the ANY route, got %v", m.ID)
	}
}

func TestFunctionFromURI(t *testing.T) {
	cases := map[string]string{
		"my-func": "my-func",
		"arn:aws:lambda:us-east-1:open-infra:function:my-func":      "my-func",
		"arn:aws:lambda:us-east-1:open-infra:function:my-func:PROD": "my-func",
	}
	for in, want := range cases {
		if got := functionFromURI(in); got != want {
			t.Errorf("functionFromURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidRouteKey(t *testing.T) {
	good := []string{"GET /items", "POST /items/{id}", "ANY /{proxy+}", "DELETE /a/b/c"}
	for _, g := range good {
		if !validRouteKey(g) {
			t.Errorf("validRouteKey(%q) should be true", g)
		}
	}
	bad := []string{"items", "GET items", "FOO /x", "/items", ""}
	for _, b := range bad {
		if validRouteKey(b) {
			t.Errorf("validRouteKey(%q) should be false", b)
		}
	}
}

func TestBuildProxyEvent20(t *testing.T) {
	r := httptest.NewRequest("POST", "/items/42?q=1&q=2&x=y", strings.NewReader(`{"hello":"world"}`))
	r.Header.Set("Content-Type", "application/json")
	ev := buildProxyEvent("2.0", r, "abc123", "$default", "POST /items/{id}", "/items/42", map[string]string{"id": "42"}, []byte(`{"hello":"world"}`), "req-1")
	if ev["version"] != "2.0" {
		t.Fatalf("version = %v", ev["version"])
	}
	if ev["rawPath"] != "/items/42" {
		t.Errorf("rawPath = %v", ev["rawPath"])
	}
	if ev["rawQueryString"] != "q=1&q=2&x=y" {
		t.Errorf("rawQueryString = %v", ev["rawQueryString"])
	}
	pp, _ := ev["pathParameters"].(map[string]string)
	if pp["id"] != "42" {
		t.Errorf("pathParameters.id = %v", pp["id"])
	}
	rc, _ := ev["requestContext"].(map[string]any)
	httpCtx, _ := rc["http"].(map[string]any)
	if httpCtx["method"] != "POST" {
		t.Errorf("requestContext.http.method = %v", httpCtx["method"])
	}
	if ev["body"] != `{"hello":"world"}` {
		t.Errorf("body = %v", ev["body"])
	}
	qs, _ := ev["queryStringParameters"].(map[string]string)
	if qs["q"] != "1,2" {
		t.Errorf("queryStringParameters.q = %q, want 1,2", qs["q"])
	}
}

func TestBuildProxyEvent10(t *testing.T) {
	r := httptest.NewRequest("GET", "/items/7", nil)
	ev := buildProxyEvent("1.0", r, "abc123", "prod", "GET /items/{id}", "/items/7", map[string]string{"id": "7"}, nil, "req-2")
	if ev["version"] != "1.0" {
		t.Fatalf("version = %v", ev["version"])
	}
	if ev["resource"] != "/items/{id}" {
		t.Errorf("resource = %v, want /items/{id}", ev["resource"])
	}
	if ev["httpMethod"] != "GET" {
		t.Errorf("httpMethod = %v", ev["httpMethod"])
	}
	if _, ok := ev["multiValueHeaders"]; !ok {
		t.Error("1.0 event should carry multiValueHeaders")
	}
}

func TestWriteProxyResponseStructured(t *testing.T) {
	w := httptest.NewRecorder()
	out := `{"statusCode":201,"headers":{"X-Test":"yes"},"body":"created"}`
	writeProxyResponse(w, "2.0", 200, []byte(out), "req-3")
	if w.Code != 201 {
		t.Errorf("status = %d, want 201", w.Code)
	}
	if w.Header().Get("X-Test") != "yes" {
		t.Errorf("X-Test header not propagated")
	}
	if w.Body.String() != "created" {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestWriteProxyResponseSimplified20(t *testing.T) {
	w := httptest.NewRecorder()
	out := `{"message":"ok"}`
	writeProxyResponse(w, "2.0", 200, []byte(out), "req-4")
	if w.Code != 200 {
		t.Errorf("simplified status = %d, want 200", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || m["message"] != "ok" {
		t.Errorf("simplified body should be the whole payload, got %q", w.Body.String())
	}
}

func TestWriteProxyResponse10RequiresStructured(t *testing.T) {
	w := httptest.NewRecorder()
	writeProxyResponse(w, "1.0", 200, []byte(`{"message":"ok"}`), "req-5")
	if w.Code != 502 {
		t.Errorf("1.0 bare payload should be 502, got %d", w.Code)
	}
}

func TestWriteProxyResponseUpstreamError(t *testing.T) {
	w := httptest.NewRecorder()
	writeProxyResponse(w, "2.0", 503, []byte(`upstream boom`), "req-6")
	if w.Code != 502 {
		t.Errorf("upstream HTTP error should map to 502, got %d", w.Code)
	}
}

func TestInvokeTargetPrefix(t *testing.T) {
	h := &apigwHandler{}
	r := httptest.NewRequest("POST", "/_apigw/abc123/items/42", nil)
	apiID, path, ok := h.invokeTarget(r)
	if !ok || apiID != "abc123" || path != "/items/42" {
		t.Errorf("invokeTarget(prefix) = (%q,%q,%v)", apiID, path, ok)
	}
	// root path
	r2 := httptest.NewRequest("GET", "/_apigw/xyz", nil)
	apiID, path, ok = h.invokeTarget(r2)
	if !ok || apiID != "xyz" || path != "/" {
		t.Errorf("invokeTarget(root) = (%q,%q,%v)", apiID, path, ok)
	}
	// control-plane path is NOT an invoke
	r3 := httptest.NewRequest("POST", "/v2/apis", nil)
	if _, _, ok := h.invokeTarget(r3); ok {
		t.Error("/v2/apis must not be treated as an invoke")
	}
}

func TestInvokeTargetExecuteApiHost(t *testing.T) {
	h := &apigwHandler{}
	r := httptest.NewRequest("GET", "/items/9", nil)
	r.Host = "abc123.execute-api.us-east-1.amazonaws.com"
	apiID, path, ok := h.invokeTarget(r)
	if !ok || apiID != "abc123" || path != "/items/9" {
		t.Errorf("invokeTarget(execute-api host) = (%q,%q,%v)", apiID, path, ok)
	}
}

func TestFirstSeg(t *testing.T) {
	cases := []struct{ in, seg, rest string }{
		{"/items/42", "items", "/42"},
		{"/items", "items", "/"},
		{"/", "", "/"},
	}
	for _, c := range cases {
		seg, rest := firstSeg(c.in)
		if seg != c.seg || rest != c.rest {
			t.Errorf("firstSeg(%q) = (%q,%q), want (%q,%q)", c.in, seg, rest, c.seg, c.rest)
		}
	}
}
