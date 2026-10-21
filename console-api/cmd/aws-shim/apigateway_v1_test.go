package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRestV1OpFromRequest(t *testing.T) {
	cases := []struct {
		method, path        string
		wantOp, wantAPI     string
		wantRes, wantMethod string
		ok                  bool
	}{
		{"POST", "/restapis", "CreateRestApi", "", "", "", true},
		{"GET", "/restapis", "GetRestApis", "", "", "", true},
		{"GET", "/restapis/abc", "GetRestApi", "abc", "", "", true},
		{"DELETE", "/restapis/abc", "DeleteRestApi", "abc", "", "", true},
		{"GET", "/restapis/abc/resources", "GetResources", "abc", "", "", true},
		{"POST", "/restapis/abc/resources/root1", "CreateResource", "abc", "root1", "", true},
		{"PUT", "/restapis/abc/resources/r1/methods/get", "PutMethod", "abc", "r1", "GET", true},
		{"PUT", "/restapis/abc/resources/r1/methods/post/integration", "PutIntegration", "abc", "r1", "POST", true},
		{"POST", "/restapis/abc/deployments", "CreateDeployment", "abc", "", "", true},
		{"POST", "/restapis/abc/stages", "CreateStage", "abc", "", "", true},
		{"GET", "/restapis/abc/stages", "GetStages", "abc", "", "", true},
		{"PUT", "/restapis/abc/resources/r1/methods/post/responses/200", "PutMethodResponse", "abc", "r1", "POST", true},
		{"POST", "/restapis/abc/models", "CreateModel", "abc", "", "", true},
		{"GET", "/restapis/abc/models", "GetModels", "abc", "", "", true},
		{"POST", "/restapis/abc/requestvalidators", "CreateRequestValidator", "abc", "", "", true},
		{"GET", "/restapis/abc/requestvalidators", "GetRequestValidators", "abc", "", "", true},
		{"GET", "/v2/apis", "", "", "", "", false}, // v2 path is not ours
		{"POST", "/restapis/abc/unknown", "", "", "", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://apigw"+c.path, nil)
		v, ok := restV1OpFromRequest(r)
		if ok != c.ok || v.Op != c.wantOp || v.APIID != c.wantAPI || v.ResourceID != c.wantRes || v.HTTPMethod != c.wantMethod {
			t.Errorf("%s %s: got (%+v,%v) want op=%q api=%q res=%q method=%q ok=%v",
				c.method, c.path, v, ok, c.wantOp, c.wantAPI, c.wantRes, c.wantMethod, c.ok)
		}
	}
}

func TestChildFullPath(t *testing.T) {
	for _, c := range []struct{ parent, part, want string }{
		{"/", "items", "/items"},
		{"", "items", "/items"},
		{"/items", "{id}", "/items/{id}"},
		{"/items/{id}", "sub", "/items/{id}/sub"},
	} {
		if got := childFullPath(c.parent, c.part); got != c.want {
			t.Errorf("childFullPath(%q,%q)=%q want %q", c.parent, c.part, got, c.want)
		}
	}
}

func TestMatchRestRoute(t *testing.T) {
	snap := restSnapshot{
		Resources: []restResource{
			{ID: "root", FullPath: "/"},
			{ID: "items", FullPath: "/items"},
			{ID: "item", FullPath: "/items/{id}"},
			{ID: "proxy", FullPath: "/files/{proxy+}"},
		},
		Methods: []restMethod{
			{ResourceID: "items", HTTPMethod: "GET"},
			{ResourceID: "item", HTTPMethod: "GET"},
			{ResourceID: "item", HTTPMethod: "ANY"},
			{ResourceID: "proxy", HTTPMethod: "ANY"},
			{ResourceID: "root", HTTPMethod: "GET"}, // no integration → must be skipped
		},
		Integrations: []restIntegration{
			{ResourceID: "items", HTTPMethod: "GET", Type: "AWS_PROXY", URI: "listItems"},
			{ResourceID: "item", HTTPMethod: "GET", Type: "AWS_PROXY", URI: "getItem"},
			{ResourceID: "item", HTTPMethod: "ANY", Type: "AWS_PROXY", URI: "anyItem"},
			{ResourceID: "proxy", HTTPMethod: "ANY", Type: "HTTP_PROXY", URI: "https://origin"},
			// note: no integration for root/GET
		},
	}

	// exact static path
	if i, _, _, ok := matchRestRoute(snap, "GET", "/items"); !ok || i.URI != "listItems" {
		t.Errorf("/items GET should match listItems; got %q ok=%v", i.URI, ok)
	}
	// path variable + exact method beats ANY
	i, _, params, ok := matchRestRoute(snap, "GET", "/items/42")
	if !ok || i.URI != "getItem" || params["id"] != "42" {
		t.Errorf("/items/42 GET should match getItem with id=42; got uri=%q params=%v ok=%v", i.URI, params, ok)
	}
	// method with no exact → ANY
	if i, _, _, ok := matchRestRoute(snap, "DELETE", "/items/42"); !ok || i.URI != "anyItem" {
		t.Errorf("/items/42 DELETE should fall to ANY (anyItem); got %q ok=%v", i.URI, ok)
	}
	// greedy proxy+
	if i, _, p, ok := matchRestRoute(snap, "GET", "/files/a/b/c"); !ok || i.URI != "https://origin" || p["proxy"] != "a/b/c" {
		t.Errorf("/files/a/b/c should match the proxy+ HTTP origin; got uri=%q proxy=%q ok=%v", i.URI, p["proxy"], ok)
	}
	// a method whose integration is missing must NOT match
	if _, _, _, ok := matchRestRoute(snap, "GET", "/"); ok {
		t.Errorf("/ GET has a method but no integration — must not match")
	}
	// unknown path
	if _, _, _, ok := matchRestRoute(snap, "GET", "/nope"); ok {
		t.Errorf("/nope must not match")
	}
}

// the mux routes /restapis/* to v1 and everything else to v2.
func TestApigwMux_Routing(t *testing.T) {
	// path classification only (no serve) — assert the mux's path predicate via splitPath.
	if segs := splitPath("/restapis/abc"); len(segs) == 0 || segs[0] != "restapis" {
		t.Fatalf("restapis path should classify to v1")
	}
	if segs := splitPath("/v2/apis"); segs[0] == "restapis" {
		t.Fatalf("v2 path must not classify to v1")
	}
	_ = http.MethodGet
}

func TestResolveCognitoIssuer(t *testing.T) {
	h := &apigwV1Handler{cognitoIssuerBase: "https://cognito-idp.us-east-1.example/"}
	// a Cognito user pool ARN resolves to <base>/<poolId>
	if got := h.resolveCognitoIssuer("arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_abc123"); got != "https://cognito-idp.us-east-1.example/us-east-1_abc123" {
		t.Errorf("pool ARN resolution got %q", got)
	}
	// a bare issuer URL is used as-is (trailing slash trimmed)
	if got := h.resolveCognitoIssuer("https://issuer.example/realm/"); got != "https://issuer.example/realm" {
		t.Errorf("issuer URL got %q", got)
	}
	// unresolvable
	if got := h.resolveCognitoIssuer("not-an-arn-or-url"); got != "" {
		t.Errorf("unresolvable should be empty, got %q", got)
	}
}

func TestHeaderFromIdentitySource(t *testing.T) {
	cases := map[string]string{
		"method.request.header.Authorization": "Authorization",
		"method.request.header.X-Api-Token":   "X-Api-Token",
		"":                                    "Authorization", // default
		"garbage":                             "Authorization", // default
	}
	for in, want := range cases {
		if got := headerFromIdentitySource(in); got != want {
			t.Errorf("headerFromIdentitySource(%q)=%q want %q", in, got, want)
		}
	}
}

func TestRestV1Op_NameAndStatusCode(t *testing.T) {
	// GetModel carries the model name; GetRequestValidator carries the validator id; PutMethodResponse
	// carries the status code.
	r := httptest.NewRequest("GET", "http://apigw/restapis/abc/models/Item", nil)
	if v, ok := restV1OpFromRequest(r); !ok || v.Op != "GetModel" || v.Name != "Item" {
		t.Errorf("GetModel got (%+v,%v)", v, ok)
	}
	r = httptest.NewRequest("GET", "http://apigw/restapis/abc/requestvalidators/val1", nil)
	if v, ok := restV1OpFromRequest(r); !ok || v.Op != "GetRequestValidator" || v.Name != "val1" {
		t.Errorf("GetRequestValidator got (%+v,%v)", v, ok)
	}
	r = httptest.NewRequest("PUT", "http://apigw/restapis/abc/resources/r1/methods/post/responses/201", nil)
	if v, ok := restV1OpFromRequest(r); !ok || v.Op != "PutMethodResponse" || v.StatusCode != "201" || v.HTTPMethod != "POST" {
		t.Errorf("PutMethodResponse got (%+v,%v)", v, ok)
	}
}

func TestRestV1Op_APIKeysAndUsagePlans(t *testing.T) {
	cases := []struct {
		method, path           string
		wantOp, wantKey, wPlan string
		ok                     bool
	}{
		{"POST", "/apikeys", "CreateApiKey", "", "", true},
		{"GET", "/apikeys", "GetApiKeys", "", "", true},
		{"GET", "/apikeys/key1", "GetApiKey", "key1", "", true},
		{"POST", "/usageplans", "CreateUsagePlan", "", "", true},
		{"GET", "/usageplans", "GetUsagePlans", "", "", true},
		{"GET", "/usageplans/up1", "GetUsagePlan", "", "up1", true},
		{"POST", "/usageplans/up1/keys", "CreateUsagePlanKey", "", "up1", true},
		{"GET", "/usageplans/up1/keys", "GetUsagePlanKeys", "", "up1", true},
		{"DELETE", "/apikeys/key1", "", "", "", false}, // delete not modelled yet
		{"POST", "/usageplans/up1/unknown", "", "", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://apigw"+c.path, nil)
		v, ok := restV1OpFromRequest(r)
		if ok != c.ok || v.Op != c.wantOp || v.KeyID != c.wantKey || v.PlanID != c.wPlan {
			t.Errorf("%s %s: got (%+v,%v) want op=%q key=%q plan=%q ok=%v",
				c.method, c.path, v, ok, c.wantOp, c.wantKey, c.wPlan, c.ok)
		}
	}
}

func TestValidateRestRequest(t *testing.T) {
	jsonSchema := func(s string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("bad schema: %v", err)
		}
		return m
	}
	snap := restSnapshot{
		Validators: []restRequestValidator{
			{ID: "v-all", ValidateRequestBody: true, ValidateRequestParameters: true},
			{ID: "v-params", ValidateRequestParameters: true},
			{ID: "v-body", ValidateRequestBody: true},
		},
		Models: []restModel{
			{Name: "Item", ContentType: "application/json", Schema: jsonSchema(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`)},
		},
	}
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
		}
		return h
	}
	q := func(raw string) url.Values { v, _ := url.ParseQuery(raw); return v }

	// no validator → always ok
	if reason, ok := validateRestRequest(snap, restMethod{}, "application/json", q(""), hdr(), nil, []byte(`{}`)); !ok {
		t.Errorf("no validator should pass, got %q", reason)
	}
	// validator not in the snapshot → ok (additive; never a silent block)
	if _, ok := validateRestRequest(snap, restMethod{RequestValidatorID: "ghost"}, "application/json", q(""), hdr(), nil, nil); !ok {
		t.Error("missing validator should pass")
	}

	// parameters: missing required query + header → 400 listing the short names, sorted
	mp := restMethod{RequestValidatorID: "v-params", RequestParameters: map[string]bool{
		"method.request.querystring.q": true, "method.request.header.X-Tok": true}}
	if reason, ok := validateRestRequest(snap, mp, "application/json", q(""), hdr(), nil, nil); ok || reason != "Missing required request parameters: [X-Tok, q]" {
		t.Errorf("missing params got ok=%v reason=%q", ok, reason)
	}
	// all present + non-blank → pass
	if _, ok := validateRestRequest(snap, mp, "application/json", q("q=1"), hdr("X-Tok", "t"), nil, nil); !ok {
		t.Error("all required params present should pass")
	}
	// a blank query value counts as missing (AWS: present but not blank)
	if reason, ok := validateRestRequest(snap, mp, "application/json", q("q="), hdr("X-Tok", "t"), nil, nil); ok || reason != "Missing required request parameters: [q]" {
		t.Errorf("blank q should be missing; got ok=%v reason=%q", ok, reason)
	}
	// path parameter satisfied from the matched route
	mpath := restMethod{RequestValidatorID: "v-params", RequestParameters: map[string]bool{"method.request.path.id": true}}
	if _, ok := validateRestRequest(snap, mpath, "application/json", q(""), hdr(), map[string]string{"id": "42"}, nil); !ok {
		t.Error("present path param should pass")
	}
	// a non-required parameter is ignored when absent
	mopt := restMethod{RequestValidatorID: "v-params", RequestParameters: map[string]bool{"method.request.querystring.opt": false}}
	if _, ok := validateRestRequest(snap, mopt, "application/json", q(""), hdr(), nil, nil); !ok {
		t.Error("optional param absent should pass")
	}

	// body: invalid against the model → "Invalid request body"
	mb := restMethod{RequestValidatorID: "v-body", RequestModels: map[string]string{"application/json": "Item"}}
	if reason, ok := validateRestRequest(snap, mb, "application/json", q(""), hdr(), nil, []byte(`{"name":5}`)); ok || reason != "Invalid request body" {
		t.Errorf("bad body got ok=%v reason=%q", ok, reason)
	}
	// valid body → pass (also proves charset params are stripped)
	if _, ok := validateRestRequest(snap, mb, "application/json; charset=utf-8", q(""), hdr(), nil, []byte(`{"name":"ok"}`)); !ok {
		t.Error("valid body should pass")
	}
	// empty body with a model → invalid (AWS rejects a missing body against a model)
	if _, ok := validateRestRequest(snap, mb, "application/json", q(""), hdr(), nil, nil); ok {
		t.Error("empty body against a model should be invalid")
	}
	// a content type with no mapped model → body validation skipped, even for garbage (AWS: no matching
	// content type → validation not performed)
	if _, ok := validateRestRequest(snap, mb, "text/plain", q(""), hdr(), nil, []byte(`not json`)); !ok {
		t.Error("unmapped content type should skip body validation")
	}

	// precedence: parameters are checked before the body — a bad body AND a missing param reports params
	mboth := restMethod{RequestValidatorID: "v-all", RequestModels: map[string]string{"application/json": "Item"},
		RequestParameters: map[string]bool{"method.request.querystring.q": true}}
	if reason, ok := validateRestRequest(snap, mboth, "application/json", q(""), hdr(), nil, []byte(`{"name":5}`)); ok || reason != "Missing required request parameters: [q]" {
		t.Errorf("params should be checked before body; got ok=%v reason=%q", ok, reason)
	}
}

func TestEnforceMethodAuthorizer_FailClosed(t *testing.T) {
	h := &apigwV1Handler{}
	// AWS_IAM is honestly refused (403)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if h.enforceMethodAuthorizer(rec, req, restSnapshot{}, "AWS_IAM", "", "rid") {
		t.Error("AWS_IAM must not authorize")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("AWS_IAM want 403 got %d", rec.Code)
	}
	// COGNITO_USER_POOLS referencing an authorizer absent from the snapshot → 401 fail-closed
	rec = httptest.NewRecorder()
	if h.enforceMethodAuthorizer(rec, req, restSnapshot{}, "COGNITO_USER_POOLS", "missing", "rid") {
		t.Error("missing authorizer must not authorize")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("missing authorizer want 401 got %d", rec.Code)
	}
}
