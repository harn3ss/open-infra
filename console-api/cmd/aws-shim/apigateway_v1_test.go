package main

import (
	"net/http"
	"net/http/httptest"
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
	if i, _, _, _, ok := matchRestRoute(snap, "GET", "/items"); !ok || i.URI != "listItems" {
		t.Errorf("/items GET should match listItems; got %q ok=%v", i.URI, ok)
	}
	// path variable + exact method beats ANY
	i, params, _, _, ok := matchRestRoute(snap, "GET", "/items/42")
	if !ok || i.URI != "getItem" || params["id"] != "42" {
		t.Errorf("/items/42 GET should match getItem with id=42; got uri=%q params=%v ok=%v", i.URI, params, ok)
	}
	// method with no exact → ANY
	if i, _, _, _, ok := matchRestRoute(snap, "DELETE", "/items/42"); !ok || i.URI != "anyItem" {
		t.Errorf("/items/42 DELETE should fall to ANY (anyItem); got %q ok=%v", i.URI, ok)
	}
	// greedy proxy+
	if i, p, _, _, ok := matchRestRoute(snap, "GET", "/files/a/b/c"); !ok || i.URI != "https://origin" || p["proxy"] != "a/b/c" {
		t.Errorf("/files/a/b/c should match the proxy+ HTTP origin; got uri=%q proxy=%q ok=%v", i.URI, p["proxy"], ok)
	}
	// a method whose integration is missing must NOT match
	if _, _, _, _, ok := matchRestRoute(snap, "GET", "/"); ok {
		t.Errorf("/ GET has a method but no integration — must not match")
	}
	// unknown path
	if _, _, _, _, ok := matchRestRoute(snap, "GET", "/nope"); ok {
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
