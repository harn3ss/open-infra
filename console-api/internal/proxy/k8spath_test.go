package proxy

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParseRequest(t *testing.T) {
	cases := []struct {
		method, path, query string
		want                Request
		ok                  bool
	}{
		{"GET", "/api/v1/namespaces/team/pods", "", Request{Verb: "list", Version: "v1", Resource: "pods", Namespace: "team"}, true},
		{"GET", "/api/v1/namespaces/team/pods/web-1/log", "", Request{Verb: "get", Version: "v1", Resource: "pods", Subresource: "log", Namespace: "team", Name: "web-1"}, true},
		{"GET", "/api/v1/nodes", "watch=true", Request{Verb: "watch", Version: "v1", Resource: "nodes"}, true},
		{"GET", "/apis/openinfra.dev/v1/namespaces/team/buckets/b", "", Request{Verb: "get", Group: "openinfra.dev", Version: "v1", Resource: "buckets", Namespace: "team", Name: "b"}, true},
		{"POST", "/apis/openinfra.dev/v1/namespaces/team/buckets", "", Request{Verb: "create", Group: "openinfra.dev", Version: "v1", Resource: "buckets", Namespace: "team"}, true},
		{"PATCH", "/apis/openinfra.dev/v1/namespaces/team/buckets/b", "", Request{Verb: "patch", Group: "openinfra.dev", Version: "v1", Resource: "buckets", Namespace: "team", Name: "b"}, true},
		{"PUT", "/apis/openinfra.dev/v1/namespaces/team/buckets/b/status", "", Request{Verb: "update", Group: "openinfra.dev", Version: "v1", Resource: "buckets", Subresource: "status", Namespace: "team", Name: "b"}, true},
		{"DELETE", "/apis/openinfra.dev/v1/namespaces/team/buckets/b", "", Request{Verb: "delete", Group: "openinfra.dev", Version: "v1", Resource: "buckets", Namespace: "team", Name: "b"}, true},
		{"DELETE", "/apis/openinfra.dev/v1/namespaces/team/buckets", "", Request{Verb: "deletecollection", Group: "openinfra.dev", Version: "v1", Resource: "buckets", Namespace: "team"}, true},
		{"GET", "/apis/openinfra.dev/v1/buckets", "", Request{Verb: "list", Group: "openinfra.dev", Version: "v1", Resource: "buckets"}, true},
		{"GET", "/api/v1/namespaces/team", "", Request{Verb: "get", Version: "v1", Resource: "namespaces", Namespace: "team", Name: "team"}, true},
		{"PUT", "/api/v1/namespaces/team/finalize", "", Request{Verb: "update", Version: "v1", Resource: "namespaces", Subresource: "finalize", Namespace: "team", Name: "team"}, true},
		{"GET", "/apis", "", Request{Verb: "get", Discovery: true}, true},
		{"GET", "/apis/openinfra.dev/v1", "", Request{Verb: "get", Discovery: true}, true},
		{"GET", "/api/v1", "", Request{Verb: "get", Discovery: true}, true},
		{"GET", "/version", "", Request{Verb: "get", Discovery: true}, true},
		{"GET", "/openapi/v3/apis/openinfra.dev/v1", "", Request{Verb: "get", Discovery: true}, true},
		{"GET", "/metrics", "", Request{}, false},
		{"GET", "/api/v1/namespaces/team/pods/a/b/c", "", Request{}, false},
		{"OPTIONS", "/api/v1/pods", "", Request{}, false},
	}
	for _, c := range cases {
		q, _ := url.ParseQuery(c.query)
		got, ok := ParseRequest(c.method, c.path, q)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s %s?%s = %+v, %v; want %+v, %v", c.method, c.path, c.query, got, ok, c.want, c.ok)
		}
	}
	if (Request{Resource: "pods", Subresource: "log"}).ResourcePath() != "pods/log" {
		t.Error("ResourcePath must join the subresource")
	}
	_ = http.MethodGet
}
