package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// Stage-2 AppSync management (forward-map §8): the translator (AWS verb → patch on the neutral
// GraphQLApi object) is pure and carries the weight of the tests; the handler adds the front-door +
// negative, exactly like the other shim services. Per-verb graduation: only the verbs proven here are
// claimed — everything else answers an honest NotImplemented.

// fakeAPIStore is an in-memory GraphQLApi store keyed by ns/name.
type fakeAPIStore struct{ objs map[string]map[string]any }

func newFakeAPIStore() *fakeAPIStore { return &fakeAPIStore{objs: map[string]map[string]any{}} }
func (s *fakeAPIStore) seed(ns, name string) {
	s.objs[ns+"/"+name] = map[string]any{"spec": map[string]any{}}
}
func (s *fakeAPIStore) Get(_ context.Context, ns, name string) (map[string]any, error) {
	o, ok := s.objs[ns+"/"+name]
	if !ok {
		return nil, context.Canceled // any error → NotFound in the handler
	}
	return o, nil
}
func (s *fakeAPIStore) Update(_ context.Context, ns, name string, obj map[string]any) error {
	s.objs[ns+"/"+name] = obj
	return nil
}
func (s *fakeAPIStore) resolvers(ns, name string) []any {
	spec, _ := s.objs[ns+"/"+name]["spec"].(map[string]any)
	l, _ := spec["resolvers"].([]any)
	return l
}

// --- translator unit tests (pure) ---

func TestApplyManagement_CreateResolverVTL(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{}}
	p := mgmtParams{apiID: "team-a.notes", ns: "team-a", name: "notes", typeName: "Query", fieldName: "getTodo",
		body: map[string]any{"fieldName": "getTodo", "dataSourceName": "todos",
			"requestMappingTemplate": "REQ", "responseMappingTemplate": "RESP"}}
	if _, err := applyManagement(obj, "CreateResolver", p); err != nil {
		t.Fatal(err)
	}
	r := obj["spec"].(map[string]any)["resolvers"].([]any)[0].(map[string]any)
	if r["type"] != "Query" || r["field"] != "getTodo" || r["dataSource"] != "todos" ||
		r["runtime"] != "appsync-vtl" || r["request"] != "REQ" || r["response"] != "RESP" {
		t.Fatalf("CreateResolver did not map to the neutral entry: %v", r)
	}
}

func TestApplyManagement_CreateResolverJS(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{}}
	p := mgmtParams{typeName: "Mutation", fieldName: "put",
		body: map[string]any{"runtime": map[string]any{"name": "APPSYNC_JS"}, "code": "export function request(){}"}}
	if _, err := applyManagement(obj, "CreateResolver", p); err != nil {
		t.Fatal(err)
	}
	r := obj["spec"].(map[string]any)["resolvers"].([]any)[0].(map[string]any)
	if r["runtime"] != "appsync-js" || r["request"] != "export function request(){}" {
		t.Fatalf("APPSYNC_JS did not map to appsync-js with code in request: %v", r)
	}
}

func TestApplyManagement_UpdateReplacesNotDuplicates(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{}}
	base := mgmtParams{typeName: "Query", fieldName: "getTodo", body: map[string]any{"requestMappingTemplate": "v1"}}
	_, _ = applyManagement(obj, "CreateResolver", base)
	upd := mgmtParams{typeName: "Query", fieldName: "getTodo", body: map[string]any{"requestMappingTemplate": "v2"}}
	_, _ = applyManagement(obj, "UpdateResolver", upd)
	list := obj["spec"].(map[string]any)["resolvers"].([]any)
	if len(list) != 1 {
		t.Fatalf("update must replace by (type,field), got %d entries", len(list))
	}
	if list[0].(map[string]any)["request"] != "v2" {
		t.Fatalf("update did not take effect: %v", list[0])
	}
}

func TestApplyManagement_DeleteResolver(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{}}
	_, _ = applyManagement(obj, "CreateResolver", mgmtParams{typeName: "Query", fieldName: "a", body: map[string]any{}})
	_, _ = applyManagement(obj, "CreateResolver", mgmtParams{typeName: "Query", fieldName: "b", body: map[string]any{}})
	_, _ = applyManagement(obj, "DeleteResolver", mgmtParams{typeName: "Query", fieldName: "a"})
	list := obj["spec"].(map[string]any)["resolvers"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["field"] != "b" {
		t.Fatalf("delete removed the wrong entry: %v", list)
	}
}

func TestApplyManagement_CreateDataSourceTypeMap(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{}}
	_, err := applyManagement(obj, "CreateDataSource", mgmtParams{dsName: "todos", body: map[string]any{"type": "AMAZON_DYNAMODB"}})
	if err != nil {
		t.Fatal(err)
	}
	ds := obj["spec"].(map[string]any)["dataSources"].([]any)[0].(map[string]any)
	if ds["name"] != "todos" || ds["type"] != "dynamodb" {
		t.Fatalf("AMAZON_DYNAMODB did not map to dynamodb: %v", ds)
	}
}

func TestSplitAPIID(t *testing.T) {
	if ns, name := splitAPIID("team-a.notes"); ns != "team-a" || name != "notes" {
		t.Fatalf("ns.name split wrong: %s/%s", ns, name)
	}
	if ns, name := splitAPIID("notes"); ns != "default" || name != "notes" {
		t.Fatalf("bare name should default namespace: %s/%s", ns, name)
	}
}

func TestParseManagement_Verbs(t *testing.T) {
	cases := []struct{ method, path, want string }{
		{"POST", "/v1/apis/team-a.notes/types/Query/resolvers", "CreateResolver"},
		{"POST", "/v1/apis/team-a.notes/types/Query/resolvers/getTodo", "UpdateResolver"},
		{"DELETE", "/v1/apis/team-a.notes/types/Query/resolvers/getTodo", "DeleteResolver"},
		{"GET", "/v1/apis/team-a.notes/types/Query/resolvers/getTodo", "GetResolver"},
		{"POST", "/v1/apis/team-a.notes/datasources", "CreateDataSource"},
		{"DELETE", "/v1/apis/team-a.notes/datasources/todos", "DeleteDataSource"},
		{"GET", "/v1/apis/team-a.notes/apikeys", ""}, // recognized shape, unhandled → NotImplemented
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "http://appsync"+c.path, strings.NewReader("{}"))
		_, verb, err := parseManagement(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		if verb != c.want {
			t.Fatalf("%s %s → verb %q, want %q", c.method, c.path, verb, c.want)
		}
	}
}

// --- handler front-door + negatives ---

func TestManagement_CreateResolverAppliesToCR(t *testing.T) {
	store := newFakeAPIStore()
	store.seed("team-a", "notes")
	h := newAppsyncHandler(csWithSAR(true), "http://unused", "default", discardLogger())
	h.apis = store

	body := `{"fieldName":"getTodo","dataSourceName":"todos","requestMappingTemplate":"REQ","responseMappingTemplate":"RESP"}`
	req := httptest.NewRequest("POST", "http://appsync/v1/apis/team-a.notes/types/Query/resolvers", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "ada", Groups: []string{"openinfra:admins"}}, "r")

	if w.Code != 201 {
		t.Fatalf("status=%d want 201; body=%s", w.Code, w.Body.String())
	}
	rs := store.resolvers("team-a", "notes")
	if len(rs) != 1 || rs[0].(map[string]any)["field"] != "getTodo" {
		t.Fatalf("CreateResolver did not patch the CR: %v", rs)
	}
}

// A caller the boundary denies cannot manage the API, and nothing is written.
func TestManagement_DeniedDoesNotPatch(t *testing.T) {
	store := newFakeAPIStore()
	store.seed("team-a", "notes")
	h := newAppsyncHandler(csWithSAR(false), "http://unused", "default", discardLogger())
	h.apis = store

	req := httptest.NewRequest("POST", "http://appsync/v1/apis/team-a.notes/types/Query/resolvers",
		strings.NewReader(`{"fieldName":"x"}`))
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "mallory"}, "r")
	if w.Code != 403 {
		t.Fatalf("status=%d want 403", w.Code)
	}
	if len(store.resolvers("team-a", "notes")) != 0 {
		t.Fatal("a denied management call must not patch the CR")
	}
}

// An unhandled management verb answers an honest NotImplemented (per-verb graduation), not a fake 200.
func TestManagement_UnhandledVerbIsNotImplemented(t *testing.T) {
	h := newAppsyncHandler(csWithSAR(true), "http://unused", "default", discardLogger())
	h.apis = newFakeAPIStore()
	req := httptest.NewRequest("GET", "http://appsync/v1/apis/team-a.notes/apikeys", nil)
	w := httptest.NewRecorder()
	h.serve(w, req, iam.Claims{Sub: "ada"}, "r")
	if w.Code != 501 {
		t.Fatalf("status=%d want 501 for an unhandled verb; body=%s", w.Code, w.Body.String())
	}
}
