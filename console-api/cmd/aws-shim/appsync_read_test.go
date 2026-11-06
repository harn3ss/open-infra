package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
)

func TestParseManagement_Reads(t *testing.T) {
	for _, c := range []struct{ path, verb, ds, fn string }{
		{"/v1/apis", "ListGraphqlApis", "", ""},
		{"/v1/apis/team-a.notes", "GetGraphqlApi", "", ""},
		{"/v1/apis/team-a.notes/schema", "GetIntrospectionSchema", "", ""},
		{"/v1/apis/team-a.notes/schemacreation", "GetSchemaCreationStatus", "", ""},
		{"/v1/apis/team-a.notes/datasources", "ListDataSources", "", ""},
		{"/v1/apis/team-a.notes/datasources/todos", "GetDataSource", "todos", ""},
		{"/v1/apis/team-a.notes/functions", "ListFunctions", "", ""},
		{"/v1/apis/team-a.notes/functions/abc", "GetFunction", "", "abc"},
	} {
		p, verb, err := parseManagement(httptest.NewRequest("GET", "http://appsync"+c.path, nil))
		if err != nil || verb != c.verb || p.dsName != c.ds || p.fnID != c.fn {
			t.Errorf("GET %s = %q %+v %v, want %s", c.path, verb, p, err, c.verb)
		}
	}
}

// notesAPI seeds a GraphQLApi with a schema, three data sources and two pipeline resolvers that share a
// function.
func notesAPI(store *fakeAPIStore, ns, name string) {
	shared := map[string]any{"dataSource": "todos", "runtime": "appsync-vtl", "request": "REQ", "response": "RESP"}
	store.objs[ns+"/"+name] = map[string]any{
		"spec": map[string]any{
			"schema": "type Query { getTodo(id: ID!): String @aws_iam }",
			"dataSources": []any{
				map[string]any{"name": "todos", "type": "dynamodb", "collection": "todos", "connectionSecret": "s"},
				map[string]any{"name": "web", "type": "http", "endpoint": "http://svc"},
				map[string]any{"name": "local", "type": "none"},
			},
			"resolvers": []any{
				map[string]any{"type": "Query", "field": "getTodo", "functions": []any{shared,
					map[string]any{"dataSource": "web", "runtime": "appsync-js", "request": "export function request(){}"}}},
				map[string]any{"type": "Query", "field": "listTodos", "functions": []any{shared}},
				map[string]any{"type": "Query", "field": "unit", "dataSource": "local", "request": "R"},
			},
		},
		"status": map[string]any{"url": "http://notes.team-a.svc/graphql",
			"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
	}
}

func appsyncRead(h *appsyncHandler, claims iam.Claims, path string) (*httptest.ResponseRecorder, map[string]any) {
	w := httptest.NewRecorder()
	h.serve(w, httptest.NewRequest("GET", "http://appsync"+path, nil), claims, "r")
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func readAppsync(allow func(a *authzv1.ResourceAttributes) bool) (*appsyncHandler, *fakeAPIStore) {
	store := newFakeAPIStore()
	notesAPI(store, "team-a", "notes")
	h := newAppsyncHandler(csWithSARFunc(allow), "http://unused", "default", discardLogger())
	h.apis = store
	h.account, h.region = "000000000000", "us-east-1"
	return h, store
}

// The reads answer the claim in AppSync's shapes, and need only get on graphqlapis (the writes still
// need update).
func TestAppsyncReads_AnswerTheClaim(t *testing.T) {
	h, _ := readAppsync(func(a *authzv1.ResourceAttributes) bool { return a.Verb == "get" && a.Namespace == "team-a" })
	u := iam.Claims{Sub: "u"}
	w, out := appsyncRead(h, u, "/v1/apis/team-a.notes")
	api, _ := out["graphqlApi"].(map[string]any)
	if w.Code != 200 || api["apiId"] != "team-a.notes" || api["name"] != "notes" || api["arn"] != "arn:aws:appsync:us-east-1:000000000000:apis/team-a.notes" ||
		api["uris"].(map[string]any)["GRAPHQL"] != "http://notes.team-a.svc/graphql" {
		t.Fatalf("GetGraphqlApi = %d %v", w.Code, out)
	}
	if _, has := api["authenticationType"]; has {
		t.Error("an API-wide authentication type was invented")
	}

	w, _ = appsyncRead(h, u, "/v1/apis/team-a.notes/schema?format=SDL")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "getTodo(id: ID!)") {
		t.Errorf("GetIntrospectionSchema SDL = %d %s", w.Code, w.Body)
	}
	if w, _ := appsyncRead(h, u, "/v1/apis/team-a.notes/schema?format=JSON"); w.Code != http.StatusBadRequest {
		t.Errorf("GetIntrospectionSchema JSON = %d, want a refusal", w.Code)
	}
	if _, out := appsyncRead(h, u, "/v1/apis/team-a.notes/schemacreation"); out["status"] != "SUCCESS" {
		t.Errorf("GetSchemaCreationStatus = %v", out)
	}

	w, out = appsyncRead(h, u, "/v1/apis/team-a.notes/datasources/todos")
	ds, _ := out["dataSource"].(map[string]any)
	if w.Code != 200 || ds["type"] != "AMAZON_DYNAMODB" || ds["dynamodbConfig"].(map[string]any)["tableName"] != "todos" {
		t.Errorf("GetDataSource = %d %v", w.Code, out)
	}
	if strings.Contains(w.Body.String(), "connectionSecret") {
		t.Error("a data source's credentials reference was answered")
	}
	_, out = appsyncRead(h, u, "/v1/apis/team-a.notes/datasources")
	if l, _ := out["dataSources"].([]any); len(l) != 3 || l[1].(map[string]any)["type"] != "HTTP" || l[2].(map[string]any)["type"] != "NONE" {
		t.Errorf("ListDataSources = %v", out)
	}
	_, out = appsyncRead(h, u, "/v1/apis/team-a.notes/datasources?maxResults=2")
	if l, _ := out["dataSources"].([]any); len(l) != 2 || out["nextToken"] != "2" {
		t.Errorf("ListDataSources page = %v", out)
	}

	// The shared function is one function; ids are stable.
	_, out = appsyncRead(h, u, "/v1/apis/team-a.notes/functions")
	fns, _ := out["functions"].([]any)
	if len(fns) != 2 {
		t.Fatalf("ListFunctions = %v, want the two distinct pipeline functions", out)
	}
	_, again := appsyncRead(h, u, "/v1/apis/team-a.notes/functions")
	id := fns[0].(map[string]any)["functionId"].(string)
	if again["functions"].([]any)[0].(map[string]any)["functionId"] != id {
		t.Error("a function's id changed between reads")
	}
	w, out = appsyncRead(h, u, "/v1/apis/team-a.notes/functions/"+id)
	fc, _ := out["functionConfiguration"].(map[string]any)
	if w.Code != 200 || fc["dataSourceName"] == nil || fc["functionArn"] != "arn:aws:appsync:us-east-1:000000000000:apis/team-a.notes/functions/"+id {
		t.Errorf("GetFunction = %d %v", w.Code, out)
	}

	// Not found.
	for _, p := range []string{"/v1/apis/team-a.missing", "/v1/apis/team-a.notes/datasources/nope", "/v1/apis/team-a.notes/functions/nope"} {
		if w, _ := appsyncRead(h, u, p); w.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, w.Code)
		}
	}
	// A write still needs update.
	w = httptest.NewRecorder()
	h.serve(w, httptest.NewRequest("POST", "http://appsync/v1/apis/team-a.notes/datasources", strings.NewReader(`{"name":"x","type":"NONE"}`)), u, "r")
	if w.Code != http.StatusForbidden {
		t.Errorf("CreateDataSource with get only = %d", w.Code)
	}
}

// A Lambda data source that names its function reads back with its function ARN (in the API's account),
// and a direct Lambda pipeline function reads back without templates and with its maxBatchSize.
func TestAppsyncReads_DirectLambda(t *testing.T) {
	h, store := readAppsync(func(a *authzv1.ResourceAttributes) bool { return a.Verb == "get" && a.Namespace == "team-a" })
	spec := store.objs["team-a/notes"]["spec"].(map[string]any)
	spec["dataSources"] = append(spec["dataSources"].([]any), map[string]any{"name": "fn", "type": "lambda", "function": "blog-fn"})
	spec["resolvers"] = append(spec["resolvers"].([]any), map[string]any{"type": "Post", "field": "author",
		"functions": []any{map[string]any{"dataSource": "fn", "runtime": "appsync-vtl", "maxBatchSize": int64(25)}}})
	u := iam.Claims{Sub: "u"}

	_, out := appsyncRead(h, u, "/v1/apis/team-a.notes/datasources/fn")
	ds, _ := out["dataSource"].(map[string]any)
	lc, _ := ds["lambdaConfig"].(map[string]any)
	if ds["type"] != "AWS_LAMBDA" || lc["lambdaFunctionArn"] != "arn:aws:lambda:us-east-1:000000000000:function:blog-fn" {
		t.Errorf("GetDataSource (lambda) = %v", out)
	}

	_, out = appsyncRead(h, u, "/v1/apis/team-a.notes/functions")
	var direct map[string]any
	for _, f := range out["functions"].([]any) {
		if m := f.(map[string]any); m["dataSourceName"] == "fn" {
			direct = m
		}
	}
	if direct == nil || direct["maxBatchSize"] != float64(25) {
		t.Fatalf("the direct function = %v, want maxBatchSize 25", direct)
	}
	if _, has := direct["requestMappingTemplate"]; has {
		t.Errorf("a direct Lambda function has no request template to answer: %v", direct)
	}
}

func TestAppsyncReads_Denied(t *testing.T) {
	h, _ := readAppsync(func(a *authzv1.ResourceAttributes) bool { return a.Namespace != "team-a" })
	for _, p := range []string{"/v1/apis/team-a.notes", "/v1/apis/team-a.notes/schema?format=SDL", "/v1/apis/team-a.notes/schemacreation",
		"/v1/apis/team-a.notes/datasources", "/v1/apis/team-a.notes/datasources/todos", "/v1/apis/team-a.notes/functions"} {
		if w, _ := appsyncRead(h, iam.Claims{Sub: "u"}, p); w.Code != http.StatusForbidden {
			t.Errorf("GET %s without get = %d", p, w.Code)
		}
	}
	// An assumed role needs appsync:<Operation> on the API.
	h, _ = readAppsync(allowAll)
	h.authz = roleChecker(dpAllow([]string{"appsync:GetGraphqlApi"}, "GraphQLApi::team-a.notes"))
	if w, _ := appsyncRead(h, ecrRoleClaims(), "/v1/apis/team-a.notes"); w.Code != 200 {
		t.Errorf("GetGraphqlApi by a role granted it = %d", w.Code)
	}
	if w, _ := appsyncRead(h, ecrRoleClaims(), "/v1/apis/team-a.notes/datasources"); w.Code != http.StatusForbidden {
		t.Errorf("ListDataSources by a role not granted it = %d", w.Code)
	}
	if w, _ := appsyncRead(h, ecrRoleClaims(), "/v1/apis"); w.Code != http.StatusForbidden {
		t.Errorf("ListGraphqlApis by a role not granted it = %d", w.Code)
	}
}

// ListGraphqlApis lists only the namespaces the caller may list, a page at a time.
func TestAppsyncListGraphqlApis_OnlyWhatTheCallerMayList(t *testing.T) {
	h, store := readAppsync(func(a *authzv1.ResourceAttributes) bool { return a.Verb == "list" && a.Namespace != "team-b" })
	notesAPI(store, "team-a", "tasks")
	notesAPI(store, "team-b", "secret")
	notesAPI(store, "team-c", "board")
	var ids []string
	token := ""
	for i := 0; i < 10; i++ {
		path := "/v1/apis?maxResults=1"
		if token != "" {
			path += "&nextToken=" + token
		}
		w, out := appsyncRead(h, iam.Claims{Sub: "u"}, path)
		if w.Code != 200 {
			t.Fatalf("ListGraphqlApis = %d %s", w.Code, w.Body)
		}
		for _, a := range out["graphqlApis"].([]any) {
			ids = append(ids, a.(map[string]any)["apiId"].(string))
		}
		token, _ = out["nextToken"].(string)
		if token == "" {
			break
		}
	}
	if strings.Join(ids, ",") != "team-a.notes,team-a.tasks,team-c.board" {
		t.Errorf("listed %v, want every API but team-b's", ids)
	}
}
