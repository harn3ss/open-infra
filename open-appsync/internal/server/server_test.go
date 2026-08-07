package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/subscription"
)

// Proves the deploy wrapper end-to-end without Mongo: a config dir (memory data source +.vtl
// template files) loads into an engine, and the HTTP handler runs a real GraphQL mutation+query
// over POST /graphql — the exact path the aws-shim forwards to.
func TestServer_LoadAndServe(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("config.json", `{
	  "dataSources": [{"name":"todos","type":"memory"}],
	  "resolvers": [
	    {"type":"Query","field":"getTodo","dataSource":"todos","request":"get.vtl","response":"resp.vtl"},
	    {"type":"Mutation","field":"createTodo","dataSource":"todos","request":"put.vtl","response":"resp.vtl"}
	  ]
	}`)
	write("get.vtl", `{"version":"2018-05-29","operation":"GetItem","key":{"id":$util.dynamodb.toDynamoDBJson($ctx.args.id)}}`)
	write("put.vtl", `{"version":"2018-05-29","operation":"PutItem","key":{"id":$util.dynamodb.toDynamoDBJson($util.autoId())},"attributeValues":$util.dynamodb.toMapValuesJson($ctx.args.input)}`)
	write("resp.vtl", `$util.toJson($ctx.result)`)

	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	h := Handler(engine)

	post := func(query string) map[string]any {
		body, _ := json.Marshal(map[string]any{"query": query})
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("response not JSON: %v (%s)", err, w.Body.String())
		}
		if errs, ok := out["errors"]; ok && errs != nil {
			t.Fatalf("graphql errors: %v", errs)
		}
		return out["data"].(map[string]any)
	}

	// Mutation: create a todo; id is a real (random) autoId.
	created := post(`mutation { createTodo(input: {name: "Ada", age: 36}) { id name age } }`)["createTodo"].(map[string]any)
	if created["name"] != "Ada" || created["age"].(float64) != 36 {
		t.Fatalf("createTodo not faithful: %v", created)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("createTodo produced no id: %v", created)
	}

	// Query the same id back through the memory store.
	got := post(`query { getTodo(id: "` + id + `") { id name } }`)["getTodo"].(map[string]any)
	if got["id"] != id || got["name"] != "Ada" {
		t.Fatalf("getTodo round-trip: %v", got)
	}
}

// TestServer_IntrospectionFromSchemaFile proves the deploy path for introspection: a schema.graphql
// sibling file loads into the engine's type graph, and __schema/__type answer over the HTTP handler —
// plus the introspection toggle is honored from config.
func TestServer_IntrospectionFromSchemaFile(t *testing.T) {
	dir := t.TempDir()
	w := func(n, c string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("config.json", `{
	  "dataSources": [{"name":"todos","type":"memory"}],
	  "resolvers": [{"type":"Query","field":"getTodo","dataSource":"todos","request":"get.vtl","response":"resp.vtl"}]
	}`)
	w("get.vtl", `{"version":"2018-05-29","operation":"GetItem","key":{"id":$util.dynamodb.toDynamoDBJson($ctx.args.id)}}`)
	w("resp.vtl", `$util.toJson($ctx.result)`)
	w("schema.graphql", `
type Todo { id: ID! name: String! tags: [String!] }
type Query { getTodo(id: ID!): Todo }
`)

	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	res := engine.Execute(context.Background(), `{ __schema { queryType { name } types { name kind } } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("introspection errored: %+v", res.Errors)
	}
	sch := res.Data["__schema"].(map[string]any)
	if qt := sch["queryType"].(map[string]any); qt["name"] != "Query" {
		t.Errorf("queryType = %v", qt)
	}
	haveTodo := false
	for _, ti := range sch["types"].([]any) {
		if tm := ti.(map[string]any); tm["name"] == "Todo" && tm["kind"] == "OBJECT" {
			haveTodo = true
		}
	}
	if !haveTodo {
		t.Error("Todo OBJECT missing from introspected types")
	}

	// Toggle from config: disabled → introspection refused, resolvers still work.
	w("config.json", `{
	  "limits": {"introspection":"disabled"},
	  "dataSources": [{"name":"todos","type":"memory"}],
	  "resolvers": [{"type":"Query","field":"getTodo","dataSource":"todos","request":"get.vtl","response":"resp.vtl"}]
	}`)
	engine2, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load (disabled): %v", err)
	}
	res = engine2.Execute(context.Background(), `{ __schema { queryType { name } } }`, nil)
	if len(res.Errors) == 0 || res.Errors[0].ErrorType != "IntrospectionDisabled" {
		t.Errorf("disabled introspection not refused: %+v", res.Errors)
	}
}

// A pipeline resolver loads from config (before + 2 functions + after) and serves end-to-end over
// HTTP — the shape kind: GraphQLApi renders. Threads $ctx.stash and $ctx.prev.result; before emits no
// Operation.
func TestServer_PipelineResolver(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("config.json", `{
	  "dataSources": [{"name":"things","type":"memory"}],
	  "resolvers": [{
	    "type":"Mutation","field":"createAndFetch",
	    "before":"before.vtl","after":"after.vtl",
	    "functions":[
	      {"dataSource":"things","request":"put.vtl","response":"resp.vtl"},
	      {"dataSource":"things","request":"get.vtl","response":"resp.vtl"}
	    ]
	  }]
	}`)
	write("before.vtl", `#set($d = $ctx.stash.put("tag", $ctx.args.tag))`)
	write("put.vtl", `{"operation":"PutItem","key":{"id":$util.dynamodb.toDynamoDBJson($util.autoId())},"attributeValues":$util.dynamodb.toMapValuesJson({"name":$ctx.args.name,"tag":$ctx.stash.tag})}`)
	write("get.vtl", `{"operation":"GetItem","key":{"id":$util.dynamodb.toDynamoDBJson($ctx.prev.result.id)}}`)
	write("resp.vtl", `$util.toJson($ctx.result)`)
	write("after.vtl", `$util.toJson($ctx.prev.result)`)

	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"query": `mutation { createAndFetch(name: "Ada", tag: "work") { name tag } }`})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	Handler(engine)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad JSON: %v (%s)", err, w.Body.String())
	}
	if errs, ok := out["errors"]; ok && errs != nil {
		t.Fatalf("graphql errors: %v", errs)
	}
	got := out["data"].(map[string]any)["createAndFetch"].(map[string]any)
	if got["name"] != "Ada" || got["tag"] != "work" {
		t.Fatalf("pipeline over HTTP not faithful: %v", got)
	}
}

// A limits block on the config is honored end-to-end: a query past maxDepth is rejected over HTTP
// before the resolver runs (wired through Load).
func TestServer_LimitsEnforced(t *testing.T) {
	dir := t.TempDir()
	w := func(n, c string) { _ = os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644) }
	w("config.json", `{
	  "dataSources":[{"name":"t","type":"memory"}],
	  "limits":{"maxDepth":2},
	  "resolvers":[{"type":"Query","field":"getTodo","dataSource":"t","request":"get.vtl","response":"resp.vtl"}]
	}`)
	w("get.vtl", `{"operation":"GetItem","key":{"id":$util.dynamodb.toDynamoDBJson($ctx.args.id)}}`)
	w("resp.vtl", `$util.toJson($ctx.result)`)

	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"query": `query { getTodo(id:"1") { a { b { c } } } }`})
	rec := httptest.NewRecorder()
	Handler(engine)(rec, httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body))))
	var out struct {
		Errors []struct{ ErrorType string } `json:"errors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Errors) != 1 || out.Errors[0].ErrorType != "MaxDepthExceeded" {
		t.Fatalf("expected MaxDepthExceeded, got %s", rec.Body.String())
	}
}

// A JS resolver (runtime: appsync-js) loads from config and serves end-to-end over HTTP — the second
// runtime through the same config→Load→executor path as VTL.
func TestServer_JSResolver(t *testing.T) {
	dir := t.TempDir()
	w := func(n, c string) { _ = os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644) }
	w("config.json", `{
	  "dataSources":[{"name":"t","type":"memory"}],
	  "resolvers":[{"type":"Mutation","field":"createTodo","dataSource":"t","runtime":"appsync-js","request":"put.js"}]
	}`)
	w("put.js", `
	  function request(ctx){ return { operation:'PutItem',
	    key:{ id: util.dynamodb.toDynamoDB(util.autoId()) },
	    attributeValues: util.dynamodb.toMapValues({ name: ctx.args.name }) }; }
	  function response(ctx){ return ctx.result; }`)

	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"query": `mutation { createTodo(name:"Ada") { id name } }`})
	rec := httptest.NewRecorder()
	Handler(engine)(rec, httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body))))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if errs, ok := out["errors"]; ok && errs != nil {
		t.Fatalf("js resolver errors: %v", errs)
	}
	got := out["data"].(map[string]any)["createTodo"].(map[string]any)
	if got["name"] != "Ada" || got["id"] == "" {
		t.Fatalf("js resolver over HTTP not faithful: %v", got)
	}
}

// A malformed JS module fails closed at load (syntax error), like a malformed VTL template.
func TestServer_JSFailsClosedOnSyntaxError(t *testing.T) {
	dir := t.TempDir()
	w := func(n, c string) { _ = os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644) }
	w("config.json", `{"dataSources":[{"name":"t","type":"memory"}],"resolvers":[{"type":"Query","field":"x","dataSource":"t","runtime":"appsync-js","request":"bad.js"}]}`)
	w("bad.js", `function request(ctx { return {}; `) // syntax error
	if _, err := Load(dir, nil); err == nil {
		t.Fatal("a malformed JS module must fail Load closed")
	}
}

// An http data source loads from config (endpoint field + type "http") and a resolver reaches it
// end-to-end over HTTP — the second call-source through the same config→Load→executor path.
func TestServer_HTTPDataSource(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "7", "name": "Grace"})
	}))
	defer api.Close()

	dir := t.TempDir()
	wf := func(n, c string) { _ = os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644) }
	wf("config.json", `{
	  "dataSources":[{"name":"api","type":"http","endpoint":"`+api.URL+`"}],
	  "resolvers":[{"type":"Query","field":"getUser","dataSource":"api","request":"get.vtl","response":"resp.vtl"}]
	}`)
	wf("get.vtl", `{"method":"GET","resourcePath":"/users/$ctx.args.id"}`)
	wf("resp.vtl", `$util.toJson($ctx.result.body)`)

	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"query": `query { getUser(id:"7") { id name } }`})
	rec := httptest.NewRecorder()
	Handler(engine)(rec, httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body))))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if errs, ok := out["errors"]; ok && errs != nil {
		t.Fatalf("http data source errors: %v", errs)
	}
	got := out["data"].(map[string]any)["getUser"].(map[string]any)
	if got["name"] != "Grace" {
		t.Fatalf("http data source over HTTP not faithful: %v", got)
	}
}

// An http data source with no endpoint fails Load closed.
func TestServer_HTTPRequiresEndpoint(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"dataSources":[{"name":"api","type":"http"}],"resolvers":[]}`), 0o644)
	if _, err := Load(dir, nil); err == nil {
		t.Fatal("expected Load to fail for an http source with no endpoint")
	}
}

// Field auth end-to-end: a resolver with an `auth` block, an injected authorizer, and the caller's
// identity from headers — a denied caller gets Unauthorized and the resolver never runs.
func TestServer_FieldAuthDeniesOverHTTP(t *testing.T) {
	dir := t.TempDir()
	wf := func(n, c string) { _ = os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644) }
	wf("config.json", `{
	  "dataSources":[{"name":"t","type":"memory"}],
	  "resolvers":[{"type":"Query","field":"getTodo","dataSource":"t","request":"get.vtl","response":"resp.vtl",
	    "auth":{"group":"openinfra.dev","resource":"graphqlapis","verb":"get"}}]
	}`)
	wf("get.vtl", `{"operation":"GetItem","key":{"id":$util.dynamodb.toDynamoDBJson($ctx.args.id)}}`)
	wf("resp.vtl", `$util.toJson($ctx.result)`)

	seen := &recordingAuthz{}
	engine, err := Load(dir, nil, graphql.WithAuthorizer(seen))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"query": `query { getTodo(id:"1") { id } }`})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("X-OpenInfra-User", "mallory")
	req.Header.Set("X-OpenInfra-Groups", "guests, readers")
	rec := httptest.NewRecorder()
	Handler(engine)(rec, req)

	var out struct {
		Errors []struct{ ErrorType string } `json:"errors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Errors) != 1 || out.Errors[0].ErrorType != "Unauthorized" {
		t.Fatalf("expected Unauthorized, got %s", rec.Body.String())
	}
	// Identity was parsed from headers and passed to the authorizer.
	if seen.lastUser != "mallory" || len(seen.lastGroups) != 2 {
		t.Fatalf("identity from headers not delivered: user=%q groups=%v", seen.lastUser, seen.lastGroups)
	}
	if seen.lastReq.Resource != "graphqlapis" {
		t.Fatalf("auth block from config not delivered: %+v", seen.lastReq)
	}
}

type recordingAuthz struct {
	lastUser   string
	lastGroups []string
	lastReq    authz.Requirement
}

func (a *recordingAuthz) Authorize(_ context.Context, id authz.Identity, need authz.Requirement) error {
	a.lastUser, a.lastGroups, a.lastReq = id.Username, id.Groups, need
	return authz.ErrDenied
}

// LoadSubscriptions reads the subscription section and builds a working Manager + publisher: a mutation
// the publisher is told about fans out to a matching subscriber (the config→Load→publish→fanout chain).
func TestServer_LoadSubscriptions(t *testing.T) {
	dir := t.TempDir()
	wf := func(n, c string) { _ = os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644) }
	wf("config.json", `{
	  "dataSources":[{"name":"t","type":"memory"}],
	  "resolvers":[{"type":"Mutation","field":"createTodo","dataSource":"t","request":"put.vtl","response":"resp.vtl"}],
	  "subscriptions":[{"field":"onCreateTodo","response":"sub.vtl","triggeredBy":["createTodo"]}]
	}`)
	wf("put.vtl", `{"operation":"PutItem","key":{"id":$util.dynamodb.toDynamoDBJson($util.autoId())},"attributeValues":$util.dynamodb.toMapValuesJson($ctx.args.input)}`)
	wf("resp.vtl", `$util.toJson($ctx.result)`)
	wf("sub.vtl", `$util.toJson($ctx.result)`)

	mgr, pub, err := LoadSubscriptions(dir, subscription.NewMemBus(), authz.AllowAll{})
	if err != nil {
		t.Fatalf("LoadSubscriptions: %v", err)
	}
	if mgr == nil || pub == nil {
		t.Fatal("expected a manager + publisher for a config with subscriptions")
	}
	if err := mgr.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()

	var got any
	if _, err := mgr.Subscribe(context.Background(), "s1", "onCreateTodo", subscription.FilterGroup{}, func(p any) { got = p }); err != nil {
		t.Fatal(err)
	}
	// The publisher maps the mutation field to the subscription and fans its result out.
	pub.PublishForMutation(context.Background(), "createTodo", map[string]any{"id": "1", "name": "Ada"})
	m, ok := got.(map[string]any)
	if !ok || m["name"] != "Ada" {
		t.Fatalf("mutation did not fan out to the subscriber: %v", got)
	}
}

// No subscriptions declared → LoadSubscriptions returns (nil, nil, nil) so main skips the WS wiring.
func TestServer_LoadSubscriptions_None(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"dataSources":[],"resolvers":[]}`), 0o644)
	mgr, pub, err := LoadSubscriptions(dir, subscription.NewMemBus(), authz.AllowAll{})
	if err != nil || mgr != nil || pub != nil {
		t.Fatalf("expected (nil,nil,nil) with no subscriptions, got mgr=%v pub=%v err=%v", mgr, pub, err)
	}
}

func TestServer_Handler_RejectsGET(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"dataSources":[],"resolvers":[]}`), 0o644)
	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	Handler(engine)(w, httptest.NewRequest(http.MethodGet, "/graphql", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET should be 405, got %d", w.Code)
	}
}

// A dynamodb data source without a Mongo DB must fail loud at load, not silently.
func TestServer_DynamoDBRequiresMongo(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"dataSources":[{"name":"t","type":"dynamodb","collection":"t"}],"resolvers":[]}`), 0o644)
	if _, err := Load(dir, nil); err == nil {
		t.Fatal("expected Load to fail for a dynamodb source with no MONGO_URI")
	}
}

// negative-proof bar: one malformed resolver template must keep the WHOLE config from loading
// (fail closed) — the engine never serves a half-broken API, and the parse error surfaces at load.
func TestServer_FailsClosedOnMalformedResolver(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("config.json", `{
	  "dataSources": [{"name":"todos","type":"memory"}],
	  "resolvers": [
	    {"type":"Query","field":"getTodo","dataSource":"todos","request":"get.vtl","response":"resp.vtl"}
	  ]
	}`)
	write("get.vtl", "#if($ctx.args.id)\n{\"operation\":\"Scan\"}\n") // no #end — malformed
	write("resp.vtl", `$util.toJson($ctx.result)`)

	if _, err := Load(dir, nil); err == nil {
		t.Fatal("Load must fail closed on a malformed resolver template, not serve a broken config")
	}
}

// An unknown runtime value is rejected (fail closed), not silently defaulted — so a typo, or a runtime
// this build doesn't have, can never quietly serve the wrong thing.
func TestServer_UnknownRuntimeRejected(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		_ = os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644)
	}
	write("config.json", `{
	  "dataSources": [{"name":"todos","type":"memory"}],
	  "resolvers": [
	    {"type":"Query","field":"getTodo","dataSource":"todos","runtime":"js","request":"get.vtl","response":"resp.vtl"}
	  ]
	}`)
	write("get.vtl", `{"operation":"Scan"}`)
	write("resp.vtl", `$util.toJson($ctx.result)`)

	if _, err := Load(dir, nil); err == nil {
		t.Fatal("Load must reject an unknown runtime value")
	}
}
