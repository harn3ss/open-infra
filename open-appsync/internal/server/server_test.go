package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Proves the deploy wrapper end-to-end without Mongo: a config dir (memory data source + .vtl
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
