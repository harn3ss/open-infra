package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A resolver backed by a lambda data source loads from config and runs end-to-end over HTTP: the request
// template emits an Invoke payload, the (stub) function returns JSON, and it becomes the GraphQL result.
// Proves the config wiring + neutrality (a lambda resolver coexists with the others, no engine branching).
func TestServer_LambdaDataSource(t *testing.T) {
	var gotPayload map[string]any
	fn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotPayload)
		id, _ := gotPayload["id"].(string)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "name": "Ada"})
	}))
	defer fn.Close()

	dir := t.TempDir()
	w := func(n, c string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("config.json", `{
	  "dataSources": [{"name":"userfn","type":"lambda","endpoint":"`+fn.URL+`"}],
	  "resolvers": [{"type":"Query","field":"getUser","dataSource":"userfn","request":"req.vtl","response":"resp.vtl"}]
	}`)
	w("req.vtl", `{"version":"2018-05-29","operation":"Invoke","payload":{"id":$util.toJson($ctx.args.id)}}`)
	w("resp.vtl", `$util.toJson($ctx.result)`)

	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	h := Handler(engine)

	body, _ := json.Marshal(map[string]any{"query": `query { getUser(id: "a1") { id name } }`})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h(rec, req)

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response not JSON: %v (%s)", err, rec.Body.String())
	}
	if errs, ok := out["errors"]; ok && errs != nil {
		t.Fatalf("graphql errors: %v", errs)
	}
	if gotPayload["id"] != "a1" {
		t.Errorf("function payload = %v, want {id:a1}", gotPayload)
	}
	user := out["data"].(map[string]any)["getUser"].(map[string]any)
	if user["id"] != "a1" || user["name"] != "Ada" {
		t.Errorf("getUser via lambda = %v", user)
	}
}
