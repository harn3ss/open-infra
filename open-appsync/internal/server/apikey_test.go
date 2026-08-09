package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
)

// End-to-end over HTTP: an @aws_api_key field is reachable only with a valid x-api-key (which
// impersonates the mapped identity); a missing or wrong key is Unauthorized.
func TestAPIKey_HTTPGate(t *testing.T) {
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
type Todo { id: ID! }
type Query { getTodo(id: ID!): Todo @aws_api_key }
`)

	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	keys := map[string]authz.Identity{"secret-key": {Username: "system:serviceaccount:demo:reader"}}
	h := Handler(engine, WithAPIKeys(keys))

	post := func(apiKey string) []map[string]any {
		body, _ := json.Marshal(map[string]any{"query": `query { getTodo(id: "x") { id } }`})
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
		if apiKey != "" {
			req.Header.Set("X-Api-Key", apiKey)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		var out struct {
			Errors []map[string]any `json:"errors"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Errors
	}
	hasUnauthorized := func(errs []map[string]any) bool {
		for _, e := range errs {
			if e["errorType"] == "Unauthorized" {
				return true
			}
		}
		return false
	}

	if !hasUnauthorized(post("")) {
		t.Error("no api key → @aws_api_key field must be Unauthorized")
	}
	if !hasUnauthorized(post("wrong-key")) {
		t.Error("wrong api key → must be Unauthorized")
	}
	if hasUnauthorized(post("secret-key")) {
		t.Error("valid api key → must pass the @aws_api_key gate")
	}
}

// An @aws_iam field is reachable when the request carries the shim's X-OpenInfra-Auth-Mode: aws_iam
// (SigV4-authenticated), and denied otherwise. Same trust boundary as the identity headers.
func TestIAM_HTTPGate(t *testing.T) {
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
type Todo { id: ID! }
type Query { getTodo(id: ID!): Todo @aws_iam }
`)
	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	h := Handler(engine)

	post := func(mode string) []map[string]any {
		body, _ := json.Marshal(map[string]any{"query": `query { getTodo(id: "x") { id } }`})
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
		if mode != "" {
			req.Header.Set("X-OpenInfra-User", "system:serviceaccount:demo:caller")
			req.Header.Set("X-OpenInfra-Auth-Mode", mode)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		var out struct {
			Errors []map[string]any `json:"errors"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Errors
	}
	unauth := func(errs []map[string]any) bool {
		for _, e := range errs {
			if e["errorType"] == "Unauthorized" {
				return true
			}
		}
		return false
	}
	if !unauth(post("")) {
		t.Error("no auth mode → @aws_iam field must be Unauthorized")
	}
	if unauth(post("aws_iam")) {
		t.Error("X-OpenInfra-Auth-Mode: aws_iam → @aws_iam field must pass the gate")
	}
}

func TestLoadAPIKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "apikeys.json")
	_ = os.WriteFile(path, []byte(`[
	  {"key":"k1","username":"system:serviceaccount:demo:reader","groups":["viewers"]},
	  {"key":"k2","username":"system:serviceaccount:demo:writer"}
	]`), 0o600)

	keys, err := LoadAPIKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	if id := keys["k1"]; id.Username != "system:serviceaccount:demo:reader" || len(id.Groups) != 1 || id.Groups[0] != "viewers" {
		t.Errorf("k1 → %+v", id)
	}
	// Missing file → nil map, no error (api-key auth simply off).
	if m, err := LoadAPIKeys(filepath.Join(dir, "nope.json")); err != nil || m != nil {
		t.Errorf("missing file should be (nil,nil), got (%v,%v)", m, err)
	}
}
