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

// A NONE data source resolves a field entirely in the mapping templates: the request template's payload
// becomes $ctx.result for the response template — no backend, end-to-end over HTTP.
func TestServer_NoneDataSource(t *testing.T) {
	dir := t.TempDir()
	w := func(n, c string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("config.json", `{
	  "dataSources": [{"name":"local","type":"none"}],
	  "resolvers": [{"type":"Query","field":"echo","dataSource":"local","request":"req.vtl","response":"resp.vtl"}]
	}`)
	// Request template puts the arg into `payload`; NONE echoes it back as $ctx.result.
	w("req.vtl", `{"version":"2018-05-29","payload":{"said":$util.toJson($ctx.args.msg)}}`)
	w("resp.vtl", `$util.toJson($ctx.result)`)

	engine, err := Load(dir, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"query": `query { echo(msg: "hi") { said } }`})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	Handler(engine)(rec, req)

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response not JSON: %v (%s)", err, rec.Body.String())
	}
	if errs, ok := out["errors"]; ok && errs != nil {
		t.Fatalf("graphql errors: %v", errs)
	}
	echo := out["data"].(map[string]any)["echo"].(map[string]any)
	if echo["said"] != "hi" {
		t.Errorf("NONE resolver echo = %v, want said=hi", echo)
	}
}
