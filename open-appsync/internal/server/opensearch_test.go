package server

import (
	"os"
	"path/filepath"
	"testing"
)

// An opensearch data source loads from its endpoint; a missing endpoint fails closed. Basic-auth creds
// (from the connectionSecret, injected as env) are optional — an unauthenticated domain loads fine.
func TestServer_OpenSearchDataSource(t *testing.T) {
	dir := t.TempDir()
	w := func(n, c string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("req.vtl", `{"operation":"POST","path":"/i/_search","params":{"body":{}}}`)
	w("resp.vtl", `$util.toJson($ctx.result)`)

	// Missing endpoint → fail closed.
	w("config.json", `{
	  "dataSources": [{"name":"search","type":"opensearch"}],
	  "resolvers": [{"type":"Query","field":"find","dataSource":"search","request":"req.vtl","response":"resp.vtl"}]
	}`)
	if _, err := Load(dir, nil); err == nil {
		t.Fatal("opensearch with no endpoint must fail Load")
	}

	// Endpoint present → loads (basic auth optional, none set here).
	w("config.json", `{
	  "dataSources": [{"name":"search","type":"opensearch","endpoint":"https://os.example.com"}],
	  "resolvers": [{"type":"Query","field":"find","dataSource":"search","request":"req.vtl","response":"resp.vtl"}]
	}`)
	if _, err := Load(dir, nil); err != nil {
		t.Fatalf("opensearch with an endpoint should load: %v", err)
	}
}
