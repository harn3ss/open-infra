package server

import (
	"os"
	"path/filepath"
	"testing"
)

// An eventbridge data source needs the NATS bus; with neither NATS_URL nor an endpoint it fails closed
// at load rather than serving a publisher that can't reach a bus. (The publish behavior itself is
// covered by internal/eventbridgesource against a fake publisher.)
func TestServer_EventBridgeNeedsNats(t *testing.T) {
	dir := t.TempDir()
	w := func(n, c string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("config.json", `{
	  "dataSources": [{"name":"bus","type":"eventbridge"}],
	  "resolvers": [{"type":"Mutation","field":"emit","dataSource":"bus","request":"req.vtl","response":"resp.vtl"}]
	}`)
	w("req.vtl", `{"operation":"PutEvents","events":[]}`)
	w("resp.vtl", `$util.toJson($ctx.result)`)

	t.Setenv("NATS_URL", "") // explicitly absent
	if _, err := Load(dir, nil); err == nil {
		t.Fatal("eventbridge with no NATS must fail Load")
	}
}
