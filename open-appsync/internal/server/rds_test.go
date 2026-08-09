package server

import (
	"os"
	"path/filepath"
	"testing"
)

// An `rds` data source loads its DSN from the Secret-injected env (APPSYNC_RDS_DSN_<NAME>); a missing
// DSN fails closed at load rather than serving a half-configured API.
func TestServer_RDSDataSource(t *testing.T) {
	dir := t.TempDir()
	w := func(n, c string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("config.json", `{
	  "dataSources": [{"name":"orders-db","type":"rds"}],
	  "resolvers": [{"type":"Query","field":"getOrder","dataSource":"orders-db","request":"req.vtl","response":"resp.vtl"}]
	}`)
	w("req.vtl", `{"version":"2018-05-29","statements":["SELECT 1"]}`)
	w("resp.vtl", `$util.toJson($ctx.result)`)

	// Missing DSN → Load fails closed.
	if _, err := Load(dir, nil); err == nil {
		t.Fatal("rds data source with no DSN env must fail Load")
	}

	// DSN present (name "orders-db" → env suffix ORDERS_DB) → Load succeeds (sql.Open is lazy; no connect).
	t.Setenv("APPSYNC_RDS_DSN_ORDERS_DB", "postgres://u:p@localhost:5432/db?sslmode=disable")
	if _, err := Load(dir, nil); err != nil {
		t.Fatalf("rds data source with a DSN should load: %v", err)
	}
}

func TestRDSEnvKey(t *testing.T) {
	cases := map[string]string{"orders-db": "ORDERS_DB", "Users": "USERS", "a.b-c": "A_B_C"}
	for in, want := range cases {
		if got := rdsEnvKey(in); got != want {
			t.Errorf("rdsEnvKey(%q) = %q, want %q", in, got, want)
		}
	}
}
