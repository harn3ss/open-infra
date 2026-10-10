package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildRecoveryCluster(t *testing.T) {
	var s cnpgClusterSpec
	s.Spec.ImageName = "ghcr.io/x/pg:16"
	s.Spec.Storage.Size = "10Gi"
	s.Spec.Storage.StorageClass = "local-path"
	s.Spec.PostgreSQL = map[string]any{"shared_preload_libraries": []any{"pg_stat_statements"}}

	m := buildRecoveryCluster("team-a", "shop-db", "shop-db-backup", "shop-db-restored-123", "2026-10-10T12:00:00Z", s)
	b, _ := json.Marshal(m)
	got := string(b)

	for _, want := range []string{
		`"kind":"Cluster"`,
		`"name":"shop-db-restored-123"`,
		`"namespace":"team-a"`,
		`"imageName":"ghcr.io/x/pg:16"`,
		`"size":"10Gi"`,
		// recovery to the target time from the source archive
		`"targetTime":"2026-10-10T12:00:00Z"`,
		`"source":"shop-db"`,
		`"barmanObjectName":"shop-db-backup"`,
		`"serverName":"shop-db"`,
		`"shared_preload_libraries"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("recovery cluster manifest missing %q\ngot: %s", want, got)
		}
	}

	// A recovery cluster must NOT re-archive WAL (no isWALArchiver plugin of its own) — it only reads.
	if strings.Contains(got, "isWALArchiver") {
		t.Errorf("recovery cluster must not be a WAL archiver; got: %s", got)
	}

	// Storage defaults when the source omitted them.
	var empty cnpgClusterSpec
	d := buildRecoveryCluster("ns", "a-db", "a-db-backup", "a-db-restored-1", "2026-10-10T00:00:00Z", empty)
	db, _ := json.Marshal(d)
	if !strings.Contains(string(db), `"size":"5Gi"`) || !strings.Contains(string(db), `"storageClass":"local-path"`) {
		t.Errorf("expected storage defaults (5Gi/local-path) when source omits them; got: %s", string(db))
	}
}
