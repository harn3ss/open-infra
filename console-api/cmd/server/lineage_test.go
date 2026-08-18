package main

import (
	"encoding/json"
	"testing"
)

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func TestEndpointLabel(t *testing.T) {
	cases := []struct{ engine, host, db, want string }{
		{"postgres", "db.acme", "orders", "postgres db.acme/orders"},
		{"mysql", "10.0.0.5", "", "mysql 10.0.0.5"},
		{"", "db.acme", "orders", "db.acme/orders"},
		{"postgres", "", "", "postgres"},
		{"", "", "", "(unknown)"},
	}
	for _, c := range cases {
		if got := endpointLabel(c.engine, c.host, c.db); got != c.want {
			t.Errorf("endpointLabel(%q,%q,%q) = %q, want %q", c.engine, c.host, c.db, got, c.want)
		}
	}
}

func TestReplicationFlow_UsesSiteAB(t *testing.T) {
	// The load-bearing regression test: replication endpoints live under spec.siteA / spec.siteB.
	f, ok := replicationFlow(raw(`{
		"metadata": {"namespace":"prod","name":"orders-repl"},
		"spec": {
			"siteA": {"engine":"postgres","host":"east.db","database":"orders"},
			"siteB": {"engine":"postgres","host":"west.db","database":"orders"}
		}
	}`))
	if !ok {
		t.Fatal("replicationFlow returned ok=false for a valid item")
	}
	if f.Kind != "Replication" || f.Origin != "Replication prod/orders-repl" {
		t.Fatalf("wrong meta: %+v", f)
	}
	if len(f.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(f.Edges))
	}
	e := f.Edges[0]
	if e.From != "postgres east.db/orders" || e.To != "postgres west.db/orders" {
		t.Fatalf("wrong edge: from=%q to=%q (siteA/siteB not read?)", e.From, e.To)
	}
	if e.Type != "replication (bidirectional)" {
		t.Fatalf("wrong edge type: %q", e.Type)
	}
}

func TestReplicationFlow_WrongShapeDropsEndpoints(t *testing.T) {
	// The old bug read a sites[] array; with that shape (and no siteA/siteB) the endpoints must NOT be
	// populated — proving the parser reads siteA/siteB, not sites[]. Edge is still emitted (as unknown),
	// which is what surfaces the misconfiguration rather than silently dropping the whole flow.
	f, ok := replicationFlow(raw(`{
		"metadata": {"namespace":"prod","name":"legacy"},
		"spec": {"sites": [{"engine":"postgres","host":"east.db"},{"engine":"postgres","host":"west.db"}]}
	}`))
	if !ok {
		t.Fatal("ok=false")
	}
	if f.Edges[0].From != "(unknown)" || f.Edges[0].To != "(unknown)" {
		t.Fatalf("sites[] must not populate endpoints, got from=%q to=%q", f.Edges[0].From, f.Edges[0].To)
	}
}

func TestMigrationFlow(t *testing.T) {
	f, ok := migrationFlow(raw(`{
		"metadata": {"namespace":"dev","name":"lift"},
		"spec": {
			"source": {"engine":"mysql","host":"legacy.db","database":"app"},
			"target": {"engine":"postgres","host":"new.db","database":"app"}
		}
	}`))
	if !ok || f.Kind != "Migration" {
		t.Fatalf("bad migration flow: ok=%v %+v", ok, f)
	}
	e := f.Edges[0]
	if e.From != "mysql legacy.db/app" || e.To != "postgres new.db/app" || e.Type != "migration" {
		t.Fatalf("wrong migration edge: %+v", e)
	}
}

func TestStreamFlow(t *testing.T) {
	f, ok := streamFlow(raw(`{
		"metadata": {"namespace":"prod","name":"orders-cdc"},
		"spec": {"source": {"engine":"postgres","host":"east.db","database":"orders"}}
	}`))
	if !ok {
		t.Fatal("ok=false")
	}
	e := f.Edges[0]
	if e.From != "postgres east.db/orders" || e.To != "jetstream:orders-cdc" || e.Type != "stream" {
		t.Fatalf("wrong stream edge: %+v", e)
	}
}

func TestDataFlowFlow(t *testing.T) {
	f, ok := dataFlowFlow(raw(`{
		"metadata": {"namespace":"prod","name":"mesh"},
		"spec": {
			"nodes": [{"name":"pg","role":"database","engine":"postgres"},{"name":"bus","role":"topic"}],
			"edges": [{"from":"pg","to":"bus","type":"stream"},{"from":"bus","to":"pg"}]
		}
	}`))
	if !ok || len(f.Nodes) != 2 || len(f.Edges) != 2 {
		t.Fatalf("bad dataflow: ok=%v nodes=%d edges=%d", ok, len(f.Nodes), len(f.Edges))
	}
	if f.Nodes[0].Engine != "postgres" || f.Nodes[0].Role != "database" {
		t.Fatalf("wrong node: %+v", f.Nodes[0])
	}
	// A typed edge keeps its type; an untyped edge falls back to "edge".
	if f.Edges[0].Type != "stream" || f.Edges[1].Type != "edge" {
		t.Fatalf("wrong edge types: %q, %q", f.Edges[0].Type, f.Edges[1].Type)
	}
}

func TestParsers_RejectMalformed(t *testing.T) {
	bad := raw(`{"metadata": not json`)
	if _, ok := dataFlowFlow(bad); ok {
		t.Error("dataFlowFlow accepted malformed JSON")
	}
	if _, ok := migrationFlow(bad); ok {
		t.Error("migrationFlow accepted malformed JSON")
	}
	if _, ok := replicationFlow(bad); ok {
		t.Error("replicationFlow accepted malformed JSON")
	}
	if _, ok := streamFlow(bad); ok {
		t.Error("streamFlow accepted malformed JSON")
	}
}
