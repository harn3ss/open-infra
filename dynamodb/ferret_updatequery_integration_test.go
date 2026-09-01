//go:build integration

// Live FerretDB round-trip for the UpdateItem and Query operations (the gating-gap ops). Run with:
//
//	FERRET_TEST_URI="mongodb://user:pass@host:27017" go test -tags integration ./internal/dynamodb/
package dynamodb

import (
	"context"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestFerretStore_UpdateAndQuery(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI to run the live FerretDB update/query round-trip")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(ctx)
	coll := client.Database("open_appsync_probe").Collection("uq_" + time.Now().Format("150405"))
	defer coll.Drop(ctx)
	s := NewFerretStore(coll)

	seed := func(id, room string, ts float64, body string) {
		if _, err := s.Execute(ctx, map[string]any{
			"operation":       "PutItem",
			"key":             map[string]any{"id": map[string]any{"S": id}},
			"attributeValues": map[string]any{"room": map[string]any{"S": room}, "ts": map[string]any{"N": ts}, "body": map[string]any{"S": body}},
		}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("m1", "general", 1, "hi")
	seed("m2", "general", 2, "there")
	seed("m3", "general", 3, "world")
	seed("x1", "random", 9, "noise")

	// Query: room=general AND ts BETWEEN 1 AND 2, ascending -> m1, m2.
	qres, err := s.Execute(ctx, map[string]any{
		"operation": "Query",
		"query": map[string]any{
			"expression":       "room = :r AND ts BETWEEN :lo AND :hi",
			"expressionValues": map[string]any{":r": map[string]any{"S": "general"}, ":lo": map[string]any{"N": 1}, ":hi": map[string]any{"N": 2}},
		},
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	items := qres.(map[string]any)["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["ts"] != float64(1) || items[1].(map[string]any)["ts"] != float64(2) {
		t.Fatalf("query BETWEEN [1,2] ascending should be m1,m2; got %v", items)
	}

	// UpdateItem m2: SET body + ADD version, guarded by attribute_exists.
	ures, err := s.Execute(ctx, map[string]any{
		"operation": "UpdateItem",
		"key":       map[string]any{"id": map[string]any{"S": "m2"}},
		"update":    map[string]any{"expression": "SET body = :b ADD version :one", "expressionValues": map[string]any{":b": map[string]any{"S": "edited"}, ":one": map[string]any{"N": 1}}},
		"condition": map[string]any{"expression": "attribute_exists(id)"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if ures.(map[string]any)["body"] != "edited" || ures.(map[string]any)["version"] != float64(1) {
		t.Fatalf("update result not faithful: %v", ures)
	}

	// Persisted?
	got, err := s.Execute(ctx, map[string]any{"operation": "GetItem", "key": map[string]any{"id": map[string]any{"S": "m2"}}})
	if err != nil || got.(map[string]any)["body"] != "edited" {
		t.Fatalf("update did not persist durably: %v (err %v)", got, err)
	}

	// Condition fail is loud (no such id).
	if _, err := s.Execute(ctx, map[string]any{
		"operation": "UpdateItem", "key": map[string]any{"id": map[string]any{"S": "ghost"}},
		"update":    map[string]any{"expression": "SET body = :b", "expressionValues": map[string]any{":b": map[string]any{"S": "x"}}},
		"condition": map[string]any{"expression": "attribute_exists(id)"},
	}); err == nil {
		t.Error("attribute_exists(id) on a missing item must fail loud, not create it")
	}
}
