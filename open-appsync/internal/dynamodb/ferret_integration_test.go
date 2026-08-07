//go:build integration

// Live FerretDB/MongoDB round-trip for FerretStore. Not run in normal CI (needs a live server);
// run against a cluster FerretDB or a local Mongo with:
//
//	FERRET_TEST_URI="mongodb://user:pass@host:27017" go test -tags integration./internal/dynamodb/
package dynamodb

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestFerretStore_RoundTrip(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI to run the live FerretDB round-trip")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(ctx)
	coll := client.Database("open_appsync_probe").Collection("todos_" + time.Now().Format("150405"))
	defer coll.Drop(ctx)

	s := NewFerretStore(coll)

	// PutItem (typed key + attributeValues, as a request template emits).
	put := map[string]any{
		"operation":       "PutItem",
		"key":             map[string]any{"id": map[string]any{"S": "1"}},
		"attributeValues": map[string]any{"name": map[string]any{"S": "Ada"}, "age": map[string]any{"N": "36"}},
	}
	created, err := s.Execute(ctx, put)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	want := map[string]any{"id": "1", "name": "Ada", "age": float64(36)}
	if !reflect.DeepEqual(created, want) {
		t.Fatalf("put result: %v want %v", created, want)
	}

	// GetItem reads it back through un-marshalling.
	got, err := s.Execute(ctx, map[string]any{"operation": "GetItem", "key": map[string]any{"id": map[string]any{"S": "1"}}})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("get round-trip: %v want %v", got, want)
	}

	// DeleteItem then a miss returns null.
	if _, err := s.Execute(ctx, map[string]any{"operation": "DeleteItem", "key": map[string]any{"id": map[string]any{"S": "1"}}}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	gone, err := s.Execute(ctx, map[string]any{"operation": "GetItem", "key": map[string]any{"id": map[string]any{"S": "1"}}})
	if err != nil || gone != nil {
		t.Fatalf("expected nil after delete, got %v (err %v)", gone, err)
	}
}
