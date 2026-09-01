package probe

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// Live AppSync resolver round-trips for UpdateItem and Query — the operations the DynamoDB
// characterization named as the gating gap. A REAL VTL request/response resolver runs the full
// request -> execute -> response cycle against the Dynamo-shaped store and returns the GraphQL
// result AWS would. The same resolver runs unchanged against the FerretDB binding (integration
// test).
func TestResolverProbe_UpdateAndQuery(t *testing.T) {
	e := engine()
	store := dynamodb.NewMemStore()

	// Seed three messages in "general" + one in "random" (direct store puts, so ids are distinct;
	// autoId is pinned in the probe engine).
	seed := func(id, room string, ts float64, body string) {
		if _, err := store.Execute(context.Background(), runtime.Operation{
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
	seed("x1", "random", 1, "noise")

	// Query resolver: messages in "general".
	queryRoom := vtlResolver(t, e, "query.request.vtl", "response.vtl", store)
	qres, err := queryRoom.Resolve(context.Background(), map[string]any{"args": map[string]any{"room": "general"}})
	if err != nil {
		t.Fatalf("queryRoom: %v", err)
	}
	items, ok := qres.(map[string]any)["items"].([]any)
	if !ok || len(items) != 3 {
		t.Fatalf("query 'general' should return 3 messages, got %v", qres)
	}
	for _, it := range items {
		if it.(map[string]any)["room"] != "general" {
			t.Fatalf("query returned a non-general message: %v", it)
		}
	}

	// UpdateItem resolver: edit m2's body and bump its version (ADD from absent -> 1).
	updateMsg := vtlResolver(t, e, "updateitem.request.vtl", "response.vtl", store)
	ures, err := updateMsg.Resolve(context.Background(), map[string]any{"args": map[string]any{"id": "m2", "body": "edited"}})
	if err != nil {
		t.Fatalf("updateMsg: %v", err)
	}
	updated := ures.(map[string]any)
	if updated["body"] != "edited" {
		t.Errorf("UpdateItem SET body = %v, want edited", updated["body"])
	}
	if updated["version"] != float64(1) {
		t.Errorf("UpdateItem ADD version = %v, want 1", updated["version"])
	}

	// The edit persisted (read it back through the store).
	got, err := store.Execute(context.Background(), runtime.Operation{
		"operation": "GetItem", "key": map[string]any{"id": map[string]any{"S": "m2"}},
	})
	if err != nil || got.(map[string]any)["body"] != "edited" {
		t.Fatalf("update did not persist: %v (err %v)", got, err)
	}

	// UpdateItem's condition is fail-closed: updating a nonexistent id (attribute_exists(id)) errors.
	if _, err := updateMsg.Resolve(context.Background(), map[string]any{"args": map[string]any{"id": "ghost", "body": "x"}}); err == nil {
		t.Error("UpdateItem with attribute_exists(id) on a missing item must fail, not create it")
	}
}
