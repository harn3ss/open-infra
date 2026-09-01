package dynamodb

import (
	"reflect"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

// The BSON→plain normalization is what makes a FerretDB-stored item read back the same shape a
// resolver wrote — the durable-path analog of MemStore's fidelity. Pure, no live DB.
func TestDocToItem_StripsIdAndNormalizes(t *testing.T) {
	doc := bson.M{
		"_id":  "todo#1",  // Mongo identity — must be stripped
		"id":   "1",       // the item's own key attribute — kept
		"name": "Ada",     // string kept
		"age":  int32(36), // BSON int → float64
		"tags": bson.A{"a", int64(2)},
		"meta": bson.M{"n": int32(5)},
	}
	got := docToItem(doc)
	want := map[string]any{
		"id":   "1",
		"name": "Ada",
		"age":  float64(36),
		"tags": []any{"a", float64(2)},
		"meta": map[string]any{"n": float64(5)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("docToItem not faithful:\n got %v\nwant %v", got, want)
	}
}

// keyString must be a stable identity for a key map regardless of Go map iteration order (so the
// same primary key always maps to the same Mongo _id).
func TestKeyString_Deterministic(t *testing.T) {
	a := keyString(map[string]any{"pk": "x", "sk": float64(2)})
	b := keyString(map[string]any{"sk": float64(2), "pk": "x"})
	if a != b {
		t.Fatalf("keyString not order-stable: %q vs %q", a, b)
	}
}
