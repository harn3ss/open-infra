package dynamodb

import (
	"context"
	"reflect"
	"testing"
)

func TestFromDynamoDB_TypedShapes(t *testing.T) {
	cases := []struct {
		typed any
		want  any
	}{
		{map[string]any{"S": "hello"}, "hello"},
		{map[string]any{"N": "5"}, float64(5)},
		{map[string]any{"N": "3.5"}, 3.5},
		{map[string]any{"BOOL": true}, true},
		{map[string]any{"NULL": true}, nil},
		{map[string]any{"L": []any{map[string]any{"S": "a"}, map[string]any{"N": "1"}}}, []any{"a", float64(1)}},
		{map[string]any{"M": map[string]any{"id": map[string]any{"S": "x"}, "n": map[string]any{"N": "2"}}},
			map[string]any{"id": "x", "n": float64(2)}},
	}
	for _, c := range cases {
		if got := fromDynamoDB(c.typed); !reflect.DeepEqual(got, c.want) {
			t.Errorf("fromDynamoDB(%v) = %v, want %v", c.typed, got, c.want)
		}
	}
}

// The store operates in plain-value space: a PutItem with a typed key + attributeValues stores a
// plain item, and GetItem with the typed key returns it. (Mirrors the AppSync DynamoDB data source.)
func TestMemStore_PutGetDelete(t *testing.T) {
	s := NewMemStore()
	put := map[string]any{
		"operation":       "PutItem",
		"key":             map[string]any{"id": map[string]any{"S": "1"}},
		"attributeValues": map[string]any{"name": map[string]any{"S": "Ada"}},
	}
	if _, err := s.Execute(context.Background(), put); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, _ := s.Execute(context.Background(), map[string]any{"operation": "GetItem", "key": map[string]any{"id": map[string]any{"S": "1"}}})
	if !reflect.DeepEqual(got, map[string]any{"id": "1", "name": "Ada"}) {
		t.Fatalf("get: %v", got)
	}
	if _, err := s.Execute(context.Background(), map[string]any{"operation": "DeleteItem", "key": map[string]any{"id": map[string]any{"S": "1"}}}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	gone, _ := s.Execute(context.Background(), map[string]any{"operation": "GetItem", "key": map[string]any{"id": map[string]any{"S": "1"}}})
	if gone != nil {
		t.Fatalf("expected nil after delete, got %v", gone)
	}
}

func TestMemStore_UnknownOperation(t *testing.T) {
	if _, err := NewMemStore().Execute(context.Background(), map[string]any{"operation": "Query"}); err == nil {
		t.Fatal("Query is not in slice 1 — must return an honest not-implemented error, not silently succeed")
	}
}
