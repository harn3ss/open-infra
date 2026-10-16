package dynamodb

import (
	"context"
	"encoding/base64"
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

// TestBinaryAttributes_RoundTrip covers the DynamoDB B/BS types that fromDynamoDB used to drop
// through to fromMap (storing the {"B":"<base64>"} wrapper AS data — a silent fake). Neutral
// placeholders only: a `payload` attribute and a few bytes.
func TestBinaryAttributes_RoundTrip(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xff, 0xfe, 0x42}
	b64 := base64.StdEncoding.EncodeToString(raw)

	// B: typed → plain decodes to the actual bytes, not the wrapper map.
	got := fromDynamoDB(map[string]any{"B": b64})
	gb, ok := got.([]byte)
	if !ok {
		t.Fatalf("B did not decode to []byte, got %T (%v) — the wrapper would leak as data", got, got)
	}
	if !reflect.DeepEqual(gb, raw) {
		t.Errorf("B bytes mismatch: got %v want %v", gb, raw)
	}

	// B: plain → typed re-dresses []byte as {"B": base64}.
	if rt := ToDynamoDB(raw); !reflect.DeepEqual(rt, map[string]any{"B": b64}) {
		t.Errorf("ToDynamoDB([]byte) = %v, want {B:%s}", rt, b64)
	}

	// Full round trip through an item attribute.
	item := map[string]any{"payload": map[string]any{"B": b64}}
	plain := fromMap(item)
	if _, ok := plain["payload"].([]byte); !ok {
		t.Fatalf("payload not decoded to []byte: %T", plain["payload"])
	}
	back := ToItem(map[string]any{"payload": plain["payload"]})
	if !reflect.DeepEqual(back["payload"], map[string]any{"B": b64}) {
		t.Errorf("payload round trip = %v, want {B:%s}", back["payload"], b64)
	}

	// BS: a set of base64 → a list of []byte (no longer the wrapper-as-data).
	bsGot := fromDynamoDB(map[string]any{"BS": []any{b64, base64.StdEncoding.EncodeToString([]byte("xy"))}})
	bsList, ok := bsGot.([]any)
	if !ok || len(bsList) != 2 {
		t.Fatalf("BS did not decode to a 2-element list: %T %v", bsGot, bsGot)
	}
	if _, ok := bsList[0].([]byte); !ok {
		t.Errorf("BS element 0 not []byte: %T", bsList[0])
	}
}
