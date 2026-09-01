package dynamodb

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// typed values as a VTL request template emits them ($util.dynamodb.toDynamoDBJson).
func s(v string) map[string]any    { return map[string]any{"S": v} }
func n(v string) map[string]any    { return map[string]any{"N": v} }
func key(id string) map[string]any { return map[string]any{"id": s(id)} }

func put(t *testing.T, st *MemStore, id string, attrs map[string]any) {
	t.Helper()
	typed := map[string]any{}
	for k, v := range attrs {
		typed[k] = v
	}
	_, err := st.Execute(context.Background(), runtime.Operation{
		"operation": "PutItem", "key": key(id), "attributeValues": typed,
	})
	if err != nil {
		t.Fatalf("seed put %s: %v", id, err)
	}
}

func TestUpdateItem_SetRemoveArithmetic(t *testing.T) {
	st := NewMemStore()
	put(t, st, "u1", map[string]any{"name": s("Alice"), "version": n("1"), "stale": s("x")})

	res, err := st.Execute(context.Background(), runtime.Operation{
		"operation": "UpdateItem",
		"key":       key("u1"),
		"update": map[string]any{
			"expression":       "SET #n = :name, version = version + :one REMOVE stale",
			"expressionNames":  map[string]any{"#n": "name"},
			"expressionValues": map[string]any{":name": s("Alice2"), ":one": n("1")},
		},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	item := res.(map[string]any)
	if item["name"] != "Alice2" {
		t.Errorf("SET name = %v, want Alice2", item["name"])
	}
	if item["version"] != float64(2) {
		t.Errorf("increment version = %v, want 2", item["version"])
	}
	if _, ok := item["stale"]; ok {
		t.Errorf("REMOVE stale failed: %v", item)
	}
}

func TestUpdateItem_IfNotExistsAndAdd(t *testing.T) {
	st := NewMemStore()
	// update a non-existent item: create-if-absent + if_not_exists default + ADD from zero.
	res, err := st.Execute(context.Background(), runtime.Operation{
		"operation": "UpdateItem",
		"key":       key("counter"),
		"update": map[string]any{
			"expression":       "SET created = if_not_exists(created, :now) ADD hits :one",
			"expressionValues": map[string]any{":now": s("2026-01-01"), ":one": n("1")},
		},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	item := res.(map[string]any)
	if item["created"] != "2026-01-01" {
		t.Errorf("if_not_exists created = %v", item["created"])
	}
	if item["hits"] != float64(1) {
		t.Errorf("ADD hits = %v, want 1", item["hits"])
	}
	if item["id"] != "counter" {
		t.Errorf("key attribute must be present: %v", item)
	}
}

func TestUpdateItem_ConditionFailIsLoud(t *testing.T) {
	st := NewMemStore()
	put(t, st, "u1", map[string]any{"version": n("1")})
	// optimistic-concurrency guard that fails.
	_, err := st.Execute(context.Background(), runtime.Operation{
		"operation": "UpdateItem",
		"key":       key("u1"),
		"update":    map[string]any{"expression": "SET x = :x", "expressionValues": map[string]any{":x": n("9")}},
		"condition": map[string]any{"expression": "version = :expected", "expressionValues": map[string]any{":expected": n("5")}},
	})
	if err == nil {
		t.Fatal("a failed condition must error (ConditionalCheckFailed), not silently apply")
	}
	// attribute_not_exists on an existing item also fails.
	_, err = st.Execute(context.Background(), runtime.Operation{
		"operation": "UpdateItem", "key": key("u1"),
		"update":    map[string]any{"expression": "SET x = :x", "expressionValues": map[string]any{":x": n("9")}},
		"condition": map[string]any{"expression": "attribute_not_exists(id)"},
	})
	if err == nil {
		t.Fatal("attribute_not_exists on an existing item must fail the condition")
	}
}

func TestUpdateItem_UnsupportedActionFailsLoud(t *testing.T) {
	st := NewMemStore()
	put(t, st, "u1", map[string]any{"tags": map[string]any{"SS": []any{"a"}}})
	_, err := st.Execute(context.Background(), runtime.Operation{
		"operation": "UpdateItem", "key": key("u1"),
		"update": map[string]any{"expression": "DELETE tags :t", "expressionValues": map[string]any{":t": map[string]any{"SS": []any{"a"}}}},
	})
	if err == nil {
		t.Fatal("an unsupported update action (DELETE) must fail loud, not be silently ignored")
	}
}

func TestQuery_PartitionAndSort(t *testing.T) {
	st := NewMemStore()
	// a chat-message table: pk=room, sk=ts.
	seed := func(id, room string, ts string) {
		put(t, st, id, map[string]any{"room": s(room), "ts": n(ts), "body": s("m" + id)})
	}
	seed("1", "general", "100")
	seed("2", "general", "300")
	seed("3", "general", "200")
	seed("4", "random", "150")

	// key-condition: room = :r AND ts BETWEEN :lo AND :hi, ascending.
	res, err := st.Execute(context.Background(), runtime.Operation{
		"operation": "Query",
		"query": map[string]any{
			"expression":       "room = :r AND ts BETWEEN :lo AND :hi",
			"expressionValues": map[string]any{":r": s("general"), ":lo": n("100"), ":hi": n("250")},
		},
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	items := res.(map[string]any)["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("expected ts in [100,250] for general = 2 items, got %d", len(items))
	}
	// sorted ascending by ts: 100 then 200.
	if items[0].(map[string]any)["ts"] != float64(100) || items[1].(map[string]any)["ts"] != float64(200) {
		t.Errorf("results not sorted ascending by sort key: %v", items)
	}
}

func TestQuery_DescendingBeginsWithAndFilter(t *testing.T) {
	st := NewMemStore()
	put(t, st, "1", map[string]any{"room": s("g"), "ts": n("1"), "kind": s("chat"), "flag": s("keep")})
	put(t, st, "2", map[string]any{"room": s("g"), "ts": n("2"), "kind": s("chat"), "flag": s("drop")})
	put(t, st, "3", map[string]any{"room": s("g"), "ts": n("3"), "kind": s("sys"), "flag": s("keep")})

	res, err := st.Execute(context.Background(), runtime.Operation{
		"operation": "Query",
		"query": map[string]any{
			"expression":       "room = :r",
			"expressionValues": map[string]any{":r": s("g")},
		},
		"filter": map[string]any{
			"expression":       "flag = :k AND begins_with(kind, :c)",
			"expressionValues": map[string]any{":k": s("keep"), ":c": s("cha")},
		},
		"scanIndexForward": false,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	items := res.(map[string]any)["items"].([]any)
	// only item 1 (kind=chat, flag=keep). item 3 is sys, item 2 is drop.
	if len(items) != 1 || items[0].(map[string]any)["id"] != "1" {
		t.Fatalf("filter should leave only item 1, got %v", items)
	}
}

func TestQuery_Pagination(t *testing.T) {
	st := NewMemStore()
	for _, ts := range []string{"1", "2", "3", "4", "5"} {
		put(t, st, ts, map[string]any{"room": s("g"), "ts": n(ts)})
	}
	q := func(token any) map[string]any {
		op := runtime.Operation{
			"operation": "Query",
			"query":     map[string]any{"expression": "room = :r", "expressionValues": map[string]any{":r": s("g")}},
			"limit":     float64(2),
		}
		if token != nil {
			op["nextToken"] = token
		}
		res, err := st.Execute(context.Background(), op)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		return res.(map[string]any)
	}
	p1 := q(nil)
	if len(p1["items"].([]any)) != 2 || p1["nextToken"] == nil {
		t.Fatalf("page 1 should have 2 items + a nextToken: %v", p1)
	}
	p2 := q(p1["nextToken"])
	if len(p2["items"].([]any)) != 2 || p2["nextToken"] == nil {
		t.Fatalf("page 2 should have 2 items + a nextToken: %v", p2)
	}
	p3 := q(p2["nextToken"])
	if len(p3["items"].([]any)) != 1 {
		t.Fatalf("page 3 should have the last item: %v", p3)
	}
	if p3["nextToken"] != nil {
		t.Fatalf("no nextToken on the final page: %v", p3)
	}
}

// A GSI query is just a key-condition on the index's attributes; no predefined index needed.
func TestQuery_ByGSIAttributes(t *testing.T) {
	st := NewMemStore()
	put(t, st, "u1", map[string]any{"email": s("a@x.com"), "name": s("A")})
	put(t, st, "u2", map[string]any{"email": s("b@x.com"), "name": s("B")})
	res, err := st.Execute(context.Background(), runtime.Operation{
		"operation": "Query",
		"index":     "by-email",
		"query":     map[string]any{"expression": "email = :e", "expressionValues": map[string]any{":e": s("b@x.com")}},
	})
	if err != nil {
		t.Fatalf("gsi query: %v", err)
	}
	items := res.(map[string]any)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != "u2" {
		t.Fatalf("GSI query by email should return u2, got %v", items)
	}
}
