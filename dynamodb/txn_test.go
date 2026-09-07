package dynamodb

import (
	"errors"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

// ApplyUpdate is the transactional path's entry into the SAME update evaluator UpdateItem uses:
// arithmetic on the current value, key re-assertion, and create-if-absent.
func TestApplyUpdate_ArithmeticAndCreateIfAbsent(t *testing.T) {
	// existing item: bal 1 -> bal + 5 = 6, key re-asserted.
	got, err := ApplyUpdate(map[string]any{"bal": float64(1)}, map[string]any{"id": "x"}, Operation{
		"update": map[string]any{"expression": "SET bal = bal + :n", "expressionValues": map[string]any{":n": n("5")}},
	})
	if err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if got["bal"] != float64(6) {
		t.Errorf("bal = %v, want 6", got["bal"])
	}
	if got["id"] != "x" {
		t.Errorf("key attribute must be re-asserted: %v", got)
	}

	// absent item (nil current): create-if-absent, key present.
	got, err = ApplyUpdate(nil, map[string]any{"id": "new"}, Operation{
		"update": map[string]any{"expression": "SET hits = :one", "expressionValues": map[string]any{":one": n("1")}},
	})
	if err != nil {
		t.Fatalf("ApplyUpdate (absent): %v", err)
	}
	if got["hits"] != float64(1) || got["id"] != "new" {
		t.Errorf("create-if-absent = %v, want hits=1 id=new", got)
	}
}

// A failed condition on an Update surfaces the ErrConditionalCheckFailed sentinel (so the
// transaction path can map exactly that item to a ConditionalCheckFailed cancellation reason).
func TestApplyUpdate_ConditionFailSentinel(t *testing.T) {
	_, err := ApplyUpdate(map[string]any{"id": "x", "version": float64(1)}, map[string]any{"id": "x"}, Operation{
		"update":    map[string]any{"expression": "SET x = :x", "expressionValues": map[string]any{":x": n("9")}},
		"condition": map[string]any{"expression": "version = :expected", "expressionValues": map[string]any{":expected": n("5")}},
	})
	if !errors.Is(err, ErrConditionalCheckFailed) {
		t.Fatalf("a failed condition must be ErrConditionalCheckFailed, got %v", err)
	}
}

func TestEvalCondition(t *testing.T) {
	item := map[string]any{"id": "x", "v": float64(2)}
	// holds
	if ok, present, err := EvalCondition(item, Operation{"condition": map[string]any{"expression": "v = :x", "expressionValues": map[string]any{":x": n("2")}}}); err != nil || !present || !ok {
		t.Errorf("v=2 == 2 should hold: ok=%v present=%v err=%v", ok, present, err)
	}
	// fails
	if ok, present, err := EvalCondition(item, Operation{"condition": map[string]any{"expression": "v = :x", "expressionValues": map[string]any{":x": n("9")}}}); err != nil || !present || ok {
		t.Errorf("v=2 == 9 should fail: ok=%v present=%v err=%v", ok, present, err)
	}
	// attribute_not_exists against an absent (nil) item holds — the Put-if-absent guard.
	if ok, present, err := EvalCondition(nil, Operation{"condition": map[string]any{"expression": "attribute_not_exists(id)"}}); err != nil || !present || !ok {
		t.Errorf("attribute_not_exists on absent item should hold: ok=%v present=%v err=%v", ok, present, err)
	}
	// no condition block: present=false, ok=true (nothing to gate on).
	if ok, present, err := EvalCondition(item, Operation{}); err != nil || present || !ok {
		t.Errorf("no condition block: ok=%v present=%v err=%v, want true,false,nil", ok, present, err)
	}
}

func TestPlainKeyAndKeyID(t *testing.T) {
	typed := map[string]any{"id": s("abc")}
	pk := PlainKey(typed)
	if pk["id"] != "abc" {
		t.Errorf("PlainKey = %v, want id:abc", pk)
	}
	// PlainKey and KeyID agree (both un-marshal the same typed key).
	if KeyID(typed) != keyString(map[string]any{"id": "abc"}) {
		t.Errorf("KeyID(%v) = %q, want %q", typed, KeyID(typed), keyString(pk))
	}
}

// DocToItem strips the stored _id and normalizes BSON types (int32/int64 -> float64, nested docs)
// exactly as the mongo-wire read path does, so a document read over the documentdb path matches.
func TestDocToItem_NormalizesLikeMongoWire(t *testing.T) {
	doc := bson.M{
		"_id":  `{"id":"x"}`,
		"id":   "x",
		"bal":  int32(10),
		"big":  int64(20),
		"name": "alice",
		"meta": bson.M{"n": int32(3)},
	}
	item := DocToItem(doc)
	if _, ok := item["_id"]; ok {
		t.Errorf("_id must be stripped: %v", item)
	}
	if item["bal"] != float64(10) || item["big"] != float64(20) {
		t.Errorf("int normalization failed: bal=%v big=%v", item["bal"], item["big"])
	}
	if item["name"] != "alice" || item["id"] != "x" {
		t.Errorf("plain fields wrong: %v", item)
	}
	meta, ok := item["meta"].(map[string]any)
	if !ok || meta["n"] != float64(3) {
		t.Errorf("nested normalization failed: %v", item["meta"])
	}
}
