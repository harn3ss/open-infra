// Transaction-path helpers shared with the aws-shim's DynamoDB front door.
//
// The aws-shim implements DynamoDB's TransactWriteItems / TransactGetItems by dropping to the
// Postgres (documentdb extension) behind FerretDB — FerretDB has no Mongo multi-document
// transactions, but the documentdb_api functions the mongo path also uses are transactional under a
// single Postgres BEGIN/COMMIT. An Update or ConditionExpression INSIDE such a transaction must be
// evaluated with the SAME semantics a standalone UpdateItem uses, or a resolver and a transactional
// SDK call would diverge. These thin exports expose the exact update/condition evaluator the store's
// UpdateItem path runs (updateItem / evalBool), so the shim reuses it verbatim rather than
// re-implementing it — the two can never drift.
package dynamodb

import (
	"errors"

	"go.mongodb.org/mongo-driver/bson"
)

// ErrConditionalCheckFailed is returned when a condition (an UpdateItem/Put/Delete ConditionExpression
// or a transactional ConditionCheck) evaluates false — DynamoDB's ConditionalCheckFailedException.
// Callers use errors.Is to tell a genuine condition failure (a 400 semantic, and inside a
// transaction a per-item cancellation reason) apart from an internal or validation error. Its
// message keeps the "ConditionalCheck" substring the shim's mapStoreError already keys off.
var ErrConditionalCheckFailed = errors.New("dynamodb: ConditionalCheckFailedException")

// ApplyUpdate is the shared UpdateItem computation the FerretStore UpdateItem path runs: evaluate
// op's optional "condition" block against the current item, apply op's "update" block (SET / REMOVE
// / ADD), re-assert the key attributes, and return the new plain-value item. `current` is the item's
// current plain-value state (nil / empty for an absent item, so attribute_not_exists is true and the
// update creates-if-absent, exactly as a standalone UpdateItem does). A failed condition returns
// ErrConditionalCheckFailed. The aws-shim calls this inside its Postgres transaction so an Update
// inside TransactWriteItems is byte-for-byte the same as a standalone UpdateItem.
func ApplyUpdate(current, key map[string]any, op Operation) (map[string]any, error) {
	if current == nil {
		current = map[string]any{}
	}
	return updateItem(current, key, op)
}

// EvalCondition evaluates op's "condition" block against the current plain-value item (what a
// transactional ConditionCheck, or a conditional Put/Delete, gates the whole transaction on). It
// uses the same boolean evaluator UpdateItem's condition uses. present is false when op carries no
// condition block; when present, ok reports whether the condition held.
func EvalCondition(current map[string]any, op Operation) (ok, present bool, err error) {
	if current == nil {
		current = map[string]any{}
	}
	b, present, err := readBlock(op, "condition")
	if err != nil || !present {
		return true, present, err
	}
	ok, err = evalBool(current, b)
	return ok, true, err
}

// PlainKey un-marshals a DynamoDB-typed key ({"id":{"S":"x"}}) to the plain-value key the update
// evaluator re-asserts and the _id derivation uses. (KeyID renders the same key to the stored _id
// string; the two agree because both go through the same un-marshalling.)
func PlainKey(keyAV any) map[string]any { return plainMap(fromDynamoDB(keyAV)) }

// DocToItem strips the stored _id and normalizes a BSON-decoded document to the plain-value shape
// the rest of the engine uses (integer types → float64, nested docs/arrays recursively). Shared so a
// document read over the documentdb (Postgres / transaction) path normalizes identically to one read
// over the mongo wire — the transactional reads decode raw BSON with the mongo driver and hand the
// result here.
func DocToItem(doc bson.M) map[string]any { return docToItem(doc) }
