// DynamoDB transactions for the aws-shim front door.
//
// FerretDB has no Mongo multi-document transactions, so an atomic multi-item write drops to the
// Postgres (documentdb extension) behind the SAME FerretDB: one BEGIN/COMMIT wrapping
// documentdb_api.update (a Put, as an upsert-replace) and documentdb_api.delete (a Delete). Those
// are the exact functions FerretDB itself calls, writing the exact document shape PutDoc produces
// (dynamodb.PutDoc), so a transactional write is read-consistent over the mongo wire — verified
// live (a documentdb_api write appears immediately through FerretDB, same _id and fields).
//
// Honest v1 scope: Put and Delete commit all-or-nothing across items and tables. Update
// expressions and ConditionExpression INSIDE a transaction are not yet honored — and rather than
// silently ignore a condition (which would break the one guarantee a transaction exists to give),
// such an item is REFUSED up front, before any write. This closes "no transactions at all" with a
// correct atomic commit, not a fake.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/harn3ss/open-infra/dynamodb"
)

func (h *dynamoHandler) transactWriteItems(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	if h.pg == nil {
		writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
			"transactions require the documentdb Postgres backend (set MONGO_PG_URI on the shim)")
		return
	}
	items, ok := body["TransactItems"].([]any)
	if !ok || len(items) == 0 {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "TransactItems must be a non-empty list.")
		return
	}
	if len(items) > 100 {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "A transaction cannot contain more than 100 items.")
		return
	}

	// A documentdb_api call to make once the whole transaction has validated.
	type call struct {
		fn  string // "update" | "delete"
		arg string // the Mongo command as JSON (cast to bson)
	}
	// Build every call up front, so a bad or unsupported item refuses BEFORE we open a
	// transaction — nothing is ever half-applied.
	var calls []call
	reject := func(msg string) {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, msg)
	}
	for _, raw := range items {
		it, _ := raw.(map[string]any)
		put, hasPut := it["Put"].(map[string]any)
		del, hasDel := it["Delete"].(map[string]any)
		_, hasUpd := it["Update"]
		_, hasCC := it["ConditionCheck"]
		switch {
		case hasUpd:
			reject("Update inside TransactWriteItems is not yet supported (Put and Delete are) — use a standalone UpdateItem.")
			return
		case hasCC:
			reject("ConditionCheck inside a transaction is not yet supported.")
			return
		case hasPut:
			if _, cond := put["ConditionExpression"]; cond {
				reject("ConditionExpression inside a transaction is not yet supported — refusing rather than not enforcing the condition.")
				return
			}
			table, _ := put["TableName"].(string)
			item, ok := put["Item"].(map[string]any)
			if table == "" || !ok {
				reject("a Put must name a TableName and an Item.")
				return
			}
			keyAttrs, ok := h.tableKeyAttrs(ctx, table)
			if !ok {
				writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Cannot do operations on a non-existent table: "+table)
				return
			}
			key, missing := keyFromItem(item, keyAttrs)
			if missing != "" {
				reject("One of the required keys was not given a value: " + missing)
				return
			}
			id, doc := dynamodb.PutDoc(key, item)
			docJSON, err := json.Marshal(doc)
			if err != nil {
				h.internal(w, requestID, err)
				return
			}
			idJSON, _ := json.Marshal(id)
			tblJSON, _ := json.Marshal(table)
			calls = append(calls, call{"update",
				fmt.Sprintf(`{"update":%s,"updates":[{"q":{"_id":%s},"u":%s,"upsert":true}]}`, tblJSON, idJSON, docJSON)})
		case hasDel:
			if _, cond := del["ConditionExpression"]; cond {
				reject("ConditionExpression inside a transaction is not yet supported — refusing rather than not enforcing the condition.")
				return
			}
			table, _ := del["TableName"].(string)
			keyAV, ok := del["Key"].(map[string]any)
			if table == "" || !ok {
				reject("a Delete must name a TableName and a Key.")
				return
			}
			idJSON, _ := json.Marshal(dynamodb.KeyID(keyAV))
			tblJSON, _ := json.Marshal(table)
			calls = append(calls, call{"delete",
				fmt.Sprintf(`{"delete":%s,"deletes":[{"q":{"_id":%s},"limit":1}]}`, tblJSON, idJSON)})
		default:
			reject("Each TransactItem must contain exactly one of Put or Delete.")
			return
		}
	}

	// Commit them all-or-nothing under one Postgres transaction.
	tx, err := h.pg.BeginTx(ctx, nil)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	for _, c := range calls {
		q := `SELECT documentdb_api.update($1, $2::documentdb_core.bson)`
		if c.fn == "delete" {
			q = `SELECT documentdb_api.delete($1, $2::documentdb_core.bson)`
		}
		if _, err := tx.ExecContext(ctx, q, h.dbName, c.arg); err != nil {
			_ = tx.Rollback()
			writeDynamoError(w, http.StatusBadRequest, "TransactionCanceledException", requestID,
				"Transaction cancelled, reasons: "+err.Error())
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeDynamoError(w, http.StatusInternalServerError, "InternalServerError", requestID, "commit failed: "+err.Error())
		return
	}
	writeDynamoJSON(w, requestID, map[string]any{})
}

// transactGetItems: a consistent multi-item read is a genuine snapshot guarantee, not just N
// point reads — doing it as separate GetItems would misrepresent it. That snapshot is a follow-on
// (a Postgres read transaction over documentdb_api), so it is refused honestly for now rather than
// faked. TransactWriteItems (the atomic-write half, the actual #104 gap) is implemented.
func (h *dynamoHandler) transactGetItems(_ context.Context, w http.ResponseWriter, requestID string, _ map[string]any) {
	writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
		"TransactGetItems (a consistent multi-item snapshot) is not yet supported; TransactWriteItems is. Use GetItem/BatchGetItem for non-snapshot reads.")
}
