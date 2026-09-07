// DynamoDB transactions for the aws-shim front door.
//
// FerretDB has no Mongo multi-document transactions, so an atomic multi-item write drops to the
// Postgres (documentdb extension) behind the SAME FerretDB: one BEGIN/COMMIT wrapping
// documentdb_api.update (a Put/Update, as an upsert-replace) and documentdb_api.delete (a Delete).
// Those are the exact functions FerretDB itself calls, writing the exact document shape PutDoc
// produces (dynamodb.PutDoc), so a transactional write is read-consistent over the mongo wire —
// verified live (a documentdb_api write appears immediately through FerretDB, same _id and fields).
//
// Update and ConditionExpression INSIDE a transaction are honored, not refused: the current row is
// read WITHIN the same Postgres transaction (documentdb_api.find_cursor_first_page), the condition /
// update expression is evaluated in Go by the SAME evaluator a standalone UpdateItem uses
// (dynamodb.ApplyUpdate / dynamodb.EvalCondition — never a re-implementation), and the write is
// applied in the same BEGIN/COMMIT. DynamoDB semantics: every condition is evaluated against the
// pre-transaction state (all reads precede all writes); if ANY item's condition fails the WHOLE
// transaction aborts (Postgres ROLLBACK — nothing partial) and the response is a
// TransactionCanceledException carrying per-item cancellation reasons (ConditionalCheckFailed / None).
// TransactGetItems returns a consistent multi-item snapshot (one REPEATABLE-READ read transaction).
//
// Isolation bound (honest): the write transaction runs at Postgres's default READ COMMITTED (the
// live-verified atomic Put/Delete path), so the condition reads and the writes are atomic
// all-or-nothing but not fully serializable against a concurrent writer that commits between them —
// DynamoDB is serializable. This closes the "Update/condition/ConditionCheck refused" gap with a
// correct atomic commit and genuinely-enforced conditions; hardening the write path to
// snapshot/serializable isolation is the remaining step.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/dynamodb"
	"go.mongodb.org/mongo-driver/bson"
)

// txnAction is one validated TransactWriteItems action, built (with no DB writes) before the
// transaction opens so a bad or unsupported item is refused up front — nothing is ever half-applied.
type txnAction struct {
	kind     string             // "Put" | "Delete" | "Update" | "ConditionCheck"
	table    string             // the DynamoDB table (a documentdb collection)
	id       string             // the stored _id (dynamodb.KeyID of the item's primary key)
	plainKey map[string]any     // Update only: the key attributes to re-assert on the updated item
	op       dynamodb.Operation // the "update" and/or "condition" expression blocks (nil if neither)
	hasCond  bool               // a ConditionExpression / ConditionCheck is present
	doc      map[string]any     // the full document to write (with _id). Put: precomputed; Update: pass 2
}

const txnDupItemMsg = "Transaction request cannot include multiple operations on one item"

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

	reject := func(msg string) {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, msg)
	}
	// Pass 1: validate + build every action, so a malformed/unsupported item refuses BEFORE the
	// transaction opens. DynamoDB forbids two actions on the same item in one transaction.
	var actions []txnAction
	seen := map[string]bool{}
	dup := func(table, id string) bool {
		k := table + "\x00" + id
		if seen[k] {
			return true
		}
		seen[k] = true
		return false
	}
	for _, raw := range items {
		it, _ := raw.(map[string]any)
		put, hasPut := it["Put"].(map[string]any)
		del, hasDel := it["Delete"].(map[string]any)
		upd, hasUpd := it["Update"].(map[string]any)
		cc, hasCC := it["ConditionCheck"].(map[string]any)
		if n := b2i(hasPut) + b2i(hasDel) + b2i(hasUpd) + b2i(hasCC); n != 1 {
			reject("Each TransactItem must contain exactly one of Put, Delete, Update, or ConditionCheck.")
			return
		}
		switch {
		case hasPut:
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
			if dup(table, id) {
				reject(txnDupItemMsg)
				return
			}
			a := txnAction{kind: "Put", table: table, id: id, doc: doc}
			if ce, ok := put["ConditionExpression"].(string); ok && ce != "" {
				a.op = dynamodb.Operation{"condition": exprBlock(ce, put["ExpressionAttributeNames"], put["ExpressionAttributeValues"])}
				a.hasCond = true
			}
			actions = append(actions, a)
		case hasDel:
			table, _ := del["TableName"].(string)
			keyAV, ok := del["Key"].(map[string]any)
			if table == "" || !ok {
				reject("a Delete must name a TableName and a Key.")
				return
			}
			if _, ok := h.tableKeyAttrs(ctx, table); !ok {
				writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Cannot do operations on a non-existent table: "+table)
				return
			}
			id := dynamodb.KeyID(keyAV)
			if dup(table, id) {
				reject(txnDupItemMsg)
				return
			}
			a := txnAction{kind: "Delete", table: table, id: id}
			if ce, ok := del["ConditionExpression"].(string); ok && ce != "" {
				a.op = dynamodb.Operation{"condition": exprBlock(ce, del["ExpressionAttributeNames"], del["ExpressionAttributeValues"])}
				a.hasCond = true
			}
			actions = append(actions, a)
		case hasUpd:
			table, _ := upd["TableName"].(string)
			keyAV, ok := upd["Key"].(map[string]any)
			ue, _ := upd["UpdateExpression"].(string)
			if table == "" || !ok {
				reject("an Update must name a TableName and a Key.")
				return
			}
			if ue == "" {
				reject("an Update requires an UpdateExpression.")
				return
			}
			if _, ok := h.tableKeyAttrs(ctx, table); !ok {
				writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Cannot do operations on a non-existent table: "+table)
				return
			}
			id := dynamodb.KeyID(keyAV)
			if dup(table, id) {
				reject(txnDupItemMsg)
				return
			}
			op := dynamodb.Operation{"update": exprBlock(ue, upd["ExpressionAttributeNames"], upd["ExpressionAttributeValues"])}
			a := txnAction{kind: "Update", table: table, id: id, plainKey: dynamodb.PlainKey(keyAV), op: op}
			if ce, ok := upd["ConditionExpression"].(string); ok && ce != "" {
				op["condition"] = exprBlock(ce, upd["ExpressionAttributeNames"], upd["ExpressionAttributeValues"])
				a.hasCond = true
			}
			actions = append(actions, a)
		case hasCC:
			table, _ := cc["TableName"].(string)
			keyAV, ok := cc["Key"].(map[string]any)
			ce, _ := cc["ConditionExpression"].(string)
			if table == "" || !ok {
				reject("a ConditionCheck must name a TableName and a Key.")
				return
			}
			if ce == "" {
				reject("a ConditionCheck requires a ConditionExpression.")
				return
			}
			if _, ok := h.tableKeyAttrs(ctx, table); !ok {
				writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Cannot do operations on a non-existent table: "+table)
				return
			}
			id := dynamodb.KeyID(keyAV)
			if dup(table, id) {
				reject(txnDupItemMsg)
				return
			}
			actions = append(actions, txnAction{kind: "ConditionCheck", table: table, id: id, hasCond: true,
				op: dynamodb.Operation{"condition": exprBlock(ce, cc["ExpressionAttributeNames"], cc["ExpressionAttributeValues"])}})
		}
	}

	// Pass 2: one Postgres transaction. Read every item a condition/update needs WITHIN it, evaluate
	// against the pre-transaction state, and only if every condition holds apply all writes.
	tx, err := h.pg.BeginTx(ctx, nil)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	reasons := make([]map[string]any, len(actions))
	for i := range reasons {
		reasons[i] = map[string]any{"Code": "None"}
	}
	anyFail := false
	for i := range actions {
		a := &actions[i]
		if !a.hasCond && a.kind != "Update" {
			continue // an unconditional Put/Delete needs no read
		}
		current, _, err := h.txnGetItem(ctx, tx, a.table, a.id)
		if err != nil {
			_ = tx.Rollback()
			h.internal(w, requestID, err)
			return
		}
		if a.kind == "Update" {
			newItem, err := dynamodb.ApplyUpdate(current, a.plainKey, a.op)
			if errors.Is(err, dynamodb.ErrConditionalCheckFailed) {
				reasons[i] = conditionalFailedReason()
				anyFail = true
				continue
			}
			if err != nil { // an unsupported/invalid update or condition expression
				_ = tx.Rollback()
				writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, err.Error())
				return
			}
			doc := map[string]any{"_id": a.id}
			for k, v := range newItem {
				doc[k] = v
			}
			a.doc = doc
			continue
		}
		// Put/Delete with a ConditionExpression, or a ConditionCheck.
		ok, _, err := dynamodb.EvalCondition(current, a.op)
		if err != nil {
			_ = tx.Rollback()
			writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, err.Error())
			return
		}
		if !ok {
			reasons[i] = conditionalFailedReason()
			anyFail = true
		}
	}
	if anyFail {
		_ = tx.Rollback()
		writeTransactionCanceled(w, requestID, reasons)
		return
	}

	// Every condition held — apply the writes. A ConditionCheck performs no write.
	for i := range actions {
		a := &actions[i]
		var q, arg string
		switch a.kind {
		case "ConditionCheck":
			continue
		case "Delete":
			idJSON, _ := json.Marshal(a.id)
			tblJSON, _ := json.Marshal(a.table)
			q = `SELECT documentdb_api.delete($1, $2::documentdb_core.bson)`
			arg = fmt.Sprintf(`{"delete":%s,"deletes":[{"q":{"_id":%s},"limit":1}]}`, tblJSON, idJSON)
		default: // Put | Update
			docJSON, err := json.Marshal(a.doc)
			if err != nil {
				_ = tx.Rollback()
				h.internal(w, requestID, err)
				return
			}
			idJSON, _ := json.Marshal(a.id)
			tblJSON, _ := json.Marshal(a.table)
			q = `SELECT documentdb_api.update($1, $2::documentdb_core.bson)`
			arg = fmt.Sprintf(`{"update":%s,"updates":[{"q":{"_id":%s},"u":%s,"upsert":true}]}`, tblJSON, idJSON, docJSON)
		}
		if _, err := tx.ExecContext(ctx, q, h.dbName, arg); err != nil {
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

// transactGetItems is a consistent multi-item snapshot read: every item is read inside ONE
// REPEATABLE-READ (snapshot-isolation) Postgres transaction, so all reads observe a single point in
// time — the guarantee TransactGetItems makes that N independent GetItems cannot. Responses are
// returned in request order; a missing item is an empty ItemResponse ({}), matching the wire shape.
func (h *dynamoHandler) transactGetItems(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	if h.pg == nil {
		writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
			"TransactGetItems (a consistent multi-item snapshot) requires the documentdb Postgres backend (set MONGO_PG_URI on the shim)")
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
	// Plan (and validate) all reads before opening the snapshot.
	type getReq struct{ table, id string }
	plan := make([]getReq, 0, len(items))
	for _, raw := range items {
		it, _ := raw.(map[string]any)
		get, ok := it["Get"].(map[string]any)
		if !ok {
			writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "Each TransactGetItem must contain a Get.")
			return
		}
		if pe, _ := get["ProjectionExpression"].(string); pe != "" {
			writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
				"ProjectionExpression is not yet supported by the open-infra shim; it would be silently ignored, so it is refused.")
			return
		}
		table, _ := get["TableName"].(string)
		keyAV, ok := get["Key"].(map[string]any)
		if table == "" || !ok {
			writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "a Get must name a TableName and a Key.")
			return
		}
		if _, ok := h.tableKeyAttrs(ctx, table); !ok {
			writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Cannot do operations on a non-existent table: "+table)
			return
		}
		plan = append(plan, getReq{table: table, id: dynamodb.KeyID(keyAV)})
	}

	tx, err := h.pg.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	defer func() { _ = tx.Rollback() }() // read-only work: nothing to commit, release the snapshot
	responses := make([]any, 0, len(plan))
	for _, g := range plan {
		item, found, err := h.txnGetItem(ctx, tx, g.table, g.id)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !found {
			responses = append(responses, map[string]any{}) // a miss is an empty ItemResponse
			continue
		}
		responses = append(responses, map[string]any{"Item": dynamodb.ToItem(item)})
	}
	writeDynamoJSON(w, requestID, map[string]any{"Responses": responses})
}

// txnGetItem reads one item by its stored _id WITHIN the given Postgres transaction, over the same
// documentdb layer the writes go to — so a condition/update sees the transaction's consistent state,
// not a separate mongo-wire read. It runs a documentdb find and decodes the returned cursor page
// (raw BSON, via the bson→bytea cast) with the mongo driver, then normalizes to plain values through
// the shared dynamodb.DocToItem so a row read here matches one read over the mongo wire byte-for-byte.
func (h *dynamoHandler) txnGetItem(ctx context.Context, tx *sql.Tx, table, id string) (map[string]any, bool, error) {
	idJSON, _ := json.Marshal(id)
	tblJSON, _ := json.Marshal(table)
	findCmd := fmt.Sprintf(`{"find":%s,"filter":{"_id":%s},"limit":1}`, tblJSON, idJSON)
	var raw []byte
	q := `SELECT cursorPage::bytea FROM documentdb_api.find_cursor_first_page($1, $2::documentdb_core.bson)`
	switch err := tx.QueryRowContext(ctx, q, h.dbName, findCmd).Scan(&raw); err {
	case nil:
	case sql.ErrNoRows:
		return nil, false, nil
	default:
		return nil, false, err
	}
	// The page is {cursor:{firstBatch:[<doc>], id, ns}, ok}. Pull the (at most one) matched document.
	var page struct {
		Cursor struct {
			FirstBatch []bson.Raw `bson:"firstBatch"`
		} `bson:"cursor"`
	}
	if err := bson.Unmarshal(raw, &page); err != nil {
		return nil, false, err
	}
	if len(page.Cursor.FirstBatch) == 0 {
		return nil, false, nil
	}
	var doc bson.M
	if err := bson.Unmarshal(page.Cursor.FirstBatch[0], &doc); err != nil {
		return nil, false, err
	}
	return dynamodb.DocToItem(doc), true, nil
}

// conditionalFailedReason is a per-item cancellation reason for a failed condition, as DynamoDB
// reports inside TransactionCanceledException.CancellationReasons.
func conditionalFailedReason() map[string]any {
	return map[string]any{"Code": "ConditionalCheckFailed", "Message": "The conditional request failed"}
}

// writeTransactionCanceled renders a TransactionCanceledException with per-item CancellationReasons
// (ConditionalCheckFailed / None), the shape a DynamoDB SDK parses to tell the caller exactly which
// item's condition failed.
func writeTransactionCanceled(w http.ResponseWriter, requestID string, reasons []map[string]any) {
	codes := make([]string, len(reasons))
	for i, r := range reasons {
		codes[i], _ = r["Code"].(string)
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"__type":              dynamoErrType + "TransactionCanceledException",
		"message":             "Transaction cancelled, please refer cancellation reasons for specific reasons [" + strings.Join(codes, ", ") + "]",
		"CancellationReasons": reasons,
	})
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
