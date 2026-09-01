// DynamoDB front door for the aws-shim.
//
// Recognizes DynamoDB requests (AWS JSON 1.0, the operation named in X-Amz-Target), authenticates
// them through the shared SigV4 path, authorizes them with the same impersonated
// SubjectAccessReview every other front door uses (one policy world), executes the supported
// operations against the shared Dynamo-shaped store over FerretDB, and speaks DynamoDB's own
// dialect. Supported today: CreateTable, DescribeTable, GetItem, PutItem, DeleteItem, Query
// (key-condition + filter + sort + pagination), UpdateItem (update + condition expressions),
// full Scan, and the batch item APIs BatchGetItem / BatchWriteItem (capped at DynamoDB's 100/25
// limits, non-transactional like the real service). Everything else — Transact*, ListTables,
// DeleteTable, Scan-with-filter, projection expressions, TTL, streams — returns an honest 501
// NotImplementedException, the shim's per-op graduation, never a silent fake.
//
// The store executor is the SHARED module github.com/harn3ss/open-infra/dynamodb — the same code
// the open-appsync engine runs, so a resolver and a raw SDK call see identical semantics.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/dynamodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"k8s.io/client-go/kubernetes"
)

// tableRegistry is the collection holding each table's key schema (DynamoDB needs it to split a
// PutItem Item into key/non-key; the store keys items by their primary key).
const tableRegistry = "_shim_dynamo_tables"

type dynamoHandler struct {
	cs      kubernetes.Interface
	authzNS string
	db      *mongo.Database // FerretDB; nil when MONGO_URI is unset (data layer not configured)
	logger  *slog.Logger
}

func newDynamoHandler(cs kubernetes.Interface, authzNS string, db *mongo.Database, logger *slog.Logger) *dynamoHandler {
	return &dynamoHandler{cs: cs, authzNS: authzNS, db: db, logger: logger}
}

const dynamoErrType = "com.amazonaws.dynamodb.v20120810#"

func writeDynamoError(w http.ResponseWriter, status int, errType, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": dynamoErrType + errType, "message": message})
}

func writeDynamoJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *dynamoHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeDynamoError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// verbForOp maps a DynamoDB operation to the coarse RBAC verb its SubjectAccessReview checks — the
// same table-agnostic coarseness S3 carries in v1.
func verbForOp(op string) (verb string, known bool) {
	switch op {
	case "GetItem", "Query", "Scan", "BatchGetItem", "DescribeTable", "ListTables":
		return "get", true
	case "PutItem", "UpdateItem", "BatchWriteItem", "CreateTable":
		return "create", true
	case "DeleteItem", "DeleteTable":
		return "delete", true
	}
	return "", false
}

func (h *dynamoHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeDynamoError(w, http.StatusBadRequest, "MissingActionException", requestID,
			"No operation named in the X-Amz-Target header.")
		return
	}
	verb, known := verbForOp(op)
	if !known {
		writeDynamoError(w, http.StatusBadRequest, "UnknownOperationException", requestID,
			"Unrecognized DynamoDB operation "+op+".")
		return
	}
	body := readJSONBody(r)
	table, _ := body["TableName"].(string)

	// Authorize with the same impersonated SubjectAccessReview every front door uses — one policy
	// world; coarse on openinfra.dev/applications in v1.
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, table); !allowed {
		writeDynamoError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if h.db == nil {
		writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
			"the DynamoDB data layer is not configured on this shim (set MONGO_URI)")
		return
	}

	ctx := r.Context()
	switch op {
	case "CreateTable":
		h.createTable(ctx, w, requestID, table, body)
	case "DescribeTable":
		h.describeTable(ctx, w, requestID, table)
	case "GetItem":
		h.getItem(ctx, w, requestID, table, body)
	case "PutItem":
		h.putItem(ctx, w, requestID, table, body)
	case "DeleteItem":
		h.deleteItem(ctx, w, requestID, table, body)
	case "Query":
		h.query(ctx, w, requestID, table, body)
	case "UpdateItem":
		h.updateItem(ctx, w, requestID, table, body)
	case "Scan":
		h.scan(ctx, w, requestID, table, body)
	case "BatchGetItem":
		h.batchGetItem(ctx, w, requestID, body)
	case "BatchWriteItem":
		h.batchWriteItem(ctx, w, requestID, body)
	default:
		writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
			"DynamoDB "+op+" is recognized but not yet implemented by the open-infra shim.")
	}
}

// --- operations ---

func (h *dynamoHandler) createTable(ctx context.Context, w http.ResponseWriter, requestID, table string, body map[string]any) {
	keyAttrs := keyAttrsFromSchema(body["KeySchema"])
	if table == "" || len(keyAttrs) == 0 {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
			"CreateTable requires a TableName and a KeySchema.")
		return
	}
	_, err := h.registry().ReplaceOne(ctx, bson.M{"_id": table},
		bson.M{"_id": table, "keyAttrs": keyAttrs}, options.Replace().SetUpsert(true))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeDynamoJSON(w, requestID, map[string]any{"TableDescription": map[string]any{
		"TableName": table, "TableStatus": "ACTIVE", "KeySchema": body["KeySchema"], "ItemCount": float64(0),
	}})
}

func (h *dynamoHandler) describeTable(ctx context.Context, w http.ResponseWriter, requestID, table string) {
	keyAttrs, ok := h.tableKeyAttrs(ctx, table)
	if !ok {
		writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID,
			"Requested resource not found: Table: "+table+" not found")
		return
	}
	schema := make([]any, 0, len(keyAttrs))
	for i, a := range keyAttrs {
		kt := "HASH"
		if i == 1 {
			kt = "RANGE"
		}
		schema = append(schema, map[string]any{"AttributeName": a, "KeyType": kt})
	}
	writeDynamoJSON(w, requestID, map[string]any{"Table": map[string]any{
		"TableName": table, "TableStatus": "ACTIVE", "KeySchema": schema,
	}})
}

func (h *dynamoHandler) getItem(ctx context.Context, w http.ResponseWriter, requestID, table string, body map[string]any) {
	key, ok := body["Key"].(map[string]any)
	if !ok {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "GetItem requires a Key.")
		return
	}
	if h.refuseProjection(w, requestID, body) {
		return
	}
	res, err := h.store(table).Execute(ctx, dynamodb.Operation{"operation": "GetItem", "key": key})
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	item, _ := res.(map[string]any)
	if item == nil {
		writeDynamoJSON(w, requestID, map[string]any{}) // a miss is an empty response, not an error
		return
	}
	writeDynamoJSON(w, requestID, map[string]any{"Item": dynamodb.ToItem(item)})
}

func (h *dynamoHandler) putItem(ctx context.Context, w http.ResponseWriter, requestID, table string, body map[string]any) {
	item, ok := body["Item"].(map[string]any)
	if !ok {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "PutItem requires an Item.")
		return
	}
	keyAttrs, ok := h.tableKeyAttrs(ctx, table)
	if !ok {
		writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID,
			"Cannot do operations on a non-existent table")
		return
	}
	key, missing := keyFromItem(item, keyAttrs)
	if missing != "" {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
			"One of the required keys was not given a value: "+missing)
		return
	}
	if _, err := h.store(table).Execute(ctx, dynamodb.Operation{"operation": "PutItem", "key": key, "attributeValues": item}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeDynamoJSON(w, requestID, map[string]any{}) // PutItem returns {} without ReturnValues
}

func (h *dynamoHandler) deleteItem(ctx context.Context, w http.ResponseWriter, requestID, table string, body map[string]any) {
	key, ok := body["Key"].(map[string]any)
	if !ok {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "DeleteItem requires a Key.")
		return
	}
	if _, err := h.store(table).Execute(ctx, dynamodb.Operation{"operation": "DeleteItem", "key": key}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeDynamoJSON(w, requestID, map[string]any{}) // returns {} without ReturnValues
}

func (h *dynamoHandler) query(ctx context.Context, w http.ResponseWriter, requestID, table string, body map[string]any) {
	kce, _ := body["KeyConditionExpression"].(string)
	if kce == "" {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "Query requires a KeyConditionExpression.")
		return
	}
	if h.refuseProjection(w, requestID, body) {
		return
	}
	names, values := body["ExpressionAttributeNames"], body["ExpressionAttributeValues"]
	op := dynamodb.Operation{"operation": "Query", "query": exprBlock(kce, names, values)}
	if fe, ok := body["FilterExpression"].(string); ok && fe != "" {
		op["filter"] = exprBlock(fe, names, values)
	}
	if v, ok := body["ScanIndexForward"].(bool); ok {
		op["scanIndexForward"] = v
	}
	if lim, ok := body["Limit"].(float64); ok {
		op["limit"] = lim
	}
	if tok := startToken(body["ExclusiveStartKey"]); tok != "" {
		op["nextToken"] = tok
	}
	res, err := h.store(table).Execute(ctx, op)
	if err != nil {
		h.mapStoreError(w, requestID, err)
		return
	}
	h.writeItemsResult(w, requestID, res)
}

func (h *dynamoHandler) scan(ctx context.Context, w http.ResponseWriter, requestID, table string, body map[string]any) {
	// The store's Scan is a full scan; a filter expression on Scan is not supported yet — refuse
	// loudly rather than silently returning unfiltered results.
	if fe, ok := body["FilterExpression"].(string); ok && fe != "" {
		writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
			"Scan with a FilterExpression is not yet supported by the open-infra shim.")
		return
	}
	if h.refuseProjection(w, requestID, body) {
		return
	}
	res, err := h.store(table).Execute(ctx, dynamodb.Operation{"operation": "Scan"})
	if err != nil {
		h.mapStoreError(w, requestID, err)
		return
	}
	h.writeItemsResult(w, requestID, res)
}

func (h *dynamoHandler) updateItem(ctx context.Context, w http.ResponseWriter, requestID, table string, body map[string]any) {
	key, ok := body["Key"].(map[string]any)
	if !ok {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "UpdateItem requires a Key.")
		return
	}
	ue, _ := body["UpdateExpression"].(string)
	if ue == "" {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "UpdateItem requires an UpdateExpression.")
		return
	}
	names, values := body["ExpressionAttributeNames"], body["ExpressionAttributeValues"]
	op := dynamodb.Operation{"operation": "UpdateItem", "key": key, "update": exprBlock(ue, names, values)}
	if ce, ok := body["ConditionExpression"].(string); ok && ce != "" {
		op["condition"] = exprBlock(ce, names, values)
	}
	res, err := h.store(table).Execute(ctx, op)
	if err != nil {
		h.mapStoreError(w, requestID, err)
		return
	}
	// ReturnValues: NONE (default) → {}; ALL_NEW / UPDATED_NEW → the updated item.
	if rv, _ := body["ReturnValues"].(string); rv == "ALL_NEW" || rv == "UPDATED_NEW" {
		if item, ok := res.(map[string]any); ok {
			writeDynamoJSON(w, requestID, map[string]any{"Attributes": dynamodb.ToItem(item)})
			return
		}
	}
	writeDynamoJSON(w, requestID, map[string]any{})
}

// batchGetItem fetches many items across one or more tables in a single call. Like the real
// service it is NOT transactional and is capped at 100 keys; a missing key is simply absent from
// the response (not an error). ProjectionExpression is refused loudly rather than silently ignored.
func (h *dynamoHandler) batchGetItem(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	reqItems, ok := body["RequestItems"].(map[string]any)
	if !ok || len(reqItems) == 0 {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "BatchGetItem requires a non-empty RequestItems.")
		return
	}
	total := 0
	for _, spec := range reqItems {
		sm, _ := spec.(map[string]any)
		if h.refuseProjection(w, requestID, sm) {
			return
		}
		keys, _ := sm["Keys"].([]any)
		total += len(keys)
	}
	if total > 100 {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
			"Too many items requested for the BatchGetItem call (the limit is 100).")
		return
	}
	responses := map[string]any{}
	for table, spec := range reqItems {
		sm, _ := spec.(map[string]any)
		keys, _ := sm["Keys"].([]any)
		out := make([]any, 0, len(keys))
		for _, k := range keys {
			km, ok := k.(map[string]any)
			if !ok {
				continue
			}
			res, err := h.store(table).Execute(ctx, dynamodb.Operation{"operation": "GetItem", "key": km})
			if err != nil {
				h.internal(w, requestID, err)
				return
			}
			if item, ok := res.(map[string]any); ok && item != nil {
				out = append(out, dynamodb.ToItem(item))
			}
		}
		responses[table] = out
	}
	// The store applies every read synchronously, so nothing is ever left unprocessed.
	writeDynamoJSON(w, requestID, map[string]any{"Responses": responses, "UnprocessedKeys": map[string]any{}})
}

// batchWriteItem applies many Put/Delete requests across one or more tables in a single call. Like
// the real service it is NOT transactional, is capped at 25 requests, and — unlike PutItem — does
// not honor condition expressions (DynamoDB forbids conditions on batch writes).
func (h *dynamoHandler) batchWriteItem(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	reqItems, ok := body["RequestItems"].(map[string]any)
	if !ok || len(reqItems) == 0 {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "BatchWriteItem requires a non-empty RequestItems.")
		return
	}
	total := 0
	for _, reqs := range reqItems {
		rl, _ := reqs.([]any)
		total += len(rl)
	}
	if total == 0 || total > 25 {
		writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
			"BatchWriteItem requires between 1 and 25 write requests.")
		return
	}
	for table, reqs := range reqItems {
		keyAttrs, ok := h.tableKeyAttrs(ctx, table)
		if !ok {
			writeDynamoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID,
				"Cannot do operations on a non-existent table: "+table)
			return
		}
		rl, _ := reqs.([]any)
		for _, r := range rl {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			switch {
			case rm["PutRequest"] != nil:
				pr, _ := rm["PutRequest"].(map[string]any)
				item, ok := pr["Item"].(map[string]any)
				if !ok {
					writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "a PutRequest requires an Item.")
					return
				}
				key, missing := keyFromItem(item, keyAttrs)
				if missing != "" {
					writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
						"One of the required keys was not given a value: "+missing)
					return
				}
				if _, err := h.store(table).Execute(ctx, dynamodb.Operation{"operation": "PutItem", "key": key, "attributeValues": item}); err != nil {
					h.internal(w, requestID, err)
					return
				}
			case rm["DeleteRequest"] != nil:
				dr, _ := rm["DeleteRequest"].(map[string]any)
				key, ok := dr["Key"].(map[string]any)
				if !ok {
					writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID, "a DeleteRequest requires a Key.")
					return
				}
				if _, err := h.store(table).Execute(ctx, dynamodb.Operation{"operation": "DeleteItem", "key": key}); err != nil {
					h.internal(w, requestID, err)
					return
				}
			default:
				writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
					"each write request must carry exactly one PutRequest or DeleteRequest.")
				return
			}
		}
	}
	// Every write is applied synchronously, so nothing is ever left unprocessed.
	writeDynamoJSON(w, requestID, map[string]any{"UnprocessedItems": map[string]any{}})
}

// writeItemsResult re-dresses a store Query/Scan result ({items, scannedCount, count, nextToken})
// as the DynamoDB wire shape ({Items, Count, ScannedCount, LastEvaluatedKey}). The continuation
// cursor is opaque — carried in a synthetic LastEvaluatedKey the client echoes back as
// ExclusiveStartKey — since the store paginates by offset, not by the last item's key.
func (h *dynamoHandler) writeItemsResult(w http.ResponseWriter, requestID string, res any) {
	m, _ := res.(map[string]any)
	src, _ := m["items"].([]any)
	items := make([]any, 0, len(src))
	for _, it := range src {
		if im, ok := it.(map[string]any); ok {
			items = append(items, dynamodb.ToItem(im))
		}
	}
	resp := map[string]any{
		"Items":        items,
		"Count":        numOr(m["count"], len(items)),
		"ScannedCount": numOr(m["scannedCount"], len(items)),
	}
	if tok, ok := m["nextToken"].(string); ok && tok != "" {
		resp["LastEvaluatedKey"] = map[string]any{"__token": map[string]any{"S": tok}}
	}
	writeDynamoJSON(w, requestID, resp)
}

// exprBlock builds the store's per-block expression shape from the wire's flat expression +
// (shared) attribute-name/value maps.
func exprBlock(expr string, names, values any) map[string]any {
	b := map[string]any{"expression": expr}
	if names != nil {
		b["expressionNames"] = names
	}
	if values != nil {
		b["expressionValues"] = values
	}
	return b
}

// startToken pulls the opaque continuation offset out of an ExclusiveStartKey the shim minted.
func startToken(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	t, ok := m["__token"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := t["S"].(string)
	return s
}

func numOr(v any, def int) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return float64(def)
}

// mapStoreError translates a store error into the DynamoDB dialect: a failed condition is a real
// DynamoDB semantic (400), an expression form the store does not implement is an honest 501, and
// anything else is an internal error.
func (h *dynamoHandler) mapStoreError(w http.ResponseWriter, requestID string, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "ConditionalCheck"):
		writeDynamoError(w, http.StatusBadRequest, "ConditionalCheckFailedException", requestID,
			"The conditional request failed")
	case strings.Contains(msg, "not implemented"), strings.Contains(msg, "unsupported"), strings.Contains(msg, "not translatable"):
		writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID, msg)
	default:
		h.internal(w, requestID, err)
	}
}

// --- helpers ---

func (h *dynamoHandler) store(table string) *dynamodb.FerretStore {
	return dynamodb.NewFerretStore(h.db.Collection(table))
}

// keyFromItem extracts a table's primary key from a full item per its key schema. It returns the
// name of the first missing key attribute (empty when the key is complete) so the caller can raise
// the DynamoDB-shaped validation error.
func keyFromItem(item map[string]any, keyAttrs []string) (key map[string]any, missing string) {
	key = map[string]any{}
	for _, ka := range keyAttrs {
		v, present := item[ka]
		if !present {
			return nil, ka
		}
		key[ka] = v
	}
	return key, ""
}

// refuseProjection rejects a ProjectionExpression loudly (501) instead of silently returning the
// full item — a projection that is ignored is a silent fake, which this front door never ships.
func (h *dynamoHandler) refuseProjection(w http.ResponseWriter, requestID string, body map[string]any) bool {
	if pe, _ := body["ProjectionExpression"].(string); pe != "" {
		writeDynamoError(w, http.StatusNotImplemented, "NotImplementedException", requestID,
			"ProjectionExpression is not yet supported by the open-infra shim; it would be silently ignored, so it is refused.")
		return true
	}
	return false
}

func (h *dynamoHandler) registry() *mongo.Collection { return h.db.Collection(tableRegistry) }

func (h *dynamoHandler) tableKeyAttrs(ctx context.Context, table string) ([]string, bool) {
	var doc struct {
		KeyAttrs []string `bson:"keyAttrs"`
	}
	if err := h.registry().FindOne(ctx, bson.M{"_id": table}).Decode(&doc); err != nil {
		return nil, false
	}
	return doc.KeyAttrs, len(doc.KeyAttrs) > 0
}

func (h *dynamoHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("dynamodb backend error", "error", err.Error())
	writeDynamoError(w, http.StatusInternalServerError, "InternalServerError", requestID, "The server encountered an internal error.")
}

// opFromTarget extracts the operation from "DynamoDB_20120810.GetItem".
func opFromTarget(target string) string {
	if i := strings.LastIndex(target, "."); i >= 0 {
		return target[i+1:]
	}
	return target
}

// keyAttrsFromSchema turns a KeySchema ([{AttributeName,KeyType}]) into ordered key attribute names
// (HASH first, then RANGE).
func keyAttrsFromSchema(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var hash, rnge string
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["AttributeName"].(string)
		switch m["KeyType"] {
		case "HASH":
			hash = name
		case "RANGE":
			rnge = name
		}
	}
	if hash == "" {
		return nil
	}
	if rnge != "" {
		return []string{hash, rnge}
	}
	return []string{hash}
}

// readJSONBody decodes a DynamoDB JSON body into a map, restoring r.Body so nothing downstream is
// disturbed.
func readJSONBody(r *http.Request) map[string]any {
	if r.Body == nil {
		return map[string]any{}
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return map[string]any{}
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	m := map[string]any{}
	_ = json.Unmarshal(buf, &m)
	return m
}
