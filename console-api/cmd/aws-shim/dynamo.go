// DynamoDB front door for the aws-shim.
//
// Recognizes DynamoDB requests (AWS JSON 1.0, the operation named in X-Amz-Target), authenticates
// them through the shared SigV4 path, authorizes them with the same impersonated
// SubjectAccessReview every other front door uses (one policy world), executes the supported
// operations against the shared Dynamo-shaped store over FerretDB, and speaks DynamoDB's own
// dialect. Supported today: CreateTable, DescribeTable, GetItem, PutItem, DeleteItem. Every other
// operation returns an honest 501 NotImplementedException — the shim's per-op graduation, never a
// silent fake. Query / UpdateItem / Scan / Batch* graduate next (the store already implements the
// executors; the wire adapter is what remains).
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
	key := map[string]any{}
	for _, ka := range keyAttrs {
		v, present := item[ka]
		if !present {
			writeDynamoError(w, http.StatusBadRequest, "ValidationException", requestID,
				"One of the required keys was not given a value: "+ka)
			return
		}
		key[ka] = v
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

// --- helpers ---

func (h *dynamoHandler) store(table string) *dynamodb.FerretStore {
	return dynamodb.NewFerretStore(h.db.Collection(table))
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
