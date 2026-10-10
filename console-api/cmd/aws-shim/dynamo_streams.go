// The aws-shim DynamoDB Streams front door (SigV4 service "dynamodbstreams").
//
// Speaks AWS JSON 1.0 (X-Amz-Target: DynamoDBStreams_20120810.<Op>): ListStreams, DescribeStream,
// GetShardIterator, GetRecords. Backed by the Postgres change-record log (dynamo_streams_store.go);
// the records are emitted by the dynamodb write path when a table's streamSpecification is set.
// Shares the shard-iterator / sequence mechanics with the Kinesis doorway (encodeIterator /
// decodeIterator / formatSeq / shardID). v1: one shard per stream; the StreamArn label is the table
// name (stable + unique; clients drive off DescribeStream, not the label text).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

type ddbStreamsHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	store   *ddbStreamStore
	dyn     *dynamoHandler          // for the table key schema (DescribeStream KeySchema)
	authz   *dataplaneauthz.Checker // fine-grained kind: Policy data-plane check (additive; may be nil)
	logger  *slog.Logger
}

func newDDBStreamsHandler(cs kubernetes.Interface, authzNS, account, region string, store *ddbStreamStore, dyn *dynamoHandler, logger *slog.Logger) *ddbStreamsHandler {
	return &ddbStreamsHandler{cs: cs, authzNS: authzNS, account: account, region: region, store: store, dyn: dyn, logger: logger}
}

func (h *ddbStreamsHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeStreamsError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func writeStreamsError(w http.ResponseWriter, status int, errType, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": "com.amazonaws.dynamodb.v20120810#" + errType, "message": message})
}

// dynamoStreamARN renders arn:aws:dynamodb:<region>:<account>:table/<table>/stream/<label>;
// the label is the table name (stable + unique; clients drive off DescribeStream, not the label).
func dynamoStreamARN(region, account, table string) string {
	return fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s/stream/%s", region, account, table, table)
}

func (h *ddbStreamsHandler) streamARN(table string) string {
	return dynamoStreamARN(h.region, h.account, table)
}

// streamViewFromSpec parses a DynamoDB StreamSpecification ({StreamEnabled, StreamViewType}) into a
// view type, or "" when streams are not enabled. Defaults to NEW_AND_OLD_IMAGES when enabled with
// no explicit view type (AWS requires one, but be lenient).
func streamViewFromSpec(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if en, ok := m["StreamEnabled"].(bool); ok && !en {
		return ""
	}
	if vt, _ := m["StreamViewType"].(string); vt != "" {
		return vt
	}
	if en, _ := m["StreamEnabled"].(bool); en {
		return "NEW_AND_OLD_IMAGES"
	}
	return ""
}

// tableFromARN extracts <table> from a stream ARN (…:table/<table>/stream/…). Empty if not one.
func tableFromStreamARN(arn string) string {
	i := strings.Index(arn, ":table/")
	if i < 0 {
		return ""
	}
	rest := arn[i+len(":table/"):]
	if j := strings.Index(rest, "/stream/"); j >= 0 {
		return rest[:j]
	}
	return ""
}

func (h *ddbStreamsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeStreamsError(w, http.StatusBadRequest, "MissingActionException", requestID, "No operation named in the X-Amz-Target header.")
		return
	}
	body := readJSONBody(r)

	// The table this op scopes to: from TableName (ListStreams) or parsed from the StreamArn.
	table, _ := body["TableName"].(string)
	if table == "" {
		if arn, _ := body["StreamArn"].(string); arn != "" {
			table = tableFromStreamARN(arn)
		}
	}

	// Authorize with the same impersonated SubjectAccessReview + data-plane policy the dynamodb
	// front door uses — one policy world. All streams ops are reads ("get").
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, "get", "openinfra.dev", "applications", h.authzNS, table); !allowed {
		writeStreamsError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if table != "" {
		if denied, reason := deniedByDataPlane(r.Context(), h.authz, claims, "dynamodb:"+op, "Table", table, r); denied {
			writeStreamsError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
	}
	if h.store == nil {
		writeStreamsError(w, http.StatusNotImplemented, "InternalServerError", requestID,
			"the DynamoDB data layer is not configured on this shim (set MONGO_PG_URI)")
		return
	}

	ctx := r.Context()
	switch op {
	case "ListStreams":
		h.listStreams(ctx, w, requestID, table)
	case "DescribeStream":
		h.describeStream(ctx, w, requestID, table)
	case "GetShardIterator":
		h.getShardIterator(ctx, w, requestID, body, table)
	case "GetRecords":
		h.getRecords(ctx, w, requestID, body)
	default:
		writeStreamsError(w, http.StatusBadRequest, "UnknownOperationException", requestID, "Unrecognized DynamoDB Streams operation "+op+".")
	}
}

func (h *ddbStreamsHandler) listStreams(ctx context.Context, w http.ResponseWriter, requestID, tableFilter string) {
	tables, err := h.store.listStreams(ctx)
	if err != nil {
		writeStreamsError(w, http.StatusInternalServerError, "InternalServerError", requestID, "could not list streams")
		return
	}
	out := make([]any, 0, len(tables))
	for _, t := range tables {
		if tableFilter != "" && t != tableFilter {
			continue
		}
		out = append(out, map[string]any{"StreamArn": h.streamARN(t), "TableName": t, "StreamLabel": t})
	}
	writeStreamsJSON(w, requestID, map[string]any{"Streams": out})
}

func (h *ddbStreamsHandler) describeStream(ctx context.Context, w http.ResponseWriter, requestID, table string) {
	viewType, ok, err := h.store.getStream(ctx, table)
	if err != nil {
		writeStreamsError(w, http.StatusInternalServerError, "InternalServerError", requestID, "could not read stream")
		return
	}
	if !ok {
		writeStreamsError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Requested resource not found: Stream for table "+table+" not found")
		return
	}
	// KeySchema from the table registry (HASH first, optional RANGE).
	var keySchema []any
	if keyAttrs, ok := h.dyn.tableKeyAttrs(ctx, table); ok {
		for i, a := range keyAttrs {
			kt := "HASH"
			if i == 1 {
				kt = "RANGE"
			}
			keySchema = append(keySchema, map[string]any{"AttributeName": a, "KeyType": kt})
		}
	}
	// The single shard; StartingSequenceNumber = TRIM_HORIZON of what's retained.
	minSeq, _, _, hasRecords, _ := h.store.shardBounds(ctx, table)
	start := int64(1)
	if hasRecords {
		start = minSeq
	}
	shard := map[string]any{
		"ShardId":             ddbStreamShard,
		"SequenceNumberRange": map[string]any{"StartingSequenceNumber": formatSeq(start)},
	}
	writeStreamsJSON(w, requestID, map[string]any{
		"StreamDescription": map[string]any{
			"StreamArn":               h.streamARN(table),
			"StreamLabel":             table,
			"StreamStatus":            "ENABLED",
			"StreamViewType":          viewType,
			"TableName":               table,
			"CreationRequestDateTime": epochSeconds(time.Now().UnixMilli()),
			"KeySchema":               keySchema,
			"Shards":                  []any{shard},
		},
	})
}

func (h *ddbStreamsHandler) getShardIterator(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, table string) {
	if _, ok, _ := h.store.getStream(ctx, table); !ok {
		writeStreamsError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Requested resource not found: Stream for table "+table+" not found")
		return
	}
	shard, _ := body["ShardId"].(string)
	itype, _ := body["ShardIteratorType"].(string)
	if shard == "" || itype == "" {
		writeStreamsError(w, http.StatusBadRequest, "ValidationException", requestID, "GetShardIterator requires ShardId and ShardIteratorType.")
		return
	}
	minSeq, latestSeq, _, hasRecords, err := h.store.shardBounds(ctx, table)
	if err != nil {
		writeStreamsError(w, http.StatusInternalServerError, "InternalServerError", requestID, "could not read shard")
		return
	}
	var next int64
	switch itype {
	case "TRIM_HORIZON":
		if hasRecords {
			next = minSeq
		} else {
			next = 1
		}
	case "LATEST":
		if hasRecords {
			next = latestSeq + 1
		} else {
			next = 1
		}
	case "AT_SEQUENCE_NUMBER":
		s, ok := parseSeq(strFromBody(body, "SequenceNumber"))
		if !ok {
			writeStreamsError(w, http.StatusBadRequest, "ValidationException", requestID, "AT_SEQUENCE_NUMBER requires a valid SequenceNumber.")
			return
		}
		next = s
	case "AFTER_SEQUENCE_NUMBER":
		s, ok := parseSeq(strFromBody(body, "SequenceNumber"))
		if !ok {
			writeStreamsError(w, http.StatusBadRequest, "ValidationException", requestID, "AFTER_SEQUENCE_NUMBER requires a valid SequenceNumber.")
			return
		}
		next = s + 1
	default:
		writeStreamsError(w, http.StatusBadRequest, "ValidationException", requestID, "unsupported ShardIteratorType "+itype)
		return
	}
	writeStreamsJSON(w, requestID, map[string]any{"ShardIterator": encodeIterator(shardIterator{Stream: table, Shard: shard, NextSeq: next})})
}

func (h *ddbStreamsHandler) getRecords(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	it, err := decodeIterator(strFromBody(body, "ShardIterator"))
	if err != nil {
		writeStreamsError(w, http.StatusBadRequest, "ValidationException", requestID, "invalid ShardIterator.")
		return
	}
	limit := 0
	if v, ok := body["Limit"]; ok {
		limit = toInt(v)
	}
	recs, err := h.store.getRecords(ctx, it.Stream, it.NextSeq, limit)
	if err != nil {
		writeStreamsError(w, http.StatusInternalServerError, "InternalServerError", requestID, "could not read records")
		return
	}
	out := make([]any, 0, len(recs))
	next := it.NextSeq
	for _, r := range recs {
		var dynamodb map[string]any
		if json.Unmarshal([]byte(r.Payload), &dynamodb) != nil {
			dynamodb = map[string]any{}
		}
		dynamodb["SequenceNumber"] = formatSeq(r.Seq)
		dynamodb["ApproximateCreationDateTime"] = epochSeconds(r.TsMs)
		out = append(out, map[string]any{
			"eventID":      fmt.Sprintf("%s-%d", it.Stream, r.Seq),
			"eventName":    r.EventName,
			"eventVersion": "1.1",
			"eventSource":  "aws:dynamodb",
			"awsRegion":    h.region,
			"dynamodb":     dynamodb,
		})
		next = r.Seq + 1
	}
	writeStreamsJSON(w, requestID, map[string]any{
		"Records":           out,
		"NextShardIterator": encodeIterator(shardIterator{Stream: it.Stream, Shard: it.Shard, NextSeq: next}),
	})
}

func writeStreamsJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}
