// Kinesis Data Streams front door for the aws-shim (polyhedron#173) — ordered, sharded, replayable
// streaming, deliberately distinct from the unordered SQS / no-retention SNS doorways.
//
// Speaks AWS JSON 1.1 (X-Amz-Target: Kinesis_20131202.<Op>). Backed by Postgres (kinesis_store.go): a
// record is assigned to a shard by hash(PartitionKey), gets a strictly monotonic per-shard SequenceNumber,
// and is replayable within the retention window. Shard iterators (TRIM_HORIZON/LATEST/AT_/AFTER_SEQUENCE_
// NUMBER/AT_TIMESTAMP) advance through the log and report MillisBehindLatest. Authorization is the one policy
// world at STREAM granularity: a tenant cannot read another tenant's stream (cross-tenant read is a
// data-exposure hole), and read (Get*) is separable from write (Put*).
package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

const defaultShardCount = 4

// maxRecordBytes is the AWS per-record data limit (1 MiB, on the decoded blob).
const maxRecordBytes = 1 << 20

type kinesisHandler struct {
	cs      kubernetes.Interface
	authzNS string
	account string
	region  string
	store   *kinesisStore
	authz   *dataplaneauthz.Checker
	logger  *slog.Logger
}

func newKinesisHandler(cs kubernetes.Interface, authzNS, account, region string, store *kinesisStore, logger *slog.Logger) *kinesisHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &kinesisHandler{cs: cs, authzNS: authzNS, account: account, region: region, store: store, logger: logger}
}

func writeKinesisError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeKinesisJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *kinesisHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeKinesisError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func verbForKinesisOp(op string) (string, bool) {
	switch op {
	case "GetRecords", "GetShardIterator", "DescribeStream", "DescribeStreamSummary", "ListStreams", "ListShards":
		return "get", true
	case "CreateStream", "PutRecord", "PutRecords", "IncreaseStreamRetentionPeriod", "DecreaseStreamRetentionPeriod":
		return "create", true
	case "DeleteStream":
		return "delete", true
	}
	return "", false
}

func (h *kinesisHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeKinesisError(w, http.StatusBadRequest, "InvalidAction", requestID, "no X-Amz-Target (expected Kinesis_20131202.<Op>).")
		return
	}
	verb, known := verbForKinesisOp(op)
	if !known {
		writeKinesisError(w, http.StatusBadRequest, "InvalidAction", requestID, "Kinesis "+op+" is not implemented by the open-infra shim.")
		return
	}
	if h.store == nil {
		writeKinesisError(w, http.StatusServiceUnavailable, "InternalFailure", requestID,
			"the Kinesis data layer is not configured on this shim (set SQS_PG_URI)")
		return
	}
	body := readJSONBody(r)

	// The stream this op scopes to. Get* by ShardIterator carry the stream inside the (opaque) iterator.
	stream, _ := body["StreamName"].(string)
	if op == "GetRecords" {
		if it, _ := body["ShardIterator"].(string); it != "" {
			if dec, err := decodeIterator(it); err == nil {
				stream = dec.Stream
			}
		}
	}
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, stream); !allowed {
		h.auditDeny(ctx, op, stream, reason)
		writeKinesisError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if stream != "" {
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "kinesis:"+op, "Stream", stream, r); denied {
			h.auditDeny(ctx, op, stream, reason)
			writeKinesisError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
	}

	switch op {
	case "CreateStream":
		h.createStream(ctx, w, requestID, body)
	case "DescribeStream":
		h.describeStream(ctx, w, requestID, stream)
	case "DescribeStreamSummary":
		h.describeStreamSummary(ctx, w, requestID, stream)
	case "ListStreams":
		h.listStreams(ctx, w, requestID)
	case "DeleteStream":
		h.deleteStream(ctx, w, requestID, stream)
	case "ListShards":
		h.listShards(ctx, w, requestID, stream)
	case "PutRecord":
		h.putRecord(ctx, w, requestID, body, stream)
	case "PutRecords":
		h.putRecords(ctx, w, requestID, body, stream)
	case "GetShardIterator":
		h.getShardIterator(ctx, w, requestID, body, stream)
	case "GetRecords":
		h.getRecords(ctx, w, requestID, body)
	case "IncreaseStreamRetentionPeriod", "DecreaseStreamRetentionPeriod":
		h.changeRetention(ctx, w, requestID, body, stream)
	default:
		writeKinesisError(w, http.StatusBadRequest, "InvalidAction", requestID, "unimplemented op "+op)
	}
}

func (h *kinesisHandler) createStream(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["StreamName"].(string)
	if name == "" {
		writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "CreateStream requires StreamName.")
		return
	}
	shardCount := defaultShardCount
	if v, ok := body["ShardCount"]; ok {
		shardCount = toInt(v)
	}
	// ON_DEMAND streams don't specify a shard count; give them a sensible fixed number (a documented divergence
	// — the shim does not auto-scale shards).
	if sm, ok := body["StreamModeDetails"].(map[string]any); ok {
		if mode, _ := sm["StreamMode"].(string); mode == "ON_DEMAND" && shardCount == 0 {
			shardCount = defaultShardCount
		}
	}
	if shardCount < 1 {
		shardCount = 1
	}
	created, err := h.store.createStream(ctx, name, shardCount, 24)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !created {
		writeKinesisError(w, http.StatusBadRequest, "ResourceInUseException", requestID, "Stream "+name+" already exists.")
		return
	}
	h.audit(ctx, "CreateStream", name, "shards", shardCount)
	writeKinesisJSON(w, requestID, map[string]any{})
}

func (h *kinesisHandler) describeStream(ctx context.Context, w http.ResponseWriter, requestID, name string) {
	st, ok, err := h.mustStream(ctx, w, requestID, name)
	if !ok {
		_ = err
		return
	}
	writeKinesisJSON(w, requestID, map[string]any{
		"StreamDescription": map[string]any{
			"StreamName":              st.Name,
			"StreamARN":               h.streamARN(st.Name),
			"StreamStatus":            "ACTIVE",
			"RetentionPeriodHours":    st.Retention,
			"StreamCreationTimestamp": epochSeconds(st.Created.UnixMilli()),
			"EncryptionType":          "NONE",
			"HasMoreShards":           false,
			"Shards":                  h.shardsJSON(st.ShardCount),
		},
	})
}

func (h *kinesisHandler) describeStreamSummary(ctx context.Context, w http.ResponseWriter, requestID, name string) {
	st, ok, _ := h.mustStream(ctx, w, requestID, name)
	if !ok {
		return
	}
	writeKinesisJSON(w, requestID, map[string]any{
		"StreamDescriptionSummary": map[string]any{
			"StreamName":              st.Name,
			"StreamARN":               h.streamARN(st.Name),
			"StreamStatus":            "ACTIVE",
			"RetentionPeriodHours":    st.Retention,
			"OpenShardCount":          st.ShardCount,
			"StreamCreationTimestamp": epochSeconds(st.Created.UnixMilli()),
			"EncryptionType":          "NONE",
		},
	})
}

func (h *kinesisHandler) listStreams(ctx context.Context, w http.ResponseWriter, requestID string) {
	names, err := h.store.listStreams(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if names == nil {
		names = []string{}
	}
	writeKinesisJSON(w, requestID, map[string]any{"StreamNames": names, "HasMoreStreams": false})
}

func (h *kinesisHandler) deleteStream(ctx context.Context, w http.ResponseWriter, requestID, name string) {
	ok, err := h.store.deleteStream(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeKinesisError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Stream "+name+" not found.")
		return
	}
	h.audit(ctx, "DeleteStream", name)
	writeKinesisJSON(w, requestID, map[string]any{})
}

func (h *kinesisHandler) listShards(ctx context.Context, w http.ResponseWriter, requestID, name string) {
	st, ok, _ := h.mustStream(ctx, w, requestID, name)
	if !ok {
		return
	}
	writeKinesisJSON(w, requestID, map[string]any{"Shards": h.shardsJSON(st.ShardCount)})
}

func (h *kinesisHandler) putRecord(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	st, ok, _ := h.mustStream(ctx, w, requestID, name)
	if !ok {
		return
	}
	pk, _ := body["PartitionKey"].(string)
	data, _ := body["Data"].(string)
	if pk == "" || data == "" {
		writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "PutRecord requires PartitionKey and Data.")
		return
	}
	if base64.StdEncoding.DecodedLen(len(data)) > maxRecordBytes {
		writeKinesisError(w, http.StatusBadRequest, "ValidationException", requestID, "record Data exceeds the 1 MiB per-record limit.")
		return
	}
	shard := shardID(shardForKey(pk, st.ShardCount))
	seq, err := h.store.appendRecord(ctx, name, shard, pk, data, time.Now().UnixMilli())
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "PutRecord", name, "shard", shard)
	writeKinesisJSON(w, requestID, map[string]any{"ShardId": shard, "SequenceNumber": formatSeq(seq)})
}

func (h *kinesisHandler) putRecords(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	st, ok, _ := h.mustStream(ctx, w, requestID, name)
	if !ok {
		return
	}
	recs := sliceOf(body["Records"])
	if len(recs) == 0 {
		writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "PutRecords requires Records.")
		return
	}
	out := make([]any, 0, len(recs))
	failed := 0
	now := time.Now().UnixMilli()
	for _, e := range recs {
		m, _ := e.(map[string]any)
		pk, _ := m["PartitionKey"].(string)
		data, _ := m["Data"].(string)
		if pk == "" || data == "" {
			failed++
			out = append(out, map[string]any{"ErrorCode": "ValidationException", "ErrorMessage": "each record requires PartitionKey and Data"})
			continue
		}
		if base64.StdEncoding.DecodedLen(len(data)) > maxRecordBytes {
			failed++
			out = append(out, map[string]any{"ErrorCode": "ValidationException", "ErrorMessage": "record Data exceeds the 1 MiB per-record limit"})
			continue
		}
		shard := shardID(shardForKey(pk, st.ShardCount))
		seq, err := h.store.appendRecord(ctx, name, shard, pk, data, now)
		if err != nil {
			failed++
			out = append(out, map[string]any{"ErrorCode": "InternalFailure", "ErrorMessage": "could not persist record"})
			continue
		}
		out = append(out, map[string]any{"ShardId": shard, "SequenceNumber": formatSeq(seq)})
	}
	h.audit(ctx, "PutRecords", name, "count", len(recs), "failed", failed)
	writeKinesisJSON(w, requestID, map[string]any{"FailedRecordCount": failed, "Records": out})
}

func (h *kinesisHandler) getShardIterator(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	if _, ok, _ := h.mustStream(ctx, w, requestID, name); !ok {
		return
	}
	shard, _ := body["ShardId"].(string)
	itype, _ := body["ShardIteratorType"].(string)
	if shard == "" || itype == "" {
		writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "GetShardIterator requires ShardId and ShardIteratorType.")
		return
	}
	minSeq, latestSeq, _, hasRecords, err := h.store.shardBounds(ctx, name, shard)
	if err != nil {
		h.internal(w, requestID, err)
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
		s, ok := parseSeq(strFromBody(body, "StartingSequenceNumber"))
		if !ok {
			writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "AT_SEQUENCE_NUMBER requires a valid StartingSequenceNumber.")
			return
		}
		next = s
	case "AFTER_SEQUENCE_NUMBER":
		s, ok := parseSeq(strFromBody(body, "StartingSequenceNumber"))
		if !ok {
			writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "AFTER_SEQUENCE_NUMBER requires a valid StartingSequenceNumber.")
			return
		}
		next = s + 1
	case "AT_TIMESTAMP":
		tsSec := parseFloatDefault(strFromBody(body, "Timestamp"), 0)
		if tsSec == 0 {
			writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "AT_TIMESTAMP requires a Timestamp.")
			return
		}
		s, terr := h.store.seqAtOrAfterTimestamp(ctx, name, shard, int64(tsSec*1000))
		if terr != nil {
			h.internal(w, requestID, terr)
			return
		}
		if s < 0 {
			next = latestSeq + 1 // nothing yet at/after that time → park at LATEST
		} else {
			next = s
		}
	default:
		writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "unsupported ShardIteratorType "+itype)
		return
	}
	writeKinesisJSON(w, requestID, map[string]any{"ShardIterator": encodeIterator(shardIterator{Stream: name, Shard: shard, NextSeq: next})})
}

func (h *kinesisHandler) getRecords(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	itStr, _ := body["ShardIterator"].(string)
	it, err := decodeIterator(itStr)
	if err != nil {
		writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "invalid ShardIterator.")
		return
	}
	limit := 0
	if v, ok := body["Limit"]; ok {
		limit = toInt(v)
	}
	recs, err := h.store.getRecords(ctx, it.Stream, it.Shard, it.NextSeq, limit)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	out := make([]any, 0, len(recs))
	next := it.NextSeq
	for _, r := range recs {
		out = append(out, map[string]any{
			"SequenceNumber":              formatSeq(r.Seq),
			"PartitionKey":                r.PartitionKey,
			"Data":                        r.Data, // already base64
			"ApproximateArrivalTimestamp": epochSeconds(r.TsMs),
		})
		next = r.Seq + 1
	}
	// MillisBehindLatest: 0 when caught up; else now - latest record's arrival.
	millisBehind := int64(0)
	_, latestSeq, latestTs, hasRecords, _ := h.store.shardBounds(ctx, it.Stream, it.Shard)
	if hasRecords && next <= latestSeq {
		if b := time.Now().UnixMilli() - latestTs; b > 0 {
			millisBehind = b
		}
	}
	writeKinesisJSON(w, requestID, map[string]any{
		"Records":            out,
		"NextShardIterator":  encodeIterator(shardIterator{Stream: it.Stream, Shard: it.Shard, NextSeq: next}),
		"MillisBehindLatest": millisBehind,
	})
}

func (h *kinesisHandler) changeRetention(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, name string) {
	if _, ok, _ := h.mustStream(ctx, w, requestID, name); !ok {
		return
	}
	hours := toInt(body["RetentionPeriodHours"])
	if hours < 24 || hours > 8760 {
		writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "RetentionPeriodHours must be between 24 and 8760.")
		return
	}
	if err := h.store.setRetention(ctx, name, hours); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "ChangeRetention", name, "hours", hours)
	writeKinesisJSON(w, requestID, map[string]any{})
}

// --- helpers ---

func (h *kinesisHandler) mustStream(ctx context.Context, w http.ResponseWriter, requestID, name string) (kinesisStream, bool, error) {
	if name == "" {
		writeKinesisError(w, http.StatusBadRequest, "InvalidArgumentException", requestID, "a StreamName is required.")
		return kinesisStream{}, false, nil
	}
	st, ok, err := h.store.getStream(ctx, name)
	if err != nil {
		h.internal(w, requestID, err)
		return kinesisStream{}, false, err
	}
	if !ok {
		writeKinesisError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Stream "+name+" not found.")
		return kinesisStream{}, false, nil
	}
	return st, true, nil
}

// shardsJSON renders the shard topology truthfully so consumers enumerate the right shards. Each shard owns
// an equal, contiguous slice of the 2^128 hash-key space (the space PartitionKey hashes into).
func (h *kinesisHandler) shardsJSON(shardCount int) []any {
	out := make([]any, 0, shardCount)
	for i := 0; i < shardCount; i++ {
		lo, hi := hashRangeDecimal(i, shardCount)
		out = append(out, map[string]any{
			"ShardId": shardID(i),
			"HashKeyRange": map[string]any{
				"StartingHashKey": lo,
				"EndingHashKey":   hi,
			},
			"SequenceNumberRange": map[string]any{"StartingSequenceNumber": formatSeq(1)},
		})
	}
	return out
}

func (h *kinesisHandler) streamARN(name string) string {
	return "arn:aws:kinesis:" + h.region + ":" + h.account + ":stream/" + name
}

func (h *kinesisHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("kinesis backend error", "error", err.Error())
	writeKinesisError(w, http.StatusInternalServerError, "InternalFailure", requestID, "An error occurred on the server side.")
}

func (h *kinesisHandler) audit(ctx context.Context, op, stream string, kv ...any) {
	args := []any{"service", "kinesis", "op", op, "decision", "allow", "principal", principalFromCtx(ctx)}
	if stream != "" {
		args = append(args, "stream", stream)
	}
	args = append(args, kv...)
	h.logger.InfoContext(ctx, "kinesis audit", args...)
}

func (h *kinesisHandler) auditDeny(ctx context.Context, op, stream, reason string) {
	args := []any{"service", "kinesis", "op", op, "decision", "deny", "principal", principalFromCtx(ctx), "reason", reason}
	if stream != "" {
		args = append(args, "stream", stream)
	}
	h.logger.InfoContext(ctx, "kinesis audit", args...)
}

// --- pure helpers ---

type shardIterator struct {
	Stream  string
	Shard   string
	NextSeq int64
}

func encodeIterator(it shardIterator) string {
	raw := "v1|" + it.Stream + "|" + it.Shard + "|" + strconv.FormatInt(it.NextSeq, 10)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func decodeIterator(s string) (shardIterator, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return shardIterator{}, err
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 || parts[0] != "v1" {
		return shardIterator{}, fmt.Errorf("malformed iterator")
	}
	seq, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return shardIterator{}, err
	}
	return shardIterator{Stream: parts[1], Shard: parts[2], NextSeq: seq}, nil
}

// shardForKey assigns a PartitionKey to a shard by the first 8 bytes of md5(key) mod shardCount — a stable
// hash so the same key always lands in the same shard and different keys distribute across shards. (A
// documented divergence from AWS's exact 128-bit hash-key-range mapping; the same-key-same-shard and
// distribution properties hold.)
func shardForKey(partitionKey string, shardCount int) int {
	if shardCount <= 1 {
		return 0
	}
	sum := md5.Sum([]byte(partitionKey))
	v := binary.BigEndian.Uint64(sum[:8])
	return int(v % uint64(shardCount))
}

// formatSeq renders a per-shard sequence number as a fixed-width, lexically-and-numerically monotonic
// decimal string (AWS SequenceNumbers are opaque decimal strings the client echoes back).
func formatSeq(seq int64) string { return fmt.Sprintf("%021d", seq) }

func parseSeq(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64) // base-10 ParseInt handles the zero-padding ("00005" -> 5)
	if err != nil {
		return 0, false
	}
	return n, true
}

// hashRangeDecimal returns the [start,end] of the 2^128 hash space owned by shard i of n (as decimal
// strings), so DescribeStream/ListShards report a truthful, contiguous topology (start of shard 0 is 0, end
// of the last shard is 2^128-1, and each shard's range abuts the next).
func hashRangeDecimal(i, n int) (string, string) {
	if n < 1 {
		n = 1
	}
	total := new(big.Int).Lsh(big.NewInt(1), 128) // 2^128
	per := new(big.Int).Div(total, big.NewInt(int64(n)))
	start := new(big.Int).Mul(per, big.NewInt(int64(i)))
	var end *big.Int
	if i == n-1 {
		end = new(big.Int).Sub(total, big.NewInt(1)) // last shard absorbs the remainder up to 2^128-1
	} else {
		end = new(big.Int).Sub(new(big.Int).Mul(per, big.NewInt(int64(i+1))), big.NewInt(1))
	}
	return start.String(), end.String()
}
