//go:build integration

// Live FerretDB round-trip for the aws-shim's DynamoDB front door — the full wire path (X-Amz-Target
// + JSON body -> the shared store over FerretDB -> a typed DynamoDB response). Run with:
//
//	FERRET_TEST_URI="mongodb://user:pass@host:27017" go test -tags integration ./cmd/aws-shim/
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestDynamo_FerretRoundTrip(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI to run the live DynamoDB front-door round-trip")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_dynamo_" + time.Now().Format("150405"))
	defer db.Drop(ctx)

	h := newDynamoHandler(csWithSAR(true), "default", db, nil, "", discardLogger())
	claims := iam.Claims{Sub: "tester"}
	call := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.serve(w, dynamoReq("DynamoDB_20120810."+op, body), claims, "r")
		return w
	}
	ok := func(t *testing.T, w *httptest.ResponseRecorder, op string) map[string]any {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", op, w.Code, w.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}

	// CreateTable establishes the key schema.
	ok(t, call("CreateTable", `{"TableName":"notes","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}]}`), "CreateTable")

	// PutItem — the whole Item; the adapter splits the key by the registered schema.
	ok(t, call("PutItem", `{"TableName":"notes","Item":{"id":{"S":"1"},"body":{"S":"hi"},"n":{"N":"7"}}}`), "PutItem")

	// GetItem reads it back as a typed Item.
	got := ok(t, call("GetItem", `{"TableName":"notes","Key":{"id":{"S":"1"}}}`), "GetItem")
	item, _ := got["Item"].(map[string]any)
	if item == nil {
		t.Fatalf("GetItem returned no Item: %v", got)
	}
	if b, _ := item["body"].(map[string]any); b["S"] != "hi" {
		t.Errorf("body = %v, want {S:hi}", item["body"])
	}
	if n, _ := item["n"].(map[string]any); n["N"] != "7" {
		t.Errorf("n = %v, want {N:7} (numbers are wire-encoded as strings)", item["n"])
	}

	// DeleteItem, then GetItem is a miss (an empty response, not an error).
	ok(t, call("DeleteItem", `{"TableName":"notes","Key":{"id":{"S":"1"}}}`), "DeleteItem")
	miss := ok(t, call("GetItem", `{"TableName":"notes","Key":{"id":{"S":"1"}}}`), "GetItem-miss")
	if _, present := miss["Item"]; present {
		t.Errorf("a deleted item should return no Item, got %v", miss)
	}

	// PutItem to a table that was never created → ResourceNotFound (not a silent auto-create).
	w := call("PutItem", `{"TableName":"ghost","Item":{"id":{"S":"1"}}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PutItem to a nonexistent table should be 400 ResourceNotFound, got %d %s", w.Code, w.Body.String())
	}

	// An un-built operation is an honest 501, never a fake.
	if w := call("ListTables", `{}`); w.Code != http.StatusNotImplemented {
		t.Errorf("ListTables should still be an honest 501, got %d", w.Code)
	}
}

func TestDynamo_QueryUpdateScan(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_dyn_qus_" + time.Now().Format("150405"))
	defer db.Drop(ctx)
	h := newDynamoHandler(csWithSAR(true), "default", db, nil, "", discardLogger())
	call := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.serve(w, dynamoReq("DynamoDB_20120810."+op, body), iam.Claims{Sub: "t"}, "r")
		return w
	}
	must := func(op, body string) map[string]any {
		w := call(op, body)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", op, w.Code, w.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}

	// A chat table: partition=room, sort=ts.
	must("CreateTable", `{"TableName":"msgs","KeySchema":[{"AttributeName":"room","KeyType":"HASH"},{"AttributeName":"ts","KeyType":"RANGE"}]}`)
	for _, m := range []string{
		`{"room":{"S":"general"},"ts":{"N":"1"},"body":{"S":"a"}}`,
		`{"room":{"S":"general"},"ts":{"N":"2"},"body":{"S":"b"}}`,
		`{"room":{"S":"general"},"ts":{"N":"3"},"body":{"S":"c"}}`,
		`{"room":{"S":"random"},"ts":{"N":"1"},"body":{"S":"z"}}`,
	} {
		must("PutItem", `{"TableName":"msgs","Item":`+m+`}`)
	}

	// Query by partition key.
	q := must("Query", `{"TableName":"msgs","KeyConditionExpression":"room = :r","ExpressionAttributeValues":{":r":{"S":"general"}}}`)
	if items, _ := q["Items"].([]any); len(items) != 3 {
		t.Fatalf("Query general = %v items, want 3", q["Count"])
	}
	// Query with a sort-key BETWEEN.
	q2 := must("Query", `{"TableName":"msgs","KeyConditionExpression":"room = :r AND ts BETWEEN :lo AND :hi","ExpressionAttributeValues":{":r":{"S":"general"},":lo":{"N":"1"},":hi":{"N":"2"}}}`)
	if items, _ := q2["Items"].([]any); len(items) != 2 {
		t.Fatalf("Query BETWEEN [1,2] = %v items, want 2", q2["Count"])
	}

	// UpdateItem: SET body + ADD version.
	must("UpdateItem", `{"TableName":"msgs","Key":{"room":{"S":"general"},"ts":{"N":"2"}},"UpdateExpression":"SET body = :b ADD version :one","ExpressionAttributeValues":{":b":{"S":"edited"},":one":{"N":"1"}}}`)
	got := must("GetItem", `{"TableName":"msgs","Key":{"room":{"S":"general"},"ts":{"N":"2"}}}`)
	item, _ := got["Item"].(map[string]any)
	if b, _ := item["body"].(map[string]any); b["S"] != "edited" {
		t.Errorf("UpdateItem SET body = %v, want edited", item["body"])
	}
	if v, _ := item["version"].(map[string]any); v["N"] != "1" {
		t.Errorf("UpdateItem ADD version = %v, want 1", item["version"])
	}

	// A failed condition is a real DynamoDB semantic: 400 ConditionalCheckFailed.
	if w := call("UpdateItem", `{"TableName":"msgs","Key":{"room":{"S":"nope"},"ts":{"N":"9"}},"UpdateExpression":"SET body = :b","ConditionExpression":"attribute_exists(room)","ExpressionAttributeValues":{":b":{"S":"x"}}}`); w.Code != http.StatusBadRequest {
		t.Errorf("a failed condition should be 400 ConditionalCheckFailed, got %d %s", w.Code, w.Body.String())
	}

	// Scan returns everything.
	s := must("Scan", `{"TableName":"msgs"}`)
	if items, _ := s["Items"].([]any); len(items) != 4 {
		t.Fatalf("Scan = %v items, want 4", s["Count"])
	}
}

func TestDynamo_Batch(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_dyn_batch_" + time.Now().Format("150405"))
	defer db.Drop(ctx)
	h := newDynamoHandler(csWithSAR(true), "default", db, nil, "", discardLogger())
	call := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.serve(w, dynamoReq("DynamoDB_20120810."+op, body), iam.Claims{Sub: "t"}, "r")
		return w
	}
	must := func(op, body string) map[string]any {
		w := call(op, body)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", op, w.Code, w.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}

	must("CreateTable", `{"TableName":"things","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}]}`)

	// BatchWriteItem: three puts in one call.
	bw := must("BatchWriteItem", `{"RequestItems":{"things":[
		{"PutRequest":{"Item":{"id":{"S":"1"},"v":{"N":"10"}}}},
		{"PutRequest":{"Item":{"id":{"S":"2"},"v":{"N":"20"}}}},
		{"PutRequest":{"Item":{"id":{"S":"3"},"v":{"N":"30"}}}}
	]}}`)
	if up, _ := bw["UnprocessedItems"].(map[string]any); len(up) != 0 {
		t.Errorf("BatchWriteItem UnprocessedItems = %v, want empty", bw["UnprocessedItems"])
	}

	// BatchGetItem: fetch two that exist + one that does not; the miss is simply absent.
	bg := must("BatchGetItem", `{"RequestItems":{"things":{"Keys":[
		{"id":{"S":"1"}},{"id":{"S":"3"}},{"id":{"S":"404"}}
	]}}}`)
	resp, _ := bg["Responses"].(map[string]any)
	got, _ := resp["things"].([]any)
	if len(got) != 2 {
		t.Fatalf("BatchGetItem returned %d items, want 2 (the missing key is absent, not an error)", len(got))
	}

	// BatchWriteItem again: a delete + a put in one call.
	must("BatchWriteItem", `{"RequestItems":{"things":[
		{"DeleteRequest":{"Key":{"id":{"S":"2"}}}},
		{"PutRequest":{"Item":{"id":{"S":"4"},"v":{"N":"40"}}}}
	]}}`)
	// id 2 is gone, id 4 is present -> a full scan sees 1,3,4.
	s := must("Scan", `{"TableName":"things"}`)
	if items, _ := s["Items"].([]any); len(items) != 3 {
		t.Fatalf("after batch delete+put, Scan = %v items, want 3", s["Count"])
	}

	// Fidelity guardrail: BatchWriteItem is capped at 25 requests.
	over := `{"RequestItems":{"things":[` + strings.Repeat(`{"PutRequest":{"Item":{"id":{"S":"x"}}}},`, 25) + `{"PutRequest":{"Item":{"id":{"S":"x"}}}}]}}`
	if w := call("BatchWriteItem", over); w.Code != http.StatusBadRequest {
		t.Errorf("26 write requests should be a 400 ValidationException, got %d", w.Code)
	}

	// A ProjectionExpression is refused loudly, not silently ignored.
	if w := call("GetItem", `{"TableName":"things","Key":{"id":{"S":"1"}},"ProjectionExpression":"v"}`); w.Code != http.StatusNotImplemented {
		t.Errorf("GetItem with a ProjectionExpression should be an honest 501, got %d", w.Code)
	}
}
