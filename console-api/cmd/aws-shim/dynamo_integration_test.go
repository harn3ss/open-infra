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

	h := newDynamoHandler(csWithSAR(true), "default", db, discardLogger())
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
	if w := call("Query", `{"TableName":"notes","KeyConditionExpression":"id = :id"}`); w.Code != http.StatusNotImplemented {
		t.Errorf("Query should still be an honest 501, got %d", w.Code)
	}
}
