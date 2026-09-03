//go:build integration

// Live transaction round-trip for the aws-shim DynamoDB front door: TransactWriteItems commits
// multiple items atomically through the documentdb Postgres behind FerretDB, and the writes are
// read-consistent over the mongo path. Run with BOTH a FerretDB and its documentdb Postgres:
//
//	FERRET_TEST_URI="mongodb://app:pass@host:27017" \
//	MONGO_PG_TEST_URI="postgres://app:pass@host:5432/postgres?sslmode=disable" \
//	go test -tags integration -run Transact ./cmd/aws-shim/
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestDynamo_TransactWriteItems(t *testing.T) {
	uri, pgURI := os.Getenv("FERRET_TEST_URI"), os.Getenv("MONGO_PG_TEST_URI")
	if uri == "" || pgURI == "" {
		t.Skip("set FERRET_TEST_URI and MONGO_PG_TEST_URI to run the live transaction round-trip")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_txn_" + time.Now().Format("150405"))
	defer db.Drop(ctx)

	pg, err := sql.Open("postgres", pgURI)
	if err != nil {
		t.Fatalf("pg open: %v", err)
	}
	defer pg.Close()
	if err := pg.PingContext(ctx); err != nil {
		t.Fatalf("pg ping: %v", err)
	}

	h := newDynamoHandler(csWithSAR(true), "default", db, pg, db.Name(), discardLogger())
	claims := iam.Claims{Sub: "tester"}
	call := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.serve(w, dynamoReq("DynamoDB_20120810."+op, body), claims, "r")
		return w
	}
	mustOK := func(op string, w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", op, w.Code, w.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}
	getItem := func(id string) map[string]any {
		w := call("GetItem", `{"TableName":"acct","Key":{"id":{"S":"`+id+`"}}}`)
		m := mustOK("GetItem", w)
		item, _ := m["Item"].(map[string]any)
		return item
	}

	mustOK("CreateTable", call("CreateTable", `{"TableName":"acct","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}]}`))
	// seed "a" so the transaction can delete it
	mustOK("PutItem", call("PutItem", `{"TableName":"acct","Item":{"id":{"S":"a"},"bal":{"N":"1"}}}`))

	// Atomic: Put x, Put y, Delete a — all or nothing.
	mustOK("TransactWriteItems", call("TransactWriteItems", `{"TransactItems":[
		{"Put":{"TableName":"acct","Item":{"id":{"S":"x"},"bal":{"N":"10"}}}},
		{"Put":{"TableName":"acct","Item":{"id":{"S":"y"},"bal":{"N":"20"}}}},
		{"Delete":{"TableName":"acct","Key":{"id":{"S":"a"}}}}
	]}`))

	// Consistency: the transactional writes are visible over the mongo read path.
	if getItem("x") == nil || getItem("y") == nil {
		t.Fatalf("transactional Puts not visible via GetItem (x=%v y=%v)", getItem("x"), getItem("y"))
	}
	if bal, _ := getItem("x")["bal"].(map[string]any); bal["N"] != "10" {
		t.Errorf("x.bal = %v, want {N:10}", getItem("x")["bal"])
	}
	if getItem("a") != nil {
		t.Errorf("transactional Delete of a did not take effect: %v", getItem("a"))
	}

	// Fail-loud: an unsupported item (Update) refuses the WHOLE transaction before any write —
	// its sibling Put must NOT land (nothing partial).
	w := call("TransactWriteItems", `{"TransactItems":[
		{"Put":{"TableName":"acct","Item":{"id":{"S":"z"},"bal":{"N":"99"}}}},
		{"Update":{"TableName":"acct","Key":{"id":{"S":"y"}},"UpdateExpression":"SET bal = :b","ExpressionAttributeValues":{":b":{"N":"1"}}}}
	]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a transaction with an Update item should be refused (400), got %d: %s", w.Code, w.Body.String())
	}
	if getItem("z") != nil {
		t.Errorf("refused transaction must write NOTHING, but z landed: %v", getItem("z"))
	}
}

func TestDynamo_TTLAndScan(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI to run the live TTL + Scan test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_ttl_" + time.Now().Format("150405"))
	defer db.Drop(ctx)

	h := newDynamoHandler(csWithSAR(true), "default", db, nil, db.Name(), discardLogger())
	claims := iam.Claims{Sub: "tester"}
	call := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.serve(w, dynamoReq("DynamoDB_20120810."+op, body), claims, "r")
		return w
	}
	mustOK := func(op string, w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", op, w.Code, w.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return m
	}

	mustOK("CreateTable", call("CreateTable", `{"TableName":"sess","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}]}`))

	// Enable TTL on "exp"; DescribeTimeToLive reflects it.
	mustOK("UpdateTimeToLive", call("UpdateTimeToLive", `{"TableName":"sess","TimeToLiveSpecification":{"Enabled":true,"AttributeName":"exp"}}`))
	desc := mustOK("DescribeTimeToLive", call("DescribeTimeToLive", `{"TableName":"sess"}`))
	if d, _ := desc["TimeToLiveDescription"].(map[string]any); d["TimeToLiveStatus"] != "ENABLED" || d["AttributeName"] != "exp" {
		t.Fatalf("DescribeTimeToLive = %v, want ENABLED on exp", desc["TimeToLiveDescription"])
	}

	// One expired (exp in the past), one live (exp far future).
	mustOK("PutItem", call("PutItem", `{"TableName":"sess","Item":{"id":{"S":"old"},"exp":{"N":"1000"}}}`))
	mustOK("PutItem", call("PutItem", `{"TableName":"sess","Item":{"id":{"S":"new"},"exp":{"N":"9999999999"}}}`))

	// Drive the reaper directly (rather than waiting for the ticker).
	h.reapExpired(ctx)

	scan := mustOK("Scan", call("Scan", `{"TableName":"sess"}`))
	items, _ := scan["Items"].([]any)
	ids := map[string]bool{}
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			if id, ok := m["id"].(map[string]any); ok {
				ids[id["S"].(string)] = true
			}
		}
	}
	if ids["old"] {
		t.Errorf("TTL reaper should have expired 'old' (exp in the past); Scan still sees it: %v", ids)
	}
	if !ids["new"] {
		t.Errorf("Scan should still return the live item 'new'; got %v", ids)
	}
}
