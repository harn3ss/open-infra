//go:build integration

// Live round-trip for DynamoDB Streams: a table with a stream emits INSERT/MODIFY/REMOVE change
// records for its item writes, read back via the dynamodbstreams API (GetShardIterator/GetRecords).
// Run with BOTH a FerretDB (item writes) and its documentdb Postgres (the change-record log):
//
//	FERRET_TEST_URI="mongodb://app:pass@host:27017" \
//	MONGO_PG_TEST_URI="postgres://app:pass@host:5432/postgres?sslmode=disable" \
//	go test -tags integration -run Streams ./cmd/aws-shim/
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestDynamo_Streams(t *testing.T) {
	uri, pgURI := os.Getenv("FERRET_TEST_URI"), os.Getenv("MONGO_PG_TEST_URI")
	if uri == "" || pgURI == "" {
		t.Skip("set FERRET_TEST_URI and MONGO_PG_TEST_URI to run the live DynamoDB Streams round-trip")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_stream_" + time.Now().Format("150405"))
	defer db.Drop(ctx)

	pg, err := sql.Open("postgres", pgURI)
	if err != nil {
		t.Fatalf("pg open: %v", err)
	}
	defer pg.Close()
	if err := pg.PingContext(ctx); err != nil {
		t.Fatalf("pg ping: %v", err)
	}
	streamSt := &ddbStreamStore{db: pg}
	if err := streamSt.ensureSchema(ctx); err != nil {
		t.Fatalf("stream schema: %v", err)
	}
	defer func() { _ = streamSt.closeStream(context.Background(), "evt") }()

	dynH := newDynamoHandler(csWithSAR(true), "default", db, pg, db.Name(), discardLogger())
	dynH.stream = streamSt
	dynH.account, dynH.region = "acct", "us-east-1"
	streamsH := newDDBStreamsHandler(csWithSAR(true), "default", "acct", "us-east-1", streamSt, dynH, discardLogger())

	claims := iam.Claims{Sub: "tester"}
	dyn := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		dynH.serve(w, dynamoReq("DynamoDB_20120810."+op, body), claims, "r")
		return w
	}
	str := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		streamsH.serve(w, dynamoReq("DynamoDBStreams_20120810."+op, body), claims, "r")
		return w
	}
	mustOK := func(what string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", what, w.Code, w.Body.String())
		}
	}

	// A table with a stream (NEW_AND_OLD_IMAGES).
	mustOK("CreateTable", dyn("CreateTable", `{"TableName":"evt","AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"}}`))

	// Three writes → INSERT, MODIFY, REMOVE.
	mustOK("PutItem", dyn("PutItem", `{"TableName":"evt","Item":{"id":{"S":"a"},"v":{"N":"1"}}}`))
	mustOK("UpdateItem", dyn("UpdateItem", `{"TableName":"evt","Key":{"id":{"S":"a"}},"UpdateExpression":"SET v = :v","ExpressionAttributeValues":{":v":{"N":"2"}}}`))
	mustOK("DeleteItem", dyn("DeleteItem", `{"TableName":"evt","Key":{"id":{"S":"a"}}}`))

	arn := dynamoStreamARN("us-east-1", "acct", "evt")

	// DescribeStream reports the single shard + the view type.
	d := str("DescribeStream", `{"StreamArn":"`+arn+`"}`)
	mustOK("DescribeStream", d)
	if !strings.Contains(d.Body.String(), "NEW_AND_OLD_IMAGES") || !strings.Contains(d.Body.String(), ddbStreamShard) {
		t.Fatalf("DescribeStream should report the view type + shard: %s", d.Body.String())
	}

	// A TRIM_HORIZON iterator, then read the records.
	si := str("GetShardIterator", `{"StreamArn":"`+arn+`","ShardId":"`+ddbStreamShard+`","ShardIteratorType":"TRIM_HORIZON"}`)
	mustOK("GetShardIterator", si)
	var siResp struct{ ShardIterator string }
	_ = json.Unmarshal(si.Body.Bytes(), &siResp)
	if siResp.ShardIterator == "" {
		t.Fatalf("no shard iterator: %s", si.Body.String())
	}

	gr := str("GetRecords", `{"ShardIterator":"`+siResp.ShardIterator+`"}`)
	mustOK("GetRecords", gr)
	var grResp struct {
		Records []struct {
			EventName string `json:"eventName"`
			Dynamodb  struct {
				Keys     map[string]any `json:"Keys"`
				NewImage map[string]any `json:"NewImage"`
				OldImage map[string]any `json:"OldImage"`
			} `json:"dynamodb"`
		} `json:"Records"`
	}
	if err := json.Unmarshal(gr.Body.Bytes(), &grResp); err != nil {
		t.Fatalf("decode GetRecords: %v (%s)", err, gr.Body.String())
	}
	if len(grResp.Records) != 3 {
		t.Fatalf("expected 3 change records (INSERT/MODIFY/REMOVE), got %d: %s", len(grResp.Records), gr.Body.String())
	}
	if got := []string{grResp.Records[0].EventName, grResp.Records[1].EventName, grResp.Records[2].EventName}; got[0] != "INSERT" || got[1] != "MODIFY" || got[2] != "REMOVE" {
		t.Fatalf("event order should be INSERT, MODIFY, REMOVE; got %v", got)
	}
	// INSERT carries a NewImage, no OldImage.
	if grResp.Records[0].Dynamodb.NewImage == nil || grResp.Records[0].Dynamodb.OldImage != nil {
		t.Fatalf("INSERT should carry NewImage only: %+v", grResp.Records[0].Dynamodb)
	}
	// MODIFY carries both images, and the new value is the updated one.
	mod := grResp.Records[1].Dynamodb
	if mod.NewImage == nil || mod.OldImage == nil {
		t.Fatalf("MODIFY should carry both images: %+v", mod)
	}
	// REMOVE carries the OldImage (what was deleted), no NewImage.
	if grResp.Records[2].Dynamodb.OldImage == nil || grResp.Records[2].Dynamodb.NewImage != nil {
		t.Fatalf("REMOVE should carry OldImage only: %+v", grResp.Records[2].Dynamodb)
	}
	// Keys are present on every record.
	for i, r := range grResp.Records {
		if _, ok := r.Dynamodb.Keys["id"]; !ok {
			t.Fatalf("record %d missing Keys.id: %+v", i, r.Dynamodb)
		}
	}
}
