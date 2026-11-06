package main

// Account isolation of the DynamoDB and DynamoDB Streams front doors against a REAL FerretDB (documentdb)
// and its Postgres: a member account's tables, items, streams, declared tables and stack-table hooks are its
// own, the management account's table of the same name is untouched and invisible to it, and the member's
// is invisible to the management account. Run with
//
//	FERRET_TEST_URI=mongodb://user:pass@host:27017/ MONGO_PG_TEST_URI=postgres://user:pass@host:5432/postgres?sslmode=disable
//
// (the Postgres behind that FerretDB — transactions and streams use it); skipped without them.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ddbStore struct {
	h      *dynamoHandler
	s      *ddbStreamsHandler
	db     *mongo.Database
	mgmt   context.Context
	member context.Context
}

func newDDBStore(t *testing.T) *ddbStore {
	t.Helper()
	uri, pgURI := os.Getenv("FERRET_TEST_URI"), os.Getenv("MONGO_PG_TEST_URI")
	if uri == "" || pgURI == "" {
		t.Skip("set FERRET_TEST_URI and MONGO_PG_TEST_URI to run the DynamoDB account-isolation store tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}
	db := client.Database(fmt.Sprintf("shim_acct_%d", time.Now().UnixNano()))
	t.Cleanup(func() { _ = db.Drop(context.Background()); _ = client.Disconnect(context.Background()) })
	pg, err := sql.Open("postgres", pgURI)
	if err != nil {
		t.Fatalf("pg open: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	streams := &ddbStreamStore{db: pg}
	if err := streams.ensureSchema(ctx); err != nil {
		t.Fatalf("stream schema: %v", err)
	}
	authz := ddbAllowAll(t)
	h := newDynamoHandler(csWithSAR(true), "default", db, pg, db.Name(), discardLogger())
	h.stream, h.authz, h.account, h.region = streams, authz, testMgmt, "us-east-1"
	s := newDDBStreamsHandler(csWithSAR(true), "default", testMgmt, "us-east-1", streams, h, discardLogger())
	s.authz = authz
	return &ddbStore{h: h, s: s, db: db, mgmt: inAccountScope(ctx), member: inAccountScope(withAccountHome(memberCtx(), memberHome))}
}

func (d *ddbStore) claims(ctx context.Context) iam.Claims {
	if isMemberRequest(ctx) {
		return ddbBob
	}
	return ddbMgmtBob
}

// call makes one DynamoDB (or, for a DynamoDBStreams_ target, Streams) request in ctx's account, and
// decodes its answer; want is the status it must have.
func (d *ddbStore) call(t *testing.T, ctx context.Context, want int, op, body string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	if strings.HasPrefix(op, "Streams.") {
		d.s.serve(w, dynamoReq("DynamoDBStreams_20120810."+strings.TrimPrefix(op, "Streams."), body).WithContext(ctx), d.claims(ctx), "r")
	} else {
		d.h.serve(w, dynamoReq("DynamoDB_20120810."+op, body).WithContext(ctx), d.claims(ctx), "r")
	}
	if w.Code != want {
		t.Fatalf("%s %s: status %d, want %d: %s", op, body, w.Code, want, w.Body.String())
	}
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func listedTables(out map[string]any) []string {
	var names []string
	for _, n := range out["TableNames"].([]any) {
		names = append(names, n.(string))
	}
	return names
}

func TestDynamoAccounts_Store_EachAccountHasItsOwnTables(t *testing.T) {
	d := newDDBStore(t)
	ok, notFound := http.StatusOK, http.StatusBadRequest
	tbl := fmt.Sprintf("orders-%d", time.Now().UnixNano()%1_000_000_000)
	t.Cleanup(func() {
		_ = d.h.stream.closeStream(context.Background(), tbl)
		_ = d.h.stream.closeStream(context.Background(), testMember+":"+tbl)
	})
	mgmt, member := d.mgmt, d.member

	// The same name in both accounts, with different key schemas: two tables.
	d.call(t, mgmt, ok, "CreateTable", `{"TableName":"`+tbl+`","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_IMAGE"}}`)
	d.call(t, mgmt, ok, "PutItem", `{"TableName":"`+tbl+`","Item":{"id":{"S":"1"},"owner":{"S":"management"}}}`)
	created := d.call(t, member, ok, "CreateTable", `{"TableName":"`+tbl+`","KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],"StreamSpecification":{"StreamEnabled":true,"StreamViewType":"NEW_AND_OLD_IMAGES"}}`)
	desc := created["TableDescription"].(map[string]any)
	if desc["TableName"] != tbl || desc["TableArn"] != "arn:aws:dynamodb:us-east-1:"+testMember+":table/"+tbl ||
		desc["LatestStreamArn"] != "arn:aws:dynamodb:us-east-1:"+testMember+":table/"+tbl+"/stream/"+tbl || desc["LatestStreamLabel"] != tbl {
		t.Fatalf("the member account's table must be named as it named it, with its ARNs: %v", desc)
	}
	d.call(t, member, ok, "PutItem", `{"TableName":"`+tbl+`","Item":{"pk":{"S":"1"},"owner":{"S":"member"},"exp":{"N":"1"}}}`)

	// Each reads its own.
	if got := d.call(t, member, ok, "GetItem", `{"TableName":"`+tbl+`","Key":{"pk":{"S":"1"}}}`); !strings.Contains(fmt.Sprint(got), "member") {
		t.Errorf("the member account reads its own item: %v", got)
	}
	if got := d.call(t, member, ok, "GetItem", `{"TableName":"`+tbl+`","Key":{"id":{"S":"1"}}}`); got["Item"] != nil {
		t.Errorf("the member account read the management account's item: %v", got)
	}
	if got := d.call(t, mgmt, ok, "GetItem", `{"TableName":"`+tbl+`","Key":{"id":{"S":"1"}}}`); !strings.Contains(fmt.Sprint(got), "management") {
		t.Errorf("the management account's item must be untouched: %v", got)
	}
	if got := d.call(t, member, ok, "Scan", `{"TableName":"`+tbl+`"}`); got["Count"] != float64(1) || strings.Contains(fmt.Sprint(got), "management") {
		t.Errorf("the member account's scan sees its own items alone: %v", got)
	}
	mdesc := d.call(t, mgmt, ok, "DescribeTable", `{"TableName":"`+tbl+`"}`)["Table"].(map[string]any)
	if !strings.Contains(fmt.Sprint(mdesc["KeySchema"]), "id") || mdesc["TableArn"] != "arn:aws:dynamodb:us-east-1:"+testMgmt+":table/"+tbl ||
		mdesc["LatestStreamArn"] != dynamoStreamARN("us-east-1", testMgmt, tbl) {
		t.Errorf("the management account's table keeps its schema and ARNs: %v", mdesc)
	}
	if ks := d.call(t, member, ok, "DescribeTable", `{"TableName":"`+tbl+`"}`)["Table"].(map[string]any)["KeySchema"]; !strings.Contains(fmt.Sprint(ks), "pk") {
		t.Errorf("the member account's table has its own schema: %v", ks)
	}
	// The management account's table is where it always was: its name is its collection and registry id.
	if n, _ := d.db.Collection(tbl).CountDocuments(context.Background(), bson.M{}); n != 1 {
		t.Errorf("the management account's collection holds %d items, want 1", n)
	}
	if err := d.db.Collection(tableRegistry).FindOne(context.Background(), bson.M{"_id": testMember + ":" + tbl}).Err(); err != nil {
		t.Errorf("the member account's table must be keyed by its account: %v", err)
	}

	// A table only one account has is invisible to the other — not described, not listed, not written.
	d.call(t, mgmt, ok, "CreateTable", `{"TableName":"only-mgmt","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}]}`)
	d.call(t, member, ok, "CreateTable", `{"TableName":"only-member","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}]}`)
	d.call(t, member, ok, "CreateTable", `{"TableName":"zz-member","KeySchema":[{"AttributeName":"id","KeyType":"HASH"}]}`)
	if e := d.call(t, member, notFound, "DescribeTable", `{"TableName":"only-mgmt"}`); !strings.Contains(fmt.Sprint(e["message"]), "Table: only-mgmt not found") {
		t.Errorf("the member account is told the table it named is not found: %v", e)
	}
	d.call(t, member, notFound, "PutItem", `{"TableName":"only-mgmt","Item":{"id":{"S":"x"}}}`)
	d.call(t, mgmt, notFound, "DescribeTable", `{"TableName":"only-member"}`)
	mlist := listedTables(d.call(t, mgmt, ok, "ListTables", `{}`))
	if strings.Join(mlist, ",") != "only-mgmt,"+tbl {
		t.Errorf("the management account lists its own tables alone: %v", mlist)
	}
	all := listedTables(d.call(t, member, ok, "ListTables", `{}`))
	if strings.Join(all, ",") != "only-member,"+tbl+",zz-member" {
		t.Errorf("the member account lists its own tables alone: %v", all)
	}
	// Paging stays in the account.
	page := d.call(t, member, ok, "ListTables", `{"Limit":2}`)
	if strings.Join(listedTables(page), ",") != "only-member,"+tbl || page["LastEvaluatedTableName"] != tbl {
		t.Errorf("first page: %v", page)
	}
	page = d.call(t, member, ok, "ListTables", `{"Limit":2,"ExclusiveStartTableName":"`+tbl+`"}`)
	if strings.Join(listedTables(page), ",") != "zz-member" || page["LastEvaluatedTableName"] != nil {
		t.Errorf("second page: %v", page)
	}
	if page := d.call(t, mgmt, ok, "ListTables", `{"Limit":1}`); strings.Join(listedTables(page), ",") != "only-mgmt" || page["LastEvaluatedTableName"] != "only-mgmt" {
		t.Errorf("the management account's first page: %v", page)
	}

	// Batches and transactions name the tables as the caller does, and reach its own.
	d.call(t, member, ok, "BatchWriteItem", `{"RequestItems":{"`+tbl+`":[{"PutRequest":{"Item":{"pk":{"S":"2"},"owner":{"S":"member"}}}}]}}`)
	bg := d.call(t, member, ok, "BatchGetItem", `{"RequestItems":{"`+tbl+`":{"Keys":[{"pk":{"S":"2"}}]},"only-member":{"Keys":[{"id":{"S":"none"}}]}}}`)
	resp := bg["Responses"].(map[string]any)
	if items, _ := resp[tbl].([]any); len(items) != 1 || len(resp) != 2 {
		t.Errorf("BatchGetItem answers per table by the caller's names: %v", bg)
	}
	d.call(t, member, ok, "TransactWriteItems", `{"TransactItems":[{"Put":{"TableName":"`+tbl+`","Item":{"pk":{"S":"3"},"owner":{"S":"member"}}}},{"ConditionCheck":{"TableName":"`+tbl+`","Key":{"pk":{"S":"1"}},"ConditionExpression":"attribute_exists(pk)"}}]}`)
	tg := d.call(t, member, ok, "TransactGetItems", `{"TransactItems":[{"Get":{"TableName":"`+tbl+`","Key":{"pk":{"S":"3"}}}}]}`)
	if !strings.Contains(fmt.Sprint(tg), "member") {
		t.Errorf("TransactGetItems reads the member account's table: %v", tg)
	}
	// A transaction naming the other account's table is refused as a missing table.
	d.call(t, member, notFound, "TransactWriteItems", `{"TransactItems":[{"Put":{"TableName":"only-mgmt","Item":{"id":{"S":"x"}}}}]}`)
	if n, _ := d.db.Collection(tbl).CountDocuments(context.Background(), bson.M{}); n != 1 {
		t.Errorf("the member account's writes reached the management account's table (%d items)", n)
	}

	// Streams: each account lists and reads its own.
	mstreams := fmt.Sprint(d.call(t, mgmt, ok, "Streams.ListStreams", `{}`)["Streams"])
	if strings.Contains(mstreams, testMember) || !strings.Contains(mstreams, dynamoStreamARN("us-east-1", testMgmt, tbl)) {
		t.Errorf("the management account's streams: %s", mstreams)
	}
	ownARN := dynamoStreamARN("us-east-1", testMember, tbl)
	streams := d.call(t, member, ok, "Streams.ListStreams", `{}`)["Streams"].([]any)
	if len(streams) != 1 || streams[0].(map[string]any)["StreamArn"] != ownARN || streams[0].(map[string]any)["TableName"] != tbl {
		t.Errorf("the member account's streams: %v", streams)
	}
	sd := d.call(t, member, ok, "Streams.DescribeStream", `{"StreamArn":"`+ownARN+`"}`)["StreamDescription"].(map[string]any)
	if sd["StreamArn"] != ownARN || sd["TableName"] != tbl || sd["StreamViewType"] != "NEW_AND_OLD_IMAGES" || !strings.Contains(fmt.Sprint(sd["KeySchema"]), "pk") {
		t.Errorf("the member account's stream: %v", sd)
	}
	it := d.call(t, member, ok, "Streams.GetShardIterator", `{"StreamArn":"`+ownARN+`","ShardId":"`+ddbStreamShard+`","ShardIteratorType":"TRIM_HORIZON"}`)["ShardIterator"].(string)
	recs := fmt.Sprint(d.call(t, member, ok, "Streams.GetRecords", `{"ShardIterator":"`+it+`"}`)["Records"])
	if !strings.Contains(recs, "member") || strings.Contains(recs, "management") {
		t.Errorf("the member account's stream records: %s", recs)
	}
	mit := d.call(t, mgmt, ok, "Streams.GetShardIterator", `{"StreamArn":"`+dynamoStreamARN("us-east-1", testMgmt, tbl)+`","ShardId":"`+ddbStreamShard+`","ShardIteratorType":"TRIM_HORIZON"}`)["ShardIterator"].(string)
	if recs := fmt.Sprint(d.call(t, mgmt, ok, "Streams.GetRecords", `{"ShardIterator":"`+mit+`"}`)["Records"]); !strings.Contains(recs, "management") || strings.Contains(recs, "member") {
		t.Errorf("the management account's stream records: %s", recs)
	}
	d.call(t, member, http.StatusForbidden, "Streams.DescribeStream", `{"StreamArn":"`+dynamoStreamARN("us-east-1", testMgmt, tbl)+`"}`)

	// TTL: the reaper, which runs in no request, sweeps each table by its own key.
	d.call(t, member, ok, "UpdateTimeToLive", `{"TableName":"`+tbl+`","TimeToLiveSpecification":{"Enabled":true,"AttributeName":"exp"}}`)
	d.h.reapExpired(context.Background())
	if got := d.call(t, member, ok, "GetItem", `{"TableName":"`+tbl+`","Key":{"pk":{"S":"1"}}}`); got["Item"] != nil {
		t.Errorf("the reaper must expire the member account's item: %v", got)
	}
	if got := d.call(t, mgmt, ok, "DescribeTimeToLive", `{"TableName":"`+tbl+`"}`); !strings.Contains(fmt.Sprint(got), "DISABLED") {
		t.Errorf("the member account's TTL reached the management account's table: %v", got)
	}

	// Deleting the member account's table leaves the management account's.
	if del := d.call(t, member, ok, "DeleteTable", `{"TableName":"`+tbl+`"}`)["TableDescription"].(map[string]any); del["TableName"] != tbl ||
		del["TableArn"] != "arn:aws:dynamodb:us-east-1:"+testMember+":table/"+tbl {
		t.Errorf("DeleteTable describes the member account's table: %v", del)
	}
	d.call(t, member, notFound, "DescribeTable", `{"TableName":"`+tbl+`"}`)
	if got := d.call(t, mgmt, ok, "GetItem", `{"TableName":"`+tbl+`","Key":{"id":{"S":"1"}}}`); !strings.Contains(fmt.Sprint(got), "management") {
		t.Errorf("the management account's table must survive the member's delete: %v", got)
	}
	if got := fmt.Sprint(d.call(t, mgmt, ok, "Streams.ListStreams", `{}`)["Streams"]); !strings.Contains(got, tbl) {
		t.Errorf("the management account's stream must survive the member's delete: %s", got)
	}
}

// A kind: Table declared in a member account's namespace is that account's table; one of the same name
// declared in a management namespace is the management account's; and a member account's stack hooks see
// and drop its own table alone.
func TestDynamoAccounts_Store_DeclaredTablesAreTheirNamespacesAccounts(t *testing.T) {
	d := newDDBStore(t)
	ctx := context.Background()
	cs := d.h.cs
	mustCreate := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: memberHome,
		Labels: map[string]string{accounts.LabelAccountID: testMember}}}, metav1.CreateOptions{})
	mustCreate(err)
	decl := func(name, claimNS, key string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: shimNS,
			Labels: map[string]string{tableConfigLabel: "sessions", tableNamespaceLabel: claimNS}},
			Data: map[string]string{"tableName": "sessions", "keyAttrs": `["` + key + `"]`}}
	}
	_, err = cs.CoreV1().ConfigMaps(shimNS).Create(ctx, decl("openinfra-dynamo-table-sessions", "app", "id"), metav1.CreateOptions{})
	mustCreate(err)
	_, err = cs.CoreV1().ConfigMaps(shimNS).Create(ctx, decl("openinfra-dynamo-table-"+memberHome+"-sessions", memberHome, "pk"), metav1.CreateOptions{})
	mustCreate(err)
	d.h.tableNS = shimNS
	d.h.syncDeclaredTables(ctx, shimNS)

	if attrs, ok := d.h.tableKeyAttrs(ctx, "sessions"); !ok || attrs[0] != "id" {
		t.Errorf("the management account's declared table: %v %v", attrs, ok)
	}
	if attrs, ok := d.h.tableKeyAttrs(ctx, testMember+":sessions"); !ok || attrs[0] != "pk" {
		t.Errorf("the member account's declared table: %v %v", attrs, ok)
	}
	if ks := d.call(t, d.member, http.StatusOK, "DescribeTable", `{"TableName":"sessions"}`)["Table"].(map[string]any)["KeySchema"]; !strings.Contains(fmt.Sprint(ks), "pk") {
		t.Errorf("the member account describes its own declared table: %v", ks)
	}
	ids := []string{}
	cur, err := d.db.Collection(tableRegistry).Find(ctx, bson.M{})
	mustCreate(err)
	for cur.Next(ctx) {
		var doc struct {
			ID string `bson:"_id"`
		}
		_ = cur.Decode(&doc)
		ids = append(ids, doc.ID)
	}
	sort.Strings(ids)
	if strings.Join(ids, ",") != testMember+":sessions,sessions" {
		t.Errorf("registry ids = %v", ids)
	}

	// The stack hooks act in the account the stack's operation acts in.
	member := withAccount(ctx, testMember, memberHome)
	if exists, err := d.h.stackTableExists(member, "sessions"); err != nil || !exists {
		t.Errorf("the member account's table exists for its stack: %v %v", exists, err)
	}
	if exists, _ := d.h.stackTableExists(member, "other"); exists {
		t.Error("a table the member account does not have must not exist for it")
	}
	d.call(t, d.member, http.StatusOK, "PutItem", `{"TableName":"sessions","Item":{"pk":{"S":"a"}}}`)
	d.call(t, d.mgmt, http.StatusOK, "PutItem", `{"TableName":"sessions","Item":{"id":{"S":"a"}}}`)
	mustCreate(cs.CoreV1().ConfigMaps(shimNS).Delete(ctx, "openinfra-dynamo-table-"+memberHome+"-sessions", metav1.DeleteOptions{}))
	if err := d.h.removeStackTable(member, "sessions"); err != nil {
		t.Fatalf("the member account's stack table must be removable once its declaration is gone: %v", err)
	}
	if _, ok := d.h.tableKeyAttrs(ctx, testMember+":sessions"); ok {
		t.Error("the member account's table must be gone")
	}
	if got := d.call(t, d.mgmt, http.StatusOK, "GetItem", `{"TableName":"sessions","Key":{"id":{"S":"a"}}}`); got["Item"] == nil {
		t.Errorf("the management account's declared table must be untouched: %v", got)
	}
}
