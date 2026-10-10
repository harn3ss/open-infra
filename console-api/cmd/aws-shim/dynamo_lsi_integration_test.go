//go:build integration

// Live test that a declared kind: Table LSI is registered, backs a real Mongo index, and answers a
// Query by IndexName under the table's partition key. Run with a FerretDB:
//
//	FERRET_TEST_URI="mongodb://app:pass@host:27017" go test -tags integration -run LSI ./cmd/aws-shim/
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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestDynamo_LSIQuery(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI to run the LSI query test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_lsi_" + time.Now().Format("150405"))
	defer db.Drop(ctx)

	// A declared table (hash id, range ts) with an LSI on an alternate sort key "score" — the
	// spec-mirror ConfigMap the composition renders (LSI keyAttrs = [tableHash, lsiRange]).
	keyAttrs, _ := json.Marshal([]string{"id", "ts"})
	lsi, _ := json.Marshal([]map[string]any{{"name": "by-score", "keyAttrs": []string{"id", "score"}}})
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "openinfra-dynamo-table-events", Namespace: "open-infra-console",
			Labels: map[string]string{tableConfigLabel: "events"},
		},
		Data: map[string]string{"tableName": "events", "keyAttrs": string(keyAttrs), "lsi": string(lsi)},
	}
	cs := fake.NewSimpleClientset(cm)
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})

	h := newDynamoHandler(cs, "default", db, nil, db.Name(), discardLogger())
	h.syncDeclaredTables(ctx, "open-infra-console")

	// The LSI is registered with [tableHash, lsiRange] key attributes.
	lsis := h.tableLSIs(ctx, "events")
	if len(lsis) != 1 || lsis[0].Name != "by-score" || len(lsis[0].KeyAttrs) != 2 ||
		lsis[0].KeyAttrs[0] != "id" || lsis[0].KeyAttrs[1] != "score" {
		t.Fatalf("LSI not registered: %#v", lsis)
	}

	// A real Mongo index was created on the LSI key (prefix lsi_, distinct from gsi_).
	cur, err := db.Collection("events").Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	sawIndex := false
	for cur.Next(ctx) {
		var idx bson.M
		_ = cur.Decode(&idx)
		if name, _ := idx["name"].(string); name == "lsi_by-score" {
			sawIndex = true
		}
	}
	if !sawIndex {
		t.Fatalf("expected a Mongo index lsi_by-score on the collection")
	}

	claims := iam.Claims{Sub: "tester"}
	call := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.serve(w, dynamoReq("DynamoDB_20120810."+op, body), claims, "r")
		return w
	}
	mustOK := func(op string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", op, w.Code, w.Body.String())
		}
	}
	mustOK("PutItem", call("PutItem", `{"TableName":"events","Item":{"id":{"S":"u1"},"ts":{"N":"1"},"score":{"N":"10"}}}`))
	mustOK("PutItem", call("PutItem", `{"TableName":"events","Item":{"id":{"S":"u1"},"ts":{"N":"2"},"score":{"N":"99"}}}`))

	// Query the LSI: same partition (id=u1), alternate sort key score=99 → only the second item.
	w := call("Query", `{"TableName":"events","IndexName":"by-score","KeyConditionExpression":"id = :i AND score = :s","ExpressionAttributeValues":{":i":{"S":"u1"},":s":{"N":"99"}}}`)
	mustOK("Query", w)
	if !strings.Contains(w.Body.String(), `"99"`) || strings.Contains(w.Body.String(), `"10"`) {
		t.Fatalf("LSI query by score should return only the score=99 item: %s", w.Body.String())
	}

	// An unknown index is a loud ValidationException, never a silent full-table query.
	if bad := call("Query", `{"TableName":"events","IndexName":"nope","KeyConditionExpression":"id = :i","ExpressionAttributeValues":{":i":{"S":"u1"}}}`); bad.Code != http.StatusBadRequest {
		t.Fatalf("an unknown IndexName must be rejected (400), got %d: %s", bad.Code, bad.Body.String())
	}

	// DescribeTable reports the LSI.
	d := call("DescribeTable", `{"TableName":"events"}`)
	mustOK("DescribeTable", d)
	if !strings.Contains(d.Body.String(), "by-score") || !strings.Contains(d.Body.String(), "LocalSecondaryIndexes") {
		t.Fatalf("DescribeTable should report the LSI: %s", d.Body.String())
	}
}
