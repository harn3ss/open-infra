//go:build integration

// Live test that a declared kind: Table GSI is registered, backs a real Mongo index, and answers a
// Query by IndexName. Run with a FerretDB:
//
//	FERRET_TEST_URI="mongodb://app:pass@host:27017" go test -tags integration -run GSI ./cmd/aws-shim/
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

func TestDynamo_GSIQuery(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI to run the GSI query test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_gsi_" + time.Now().Format("150405"))
	defer db.Drop(ctx)

	// A declared table with a GSI on "email" (the spec-mirror ConfigMap the composition renders).
	keyAttrs, _ := json.Marshal([]string{"id"})
	gsi, _ := json.Marshal([]map[string]any{{"name": "by-email", "keyAttrs": []string{"email"}}})
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "openinfra-dynamo-table-users", Namespace: "open-infra-console",
			Labels: map[string]string{tableConfigLabel: "users"},
		},
		Data: map[string]string{"tableName": "users", "keyAttrs": string(keyAttrs), "gsi": string(gsi)},
	}
	cs := fake.NewSimpleClientset(cm)
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})

	h := newDynamoHandler(cs, "default", db, nil, db.Name(), discardLogger())
	h.syncDeclaredTables(ctx, "open-infra-console")

	// The GSI is registered.
	gsis := h.tableGSIs(ctx, "users")
	if len(gsis) != 1 || gsis[0].Name != "by-email" || len(gsis[0].KeyAttrs) != 1 || gsis[0].KeyAttrs[0] != "email" {
		t.Fatalf("GSI not registered: %#v", gsis)
	}

	// A real Mongo index was created on the GSI key.
	cur, err := db.Collection("users").Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	sawIndex := false
	for cur.Next(ctx) {
		var idx bson.M
		_ = cur.Decode(&idx)
		if name, _ := idx["name"].(string); name == "gsi_by-email" {
			sawIndex = true
		}
	}
	if !sawIndex {
		t.Fatalf("expected a Mongo index gsi_by-email on the collection")
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
	mustOK("PutItem", call("PutItem", `{"TableName":"users","Item":{"id":{"S":"u1"},"email":{"S":"a@x.com"}}}`))
	mustOK("PutItem", call("PutItem", `{"TableName":"users","Item":{"id":{"S":"u2"},"email":{"S":"b@x.com"}}}`))

	// Query the GSI by email.
	w := call("Query", `{"TableName":"users","IndexName":"by-email","KeyConditionExpression":"email = :e","ExpressionAttributeValues":{":e":{"S":"b@x.com"}}}`)
	mustOK("Query", w)
	if !strings.Contains(w.Body.String(), `"u2"`) || strings.Contains(w.Body.String(), `"u1"`) {
		t.Fatalf("GSI query by email should return only u2: %s", w.Body.String())
	}

	// An unknown index is a loud ValidationException, never a silent full-table query.
	if bad := call("Query", `{"TableName":"users","IndexName":"nope","KeyConditionExpression":"email = :e","ExpressionAttributeValues":{":e":{"S":"b@x.com"}}}`); bad.Code != http.StatusBadRequest {
		t.Fatalf("an unknown IndexName must be rejected (400), got %d: %s", bad.Code, bad.Body.String())
	}

	// DescribeTable reports the GSI as ACTIVE.
	d := call("DescribeTable", `{"TableName":"users"}`)
	mustOK("DescribeTable", d)
	if !strings.Contains(d.Body.String(), "by-email") || !strings.Contains(d.Body.String(), "GlobalSecondaryIndexes") {
		t.Fatalf("DescribeTable should report the GSI: %s", d.Body.String())
	}
}
