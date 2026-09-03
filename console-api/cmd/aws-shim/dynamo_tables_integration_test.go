//go:build integration

// Live test that a declared kind: Table (its spec-mirror ConfigMap) is registered by the shim so
// the table is usable without a runtime CreateTable — the mechanism that makes `cfn deploy` of an
// AWS::DynamoDB::Table produce a working table. Run with a FerretDB:
//
//	FERRET_TEST_URI="mongodb://app:pass@host:27017" go test -tags integration -run DeclaredTable ./cmd/aws-shim/
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
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestDynamo_DeclaredTableSync(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI to run the declared-table sync test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_decl_" + time.Now().Format("150405"))
	defer db.Drop(ctx)

	// The spec-mirror ConfigMap the Table composition renders.
	keyAttrs, _ := json.Marshal([]string{"pk"})
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "openinfra-dynamo-table-sessions", Namespace: "open-infra-console",
			Labels: map[string]string{tableConfigLabel: "sessions"},
		},
		Data: map[string]string{"tableName": "sessions", "keyAttrs": string(keyAttrs), "ttlAttribute": "exp"},
	}
	cs := fake.NewSimpleClientset(cm)
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})

	h := newDynamoHandler(cs, "default", db, nil, db.Name(), discardLogger())
	h.syncDeclaredTables(ctx, "open-infra-console")

	// Registered without a runtime CreateTable — the declaration alone made the schema known.
	if attrs, ok := h.tableKeyAttrs(ctx, "sessions"); !ok || len(attrs) != 1 || attrs[0] != "pk" {
		t.Fatalf("declared table not registered: attrs=%v ok=%v", attrs, ok)
	}

	claims := iam.Claims{Sub: "tester"}
	call := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.serve(w, dynamoReq("DynamoDB_20120810."+op, body), claims, "r")
		return w
	}
	// PutItem works with no prior CreateTable — the whole point of the declarative kind.
	if w := call("PutItem", `{"TableName":"sessions","Item":{"pk":{"S":"a"},"v":{"N":"1"}}}`); w.Code != http.StatusOK {
		t.Fatalf("PutItem on a declared table failed: %d %s", w.Code, w.Body.String())
	}
	if w := call("GetItem", `{"TableName":"sessions","Key":{"pk":{"S":"a"}}}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"v"`) {
		t.Fatalf("GetItem after declared PutItem failed: %d %s", w.Code, w.Body.String())
	}
	// TTL from the declaration is applied (no runtime UpdateTimeToLive needed).
	if w := call("DescribeTimeToLive", `{"TableName":"sessions"}`); !strings.Contains(w.Body.String(), "ENABLED") {
		t.Fatalf("declared TTL not applied: %s", w.Body.String())
	}
}
