//go:build integration

// Live test that a stack's DynamoDB table is deleted with its data once its kind: Table declaration is
// gone, so a stack re-created with the same name starts with an empty table. Run with a FerretDB:
//
//	FERRET_TEST_URI="mongodb://app:pass@host:27017" go test -tags integration -run CFNTables ./cmd/aws-shim/
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

func TestCFNTables_StackTableDeletedWithItsData(t *testing.T) {
	uri := os.Getenv("FERRET_TEST_URI")
	if uri == "" {
		t.Skip("set FERRET_TEST_URI to run the stack-table delete test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("mongo connect: %v", err)
	}
	defer client.Disconnect(ctx)
	db := client.Database("shim_stacktbl_" + time.Now().Format("150405"))
	defer db.Drop(ctx)

	keyAttrs, _ := json.Marshal([]string{"id"})
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "openinfra-dynamo-table-app-orders", Namespace: shimNS,
			Labels: map[string]string{tableConfigLabel: "app-orders"}},
		Data: map[string]string{"tableName": "app-orders", "keyAttrs": string(keyAttrs)},
	}
	cs := fake.NewSimpleClientset(cm)
	cs.PrependReactor("create", "subjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})
	h := newDynamoHandler(cs, "default", db, nil, db.Name(), discardLogger())
	h.tableNS = shimNS
	h.syncDeclaredTables(ctx, shimNS)
	call := func(op, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.serve(w, dynamoReq("DynamoDB_20120810."+op, body), iam.Claims{Sub: "tester"}, "r")
		return w
	}
	if w := call("PutItem", `{"TableName":"app-orders","Item":{"id":{"S":"a"},"secret":{"S":"old"}}}`); w.Code != http.StatusOK {
		t.Fatalf("PutItem: %d %s", w.Code, w.Body.String())
	}
	if ok, err := h.stackTableExists(ctx, "app-orders"); err != nil || !ok {
		t.Fatalf("the declared table must exist: %v %v", ok, err)
	}
	if w := call("ListTables", `{}`); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"app-orders"`) {
		t.Fatalf("ListTables must list the table: %d %s", w.Code, w.Body.String())
	}
	// The stack is deleted: its claim (and with it the declaration) goes, then the table with its data.
	if err := cs.CoreV1().ConfigMaps(shimNS).Delete(ctx, cm.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := h.removeStackTable(ctx, "app-orders"); err != nil {
		t.Fatalf("removeStackTable: %v", err)
	}
	if ok, _ := h.stackTableExists(ctx, "app-orders"); ok {
		t.Fatal("the table must be gone")
	}
	// A stack re-created with the same name declares the table again: it is empty.
	if _, err := cs.CoreV1().ConfigMaps(shimNS).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.syncDeclaredTables(ctx, shimNS)
	if w := call("GetItem", `{"TableName":"app-orders","Key":{"id":{"S":"a"}}}`); w.Code != http.StatusOK || strings.Contains(w.Body.String(), "old") {
		t.Fatalf("the re-created table must not hold the earlier stack's item: %d %s", w.Code, w.Body.String())
	}
}
