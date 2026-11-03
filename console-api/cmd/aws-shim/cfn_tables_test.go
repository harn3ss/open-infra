package main

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// A stack's table is deleted only once its kind: Table declaration is gone — while it is present the
// table sync would register the table again — and a declaration that lingers fails the delete (DeleteStack
// again finishes it) without touching the table's data.
func TestCFNTables_RemoveWaitsForTheDeclaration(t *testing.T) {
	prevWait, prevPoll := tableDeclarationGoneWait, tableDeclarationPoll
	tableDeclarationGoneWait, tableDeclarationPoll = 50*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { tableDeclarationGoneWait, tableDeclarationPoll = prevWait, prevPoll })

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "openinfra-dynamo-table-app-orders", Namespace: shimNS,
			Labels: map[string]string{tableConfigLabel: "app-orders"}},
		Data: map[string]string{"tableName": "app-orders", "keyAttrs": `["id"]`},
	}
	h := &dynamoHandler{cs: fake.NewSimpleClientset(cm), tableNS: shimNS, logger: discardLogger()}
	declared, err := h.tableDeclared(context.Background(), "app-orders")
	if err != nil || !declared {
		t.Fatalf("the declaration must be seen: %v %v", declared, err)
	}
	if other, _ := h.tableDeclared(context.Background(), "app-other"); other {
		t.Fatal("another table's declaration must not count")
	}
	// h.db is nil: reaching the drop would panic, so an error here proves nothing was dropped.
	err = h.removeStackTable(context.Background(), "app-orders")
	if err == nil || !strings.Contains(err.Error(), "declaration is still present") {
		t.Fatalf("a lingering declaration must fail the delete: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tableDeclarationGoneWait = time.Hour
	if err := h.removeStackTable(ctx, "app-orders"); err == nil {
		t.Fatal("a cancelled operation must stop waiting")
	}
}
