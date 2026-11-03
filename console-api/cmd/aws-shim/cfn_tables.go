package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A stack's DynamoDB tables (cfn.DeployOptions.TableExists / RemoveTable): the CloudFormation front door
// creates a kind: Table only where no table of that name exists, and deletes the table — its items,
// stream and registry entry — with the resource, as AWS deletes a stack's table. Without that, the items
// outlived the stack, and the next stack of the same name (whose table name is derived the same way)
// read them.

// tableDeclarationGoneWait bounds how long a stack's table delete waits for the table's kind: Table
// declaration (its spec-mirror ConfigMap, removed with the claim) to go. While it is there the table sync
// would register the table again.
var tableDeclarationGoneWait = 2 * time.Minute

// tableDeclarationPoll is how often that wait looks again.
var tableDeclarationPoll = 2 * time.Second

// stackTableExists reports whether a DynamoDB table of that name exists (its registry entry).
func (h *dynamoHandler) stackTableExists(ctx context.Context, table string) (bool, error) {
	err := h.registry().FindOne(ctx, bson.M{"_id": table}).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return false, nil
	}
	return err == nil, err
}

// tableDeclared reports whether a kind: Table declaration for the table is still present.
func (h *dynamoHandler) tableDeclared(ctx context.Context, table string) (bool, error) {
	if h.cs == nil || h.tableNS == "" {
		return false, nil
	}
	cms, err := h.cs.CoreV1().ConfigMaps(h.tableNS).List(ctx, metav1.ListOptions{LabelSelector: tableConfigLabel})
	if err != nil {
		return false, err
	}
	for _, cm := range cms.Items {
		if cm.Data["tableName"] == table {
			return true, nil
		}
	}
	return false, nil
}

// removeStackTable deletes a stack's table and its data once the table's kind: Table declaration is gone
// (its claim was just deleted). A declaration still present after tableDeclarationGoneWait fails the
// delete — retrying it (DeleteStack again) finishes the job — rather than drop a table the sync would
// register again as an empty table no stack owns.
func (h *dynamoHandler) removeStackTable(ctx context.Context, table string) error {
	deadline := time.Now().Add(tableDeclarationGoneWait)
	for {
		declared, err := h.tableDeclared(ctx, table)
		if err != nil {
			return fmt.Errorf("reading the table's declaration: %w", err)
		}
		if !declared {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("its kind: Table declaration is still present after %s; delete the stack again once it is gone", tableDeclarationGoneWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(tableDeclarationPoll):
		}
	}
	return h.dropTable(ctx, table)
}
