package cfn

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// fakeTables is the DynamoDB data layer the table hooks reach.
type fakeTables struct {
	mu      sync.Mutex
	exists  map[string]bool
	removed []string
}

func (f *fakeTables) hook(opts *DeployOptions) {
	opts.TableExists = func(_ context.Context, t string) (bool, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.exists[t], nil
	}
	opts.RemoveTable = func(_ context.Context, t string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.removed = append(f.removed, t)
		delete(f.exists, t)
		return nil
	}
}

const tableStackTmpl = `
Resources:
  Orders:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      KeySchema: [ { AttributeName: id, KeyType: HASH } ]
      AttributeDefinitions: [ { AttributeName: id, AttributeType: S } ]
  Kept:
    Type: AWS::DynamoDB::Table
    DeletionPolicy: Retain
    Properties:
      TableName: kept-table
      BillingMode: PAY_PER_REQUEST
      KeySchema: [ { AttributeName: id, KeyType: HASH } ]
      AttributeDefinitions: [ { AttributeName: id, AttributeType: S } ]
`

// #350 R / #348: DeleteStack deletes a stack's DynamoDB table with its data (a Retain one stays), so a
// stack re-created with the same name starts with an empty table, never the earlier stack's items.
func TestTables_DeleteStackDeletesTheTable(t *testing.T) {
	tables := &fakeTables{exists: map[string]bool{}}
	f := &fakeApplier{}
	opts := deployOpts()
	tables.hook(&opts)
	if _, err := Deploy(context.Background(), []byte(tableStackTmpl), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, err := Destroy(context.Background(), opts, f); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if strings.Join(tables.removed, ",") != "s-orders" {
		t.Fatalf("the stack's table (not the Retain one) must be deleted with its data, removed %v", tables.removed)
	}
}

// A table whose name is already a table's — one a runtime CreateTable made, or one an earlier stack left —
// is refused, as AWS refuses it ("Table already exists"), and the existing table is left alone.
func TestTables_CreateRefusesAnExistingTable(t *testing.T) {
	tables := &fakeTables{exists: map[string]bool{"s-orders": true}}
	f := &fakeApplier{}
	opts := deployOpts()
	tables.hook(&opts)
	rec, err := Deploy(context.Background(), []byte(tableStackTmpl), opts, f)
	if err == nil || !strings.Contains(err.Error(), "Table already exists: s-orders") {
		t.Fatalf("want the create refused: %v", err)
	}
	if rec.Status != "ROLLBACK_COMPLETE" || len(tables.removed) != 0 || !tables.exists["s-orders"] {
		t.Fatalf("the existing table must be left alone: %s removed=%v", rec.Status, tables.removed)
	}
	if f.appliedHas("Table/s-orders") {
		t.Fatalf("the claim must not be applied over an existing table: %v", f.applied)
	}
}

// A rolled-back create deletes the table it created, data included; so does an update that removes it.
func TestTables_RollbackAndRemovalDeleteTheTable(t *testing.T) {
	tables := &fakeTables{exists: map[string]bool{}}
	f := &fakeApplier{notReady: "s-last"}
	opts := deployOpts()
	tables.hook(&opts)
	failing := tableStackTmpl + `
  Last:
    Type: AWS::KMS::Key
    DependsOn: Orders
`
	if _, err := Deploy(context.Background(), []byte(failing), opts, f); err == nil {
		t.Fatal("test premise: the create fails at Last")
	}
	if !strings.Contains(strings.Join(tables.removed, ","), "s-orders") {
		t.Fatalf("the rolled-back create must delete the table it made, removed %v", tables.removed)
	}

	tables2 := &fakeTables{exists: map[string]bool{}}
	f2 := &fakeApplier{}
	opts2 := deployOpts()
	tables2.hook(&opts2)
	if _, err := Deploy(context.Background(), []byte(tableStackTmpl), opts2, f2); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	without := `
Resources:
  Kept:
    Type: AWS::DynamoDB::Table
    DeletionPolicy: Retain
    Properties:
      TableName: kept-table
      BillingMode: PAY_PER_REQUEST
      KeySchema: [ { AttributeName: id, KeyType: HASH } ]
      AttributeDefinitions: [ { AttributeName: id, AttributeType: S } ]
`
	if _, err := Update(context.Background(), []byte(without), opts2, f2); err != nil {
		t.Fatalf("update: %v", err)
	}
	if strings.Join(tables2.removed, ",") != "s-orders" {
		t.Fatalf("an update that removes the table must delete it, removed %v", tables2.removed)
	}
}
