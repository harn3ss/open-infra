package cfn

import (
	"context"
	"fmt"
)

// A stack's DynamoDB table (kind: Table) is AWS's: its data lives and dies with the resource. Deleting the
// claim alone would leave the table's items in the DynamoDB data layer under a name the next stack of the
// same name derives again, so a re-created stack would read the earlier stack's data. The hooks
// (DeployOptions.TableExists / RemoveTable) close that: a table is removed with its resource, and a new
// table never takes over one that already exists.

// isTable reports whether a recorded resource is a stack's DynamoDB table.
func isTable(r StackResource) bool { return r.APIVersion == "openinfra.dev/v1" && r.Kind == "Table" }

// tableNameOf is a kind: Table's DynamoDB name: its explicit tableName, else the claim's name.
func tableNameOf(r StackResource) string {
	_, name := physicalName(r.APIVersion, r.Kind, r.Name, r.Spec)
	return name
}

// removeTableData deletes a deleted kind: Table's DynamoDB table and its data (opts.RemoveTable); a
// no-op for any other resource, or where the hook is unset.
func removeTableData(ctx context.Context, opts DeployOptions, r StackResource) error {
	if !isTable(r) || opts.RemoveTable == nil {
		return nil
	}
	if err := opts.RemoveTable(ctx, tableNameOf(r)); err != nil {
		return fmt.Errorf("deleting table %s of %s: %w", tableNameOf(r), r.LogicalID, err)
	}
	return nil
}

// tableTaken refuses to create a kind: Table whose DynamoDB name is already a table's — one a runtime
// CreateTable made, or one an earlier stack left — as AWS refuses ("Table already exists"): the stack
// would otherwise take over that table and its items. A no-op for any other resource, or where the hook
// is unset.
func tableTaken(ctx context.Context, opts DeployOptions, r StackResource) error {
	if !isTable(r) || opts.TableExists == nil {
		return nil
	}
	name := tableNameOf(r)
	exists, err := opts.TableExists(ctx, name)
	if err != nil {
		return fmt.Errorf("checking whether table %s exists: %w", name, err)
	}
	if exists {
		return fmt.Errorf("Table already exists: %s", name)
	}
	return nil
}
