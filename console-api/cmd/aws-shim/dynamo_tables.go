// Declarative table registration for the aws-shim DynamoDB front door.
//
// kind: Table (platform/abstraction/table-{xrd,composition}.yaml) renders a spec-mirror
// ConfigMap — labeled openinfra.dev/dynamo-table — carrying a table's name, ordered key
// attributes, and an optional TTL attribute. The shim is the reconciler for those: it is the
// one process holding the FerretDB creds and owning the table registry (the _shim_dynamo_tables
// collection), so it reads the declared ConfigMaps and upserts the same registry entry a runtime
// CreateTable writes. A declared table is then usable (PutItem/GetItem/…) without a manual
// CreateTable call, which is what makes `cfn deploy` of an AWS::DynamoDB::Table produce a working
// table.
//
// This is CONVERGENCE, not fire-once: the sync runs at startup and on a ticker, so a Table
// applied while the shim is running is picked up within one interval. The key schema is immutable
// (as in DynamoDB), so re-registering an existing table is a harmless no-op replace.
package main

import (
	"context"
	"encoding/json"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const tableConfigLabel = "openinfra.dev/dynamo-table"

// startTableSync registers declared tables at startup and on a ticker. It is a no-op unless the
// data layer (FerretDB), a Kubernetes client, and a namespace to read from are all present, so a
// shim without the DynamoDB backend (or without ConfigMap read access) simply does nothing.
func (h *dynamoHandler) startTableSync(ctx context.Context, namespace string, interval time.Duration) {
	if h.db == nil || h.cs == nil || namespace == "" {
		return
	}
	h.syncDeclaredTables(ctx, namespace) // register what already exists before serving
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.syncDeclaredTables(ctx, namespace)
			}
		}
	}()
}

// syncDeclaredTables lists the table spec-mirror ConfigMaps and registers each one. A malformed
// ConfigMap is skipped with a warning, never fatal — one bad declaration must not stop the rest.
func (h *dynamoHandler) syncDeclaredTables(ctx context.Context, namespace string) {
	cms, err := h.cs.CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{LabelSelector: tableConfigLabel})
	if err != nil {
		h.logger.Warn("table sync: cannot list declared tables", "namespace", namespace, "err", err)
		return
	}
	for i := range cms.Items {
		cm := &cms.Items[i]
		table := cm.Data["tableName"]
		var keyAttrs []string
		if err := json.Unmarshal([]byte(cm.Data["keyAttrs"]), &keyAttrs); err != nil || table == "" || len(keyAttrs) == 0 {
			h.logger.Warn("table sync: skipping malformed table declaration", "configMap", cm.Name)
			continue
		}
		var gsis []gsiDef
		if raw := cm.Data["gsi"]; raw != "" {
			if err := json.Unmarshal([]byte(raw), &gsis); err != nil {
				h.logger.Warn("table sync: ignoring malformed gsi declaration", "configMap", cm.Name, "err", err)
			}
		}
		if err := h.registerDeclaredTable(ctx, table, keyAttrs, cm.Data["ttlAttribute"], gsis); err != nil {
			h.logger.Warn("table sync: registration failed", "table", table, "err", err)
		}
	}
}

// registerDeclaredTable upserts a table's registry entry (name + key schema, the exact shape
// CreateTable writes) and, when a TTL attribute is declared, its TTL config — so the declared
// table behaves identically to one created at runtime.
func (h *dynamoHandler) registerDeclaredTable(ctx context.Context, table string, keyAttrs []string, ttlAttr string, gsis []gsiDef) error {
	entry := bson.M{"_id": table, "keyAttrs": keyAttrs}
	if ttlAttr != "" {
		entry["ttl"] = bson.M{"enabled": true, "attribute": ttlAttr}
	}
	if len(gsis) > 0 {
		entry["gsi"] = gsis
	}
	if _, err := h.registry().ReplaceOne(ctx, bson.M{"_id": table}, entry, options.Replace().SetUpsert(true)); err != nil {
		return err
	}
	h.ensureGSIIndexes(ctx, table, gsis)
	return nil
}
