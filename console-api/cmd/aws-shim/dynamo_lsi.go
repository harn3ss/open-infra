// Local secondary indexes for the aws-shim DynamoDB front door.
//
// An LSI lets you Query a table by an ALTERNATE sort key under the SAME partition (HASH) key as the
// base table. It is the GSI mechanism's sibling: the store already answers a Query by whatever
// attributes the KeyConditionExpression names (runQuery scans + filters — "correctness over
// index-pushdown"), so an LSI Query is functionally correct through the same path. What this file
// adds is the declaration side — the LSI key schema is recorded per table (so Query can validate
// IndexName and DescribeTable can report it) and a real Mongo index is created on the LSI's key
// attributes (table HASH + the LSI's RANGE). The stored shape is identical to a GSI's
// ([HASH, RANGE] key attributes), so LSIs reuse gsiDef; only the registry field (`lsi`), the Mongo
// index name prefix (`lsi_`), and the DescribeTable section (LocalSecondaryIndexes) differ.
//
// Honest scope: like a GSI, an LSI Query is correct but SCAN-based today; the Mongo index is a real
// backend artifact (DescribeTable reports the LSI as ACTIVE, ready for a future pushdown), not a
// performance claim.
package main

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// lsisFromCreateTable parses the LocalSecondaryIndexes of an AWS CreateTable request. Each LSI's
// KeySchema is [HASH=tableHashKey, RANGE=lsiSortKey]; keyAttrsFromSchema returns them in order.
func lsisFromCreateTable(body map[string]any) []gsiDef {
	list, _ := body["LocalSecondaryIndexes"].([]any)
	var out []gsiDef
	for _, l := range list {
		lm, ok := l.(map[string]any)
		if !ok {
			continue
		}
		name, _ := lm["IndexName"].(string)
		ka := keyAttrsFromSchema(lm["KeySchema"])
		if name != "" && len(ka) > 0 {
			out = append(out, gsiDef{Name: name, KeyAttrs: ka})
		}
	}
	return out
}

// tableLSIs returns a table's declared local secondary indexes (empty if none/unknown).
func (h *dynamoHandler) tableLSIs(ctx context.Context, table string) []gsiDef {
	var doc struct {
		LSI []gsiDef `bson:"lsi"`
	}
	if err := h.registry().FindOne(ctx, bson.M{"_id": table}).Decode(&doc); err != nil {
		return nil
	}
	return doc.LSI
}

// ensureLSIIndexes creates a Mongo index on each LSI's key attributes (idempotent). Best-effort:
// an index failure is logged, never fatal, because the Query path is correct without it.
func (h *dynamoHandler) ensureLSIIndexes(ctx context.Context, table string, lsis []gsiDef) {
	if len(lsis) == 0 {
		return
	}
	coll := h.db.Collection(table)
	for _, l := range lsis {
		if len(l.KeyAttrs) == 0 {
			continue
		}
		keys := bson.D{}
		for _, a := range l.KeyAttrs {
			keys = append(keys, bson.E{Key: a, Value: 1})
		}
		if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys:    keys,
			Options: options.Index().SetName("lsi_" + l.Name),
		}); err != nil {
			h.logger.Warn("lsi index create failed", "table", table, "index", l.Name, "err", err)
		}
	}
}

// lsiDescriptions renders the DescribeTable LocalSecondaryIndexes shape (ALL projection — the store
// keeps full items, so projection is not enforced).
func lsiDescriptions(lsis []gsiDef) []any {
	var out []any
	for _, l := range lsis {
		schema := make([]any, 0, len(l.KeyAttrs))
		for i, a := range l.KeyAttrs {
			kt := "HASH"
			if i == 1 {
				kt = "RANGE"
			}
			schema = append(schema, map[string]any{"AttributeName": a, "KeyType": kt})
		}
		out = append(out, map[string]any{
			"IndexName":  l.Name,
			"KeySchema":  schema,
			"Projection": map[string]any{"ProjectionType": "ALL"},
		})
	}
	return out
}
