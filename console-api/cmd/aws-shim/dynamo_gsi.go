// Global secondary indexes for the aws-shim DynamoDB front door.
//
// A DynamoDB GSI lets you Query a table by a non-primary key. The store already answers a Query by
// whatever attributes its KeyConditionExpression names (runQuery filters candidates on those
// attributes — see dynamodb.runQuery + TestQuery_ByGSIAttributes), so a GSI Query is functionally
// correct through the same path a base-table Query takes. What this file adds is the declaration
// side: the GSI key schema is recorded per table (so Query can validate IndexName and DescribeTable
// can report the index), and a real Mongo index is created on the GSI's key attributes.
//
// Honest scope: like base-table Query, a GSI Query is correct but SCAN-based today (the store's
// FerretStore.Query fetches all docs and filters in memory — "correctness over index-pushdown").
// The Mongo index is a real backend artifact (it exists, DescribeTable reports the GSI as ACTIVE,
// and it is ready for a future pushdown), not a performance claim.
package main

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// gsiDef is a global secondary index: a name and its ordered key attributes (HASH first, then an
// optional RANGE) — the shape stored in the table registry.
type gsiDef struct {
	Name     string   `bson:"name" json:"name"`
	KeyAttrs []string `bson:"keyAttrs" json:"keyAttrs"`
}

// gsisFromCreateTable parses the GlobalSecondaryIndexes of an AWS CreateTable request into gsiDefs.
func gsisFromCreateTable(body map[string]any) []gsiDef {
	list, _ := body["GlobalSecondaryIndexes"].([]any)
	var out []gsiDef
	for _, g := range list {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		name, _ := gm["IndexName"].(string)
		ka := keyAttrsFromSchema(gm["KeySchema"])
		if name != "" && len(ka) > 0 {
			out = append(out, gsiDef{Name: name, KeyAttrs: ka})
		}
	}
	return out
}

// tableGSIs returns a table's declared global secondary indexes (empty if none/unknown).
func (h *dynamoHandler) tableGSIs(ctx context.Context, table string) []gsiDef {
	var doc struct {
		GSI []gsiDef `bson:"gsi"`
	}
	if err := h.registry().FindOne(ctx, bson.M{"_id": table}).Decode(&doc); err != nil {
		return nil
	}
	return doc.GSI
}

// ensureGSIIndexes creates a Mongo index on each GSI's key attributes (idempotent — a repeated
// CreateOne with the same name is a no-op). Best-effort: an index failure is logged, never fatal,
// because the Query path is correct without it (scan + filter).
func (h *dynamoHandler) ensureGSIIndexes(ctx context.Context, table string, gsis []gsiDef) {
	if len(gsis) == 0 {
		return
	}
	coll := h.db.Collection(table)
	for _, g := range gsis {
		if len(g.KeyAttrs) == 0 {
			continue
		}
		keys := bson.D{}
		for _, a := range g.KeyAttrs {
			keys = append(keys, bson.E{Key: a, Value: 1})
		}
		if _, err := coll.Indexes().CreateOne(ctx, mongo.IndexModel{
			Keys:    keys,
			Options: options.Index().SetName("gsi_" + g.Name),
		}); err != nil {
			h.logger.Warn("gsi index create failed", "table", table, "index", g.Name, "err", err)
		}
	}
}

// gsiDescriptions renders the DescribeTable GlobalSecondaryIndexes shape (each ACTIVE, ALL
// projection — the store keeps full items, so projection is not enforced).
func gsiDescriptions(gsis []gsiDef) []any {
	var out []any
	for _, g := range gsis {
		schema := make([]any, 0, len(g.KeyAttrs))
		for i, a := range g.KeyAttrs {
			kt := "HASH"
			if i == 1 {
				kt = "RANGE"
			}
			schema = append(schema, map[string]any{"AttributeName": a, "KeyType": kt})
		}
		out = append(out, map[string]any{
			"IndexName":   g.Name,
			"IndexStatus": "ACTIVE",
			"KeySchema":   schema,
			"Projection":  map[string]any{"ProjectionType": "ALL"},
		})
	}
	return out
}
