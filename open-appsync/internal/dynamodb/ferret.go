package dynamodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// FerretStore is the durable DynamoDB-style Store, backed by FerretDB (MongoDB wire protocol) — the
// existing open-infra DynamoDB→Mongo parity mapping (piece 3). It translates the VTL-emitted DynamoDB
// operation onto Mongo operations against ONE collection (the resolver's data-source "table"), so a
// resolver's request template output runs against durable storage. It is the exact same Store
// interface MemStore implements, so a resolver runs unchanged against either.
//
// The primary key: DynamoDB's typed key is un-marshalled to plain values and serialized into Mongo's
// `_id` (deterministic), so GetItem/PutItem/DeleteItem address items by key; `_id` is stripped from
// results (AppSync returns the item's own attributes).
type FerretStore struct{ coll *mongo.Collection }

// NewFerretStore binds a Store to a Mongo/FerretDB collection (one per data-source table).
func NewFerretStore(coll *mongo.Collection) *FerretStore { return &FerretStore{coll: coll} }

func (s *FerretStore) Execute(ctx context.Context, op map[string]any) (any, error) {
	switch operation, _ := op["operation"].(string); operation {
	case "GetItem":
		id := keyString(plainMap(fromDynamoDB(op["key"])))
		var doc bson.M
		err := s.coll.FindOne(ctx, bson.M{"_id": id}).Decode(&doc)
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return docToItem(doc), nil

	case "PutItem":
		key := plainMap(fromDynamoDB(op["key"]))
		item := map[string]any{}
		for k, v := range plainMap(fromDynamoDB(op["attributeValues"])) {
			item[k] = v
		}
		for k, v := range key {
			item[k] = v
		}
		id := keyString(key)
		doc := bson.M{"_id": id}
		for k, v := range item {
			doc[k] = v
		}
		if _, err := s.coll.ReplaceOne(ctx, bson.M{"_id": id}, doc, options.Replace().SetUpsert(true)); err != nil {
			return nil, err
		}
		return item, nil

	case "DeleteItem":
		id := keyString(plainMap(fromDynamoDB(op["key"])))
		var doc bson.M
		err := s.coll.FindOneAndDelete(ctx, bson.M{"_id": id}).Decode(&doc)
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return docToItem(doc), nil

	case "Scan":
		cur, err := s.coll.Find(ctx, bson.M{})
		if err != nil {
			return nil, err
		}
		defer cur.Close(ctx)
		items := []any{}
		for cur.Next(ctx) {
			var doc bson.M
			if err := cur.Decode(&doc); err != nil {
				return nil, err
			}
			items = append(items, docToItem(doc))
		}
		return map[string]any{"items": items, "scannedCount": float64(len(items))}, cur.Err()

	default:
		return nil, fmt.Errorf("dynamodb(ferret): operation %q not implemented (slice 1: GetItem/PutItem/DeleteItem/Scan)", op["operation"])
	}
}

// docToItem strips Mongo's _id and normalizes BSON types back to plain values (the shape a response
// template + GraphQL client expect).
func docToItem(doc bson.M) map[string]any {
	out := map[string]any{}
	for k, v := range doc {
		if k == "_id" {
			continue
		}
		out[k] = normalizeBSON(v)
	}
	return out
}

// normalizeBSON converts BSON-decoded values to plain Go values: nested docs→map, arrays→slice, and
// integer types→float64 (so numbers match the float64 the rest of the engine and JSON use).
func normalizeBSON(v any) any {
	switch x := v.(type) {
	case bson.M:
		m := map[string]any{}
		for k, e := range x {
			m[k] = normalizeBSON(e)
		}
		return m
	case bson.D:
		m := map[string]any{}
		for _, e := range x {
			m[e.Key] = normalizeBSON(e.Value)
		}
		return m
	case bson.A:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = normalizeBSON(e)
		}
		return a
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	}
	return v
}
