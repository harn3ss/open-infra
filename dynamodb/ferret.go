package dynamodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// FerretStore is the durable DynamoDB-style Store, backed by FerretDB (MongoDB wire protocol) — the
// existing open-infra DynamoDB→Mongo parity mapping. It translates the VTL-emitted DynamoDB
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

func (s *FerretStore) Execute(ctx context.Context, op Operation) (any, error) {
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
		// PutDoc is the shared source of truth for the stored shape (see dynamodb.go), so a doc
		// written here reads identically to one written via the shim's transactional path.
		id, doc := PutDoc(op["key"], op["attributeValues"])
		if _, err := s.coll.ReplaceOne(ctx, bson.M{"_id": id}, doc, options.Replace().SetUpsert(true)); err != nil {
			return nil, err
		}
		item := map[string]any{}
		for k, v := range doc {
			if k != "_id" {
				item[k] = v
			}
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
		// Memory-safe scan: one request never materialises the whole table.
		//  - Select=COUNT with no client Limit counts SERVER-SIDE (CountDocuments) — no result set built.
		//  - Otherwise page with Skip/Limit, capped at scanDefaultLimit even when the client sends no
		//    Limit, returning an offset nextToken so a client (or an unmodified SDK) paginates — the
		//    same op contract MemStore honours via pageScanResult. A COUNT page projects to _id only.
		countOnly := op["select"] == "COUNT"
		offset := decodeToken(op["nextToken"])
		if offset < 0 {
			offset = 0
		}
		limit := 0
		if l, ok := toFloat(op["limit"]); ok && l > 0 {
			limit = int(l)
		}
		if countOnly && limit <= 0 && offset == 0 {
			n, err := s.coll.CountDocuments(ctx, bson.M{})
			if err != nil {
				return nil, err
			}
			return map[string]any{"items": []any{}, "count": float64(n), "scannedCount": float64(n)}, nil
		}
		page := limit
		if page <= 0 {
			page = scanDefaultLimit
		}
		findOpts := options.Find().SetLimit(int64(page) + 1) // +1 sentinel: detect "there is more"
		if offset > 0 {
			findOpts.SetSkip(int64(offset))
		}
		if countOnly {
			findOpts.SetProjection(bson.M{"_id": 1}) // a COUNT page only needs to count rows, not ship them
		}
		cur, err := s.coll.Find(ctx, bson.M{}, findOpts)
		if err != nil {
			return nil, err
		}
		defer cur.Close(ctx)
		items := []any{}
		got := 0
		for cur.Next(ctx) {
			got++
			if got > page { // the sentinel row — more than one page exists; stop
				break
			}
			if !countOnly {
				var doc bson.M
				if err := cur.Decode(&doc); err != nil {
					return nil, err
				}
				items = append(items, docToItem(doc))
			}
		}
		if err := cur.Err(); err != nil {
			return nil, err
		}
		more := got > page
		counted := got
		if more {
			counted = page
		}
		res := map[string]any{"count": float64(counted), "scannedCount": float64(counted)}
		if countOnly {
			res["items"] = []any{}
		} else {
			res["items"] = items
			res["count"] = float64(len(items))
		}
		if more {
			res["nextToken"] = encodeToken(offset + page)
		}
		return res, nil

	case "UpdateItem":
		key := plainMap(fromDynamoDB(op["key"]))
		id := keyString(key)
		var doc bson.M
		item := map[string]any{}
		switch err := s.coll.FindOne(ctx, bson.M{"_id": id}).Decode(&doc); err {
		case nil:
			item = docToItem(doc)
		case mongo.ErrNoDocuments:
			// Absent: leave item empty so the condition sees the true prior state
			// (attribute_exists(id) is false). updateItem re-asserts the key after the update.
		default:
			return nil, err
		}
		newItem, err := updateItem(item, key, op)
		if err != nil {
			return nil, err
		}
		ndoc := bson.M{"_id": id}
		for k, v := range newItem {
			ndoc[k] = v
		}
		if _, err := s.coll.ReplaceOne(ctx, bson.M{"_id": id}, ndoc, options.Replace().SetUpsert(true)); err != nil {
			return nil, err
		}
		return newItem, nil

	case "Query":
		// Fetch candidates and run the SAME query logic MemStore does, so the result is identical
		// across stores. (Correctness over index-pushdown — Query is not indexed here.)
		cur, err := s.coll.Find(ctx, bson.M{})
		if err != nil {
			return nil, err
		}
		defer cur.Close(ctx)
		var candidates []map[string]any
		for cur.Next(ctx) {
			var doc bson.M
			if err := cur.Decode(&doc); err != nil {
				return nil, err
			}
			candidates = append(candidates, docToItem(doc))
		}
		if err := cur.Err(); err != nil {
			return nil, err
		}
		return runQuery(candidates, op)

	default:
		return nil, fmt.Errorf("dynamodb(ferret): operation %q not implemented (supported: GetItem, PutItem, DeleteItem, Scan, UpdateItem, Query)", op["operation"])
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
	case primitive.Binary:
		// BSON binary → plain []byte, so the binary round-trips as a B attribute (ToDynamoDB
		// re-dresses []byte as {"B": base64}) rather than leaking a driver type.
		return x.Data
	}
	return v
}
