// Package dynamodb is open-appsync's DynamoDB-style data source: it executes the operation a VTL
// request mapping template emits ({operation:GetItem, key:{id:{S:…}}, …}) and returns the raw
// result the response template sees as $ctx.result. AppSync's DynamoDB data source un-marshals the
// stored typed item back to plain values before the response template runs, so this does too
// (fromDynamoDB), and stores/operates in plain-value space.
//
// It provides two implementations of the neutral datasource.Store contract: MemStore (in-memory,
// deterministic — the slice-1 probe runs against it) and FerretStore (the real DynamoDB→Mongo binding,
// integration-tested). Both are DynamoDB-shaped; a non-DynamoDB source (e.g. internal/httpsource) is a
// different Store with a different operation shape, which is the whole point of's neutrality.
package dynamodb

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// MemStore and FerretStore implement the neutral datasource.Store contract (the call-source seam;
// that interface lives in internal/datasource, not here, so the contract is not DynamoDB-shaped).
var (
	_ datasource.Store = (*MemStore)(nil)
	_ datasource.Store = (*FerretStore)(nil)
)

// fromDynamoDB is the inverse of $util.dynamodb.toDynamoDBJson: a DynamoDB-typed value → a plain
// value. AppSync applies this to the stored item before the response template sees it.
func fromDynamoDB(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if len(m) == 1 {
		for typ, val := range m {
			switch typ {
			case "S":
				return val
			case "N":
				// Normalize to float64 regardless of how N arrived: a JSON number (VTL), a JS int64
				// (goja), or a stringified DynamoDB-SDK value. The un-marshalled result is always a
				// plain float64, as the response phase expects.
				switch n := val.(type) {
				case float64:
					return n
				case int64:
					return float64(n)
				case int:
					return float64(n)
				case string:
					if f, err := strconv.ParseFloat(n, 64); err == nil {
						return f
					}
				}
				return val
			case "BOOL":
				return val
			case "NULL":
				return nil
			case "L":
				if list, ok := val.([]any); ok {
					out := make([]any, len(list))
					for i, e := range list {
						out[i] = fromDynamoDB(e)
					}
					return out
				}
			case "M":
				if mm, ok := val.(map[string]any); ok {
					return fromMap(mm)
				}
			case "SS", "NS":
				return val
			}
		}
	}
	// Not a typed wrapper — recurse plain maps (defensive).
	return fromMap(m)
}

func fromMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = fromDynamoDB(v)
	}
	return out
}

// MemStore is an in-memory table keyed by the (typed) primary key the operation supplies. It gives
// the resolver lifecycle a deterministic, dependency-free store to prove faithfulness against.
type MemStore struct {
	items map[string]map[string]any // keyString → plain item
}

func NewMemStore() *MemStore { return &MemStore{items: map[string]map[string]any{}} }

func (s *MemStore) Execute(_ context.Context, op runtime.Operation) (any, error) {
	operation, _ := op["operation"].(string)
	switch operation {
	case "GetItem":
		key := plainMap(fromDynamoDB(op["key"]))
		if item, ok := s.items[keyString(key)]; ok {
			return item, nil
		}
		return nil, nil // AppSync returns null for a miss
	case "PutItem":
		key := plainMap(fromDynamoDB(op["key"]))
		item := map[string]any{}
		for k, v := range plainMap(fromDynamoDB(op["attributeValues"])) {
			item[k] = v
		}
		for k, v := range key { // key attributes always present on the item
			item[k] = v
		}
		s.items[keyString(key)] = item
		return item, nil // AppSync PutItem returns the written item
	case "DeleteItem":
		key := plainMap(fromDynamoDB(op["key"]))
		ks := keyString(key)
		old := s.items[ks]
		delete(s.items, ks)
		if old == nil {
			return nil, nil
		}
		return old, nil
	case "Scan":
		list := make([]any, 0, len(s.items))
		for _, k := range s.sortedKeys() {
			list = append(list, s.items[k])
		}
		return map[string]any{"items": list, "scannedCount": float64(len(list))}, nil
	default:
		return nil, fmt.Errorf("dynamodb: operation %q not implemented (slice 1: GetItem/PutItem/DeleteItem/Scan)", operation)
	}
}

func (s *MemStore) sortedKeys() []string {
	keys := make([]string, 0, len(s.items))
	for k := range s.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func plainMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// keyString is a deterministic identity for a primary-key map (encoding/json sorts keys).
func keyString(key map[string]any) string {
	b, err := json.Marshal(key)
	if err != nil {
		return fmt.Sprintf("%v", key)
	}
	return strings.TrimSpace(string(b))
}
