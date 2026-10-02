// Iceberg-schema -> Glue/Hive type + column translation for the Glue Data Catalog front door
// (polyhedron#179).
//
// The Glue doorway fronts the platform's existing Iceberg REST catalog: a Glue table IS an Iceberg
// table, and the one real translation it performs is turning an Iceberg table's schema into the Glue
// Column + type shape an AWS SDK/CLI expects. That mapping lives here, pure and dependency-free, so it
// can be unit-tested exhaustively away from any HTTP backend. Nothing here does I/O.
//
// Iceberg primitive types render as their Hive/Glue equivalents (int -> int, long -> bigint, …), and
// Iceberg's nested types render as Hive's angle-bracket forms (struct<…>, array<…>, map<…,…>). An
// unrecognized type is passed through verbatim rather than dropped or guessed — a column is NEVER lost
// and a translation NEVER panics, because a wrong-but-visible type is far better than a missing column.
package main

import (
	"fmt"
	"strings"
)

// glueType translates one Iceberg field type to its Glue/Hive type string. The Iceberg type is either a
// JSON string (a primitive, e.g. "long", "decimal(10,2)", "fixed[16]") or a JSON object (a nested type:
// struct/list/map). Anything else (or an unrecognized string) is rendered best-effort, never dropped.
func glueType(t any) string {
	switch v := t.(type) {
	case string:
		return glueScalarType(v)
	case map[string]any:
		return glueComplexType(v)
	}
	// Not a shape Iceberg emits for a type; render something rather than crash or drop the column.
	return fmt.Sprint(t)
}

// glueScalarType maps an Iceberg primitive type string to its Hive/Glue equivalent. Parameterized
// primitives (decimal(P,S), fixed[n]) are matched by prefix. An unknown string is returned verbatim.
func glueScalarType(t string) string {
	switch t {
	case "boolean":
		return "boolean"
	case "int":
		return "int"
	case "long":
		return "bigint"
	case "float":
		return "float"
	case "double":
		return "double"
	case "date":
		return "date"
	case "time":
		// Hive/Glue has no TIME type; Iceberg time-of-day is surfaced as a string (its ISO rendering).
		return "string"
	case "timestamp":
		return "timestamp"
	case "timestamptz":
		// Glue/Hive timestamp carries no zone; both Iceberg timestamp variants collapse to "timestamp".
		return "timestamp"
	case "string":
		return "string"
	case "uuid":
		return "string"
	case "binary":
		return "binary"
	}
	// fixed[n] is a fixed-length byte array -> Hive binary.
	if strings.HasPrefix(t, "fixed") {
		return "binary"
	}
	// decimal(P,S) carries the same spelling in Hive/Glue — pass it through unchanged.
	if strings.HasPrefix(t, "decimal") {
		return t
	}
	// Unknown primitive: pass through verbatim (never drop the column, never guess).
	return t
}

// glueComplexType renders an Iceberg nested type (struct/list/map) as its Hive angle-bracket form. The
// nested kind is identified by its "type" discriminator, falling back to its distinguishing member
// ("fields" for struct, "element" for list, "key"/"value" for map) so a missing discriminator is still
// handled. Element/field/key/value types recurse through glueType, so nesting is arbitrary-depth.
func glueComplexType(m map[string]any) string {
	kind, _ := m["type"].(string)
	switch {
	case kind == "struct" || hasKey(m, "fields"):
		fields, _ := m["fields"].([]any)
		parts := make([]string, 0, len(fields))
		for _, f := range fields {
			fm, ok := f.(map[string]any)
			if !ok {
				continue
			}
			name, _ := fm["name"].(string)
			parts = append(parts, name+":"+glueType(fm["type"]))
		}
		return "struct<" + strings.Join(parts, ",") + ">"
	case kind == "list" || hasKey(m, "element"):
		return "array<" + glueType(m["element"]) + ">"
	case kind == "map" || (hasKey(m, "key") && hasKey(m, "value")):
		return "map<" + glueType(m["key"]) + "," + glueType(m["value"]) + ">"
	}
	// An unrecognizable object: fall back to its "type" discriminator if it has one, else a best-effort
	// rendering. Either way a value is returned, so the column is kept.
	if kind != "" {
		return glueScalarType(kind)
	}
	return fmt.Sprint(m)
}

// icebergColumns translates an Iceberg schema's fields into Glue Columns ({Name, Type, Comment?}). An
// Iceberg field's optional "doc" becomes the Glue Column Comment. The result is never nil (an empty
// schema yields an empty list, which marshals to []), and a non-object entry is skipped, not fatal.
func icebergColumns(fields []any) []map[string]any {
	cols := make([]map[string]any, 0, len(fields))
	for _, f := range fields {
		fm, ok := f.(map[string]any)
		if !ok {
			continue
		}
		name, _ := fm["name"].(string)
		col := map[string]any{
			"Name": name,
			"Type": glueType(fm["type"]),
		}
		if doc, _ := fm["doc"].(string); doc != "" {
			col["Comment"] = doc
		}
		cols = append(cols, col)
	}
	return cols
}

// currentSchemaFields selects the fields of the schema a table is CURRENTLY on: the schema whose
// schema-id equals currentID, else (no match, or no id on any schema) the first schema's fields, else
// nil. Iceberg table metadata carries every historical schema in "schemas" plus a "current-schema-id";
// Glue only ever shows the current one.
func currentSchemaFields(schemas []any, currentID int) []any {
	if len(schemas) == 0 {
		return nil
	}
	for _, s := range schemas {
		sm, ok := s.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := intFromAny(sm["schema-id"]); ok && id == currentID {
			if f, ok := sm["fields"].([]any); ok {
				return f
			}
		}
	}
	if sm, ok := schemas[0].(map[string]any); ok {
		if f, ok := sm["fields"].([]any); ok {
			return f
		}
	}
	return nil
}

// firstPartitionSpecFields returns the fields of the first partition spec (Iceberg carries the active
// spec first). Returns nil when there is no spec, which is the common case for an unpartitioned table.
func firstPartitionSpecFields(specs []any) []any {
	if len(specs) == 0 {
		return nil
	}
	if sm, ok := specs[0].(map[string]any); ok {
		if f, ok := sm["fields"].([]any); ok {
			return f
		}
	}
	return nil
}

// partitionKeys derives Glue PartitionKeys from an Iceberg partition spec. Only IDENTITY-transform
// partition fields map to a Hive-style partition column (its name + the source column's type); Iceberg's
// hidden transforms (bucket/truncate/year/month/day/hour) are internal physical partitioning with no
// Hive partition-column equivalent, so they are omitted. The result is frequently empty — which is
// faithful: an Iceberg table usually exposes NO Hive partition columns. Never nil (marshals to []).
func partitionKeys(specFields, schemaFields []any) []map[string]any {
	byID := make(map[int]map[string]any, len(schemaFields))
	for _, f := range schemaFields {
		fm, ok := f.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := intFromAny(fm["id"]); ok {
			byID[id] = fm
		}
	}
	keys := make([]map[string]any, 0)
	for _, pf := range specFields {
		pm, ok := pf.(map[string]any)
		if !ok {
			continue
		}
		if transform, _ := pm["transform"].(string); transform != "identity" {
			continue
		}
		name, _ := pm["name"].(string)
		col := map[string]any{"Name": name, "Type": "string"}
		if srcID, ok := intFromAny(pm["source-id"]); ok {
			if sf, ok := byID[srcID]; ok {
				col["Type"] = glueType(sf["type"])
				if name == "" {
					if n, _ := sf["name"].(string); n != "" {
						col["Name"] = n
					}
				}
			}
		}
		keys = append(keys, col)
	}
	return keys
}

// --- pure helpers ---

func hasKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

// intFromAny extracts an int from the numeric shapes encoding/json yields into an any (float64), plus
// the plain int/int64 a caller might pass directly. Reports false for anything non-numeric.
func intFromAny(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}
