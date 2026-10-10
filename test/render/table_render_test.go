package render

import (
	"strings"
	"testing"
)

const tableCompositionPath = "../../platform/abstraction/table-composition.yaml"

func tableCtx(spec map[string]any) map[string]any {
	return map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
			"spec": spec,
			"metadata": map[string]any{"labels": map[string]any{
				"crossplane.io/claim-name":      "events",
				"crossplane.io/claim-namespace": "team-a",
			}},
		}}},
	}
}

// A local secondary index renders into the spec-mirror ConfigMap as {name, keyAttrs:[tableHash,
// lsiRange]} — the shape the aws-shim reads to register the LSI + its Mongo index.
func TestTable_LocalSecondaryIndex(t *testing.T) {
	tmpl := extractInlineTemplate(t, tableCompositionPath)
	spec := map[string]any{
		"hashKey":  map[string]any{"name": "id", "type": "S"},
		"rangeKey": map[string]any{"name": "ts", "type": "N"},
		"localSecondaryIndexes": []any{
			map[string]any{"name": "by-score", "rangeKey": map[string]any{"name": "score", "type": "N"}},
		},
	}
	out := render(t, tmpl, tableCtx(spec))
	if !strings.Contains(out, "lsi:") || !strings.Contains(out, "by-score") {
		t.Errorf("LSI should render an lsi field naming the index; got:\n%s", grepCtx(out, "lsi"))
	}
	// keyAttrs must be [tableHashKey, lsiRangeKey] = ["id","score"] (JSON, quote-escaped in YAML).
	for _, want := range []string{`id`, `score`} {
		if !strings.Contains(grepCtx(out, "lsi:"), want) {
			t.Errorf("LSI keyAttrs should include %q (= [tableHash, lsiRange]); got:\n%s", want, grepCtx(out, "lsi:"))
		}
	}
	// A table with no LSI must not render the lsi field.
	bare := render(t, tmpl, tableCtx(map[string]any{
		"hashKey":  map[string]any{"name": "id", "type": "S"},
		"rangeKey": map[string]any{"name": "ts", "type": "N"},
	}))
	if strings.Contains(bare, "lsi:") {
		t.Errorf("a table without LSIs must not render an lsi field; got:\n%s", grepCtx(bare, "lsi"))
	}
}

// streamSpecification renders the view type into the spec-mirror ConfigMap, so the shim opens a
// change stream for the table.
func TestTable_StreamSpecification(t *testing.T) {
	tmpl := extractInlineTemplate(t, tableCompositionPath)
	out := render(t, tmpl, tableCtx(map[string]any{
		"hashKey":             map[string]any{"name": "id", "type": "S"},
		"streamSpecification": map[string]any{"streamViewType": "NEW_AND_OLD_IMAGES"},
	}))
	if !strings.Contains(out, "streamViewType:") || !strings.Contains(out, "NEW_AND_OLD_IMAGES") {
		t.Errorf("streamSpecification should render streamViewType; got:\n%s", grepCtx(out, "stream"))
	}
	// No streamSpecification → no streamViewType field.
	bare := render(t, tmpl, tableCtx(map[string]any{"hashKey": map[string]any{"name": "id", "type": "S"}}))
	if strings.Contains(bare, "streamViewType:") {
		t.Errorf("a table without a stream must not render streamViewType; got:\n%s", grepCtx(bare, "stream"))
	}
}

// An LSI needs the table to have a range key (DynamoDB rule) — rendering must fail loud, not emit
// a half-formed index.
func TestTable_LSIRequiresRangeKey(t *testing.T) {
	tmpl := extractInlineTemplate(t, tableCompositionPath)
	spec := map[string]any{
		"hashKey": map[string]any{"name": "id", "type": "S"},
		"localSecondaryIndexes": []any{
			map[string]any{"name": "by-score", "rangeKey": map[string]any{"name": "score", "type": "N"}},
		},
	}
	if err := renderErr(tmpl, tableCtx(spec)); err == nil {
		t.Error("an LSI on a table with no rangeKey should abort the render")
	}
}
