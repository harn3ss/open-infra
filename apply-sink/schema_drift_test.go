package main

import (
	"strings"
	"testing"
)

func mkMeta(cols, pk []string) meta {
	ct := map[string]string{}
	for _, c := range cols {
		ct[c] = "sometype"
	}
	return meta{cols: cols, colType: ct, pk: pk}
}

const dv, do = "_mm_version", "_mm_origin"

// A table with an identical column-name set + PK on every member — even with columns declared in a
// different order or with different type NAMES (cross-engine) — is aligned, not drift.
func TestAnalyzeDrift_Aligned(t *testing.T) {
	a := mkMeta([]string{"id", "name", dv, do}, []string{"id"})
	b := mkMeta([]string{"name", "id", do, dv}, []string{"id"}) // different order
	// different type names must NOT count as drift (cross-engine types map, not match)
	b.colType["id"] = "int"
	a.colType["id"] = "integer"
	f := analyzeDrift("t", map[string]meta{"a": a, "b": b}, []string{"a", "b"}, dv, do)
	if !f.aligned {
		t.Fatalf("want aligned, got drift: %s", f.detail)
	}
}

func TestAnalyzeDrift_MissingTable(t *testing.T) {
	a := mkMeta([]string{"id", "name", dv, do}, []string{"id"})
	f := analyzeDrift("t", map[string]meta{"a": a}, []string{"a", "b"}, dv, do)
	if f.aligned || !strings.Contains(f.detail, "missing on [b]") {
		t.Fatalf("want 'missing on [b]', got aligned=%v detail=%q", f.aligned, f.detail)
	}
}

func TestAnalyzeDrift_MissingMMColumns(t *testing.T) {
	a := mkMeta([]string{"id", "name", dv, do}, []string{"id"})
	b := mkMeta([]string{"id", "name"}, []string{"id"}) // never mm-prepped
	f := analyzeDrift("t", map[string]meta{"a": a, "b": b}, []string{"a", "b"}, dv, do)
	if f.aligned || !strings.Contains(f.detail, "missing mm columns") || !strings.Contains(f.detail, "b") {
		t.Fatalf("want missing-mm on b, got aligned=%v detail=%q", f.aligned, f.detail)
	}
}

func TestAnalyzeDrift_ExtraColumn(t *testing.T) {
	a := mkMeta([]string{"id", "name", dv, do}, []string{"id"})
	b := mkMeta([]string{"id", "name", "extra", dv, do}, []string{"id"})
	f := analyzeDrift("t", map[string]meta{"a": a, "b": b}, []string{"a", "b"}, dv, do)
	if f.aligned || !strings.Contains(f.detail, "cols on b not a: [extra]") {
		t.Fatalf("want extra-col on b, got aligned=%v detail=%q", f.aligned, f.detail)
	}
}

func TestAnalyzeDrift_PKDiffers(t *testing.T) {
	a := mkMeta([]string{"id", "name", dv, do}, []string{"id"})
	b := mkMeta([]string{"id", "name", dv, do}, []string{"id", "name"})
	f := analyzeDrift("t", map[string]meta{"a": a, "b": b}, []string{"a", "b"}, dv, do)
	if f.aligned || !strings.Contains(f.detail, "PK differs") {
		t.Fatalf("want PK-differs, got aligned=%v detail=%q", f.aligned, f.detail)
	}
}

// Three members, one drifted: the aligned pair stays quiet, the odd one out is named.
func TestAnalyzeDrift_ThreeMembersOneDrift(t *testing.T) {
	good := mkMeta([]string{"id", "name", dv, do}, []string{"id"})
	bad := mkMeta([]string{"id", "name", "surprise", dv, do}, []string{"id"})
	f := analyzeDrift("t", map[string]meta{"a": good, "b": good, "c": bad}, []string{"a", "b", "c"}, dv, do)
	if f.aligned {
		t.Fatal("want drift with c the odd one out")
	}
	if !strings.Contains(f.detail, "c:") || !strings.Contains(f.detail, "surprise") {
		t.Fatalf("want c named with 'surprise', got %q", f.detail)
	}
}

func TestShapeSignature_OrderInsensitive(t *testing.T) {
	a := mkMeta([]string{"b", "a", "c"}, []string{"c", "a"})
	b := mkMeta([]string{"c", "b", "a"}, []string{"a", "c"})
	if shapeSignature(a) != shapeSignature(b) {
		t.Fatalf("signature must be order-insensitive:\n a=%s\n b=%s", shapeSignature(a), shapeSignature(b))
	}
}

func TestColDiffAndPKDiff(t *testing.T) {
	a := mkMeta([]string{"id", "x"}, []string{"id"})
	b := mkMeta([]string{"id", "y"}, []string{"id"})
	onlyA, onlyB := colDiff(a, b)
	if strings.Join(onlyA, ",") != "x" || strings.Join(onlyB, ",") != "y" {
		t.Fatalf("colDiff = %v / %v", onlyA, onlyB)
	}
	if pkDiff(a, b) != "" {
		t.Fatalf("identical PKs should report no diff, got %q", pkDiff(a, b))
	}
	if pkDiff(mkMeta([]string{"id"}, []string{"id"}), mkMeta([]string{"id"}, []string{"id", "x"})) == "" {
		t.Fatal("differing PKs should report a diff")
	}
}
