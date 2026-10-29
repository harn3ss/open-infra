package dynamodb

import (
	"context"
	"testing"
)

// A Scan must never materialise a whole large table in one request. These assert the op
// contract both stores honour (MemStore here, pure; the FerretStore enforces the same server-side):
// Select=COUNT counts without building items, Limit is honoured, an unbounded scan is capped at
// scanDefaultLimit, and an offset nextToken pages the rest. Data is generated, never a fixture.
func seedN(t *testing.T, st *MemStore, nItems int) {
	t.Helper()
	for i := 0; i < nItems; i++ {
		put(t, st, itoa4(i), map[string]any{"v": n("1")})
	}
}

// itoa4 gives a zero-padded id so sortedKeys() ordering is stable/lexicographic across pages.
func itoa4(i int) string {
	const d = "0123456789"
	b := []byte("k0000")
	b[4] = d[i%10]
	b[3] = d[(i/10)%10]
	b[2] = d[(i/100)%10]
	b[1] = d[(i/1000)%10]
	return string(b)
}

func scanOp(t *testing.T, st *MemStore, op Operation) map[string]any {
	t.Helper()
	op["operation"] = "Scan"
	res, err := st.Execute(context.Background(), op)
	if err != nil {
		t.Fatalf("scan %v: %v", op, err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("scan result not a map: %T", res)
	}
	return m
}

func itemsLen(m map[string]any) int {
	if it, ok := m["items"].([]any); ok {
		return len(it)
	}
	return 0
}

func TestScan_SelectCount_NoMaterialise(t *testing.T) {
	st := NewMemStore()
	seedN(t, st, 2500)

	m := scanOp(t, st, Operation{"select": "COUNT"})
	if got := m["count"].(float64); got != 2500 {
		t.Fatalf("COUNT count = %v, want 2500", got)
	}
	if itemsLen(m) != 0 {
		t.Fatalf("COUNT returned %d items, want 0 (must not build a result set)", itemsLen(m))
	}
}

func TestScan_UnboundedIsCapped(t *testing.T) {
	st := NewMemStore()
	seedN(t, st, 2500)

	m := scanOp(t, st, Operation{}) // no Limit — must still be bounded
	if got := itemsLen(m); got != scanDefaultLimit {
		t.Fatalf("unbounded scan returned %d items, want the %d cap", got, scanDefaultLimit)
	}
	if _, ok := m["nextToken"].(string); !ok {
		t.Fatalf("a capped scan must return a nextToken so the client can page the rest")
	}
}

func TestScan_HonoursLimitAndPagesAll(t *testing.T) {
	st := NewMemStore()
	seedN(t, st, 2500)

	seen := map[string]bool{}
	op := Operation{"limit": float64(500)}
	pages := 0
	for {
		m := scanOp(t, st, op)
		if l := itemsLen(m); l > 500 {
			t.Fatalf("page returned %d items, want <= Limit 500", l)
		}
		for _, it := range m["items"].([]any) {
			id, _ := it.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatalf("item %q returned on more than one page", id)
			}
			seen[id] = true
		}
		pages++
		tok, more := m["nextToken"].(string)
		if !more || tok == "" {
			break
		}
		op = Operation{"limit": float64(500), "nextToken": tok}
		if pages > 20 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != 2500 {
		t.Fatalf("paged %d distinct items across %d pages, want 2500", len(seen), pages)
	}
}
