//go:build convergence

package main

// Convergence harness — the "does multi-master actually converge?" test the README's
// Maturity section calls out as the missing correctness evidence. Point it at the
// members of a RUNNING multi-master flow; it drives concurrent and deliberately
// CONFLICTING writes, then asserts every member ends byte-identical: same key set
// (no lost writes) and the same HLC-winning version+value per key (deterministic
// last-write-wins). Run it WHILE injecting a fault (kind: FaultInjection
// network-partition or pod-kill) to prove convergence survives partition / node loss
// — the harness retries writes through the fault and polls until the mesh re-converges
// after it heals. See docs/convergence-harness.md.
//
// Opt-in (build tag `convergence`, skips without CONV_MEMBERS):
//   CONV_MEMBERS='[{"name":"pg-a","engine":"postgres","dsn":"...","site":"a","schema":"public"},
//                  {"name":"pg-b","engine":"postgres","dsn":"...","site":"b","schema":"public"}]' \
//   CONV_CREATE=true CONV_TABLE=public.conv_test \
//     go test -tags convergence -run TestConvergence -timeout 30m ./...

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConvergence(t *testing.T) {
	raw := os.Getenv("CONV_MEMBERS")
	if raw == "" {
		t.Skip("set CONV_MEMBERS (same JSON shape as the engine's MEMBERS) to run")
	}
	var members []*reconcileMember
	if err := json.Unmarshal([]byte(raw), &members); err != nil {
		t.Fatalf("parse CONV_MEMBERS: %v", err)
	}
	if len(members) < 2 {
		t.Fatalf("need >= 2 members, got %d", len(members))
	}

	vcol := env("VERSION_COLUMN", "_mm_version")
	ocol := env("ORIGIN_COLUMN", "_mm_origin")
	table := env("CONV_TABLE", "public.conv_test")
	pk := env("CONV_PK", "id")
	nKeys := atoiEnv("CONV_KEYS", 200)
	nConf := atoiEnv("CONV_CONFLICTS", 20)
	settle := time.Duration(atoiEnv("CONV_SETTLE", 8)) * time.Second
	timeout := time.Duration(atoiEnv("CONV_TIMEOUT", 120)) * time.Second

	srcSchema, tbl := "public", table
	if i := strings.IndexByte(table, '.'); i >= 0 {
		srcSchema, tbl = table[:i], table[i+1:]
	}
	qt := func(m *reconcileMember) string {
		return qualified(m.Engine, targetSchema(m.Engine, srcSchema), tbl)
	}

	for _, m := range members {
		db, err := openDB(m.Engine, os.ExpandEnv(m.DSN))
		if err != nil {
			t.Fatalf("open %s: %v", m.Name, err)
		}
		m.db = db
		t.Cleanup(func() { db.Close() })
	}

	// Optionally create + mm-prep the dedicated (id, val) table on every member. The
	// running flow must CAPTURE it (capture-all CDC / autoSyncTables) for writes to
	// replicate — otherwise point CONV_TABLE at a table already in the flow that has
	// (id, val) columns.
	if os.Getenv("CONV_CREATE") == "true" {
		for _, m := range members {
			ttype := "text"
			switch driverName(m.Engine) {
			case "mysql":
				ttype = "varchar(255)"
			case "sqlserver":
				ttype = "nvarchar(255)"
			}
			sch := targetSchema(m.Engine, srcSchema)
			ddl := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s %s PRIMARY KEY, val %s)",
				qt(m), quoteIdent(m.Engine, pk), ttype, ttype)
			if driverName(m.Engine) == "sqlserver" {
				ddl = fmt.Sprintf("IF OBJECT_ID('%s.%s','U') IS NULL CREATE TABLE %s (%s %s PRIMARY KEY, val %s)",
					sch, tbl, qt(m), quoteIdent(m.Engine, pk), ttype, ttype)
			}
			if _, err := m.db.Exec(ddl); err != nil {
				t.Fatalf("create table on %s: %v", m.Name, err)
			}
			if err := mmPrepSetup(m.db, m.Engine, m.Site, vcol); err != nil {
				t.Fatalf("mmPrepSetup %s: %v", m.Name, err)
			}
			if err := mmPrepTable(m.db, m.Engine, m.Site, vcol, ocol, sch, tbl); err != nil {
				t.Fatalf("mmPrepTable %s: %v", m.Name, err)
			}
		}
		t.Logf("created + mm-prepped %s on %d members", table, len(members))
	}

	// write helpers, tolerant of transient errors during a fault window
	exec := func(m *reconcileMember, q string, args ...any) error {
		var err error
		for i := 0; i < 6; i++ {
			if _, err = m.db.Exec(q, args...); err == nil {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return err
	}
	insert := func(m *reconcileMember, id, val string) error {
		return exec(m, fmt.Sprintf("INSERT INTO %s (%s, val) VALUES (%s, %s)",
			qt(m), quoteIdent(m.Engine, pk), placeholder(m.Engine, 0), placeholder(m.Engine, 1)), id, val)
	}
	update := func(m *reconcileMember, id, val string) error {
		return exec(m, fmt.Sprintf("UPDATE %s SET val=%s WHERE %s=%s",
			qt(m), placeholder(m.Engine, 0), quoteIdent(m.Engine, pk), placeholder(m.Engine, 1)), val, id)
	}

	expected := map[string]bool{}
	var wg sync.WaitGroup

	// Distinct keys spread across all members — each must end present on every member.
	for i := 0; i < nKeys; i++ {
		id := fmt.Sprintf("k%05d", i)
		expected[id] = true
		m := members[i%len(members)]
		wg.Add(1)
		go func(m *reconcileMember, id string) {
			defer wg.Done()
			if err := insert(m, id, "d:"+m.Name); err != nil {
				t.Errorf("insert %s on %s: %v", id, m.Name, err)
			}
		}(m, id)
	}
	wg.Wait()

	// Conflict keys: seed on member[0], let them replicate, then race an UPDATE from
	// two members with different values — LWW must pick one winner, identical everywhere.
	for j := 0; j < nConf; j++ {
		id := fmt.Sprintf("c%05d", j)
		expected[id] = true
		if err := insert(members[0], id, "seed"); err != nil {
			t.Fatalf("seed conflict %s: %v", id, err)
		}
	}
	time.Sleep(settle)
	for j := 0; j < nConf; j++ {
		id := fmt.Sprintf("c%05d", j)
		wg.Add(2)
		go func(id string) { defer wg.Done(); _ = update(members[0], id, "w:"+members[0].Name) }(id)
		go func(id string) { defer wg.Done(); _ = update(members[1], id, "w:"+members[1].Name) }(id)
	}
	wg.Wait()

	// Converge: poll until every member's (id -> version+val) map is identical.
	snapshot := func(m *reconcileMember) (map[string][2]string, error) {
		rows, err := m.db.Query(fmt.Sprintf("SELECT %s, val, %s FROM %s",
			quoteIdent(m.Engine, pk), quoteIdent(m.Engine, vcol), qt(m)))
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string][2]string{}
		for rows.Next() {
			var id, val string
			var ver sql.NullInt64
			if err := rows.Scan(&id, &val, &ver); err != nil {
				return nil, err
			}
			out[id] = [2]string{fmt.Sprint(ver.Int64), val}
		}
		return out, rows.Err()
	}

	deadline := time.Now().Add(timeout)
	var last map[string]map[string][2]string
	converged := false
	for time.Now().Before(deadline) {
		snaps := map[string]map[string][2]string{}
		ok := true
		for _, m := range members {
			s, err := snapshot(m)
			if err != nil {
				ok = false
				break
			}
			snaps[m.Name] = s
		}
		last = snaps
		if ok && allIdentical(snaps, members) {
			converged = true
			break
		}
		time.Sleep(2 * time.Second)
	}

	if !converged {
		t.Fatalf("members did NOT converge within %s\n%s", timeout, convDiff(last, members, expected))
	}
	base := last[members[0].Name]
	var missing []string
	for id := range expected {
		if _, ok := base[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("LOST WRITES: %d/%d expected keys absent after convergence (e.g. %v)",
			len(missing), len(expected), convFirst(missing, 10))
	}
	t.Logf("CONVERGED: %d members, %d keys (%d conflicts) — identical version+value on every member, zero lost writes",
		len(members), len(expected), nConf)
}

func allIdentical(snaps map[string]map[string][2]string, members []*reconcileMember) bool {
	base := snaps[members[0].Name]
	for _, m := range members[1:] {
		s := snaps[m.Name]
		if len(s) != len(base) {
			return false
		}
		for id, v := range base {
			if s[id] != v {
				return false
			}
		}
	}
	return true
}

func convDiff(snaps map[string]map[string][2]string, members []*reconcileMember, expected map[string]bool) string {
	var b strings.Builder
	for _, m := range members {
		fmt.Fprintf(&b, "  %s: %d rows\n", m.Name, len(snaps[m.Name]))
	}
	base := snaps[members[0].Name]
	shown := 0
	for id := range expected {
		if shown >= 8 {
			break
		}
		want := base[id]
		for _, m := range members[1:] {
			if got := snaps[m.Name][id]; got != want {
				fmt.Fprintf(&b, "  DIVERGE key=%s  %s=%v  %s=%v\n", id, members[0].Name, want, m.Name, got)
				shown++
				break
			}
		}
	}
	return b.String()
}

func convFirst(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
