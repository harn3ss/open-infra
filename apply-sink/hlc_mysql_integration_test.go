//go:build integration

package main

// Tier 1 — MySQL HLC integration test. Exercises the REAL stamping trigger installed
// by mmPrepSetup + mmPrepTable against a live MySQL, proving the T6 fix: the Hybrid
// Logical Clock stays strictly monotonic even when the wall clock is behind the stored
// physical time (NTP step / skew) — the logical counter advances instead of regressing,
// so last-write-wins can never be corrupted by a backward clock.
//
// Opt-in (kept out of the default unit run by the `integration` build tag):
//   MYSQL_TEST_DSN='root:pw@tcp(127.0.0.1:3306)/testdb' \
//     go test -tags integration -run TestMySQLHLC ./...
// Use a THROWAWAY database — the test creates/drops a table and rewrites mm_hlc_state.

import (
	"database/sql"
	"os"
	"testing"
	"time"
)

func TestMySQLHLCMonotonicUnderBackwardClock(t *testing.T) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("set MYSQL_TEST_DSN (throwaway db) to run, e.g. root:pw@tcp(127.0.0.1:3306)/testdb")
	}
	db, err := sql.Open("mysql", dsn) // driver registered by main.go's blank import
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	// Single connection so the session (and @app_replication=NULL native path) and the
	// FOR UPDATE on mm_hlc_state behave deterministically.
	db.SetMaxOpenConns(1)

	const tbl = "hlc_mono_test"
	site, vcol, ocol := "siteA", "_mm_version", "_mm_origin"

	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	version := func(id int) int64 {
		t.Helper()
		var v int64
		if err := db.QueryRow("SELECT "+vcol+" FROM "+tbl+" WHERE id=?", id).Scan(&v); err != nil {
			t.Fatalf("read version id=%d: %v", id, err)
		}
		return v
	}

	mustExec("DROP TABLE IF EXISTS " + tbl)
	mustExec("CREATE TABLE " + tbl + " (id INT PRIMARY KEY, name VARCHAR(64))")
	t.Cleanup(func() { db.Exec("DROP TABLE IF EXISTS " + tbl) })

	// Install the real HLC state + per-site stamping trigger via production code paths.
	if err := mmPrepSetup(db, "mysql", site, vcol); err != nil {
		t.Fatalf("mmPrepSetup: %v", err)
	}
	if err := mmPrepTable(db, "mysql", site, vcol, ocol, "", tbl); err != nil {
		t.Fatalf("mmPrepTable: %v", err)
	}
	// Deterministic start.
	mustExec("UPDATE mm_hlc_state SET pt=0, lc=0 WHERE id=1")

	var prev int64 = -1

	// Case 1: a burst of inserts within the same millisecond still strictly increases —
	// the logical counter (low 16 bits) advances when the physical part is unchanged.
	for i := 0; i < 50; i++ {
		mustExec("INSERT INTO "+tbl+" (id,name) VALUES (?,?)", i, "burst")
		v := version(i)
		if v <= prev {
			t.Fatalf("burst: version not strictly increasing at i=%d: %d <= %d", i, v, prev)
		}
		prev = v
	}

	// Case 2: simulate a BACKWARD wall clock by shoving stored pt an hour into the future.
	// Every subsequent insert sees now < stored pt, so the trigger pins pt and bumps lc.
	// Versions must keep rising and never regress below the future physical time.
	future := time.Now().UnixMilli() + 3600_000
	mustExec("UPDATE mm_hlc_state SET pt=?, lc=0 WHERE id=1", future)
	for i := 100; i < 130; i++ {
		mustExec("INSERT INTO "+tbl+" (id,name) VALUES (?,?)", i, "backclock")
		v := version(i)
		if v <= prev {
			t.Fatalf("backward-clock: version REGRESSED at i=%d: %d <= %d", i, v, prev)
		}
		if pt := v >> 16; pt != future {
			t.Fatalf("backward-clock: physical part = %d, want pinned to future %d (clock went backward relative to it)", pt, future)
		}
		prev = v
	}

	t.Logf("HLC stayed monotonic across 80 inserts incl. a +1h backward-clock jump; final version=%d", prev)
}
