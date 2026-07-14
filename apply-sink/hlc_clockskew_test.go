//go:build convergence

package main

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

// TestClockSkewMonotonic is the automated T6 regression (chaos suite, Scenario 2).
//
// T6 was a MySQL backward-clock lost write: when a member's physical clock ran backward
// (NTP step / skew), its HLC stamped a LOWER version, so a write that was genuinely the
// latest silently lost last-write-wins. The fix makes the stamp monotonic —
// max(clock, stored_pt) — so a backward clock bumps the logical counter instead of the
// version going down.
//
// This forces the backward clock DETERMINISTICALLY via the injectable clk_off offset in
// mm_hlc_state (no Chaos Mesh TimeChaos, no real clock touched) and asserts the stamped
// version still strictly increases. It installs mm-prep from local source, so it needs
// only a single mm-preppable member — no mesh/Debezium.
//
// Skips unless CONV_SKEW_DSN is set (same guard style as TestConvergence):
//
//	CONV_SKEW_ENGINE  default mysql
//	CONV_SKEW_DSN     required, e.g. mysql://app:${PW}@10.0.0.5:3306/app
//	CONV_SKEW_MS      default -3600000 (one hour backward)
func TestClockSkewMonotonic(t *testing.T) {
	dsn := os.Getenv("CONV_SKEW_DSN")
	if dsn == "" {
		t.Skip("set CONV_SKEW_DSN to run the clock-skew (T6) regression")
	}
	engine := env("CONV_SKEW_ENGINE", "mysql")
	skew := int64(atoiEnv("CONV_SKEW_MS", -3600000))
	vcol := env("VERSION_COLUMN", "_mm_version")
	ocol := env("ORIGIN_COLUMN", "_mm_origin")
	site := "s"
	schema, table := targetSchema(engine, "public"), "conv_test"

	db, err := openDB(engine, os.ExpandEnv(dsn))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	ttype := "text"
	if driverName(engine) == "mysql" {
		ttype = "varchar(255)"
	}
	qt := qualified(engine, schema, table)
	if _, err := db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s %s PRIMARY KEY, val %s)",
		qt, quoteIdent(engine, "id"), ttype, ttype)); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if err := mmPrepSetup(db, engine, site, vcol); err != nil {
		t.Fatalf("mmPrepSetup: %v", err)
	}
	if err := mmPrepTable(db, engine, site, vcol, ocol, schema, table); err != nil {
		t.Fatalf("mmPrepTable: %v", err)
	}

	readVer := func(id string) int64 {
		var v int64
		q := fmt.Sprintf("SELECT %s FROM %s WHERE %s = %s",
			quoteIdent(engine, vcol), qt, quoteIdent(engine, "id"), placeholder(engine, 0))
		if err := db.QueryRow(q, id).Scan(&v); err != nil {
			t.Fatalf("read version %s: %v", id, err)
		}
		return v
	}
	write := func(id string) {
		if _, err := db.Exec(fmt.Sprintf("INSERT INTO %s (%s, val) VALUES (%s, %s)",
			qt, quoteIdent(engine, "id"), placeholder(engine, 0), placeholder(engine, 1)), id, "v"); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	// 1. baseline write at the real clock
	write("skew-a")
	v1 := readVer("skew-a")

	// 2. force the physical clock BACKWARD via the injectable offset (nothing real skewed)
	if _, err := db.Exec("UPDATE mm_hlc_state SET clk_off = " + strconv.FormatInt(skew, 10)); err != nil {
		t.Fatalf("set clk_off: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec("UPDATE mm_hlc_state SET clk_off = 0") })

	// 3. write under the backward clock and assert the version still increased
	write("skew-b")
	v2 := readVer("skew-b")

	if v2 <= v1 {
		t.Fatalf("T6 REGRESSION: a %d ms backward clock produced a non-increasing HLC version "+
			"(v1=%d, v2=%d) — that write would silently lose last-write-wins", skew, v1, v2)
	}
	t.Logf("MONOTONIC under a %d ms backward clock: v1=%d < v2=%d (Δ=%d) — HLC held, no lost write",
		skew, v1, v2, v2-v1)
}
