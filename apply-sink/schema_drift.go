package main

// MODE=schema-drift: periodic cross-engine schema-drift detection for a multi-master flow.
//
// The reconciler (MODE=reconcile) keeps the table SET aligned across members, but a table's SHAPE can
// still diverge — a column added on one member, a primary key that differs, or a member that never got
// mm-prepped (missing _mm_version/_mm_origin). Any of those silently breaks replication: the per-edge
// apply upserts by column and needs the version/origin columns for conflict resolution, so a shape
// mismatch shows up much later as apply errors or lost writes. This mode introspects every member's
// tables each cycle and alerts (a distinctive log line a Loki/PrometheusRule alert can match) when a
// table's shape is not identical across the members that have it.
//
// Scope, stated honestly: the drift SIGNATURE is the column-NAME set + primary-key set + presence of the
// multi-master columns — NOT column data types. Across engines the same logical column has different type
// names (Postgres `integer` vs MySQL `int` vs SQL Server `int`), which the CDC path maps rather than
// requires equal; comparing raw types would report drift on every cross-engine flow. Name/PK/mm drift is
// exactly what breaks the apply, so that is what this detects.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

func runSchemaDrift() {
	raw := env("MEMBERS", "")
	vcol := env("VERSION_COLUMN", "_mm_version")
	ocol := env("ORIGIN_COLUMN", "_mm_origin")
	interval := time.Duration(atoiEnv("DRIFT_INTERVAL", 60)) * time.Second
	oneshot := env("DRIFT_ONESHOT", "") == "true"
	if raw == "" {
		log.Fatal("MEMBERS required for schema-drift mode")
	}
	var members []*reconcileMember
	if err := json.Unmarshal([]byte(raw), &members); err != nil {
		log.Fatalf("parse MEMBERS: %v", err)
	}
	for _, m := range members {
		db, err := openDB(m.Engine, os.ExpandEnv(m.DSN))
		if err != nil {
			log.Fatalf("schema-drift open %s: %v", m.Name, err)
		}
		m.db = db
	}
	log.Printf("schema-drift: %d members, interval=%s oneshot=%v", len(members), interval, oneshot)
	for {
		drifted := driftCycle(members, vcol, ocol)
		if oneshot {
			if drifted > 0 {
				os.Exit(1) // non-zero so a probe/CI job flags the drift
			}
			os.Exit(0)
		}
		time.Sleep(interval)
	}
}

// driftCycle introspects every member's tables once, analyzes each table for divergence, logs findings,
// and returns the count of tables that drifted.
func driftCycle(members []*reconcileMember, vcol, ocol string) int {
	memberNames := make([]string, 0, len(members))
	for _, m := range members {
		memberNames = append(memberNames, m.Name)
	}
	// table -> member -> shape (absent member = table missing there)
	perTable := map[string]map[string]meta{}
	for _, m := range members {
		tl, err := discoverTables(m.db, m.Engine)
		if err != nil {
			log.Printf("schema-drift: discover %s: %v", m.Name, err)
			continue
		}
		for _, t := range dropHelperTables(tl) {
			sch, tbl := t[0], t[1]
			// Confine to the member's home schema (pgx/sqlserver expose multiple), same as the reconciler.
			if d := driverName(m.Engine); (d == "pgx" || d == "sqlserver") && m.Schema != "" && sch != m.Schema {
				continue
			}
			mt, err := introspectFresh(m.db, m.Engine, sch, tbl)
			if err != nil {
				log.Printf("schema-drift: introspect %s.%s on %s: %v", sch, tbl, m.Name, err)
				continue
			}
			if perTable[tbl] == nil {
				perTable[tbl] = map[string]meta{}
			}
			perTable[tbl][m.Name] = mt
		}
	}
	tables := make([]string, 0, len(perTable))
	for t := range perTable {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	drifted, aligned := 0, 0
	for _, tbl := range tables {
		f := analyzeDrift(tbl, perTable[tbl], memberNames, vcol, ocol)
		if f.aligned {
			aligned++
			continue
		}
		drifted++
		log.Printf("schema-drift: DIVERGENCE table=%q %s", tbl, f.detail)
	}
	log.Printf("schema-drift: cycle complete tables=%d aligned=%d drifted=%d", len(tables), aligned, drifted)
	return drifted
}

// introspectFresh introspects one table WITHOUT the getMeta cache (drift detection must see current
// state each cycle) and WITHOUT getMeta's no-PK fatal (a missing PK is itself drift worth reporting).
func introspectFresh(db *sql.DB, engine, schema, table string) (meta, error) {
	switch driverName(engine) {
	case "pgx":
		return introspectPostgres(db, schema, table)
	case "mysql":
		return introspectMysql(db, schema, table)
	case "sqlserver":
		return introspectSqlserver(db, schema, table)
	default:
		return meta{}, fmt.Errorf("schema-drift: introspection not implemented for engine %s", engine)
	}
}

// ── Pure drift analysis (no DB — unit-tested) ──────────────────────────────────────────────

type driftFinding struct {
	table   string
	aligned bool
	detail  string
}

// shapeSignature is the deterministic, cross-engine-comparable shape of a table: its sorted column-name
// set and sorted primary-key set. (Types are deliberately excluded — see the package note.)
func shapeSignature(m meta) string {
	cols := append([]string(nil), m.cols...)
	sort.Strings(cols)
	pk := append([]string(nil), m.pk...)
	sort.Strings(pk)
	return "cols=[" + strings.Join(cols, ",") + "] pk=[" + strings.Join(pk, ",") + "]"
}

func hasCol(m meta, name string) bool {
	for _, c := range m.cols {
		if c == name {
			return true
		}
	}
	return false
}

// analyzeDrift decides whether a table's shape is identical across the members that have it, and — when
// not — describes exactly how it diverges: members missing the table, members missing the multi-master
// columns, and per-member column/PK differences against a stable reference.
func analyzeDrift(table string, byMember map[string]meta, allMembers []string, vcol, ocol string) driftFinding {
	present := []string{}
	for _, name := range allMembers {
		if _, ok := byMember[name]; ok {
			present = append(present, name)
		}
	}
	sort.Strings(present)
	if len(present) == 0 {
		return driftFinding{table: table, aligned: true}
	}

	var problems []string

	// 1. members missing the table entirely
	var missing []string
	for _, name := range allMembers {
		if _, ok := byMember[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		problems = append(problems, "missing on ["+strings.Join(missing, ",")+"]")
	}

	// 2. members missing the multi-master columns (not mm-prepped)
	var noMM []string
	for _, name := range present {
		m := byMember[name]
		if !hasCol(m, vcol) || !hasCol(m, ocol) {
			noMM = append(noMM, name)
		}
	}
	if len(noMM) > 0 {
		problems = append(problems, "missing mm columns ("+vcol+"/"+ocol+") on ["+strings.Join(noMM, ",")+"]")
	}

	// 3. shape divergence among present members, described against a stable reference (first present)
	ref := present[0]
	refSig := shapeSignature(byMember[ref])
	var diffs []string
	for _, name := range present[1:] {
		if shapeSignature(byMember[name]) == refSig {
			continue
		}
		onlyRef, onlyOther := colDiff(byMember[ref], byMember[name])
		var parts []string
		if len(onlyRef) > 0 {
			parts = append(parts, "cols on "+ref+" not "+name+": ["+strings.Join(onlyRef, ",")+"]")
		}
		if len(onlyOther) > 0 {
			parts = append(parts, "cols on "+name+" not "+ref+": ["+strings.Join(onlyOther, ",")+"]")
		}
		if pk := pkDiff(byMember[ref], byMember[name]); pk != "" {
			parts = append(parts, pk+" ("+ref+" vs "+name+")")
		}
		if len(parts) == 0 {
			parts = append(parts, "shape differs")
		}
		diffs = append(diffs, name+": "+strings.Join(parts, "; "))
	}
	if len(diffs) > 0 {
		problems = append(problems, "shape differs vs "+ref+" — "+strings.Join(diffs, " | "))
	}

	if len(problems) == 0 {
		return driftFinding{table: table, aligned: true}
	}
	return driftFinding{table: table, aligned: false, detail: strings.Join(problems, "; ")}
}

// colDiff returns the columns present on a but not b, and on b but not a (sorted).
func colDiff(a, b meta) (onlyA, onlyB []string) {
	bs := map[string]bool{}
	for _, c := range b.cols {
		bs[c] = true
	}
	as := map[string]bool{}
	for _, c := range a.cols {
		as[c] = true
		if !bs[c] {
			onlyA = append(onlyA, c)
		}
	}
	for _, c := range b.cols {
		if !as[c] {
			onlyB = append(onlyB, c)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return onlyA, onlyB
}

// pkDiff describes a primary-key divergence between a and b, or "" if their PKs match (order-insensitive).
func pkDiff(a, b meta) string {
	pa := append([]string(nil), a.pk...)
	pb := append([]string(nil), b.pk...)
	sort.Strings(pa)
	sort.Strings(pb)
	if strings.Join(pa, ",") == strings.Join(pb, ",") {
		return ""
	}
	return "PK differs [" + strings.Join(pa, ",") + "] vs [" + strings.Join(pb, ",") + "]"
}
