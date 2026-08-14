//go:build convergence

package main

// Migration fidelity harness — the MIGRATION adapter of the singular chaos oracle (see
// oracle_framework.go). Where the replication adapter tests a SYMMETRIC contract (every peer must
// agree), migration is the ASYMMETRIC one: a one-way source → target load, where the only thing
// that must hold is that every row the SOURCE acknowledged appears, identically, in the TARGET.
// This is the first non-convergence oracle — the keystone the whole chain vision turns on, because
// "did the workload survive chaos" for a migration is a fidelity question, not an agreement one.
//
// It exists specifically to prove the framework seam: it reuses the shared runner's drive → poll →
// conserve loop unchanged, supplying only a one-sided driver and a one-way steady-state predicate.
// If this drops on cleanly, the runner is genuinely workload-agnostic; if it had to fight the
// runner, the runner was still replication-shaped. (It dropped on cleanly.)
//
// Run it against a RUNNING kind: Migration (source DB → managed target) WHILE injecting a fault to
// prove the load survives partition / sink loss / pressure — the driver retries source writes
// through the fault, the runner polls until the target catches up after it heals.
//
// Opt-in (build tag `convergence`, skips without MIG_SOURCE):
//   MIG_SOURCE='{"name":"src","engine":"mysql","dsn":"...","schema":"public"}' \
//   MIG_TARGET='{"name":"tgt","engine":"postgres","dsn":"...","schema":"public"}' \
//   MIG_CREATE=true MIG_TABLE=public.mig_test \
//     go test -tags convergence -run TestMigrationFidelity -timeout 30m ./...

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMigrationFidelity(t *testing.T) {
	rawSrc := os.Getenv("MIG_SOURCE")
	if rawSrc == "" {
		t.Skip("set MIG_SOURCE (a single reconcileMember JSON) to run")
	}
	rawTgt := os.Getenv("MIG_TARGET")
	if rawTgt == "" {
		t.Fatalf("MIG_SOURCE set but MIG_TARGET missing — need both endpoints")
	}
	var src, tgt reconcileMember
	if err := json.Unmarshal([]byte(rawSrc), &src); err != nil {
		t.Fatalf("parse MIG_SOURCE: %v", err)
	}
	if err := json.Unmarshal([]byte(rawTgt), &tgt); err != nil {
		t.Fatalf("parse MIG_TARGET: %v", err)
	}
	runOracle(t, newMigrationOracle(t, &src, &tgt))
}

// migrationOracle is the one-way fidelity contract: work is driven ONLY at the source, and the
// target must reflect every acknowledged source row identically. It implements Oracle.
type migrationOracle struct {
	src, tgt *reconcileMember
	pk       string
	nRows    int
	nUpd     int
	settle   time.Duration
	qtSrc    string
	qtTgt    string
	write    func(q string, args ...any) error

	// want is the source's FINAL (id -> val) after inserts+updates — the acknowledged state the
	// target must converge to. Built in Drive, read by SteadyState/Reconcile so the check is
	// against what the source promised, not a live re-read that could race further writes.
	want map[string]string

	// lastTarget caches the most recent target sample so Reconcile inspects the settled state.
	lastTarget map[string]string
}

func newMigrationOracle(t *testing.T, src, tgt *reconcileMember) *migrationOracle {
	pk := env("MIG_PK", "id")
	table := env("MIG_TABLE", "public.mig_test")
	srcSchema, tbl := "public", table
	if i := strings.IndexByte(table, '.'); i >= 0 {
		srcSchema, tbl = table[:i], table[i+1:]
	}

	for _, m := range []*reconcileMember{src, tgt} {
		db, err := openDB(m.Engine, os.ExpandEnv(m.DSN))
		if err != nil {
			t.Fatalf("open %s: %v", m.Name, err)
		}
		m.db = db
		t.Cleanup(func() { db.Close() })
	}

	qtSrc := qualified(src.Engine, targetSchema(src.Engine, srcSchema), tbl)
	qtTgt := qualified(tgt.Engine, targetSchema(tgt.Engine, srcSchema), tbl)

	// Create the (id, val) table on the SOURCE only — migration is one-way, so the pipeline
	// (snapshot/full-load + CDC) is what must create it and its rows on the target. If the target
	// table never appears, that is itself a fidelity failure the poll will surface as "0 rows".
	if os.Getenv("MIG_CREATE") == "true" {
		ttype := "text"
		switch driverName(src.Engine) {
		case "mysql":
			ttype = "varchar(255)"
		case "sqlserver":
			ttype = "nvarchar(255)"
		}
		ddl := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s %s PRIMARY KEY, val %s)",
			qtSrc, quoteIdent(src.Engine, pk), ttype, ttype)
		if driverName(src.Engine) == "sqlserver" {
			ddl = fmt.Sprintf("IF OBJECT_ID('%s.%s','U') IS NULL CREATE TABLE %s (%s %s PRIMARY KEY, val %s)",
				targetSchema(src.Engine, srcSchema), tbl, qtSrc, quoteIdent(src.Engine, pk), ttype, ttype)
		}
		if _, err := src.db.Exec(ddl); err != nil {
			t.Fatalf("create table on source %s: %v", src.Name, err)
		}
		t.Logf("created %s on source %s (pipeline must replicate schema+rows to target %s)", table, src.Name, tgt.Name)
	}

	return &migrationOracle{
		src:    src,
		tgt:    tgt,
		pk:     pk,
		nRows:  atoiEnv("MIG_ROWS", 200),
		nUpd:   atoiEnv("MIG_UPDATES", 20),
		settle: time.Duration(atoiEnv("CONV_SETTLE", 8)) * time.Second,
		qtSrc:  qtSrc,
		qtTgt:  qtTgt,
		write:  retryWriter(src.db),
		want:   map[string]string{},
	}
}

func (o *migrationOracle) Name() string { return "migration-fidelity" }

func (o *migrationOracle) insert(id, val string) error {
	return o.write(fmt.Sprintf("INSERT INTO %s (%s, val) VALUES (%s, %s)",
		o.qtSrc, quoteIdent(o.src.Engine, o.pk), placeholder(o.src.Engine, 0), placeholder(o.src.Engine, 1)), id, val)
}
func (o *migrationOracle) updateRow(id, val string) error {
	return o.write(fmt.Sprintf("UPDATE %s SET val=%s WHERE %s=%s",
		o.qtSrc, placeholder(o.src.Engine, 0), quoteIdent(o.src.Engine, o.pk), placeholder(o.src.Engine, 1)), val, id)
}

func (o *migrationOracle) Drive(t *testing.T) map[string]bool {
	ledger := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Insert rows at the source only. Each acknowledged row is a promise the target must keep.
	for i := 0; i < o.nRows; i++ {
		id := fmt.Sprintf("m%05d", i)
		val := fmt.Sprintf("v:%d", i)
		wg.Add(1)
		go func(id, val string) {
			defer wg.Done()
			if err := o.insert(id, val); err != nil {
				t.Errorf("insert %s on source: %v", id, err)
				return
			}
			mu.Lock()
			o.want[id] = val
			ledger[id] = true
			mu.Unlock()
		}(id, val)
	}
	wg.Wait()

	// Update a fraction — fidelity must track the FINAL value, not just first-write, so this proves
	// the pipeline carries CDC updates and not merely the initial snapshot. One-sided (source only);
	// there is no conflicting writer, which is exactly what makes this the asymmetric contract.
	time.Sleep(o.settle)
	for j := 0; j < o.nUpd && j < o.nRows; j++ {
		id := fmt.Sprintf("m%05d", j)
		val := fmt.Sprintf("v2:%d", j)
		wg.Add(1)
		go func(id, val string) {
			defer wg.Done()
			if err := o.updateRow(id, val); err != nil {
				t.Errorf("update %s on source: %v", id, err)
				return
			}
			mu.Lock()
			o.want[id] = val
			mu.Unlock()
		}(id, val)
	}
	wg.Wait()
	return ledger
}

func (o *migrationOracle) targetSnapshot() (map[string]string, error) {
	rows, err := o.tgt.db.Query(fmt.Sprintf("SELECT %s, val FROM %s",
		quoteIdent(o.tgt.Engine, o.pk), o.qtTgt))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, val string
		if err := rows.Scan(&id, &val); err != nil {
			return nil, err
		}
		out[id] = val
	}
	return out, rows.Err()
}

func (o *migrationOracle) SteadyState() (bool, string, error) {
	tgt, err := o.targetSnapshot()
	if err != nil {
		// The target table may not exist yet early in a load — treat as not-yet-steady, not fatal.
		return false, "", err
	}
	o.lastTarget = tgt

	var mismatch, missing int
	var sample []string
	for id, want := range o.want {
		got, ok := tgt[id]
		if !ok {
			missing++
			if len(sample) < 6 {
				sample = append(sample, fmt.Sprintf("%s: absent (want %q)", id, want))
			}
			continue
		}
		if got != want {
			mismatch++
			if len(sample) < 6 {
				sample = append(sample, fmt.Sprintf("%s: target=%q want=%q", id, got, want))
			}
		}
	}
	if missing == 0 && mismatch == 0 {
		return true, "", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  source acked: %d rows   target: %d rows\n", len(o.want), len(tgt))
	fmt.Fprintf(&b, "  missing: %d   value-mismatch: %d\n", missing, mismatch)
	for _, s := range sample {
		fmt.Fprintf(&b, "  DRIFT %s\n", s)
	}
	return false, b.String(), nil
}

func (o *migrationOracle) Reconcile(ledger map[string]bool) []string {
	var lost []string
	for id := range ledger {
		got, ok := o.lastTarget[id]
		if !ok || got != o.want[id] {
			lost = append(lost, id)
		}
	}
	return lost
}

// TestMigrationRedGreen — prove-red for the one-way fidelity adapter (§6 guardrail). Without a live
// target DB, drive the Reconcile pillar directly (want = source's acked state, lastTarget = settled
// target sample): the target must reflect every acknowledged source row identically, so a dropped row
// or a stale value is lost work. Confirms the judge distinguishes red from green.
func TestMigrationRedGreen(t *testing.T) {
	o := &migrationOracle{want: map[string]string{"a": "1", "b": "2", "c": "3"}}
	ledger := map[string]bool{"a": true, "b": true, "c": true}

	// GREEN: target reflects every acknowledged source row identically.
	o.lastTarget = map[string]string{"a": "1", "b": "2", "c": "3"}
	if lost := o.Reconcile(ledger); len(lost) != 0 {
		t.Fatalf("GREEN: target matches source but reported lost: %v", lost)
	}
	// RED (dropped row): target is MISSING an acknowledged source row — the one-way load lost it.
	o.lastTarget = map[string]string{"a": "1", "c": "3"}
	if lost := o.Reconcile(ledger); len(lost) != 1 || lost[0] != "b" {
		t.Fatalf("a dropped acknowledged row MUST be reported lost: got %v", lost)
	}
	// RED (value drift): target holds a STALE value for an acknowledged row — a fidelity break.
	o.lastTarget = map[string]string{"a": "1", "b": "STALE", "c": "3"}
	if lost := o.Reconcile(ledger); len(lost) != 1 || lost[0] != "b" {
		t.Fatalf("a value-drifted acknowledged row MUST be reported lost: got %v", lost)
	}
}
