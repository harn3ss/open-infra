//go:build convergence

package main

// Convergence harness — the REPLICATION adapter of the singular chaos oracle (see
// oracle_framework.go). It is the "does multi-master actually converge?" evidence the README's
// Maturity section calls out. Point it at the members of a RUNNING multi-master flow; it drives
// concurrent and deliberately CONFLICTING writes (the ledger of acknowledged work), then the
// shared runner asserts every member ends byte-identical — same key set (conservation: no lost
// writes) and the same HLC-winning version+value per key (deterministic last-write-wins). Run it
// WHILE injecting a fault (kind: FaultInjection network-partition or pod-kill) to prove
// convergence survives partition / node loss — the driver retries writes through the fault and
// the runner polls until the mesh re-converges after it heals. See docs/convergence-harness.md.
//
// This is the FIRST adapter, and its correctness contract is the symmetric one: every member must
// agree. The migration adapter (migration_test.go) is the asymmetric counterpart. Behaviour here
// is unchanged from the original monolithic harness — only the verdict/poll machinery moved to the
// shared runner — because this test drives the 30-night graduation clock.
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
	runOracle(t, newReplicationOracle(t, members))
}

// replicationOracle is the multi-master correctness contract: symmetric peers that must all end
// byte-identical. It implements Oracle — Drive races conflicting writes, SteadyState checks
// all-identical, Reconcile checks no expected key was lost.
type replicationOracle struct {
	members []*reconcileMember
	vcol    string
	pk      string
	nKeys   int
	nConf   int
	settle  time.Duration
	qt      func(m *reconcileMember) string
	writers map[*reconcileMember]func(q string, args ...any) error

	// lastSnap caches the most recent full sample so Reconcile can inspect the SETTLED state
	// SteadyState just validated, rather than re-querying and racing further replication.
	lastSnap map[string]map[string][2]string
}

func newReplicationOracle(t *testing.T, members []*reconcileMember) *replicationOracle {
	vcol := env("VERSION_COLUMN", "_mm_version")
	ocol := env("ORIGIN_COLUMN", "_mm_origin")
	table := env("CONV_TABLE", "public.conv_test")
	pk := env("CONV_PK", "id")

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

	// Optionally create + mm-prep the dedicated (id, val) table on every member. The running flow
	// must CAPTURE it (capture-all CDC / autoSyncTables) for writes to replicate — otherwise point
	// CONV_TABLE at a table already in the flow that has (id, val) columns.
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

	writers := map[*reconcileMember]func(q string, args ...any) error{}
	for _, m := range members {
		writers[m] = retryWriter(m.db)
	}

	return &replicationOracle{
		members: members,
		vcol:    vcol,
		pk:      pk,
		nKeys:   atoiEnv("CONV_KEYS", 200),
		nConf:   atoiEnv("CONV_CONFLICTS", 20),
		settle:  time.Duration(atoiEnv("CONV_SETTLE", 8)) * time.Second,
		qt:      qt,
		writers: writers,
	}
}

func (o *replicationOracle) Name() string { return "convergence" }

func (o *replicationOracle) insert(m *reconcileMember, id, val string) error {
	return o.writers[m](fmt.Sprintf("INSERT INTO %s (%s, val) VALUES (%s, %s)",
		o.qt(m), quoteIdent(m.Engine, o.pk), placeholder(m.Engine, 0), placeholder(m.Engine, 1)), id, val)
}
func (o *replicationOracle) update(m *reconcileMember, id, val string) error {
	return o.writers[m](fmt.Sprintf("UPDATE %s SET val=%s WHERE %s=%s",
		o.qt(m), placeholder(m.Engine, 0), quoteIdent(m.Engine, o.pk), placeholder(m.Engine, 1)), val, id)
}

func (o *replicationOracle) Drive(t *testing.T) map[string]bool {
	expected := map[string]bool{}
	var wg sync.WaitGroup

	// Distinct keys spread across all members — each must end present on every member.
	for i := 0; i < o.nKeys; i++ {
		id := fmt.Sprintf("k%05d", i)
		expected[id] = true
		m := o.members[i%len(o.members)]
		wg.Add(1)
		go func(m *reconcileMember, id string) {
			defer wg.Done()
			if err := o.insert(m, id, "d:"+m.Name); err != nil {
				t.Errorf("insert %s on %s: %v", id, m.Name, err)
			}
		}(m, id)
	}
	wg.Wait()

	// Conflict keys: seed on member[0], let them replicate, then race an UPDATE from two members
	// with different values — LWW must pick one winner, identical everywhere.
	for j := 0; j < o.nConf; j++ {
		id := fmt.Sprintf("c%05d", j)
		expected[id] = true
		if err := o.insert(o.members[0], id, "seed"); err != nil {
			t.Fatalf("seed conflict %s: %v", id, err)
		}
	}
	time.Sleep(o.settle)
	for j := 0; j < o.nConf; j++ {
		id := fmt.Sprintf("c%05d", j)
		wg.Add(2)
		go func(id string) { defer wg.Done(); _ = o.update(o.members[0], id, "w:"+o.members[0].Name) }(id)
		go func(id string) { defer wg.Done(); _ = o.update(o.members[1], id, "w:"+o.members[1].Name) }(id)
	}
	wg.Wait()
	return expected
}

func (o *replicationOracle) snapshot(m *reconcileMember) (map[string][2]string, error) {
	rows, err := m.db.Query(fmt.Sprintf("SELECT %s, val, %s FROM %s",
		quoteIdent(m.Engine, o.pk), quoteIdent(m.Engine, o.vcol), o.qt(m)))
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

func (o *replicationOracle) SteadyState() (bool, string, error) {
	snaps := map[string]map[string][2]string{}
	for _, m := range o.members {
		s, err := o.snapshot(m)
		if err != nil {
			return false, "", err
		}
		snaps[m.Name] = s
	}
	o.lastSnap = snaps
	if allIdentical(snaps, o.members) {
		return true, "", nil
	}
	return false, convDiff(snaps, o.members), nil
}

func (o *replicationOracle) Reconcile(expected map[string]bool) []string {
	base := o.lastSnap[o.members[0].Name]
	var missing []string
	for id := range expected {
		if _, ok := base[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
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

func convDiff(snaps map[string]map[string][2]string, members []*reconcileMember) string {
	var b strings.Builder
	for _, m := range members {
		fmt.Fprintf(&b, "  %s: %d rows\n", m.Name, len(snaps[m.Name]))
	}
	base := snaps[members[0].Name]
	shown := 0
	for id, want := range base {
		if shown >= 8 {
			break
		}
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

// TestConvergenceRedGreen — prove-red for the ORIGINAL adapter (the lottery's own judge). §6 of the
// plane-wide-lottery design: a judge that has never been shown able to go red has not earned a counted
// green. Exercises both verdict pillars WITHOUT a live DB — allIdentical (SteadyState's convergence
// signal) and Reconcile (no acknowledged write lost) — asserting each distinguishes red from green.
func TestConvergenceRedGreen(t *testing.T) {
	members := []*reconcileMember{{Name: "pg-a"}, {Name: "pg-b"}, {Name: "pg-c"}}
	o := &replicationOracle{members: members}

	// ---- SteadyState pillar: allIdentical ----
	converged := map[string]map[string][2]string{
		"pg-a": {"k1": {"1", "v"}, "k2": {"2", "w"}},
		"pg-b": {"k1": {"1", "v"}, "k2": {"2", "w"}},
		"pg-c": {"k1": {"1", "v"}, "k2": {"2", "w"}},
	}
	if !allIdentical(converged, members) {
		t.Fatal("GREEN: byte-identical members must be reported converged (steady)")
	}
	// RED: a diverged mesh (one member missing a row, another holding a different value) must NOT read
	// steady — else SteadyState can never fail and convergence never reds.
	diverged := map[string]map[string][2]string{
		"pg-a": {"k1": {"1", "v"}, "k2": {"2", "w"}},
		"pg-b": {"k1": {"1", "v"}},                           // dropped k2
		"pg-c": {"k1": {"1", "v"}, "k2": {"9", "DIFFERENT"}}, // conflicting value at equal key
	}
	if allIdentical(diverged, members) {
		t.Fatal("a diverged mesh MUST NOT be reported converged — else convergence is dead code")
	}

	// ---- Reconcile pillar: no acknowledged write lost ----
	o.lastSnap = converged
	if lost := o.Reconcile(map[string]bool{"k1": true, "k2": true}); len(lost) != 0 {
		t.Fatalf("GREEN: the converged mesh holds every acknowledged write but reported lost: %v", lost)
	}
	// RED: an acknowledged write (k3) is absent from the converged base — genuinely lost work.
	o.lastSnap = map[string]map[string][2]string{"pg-a": {"k1": {"1", "v"}, "k2": {"2", "w"}}}
	lost := o.Reconcile(map[string]bool{"k1": true, "k2": true, "k3": true})
	if len(lost) != 1 || lost[0] != "k3" {
		t.Fatalf("an acknowledged write missing from the converged mesh MUST be reported lost: got %v", lost)
	}
}
