//go:build convergence

package main

// The singular chaos-oracle CONTRACT (docs/chaos-oracle.md).
//
// Every chaos scenario — multi-master convergence, one-way migration fidelity, and the
// App/Stream/Query chains to come — is this ONE contract with a different workload driver and
// a different steady-state predicate. There is deliberately no monolithic god-oracle branching
// per workload (an oracle nobody can audit prints green you can't stand behind), and no N
// bespoke oracles either (that forks the verdict machinery that must be identical everywhere).
// Instead: a shared runner owns the parts that must never differ — the reconvergence poll, the
// GREEN/RED verdict, and the "no acknowledged work lost" safety check — and each adapter supplies
// only what "correct" MEANS for its workload.
//
// The unifying principle every adapter instantiates is CONSERVATION OF ACKNOWLEDGED WORK: the
// system may drop in-flight/unacked work and may serve degraded during a fault, but it must never
// lose or corrupt what it acknowledged, and it must reconverge to a state consistent with those
// acks. "Acknowledged unit" and "consistent state" are the two things an adapter defines;
// everything else is shared.
//
// The convergence harness (the replication adapter) was the FIRST instantiation; the migration
// adapter is the second, and it is the real test of this seam — if a non-symmetric, one-way
// workload drops onto the shared runner cleanly, the framework is genuinely workload-agnostic; if
// it fights the runner, the runner was still replication-shaped and we learn that on adapter #2.

import (
	"database/sql"
	"testing"
	"time"
)

// Oracle is the contract each scenario implements. The three methods are exactly the three
// workload-specific decisions; nothing about verdicts or timing lives here.
type Oracle interface {
	// Name identifies the workload in log/verdict lines.
	Name() string

	// Drive generates work against the system under test and returns the LEDGER: the set of
	// acknowledged units that MUST be reflected once the system reaches steady state. The driver
	// is expected to tolerate the fault window (retry), so a write that never landed is simply
	// absent from the ledger — never a spurious failure. Anything in the returned map is a
	// promise the system made and must keep.
	Drive(t *testing.T) map[string]bool

	// SteadyState samples the system once and reports whether it has reconverged to this
	// workload's correctness contract (members byte-identical / target==source / …), with a
	// human-readable diff when it has not yet. A non-nil err is a transient sampling failure and
	// is treated as "not yet steady" so the poll keeps trying through the fault window.
	SteadyState() (ok bool, diff string, err error)

	// Reconcile returns the acknowledged units (from the ledger) that are NOT reflected in the
	// converged state — i.e. lost or corrupted work. Empty means every acknowledgement was
	// conserved. It runs only AFTER SteadyState has reported ok, so it reads the settled state.
	Reconcile(ledger map[string]bool) (lost []string)
}

// runOracle is the SHARED verdict engine and the single place a GREEN/RED is decided, so every
// scenario grades identically: drive the workload, poll to steady state within a bound, then
// assert conservation. (INCONCLUSIVE lives one level up, in the shell driver, where a fault that
// never fired or a starved cluster is distinguished from a real red.)
func runOracle(t *testing.T, o Oracle) {
	timeout := time.Duration(atoiEnv("CONV_TIMEOUT", 120)) * time.Second

	// Pillar: the workload runs and records what the system acknowledged.
	ledger := o.Drive(t)

	// Pillar (liveness): reconverge to the correctness contract within the bound.
	deadline := time.Now().Add(timeout)
	var lastDiff string
	converged := false
	for time.Now().Before(deadline) {
		ok, diff, err := o.SteadyState()
		if diff != "" {
			lastDiff = diff
		}
		if err == nil && ok {
			converged = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !converged {
		t.Fatalf("%s: did NOT reach steady state within %s\n%s", o.Name(), timeout, lastDiff)
	}

	// Pillar (safety): no acknowledged work lost.
	if lost := o.Reconcile(ledger); len(lost) > 0 {
		t.Fatalf("%s: LOST WORK — %d/%d acknowledged units absent after convergence (e.g. %v)",
			o.Name(), len(lost), len(ledger), firstN(lost, 10))
	}

	t.Logf("%s: STEADY — reached correctness contract with %d acknowledged units, zero lost work",
		o.Name(), len(ledger))
}

// retryWriter returns an exec closure that tolerates the fault window. Every workload driver must
// out-live the fault it is testing — a CNPG primary promotion (~4-10s) or a partition far exceeds
// a few hundred ms, and a driver that can't survive the fault produces spurious reds. Conservation
// is still asserted independently, so a write that genuinely never lands shows up as a missing
// ledger entry rather than being masked. Shared because this budget is workload-agnostic.
func retryWriter(db *sql.DB) func(q string, args ...any) error {
	retries := atoiEnv("CONV_WRITE_RETRIES", 40) // x500ms = 20s
	return func(q string, args ...any) error {
		var err error
		for i := 0; i < retries; i++ {
			if _, err = db.Exec(q, args...); err == nil {
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return err
	}
}

// firstN caps an example list for log lines (shared by every adapter's diff).
func firstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}
