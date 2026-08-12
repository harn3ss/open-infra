//go:build convergence

package main

// The three verdict MODES of the singular oracle, so a generated chain in any plane grades
// through one engine instead of a per-scenario fork. chaos/scenarios.json already tags every
// scenario oracle.mode ∈ {recover, tolerate, deny}; runOracle (oracle_framework.go) implemented
// only recover. This adds the two CONTINUOUS modes:
//
//	recover  — the settled state AFTER the fault heals conserves every acknowledged unit
//	           (drive → poll-to-steady → reconcile). Engine: runOracle + the Oracle interface.
//	tolerate — a continuous SLO sampled THROUGHOUT the fault: good-rate stays >= threshold.
//	deny     — continuous ZERO-tolerance: a forbidden action must never succeed; the FIRST leak
//	           is an immediate red.
//
// recover judges state after heal; tolerate/deny judge a signal during the fault. The two
// continuous modes share ONE sub-engine (sampleContinuous + gradeContinuous) and differ only by
// threshold + fail-fast — the verdict machinery never forks. The verdict itself is a pure
// function (gradeContinuous) so it is unit-testable and lives in exactly one place.

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
)

// Mode mirrors oracle.mode in chaos/scenarios.json.
type Mode string

const (
	ModeRecover  Mode = "recover"
	ModeTolerate Mode = "tolerate"
	ModeDeny     Mode = "deny"
)

// ContinuousOracle is the contract for tolerate + deny: a signal sampled repeatedly during the
// fault window. Probe reports ok=true when the system is correct AT THIS INSTANT — a request
// served (tolerate) or a forbidden action blocked (deny) — with a short detail for the diff. It
// is the continuous-mode analogue of Oracle.SteadyState; the adapter still defines only what
// "correct right now" means, never the verdict or the timing.
type ContinuousOracle interface {
	Name() string
	Probe() (ok bool, detail string)
}

// probeResult is the tally sampleContinuous produces and gradeContinuous judges.
type probeResult struct {
	good, total int
	firstBad    string
	leaked      bool // a bad sample occurred while fail-fast (deny) was set
	maxStreak   int  // longest run of consecutive bad samples (endpoint-lag SLO)
}

// gradeContinuous is the PURE verdict for the continuous modes — no clock, no t, so the decision
// lives in one testable place.
//
//	tolerate: threshold = SLO (e.g. 0.90), failFast = false — some failure tolerated, rate must hold.
//	deny:     threshold = 1.0,             failFast = true  — zero-tolerance, first leak is red.
//
// streakLimit is the max tolerated run of consecutive bad samples (0 = unlimited); it catches an
// availability dip that hides inside an acceptable overall rate (a long outage the endpoints never
// recovered from within the window).
func gradeContinuous(r probeResult, threshold float64, streakLimit int, failFast bool) (pass bool, msg string) {
	if failFast && r.leaked {
		return false, fmt.Sprintf("LEAK — a forbidden action succeeded: %s (zero-tolerance)", r.firstBad)
	}
	if r.total == 0 {
		return false, "no probes taken — the fault window was never sampled"
	}
	rate := float64(r.good) / float64(r.total)
	if rate+1e-9 < threshold {
		return false, fmt.Sprintf("SLO BREACH — %.1f%% good over %d probes < %.1f%% required (first bad: %s)",
			rate*100, r.total, threshold*100, r.firstBad)
	}
	if streakLimit > 0 && r.maxStreak > streakLimit {
		return false, fmt.Sprintf("SLO BREACH — %d consecutive bad samples > %d allowed (a sustained outage inside an OK rate)",
			r.maxStreak, streakLimit)
	}
	return true, fmt.Sprintf("HELD — %.1f%% good over %d probes >= %.1f%% (longest bad streak %d ≤ %d)",
		rate*100, r.total, threshold*100, r.maxStreak, streakLimit)
}

// sampleContinuous drives the probe loop. It samples until the deadline, or (fail-fast) the first
// bad sample, or an optional probe cap (PROBE_MAX, 0 = unbounded) — the cap keeps the loop
// deterministic under test without a wall-clock dependency.
func sampleContinuous(o ContinuousOracle, failFast bool, deadline time.Time, interval time.Duration, maxProbes int) probeResult {
	var r probeResult
	streak := 0
	for time.Now().Before(deadline) {
		if maxProbes > 0 && r.total >= maxProbes {
			break
		}
		ok, detail := o.Probe()
		r.total++
		if ok {
			r.good++
			streak = 0
			continue
		}
		streak++
		if streak > r.maxStreak {
			r.maxStreak = streak
		}
		if r.firstBad == "" {
			r.firstBad = detail
		}
		if failFast {
			r.leaked = true
			break
		}
		time.Sleep(interval)
	}
	return r
}

// runContinuous is the shared t-facing engine for tolerate + deny: sample, grade, then emit the
// same GREEN/RED vocabulary the recover engine uses. The engine owns the timing; the adapter owns
// only Probe.
func runContinuous(t *testing.T, o ContinuousOracle, threshold float64, streakLimit int, failFast bool) {
	t.Helper()
	window := time.Duration(atoiEnv("CONV_TIMEOUT", 120)) * time.Second
	interval := time.Duration(atoiEnv("PROBE_INTERVAL_MS", 500)) * time.Millisecond
	maxProbes := atoiEnv("PROBE_MAX", 0)
	r := sampleContinuous(o, failFast, time.Now().Add(window), interval, maxProbes)
	pass, msg := gradeContinuous(r, threshold, streakLimit, failFast)
	if !pass {
		t.Fatalf("%s: %s", o.Name(), msg)
	}
	t.Logf("%s: %s (zero-tolerance=%v)", o.Name(), msg, failFast)
}

// runTolerate grades a continuous SLO: good-rate ≥ CHAOS_SLO (default 90%) AND no bad streak longer
// than CHAOS_MAX_STREAK (default 0 = unlimited).
func runTolerate(t *testing.T, o ContinuousOracle) {
	runContinuous(t, o, floatEnv("CHAOS_SLO", 0.90), atoiEnv("CHAOS_MAX_STREAK", 0), false)
}

// runDeny grades continuous zero-tolerance: a forbidden action must never succeed.
func runDeny(t *testing.T, o ContinuousOracle) {
	runContinuous(t, o, 1.0, 0, true)
}

// floatEnv reads a float fraction from the environment (companion to atoiEnv).
func floatEnv(k string, d float64) float64 {
	if v := os.Getenv(k); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return d
}
