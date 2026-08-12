//go:build convergence

package main

import (
	"fmt"
	"testing"
	"time"
)

// fakeProbe replays a fixed sequence of good/bad samples (then good), so continuous-mode
// grading is deterministic without a real workload or a live cluster.
type fakeProbe struct {
	name string
	seq  []bool
	i    int
}

func (f *fakeProbe) Name() string { return f.name }
func (f *fakeProbe) Probe() (bool, string) {
	ok := true
	if f.i < len(f.seq) {
		ok = f.seq[f.i]
	}
	f.i++
	if ok {
		return true, ""
	}
	return false, fmt.Sprintf("bad@%d", f.i)
}

// The verdict itself (recover's conservation check lives in runOracle; this is its tolerate/deny
// analogue) — proven to go BOTH green and red, since an oracle that has never gone red has never
// been shown it can.
func TestModeEngineGradeVerdict(t *testing.T) {
	cases := []struct {
		name      string
		r         probeResult
		threshold float64
		failFast  bool
		wantPass  bool
	}{
		{"tolerate all good", probeResult{good: 10, total: 10}, 0.90, false, true},
		{"tolerate at SLO boundary", probeResult{good: 9, total: 10}, 0.90, false, true},
		{"tolerate below SLO -> RED", probeResult{good: 8, total: 10, firstBad: "bad@3"}, 0.90, false, false},
		{"deny clean", probeResult{good: 20, total: 20}, 1.0, true, true},
		{"deny leak -> RED", probeResult{good: 5, total: 6, firstBad: "bad@6", leaked: true}, 1.0, true, false},
		{"no probes -> RED", probeResult{}, 0.90, false, false},
	}
	for _, c := range cases {
		pass, msg := gradeContinuous(c.r, c.threshold, c.failFast)
		if pass != c.wantPass {
			t.Errorf("%s: gradeContinuous pass=%v want %v (msg=%q)", c.name, pass, c.wantPass, msg)
		}
	}
}

// The sampler tallies deterministically under a probe cap, and — crucially — deny STOPS at the
// first leak (it does not keep sampling past a zero-tolerance breach).
func TestModeEngineSampler(t *testing.T) {
	far := time.Now().Add(time.Hour)

	// tolerate-style: run the full cap, count good/total, remember the first bad.
	r := sampleContinuous(&fakeProbe{name: "t", seq: []bool{true, true, false, true}}, false, far, 0, 4)
	if r.total != 4 || r.good != 3 || r.firstBad != "bad@3" || r.leaked {
		t.Fatalf("tolerate sample = %+v, want total4 good3 firstBad bad@3 leaked=false", r)
	}

	// deny-style: fail-fast stops at the first bad sample and flags leaked.
	r = sampleContinuous(&fakeProbe{name: "d", seq: []bool{true, false, true, true}}, true, far, 0, 10)
	if !r.leaked || r.total != 2 || r.good != 1 {
		t.Fatalf("deny sample = %+v, want leaked=true total2 good1 (stopped at the leak)", r)
	}
}

// End-to-end GREEN through the real engine (sample -> grade -> report): if these fatal, the mode
// engine is broken. PROBE_MAX bounds the loop and interval 0 keeps it instant.
func TestModeEngineGreenEndToEnd(t *testing.T) {
	t.Setenv("PROBE_MAX", "20")
	t.Setenv("PROBE_INTERVAL_MS", "0")
	t.Setenv("CONV_TIMEOUT", "60")

	// deny: 20 clean probes, zero leaks -> HELD.
	runDeny(t, &fakeProbe{name: "fence", seq: repeat(true, 20)})

	// tolerate: 19/20 good = 95% >= default 90% SLO -> HELD.
	seq := repeat(true, 20)
	seq[7] = false
	runTolerate(t, &fakeProbe{name: "http", seq: seq})
}

func repeat(v bool, n int) []bool {
	s := make([]bool, n)
	for i := range s {
		s[i] = v
	}
	return s
}
