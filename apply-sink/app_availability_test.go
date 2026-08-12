//go:build convergence

package main

// app-availability plane — the TOLERATE mode reference adapter. A continuous SLO measured DURING the
// fault: does the Service keep serving 2xx while a replica is killed? The verdict is the singular
// mode engine (runTolerate): red if the success rate drops below CHAOS_SLO or a bad streak exceeds
// CHAOS_MAX_STREAK. The shell scenario provisions the HA app + prober, injects the replica kill, and
// proves-fire; this adapter owns only the VERDICT.

import (
	"os/exec"
	"testing"
	"time"
)

// appOracle is a ContinuousOracle whose Probe is one availability sample. Injectable so the verdict
// is unit-provable without the cluster.
type appOracle struct {
	name  string
	probe func() (bool, string)
}

func (o *appOracle) Name() string          { return o.name }
func (o *appOracle) Probe() (bool, string) { return o.probe() }

// TestAppAvailability — LIVE. The app's NetworkPolicy denies off-cluster ingress, so it must be
// probed from the in-namespace prober pod (that the probe succeeds is itself the allow-path working).
func TestAppAvailability(t *testing.T) {
	ns := envOr("CHAOS_SANDBOX_NS", "chaos-sandbox")
	prober := envOr("AVAIL_PROBER", "avail-prober")
	url := envOr("APP_URL", "http://web/")
	o := &appOracle{name: "app-availability", probe: func() (bool, string) {
		if exec.Command("kubectl", "-n", ns, "exec", prober, "--",
			"curl", "-sf", "-m", "2", "-o", "/dev/null", url).Run() == nil {
			return true, ""
		}
		return false, "app returned non-2xx / unreachable"
	}}
	runTolerate(t, o) // rate >= CHAOS_SLO and no bad streak > CHAOS_MAX_STREAK
}

// TestAppAvailabilityRedGreen — PROVE-RED (no cluster). The adapter must go both green and red: a
// mostly-up app passes; a low success rate reds; and a sustained outage streak reds even when the
// overall rate is at the SLO (the availability dip an averaged rate would hide).
func TestAppAvailabilityRedGreen(t *testing.T) {
	far := time.Now().Add(time.Hour)
	replay := func(seq []bool) *appOracle {
		i := 0
		return &appOracle{name: "app", probe: func() (bool, string) {
			ok := true
			if i < len(seq) {
				ok = seq[i]
			}
			i++
			if ok {
				return true, ""
			}
			return false, "down"
		}}
	}

	// GREEN: 19/20 up (95% ≥ 90%), no streak > 4.
	g := repeat(true, 20)
	g[5] = false
	if pass, msg := gradeContinuous(sampleContinuous(replay(g), false, far, 0, 20), 0.90, 4, false); !pass {
		t.Fatalf("healthy app should PASS: %s", msg)
	}

	// RED (rate): 10/20 up = 50% < 90%.
	b := repeat(true, 20)
	for i := 0; i < 10; i++ {
		b[i] = false
	}
	if pass, _ := gradeContinuous(sampleContinuous(replay(b), false, far, 0, 20), 0.90, 4, false); pass {
		t.Fatal("app at 50% success must RED")
	}

	// RED (streak): 45/50 = 90% overall, but a 5-long consecutive outage > 4 allowed.
	s := repeat(true, 50)
	for i := 10; i < 15; i++ {
		s[i] = false
	}
	if pass, _ := gradeContinuous(sampleContinuous(replay(s), false, far, 0, 50), 0.90, 4, false); pass {
		t.Fatal("a 5-sample sustained outage must RED even at a 90% overall rate")
	}
}
