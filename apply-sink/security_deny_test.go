//go:build convergence

package main

// security-deny plane — the DENY mode reference adapter. A NEGATIVE invariant verified continuously
// with ZERO tolerance: while the forbidden destination churns under a fault, an egress-locked client
// must NEVER reach it. Where recover checks state after healing and tolerate allows a small SLO
// breach, a security fence may not leak even once — the FIRST fail-open is an immediate red.
//
// The bash scenario (chaos/scenario-security-deny.sh) provisions svc-allowed + svc-forbidden + the
// two SecurityGroups (svc-tier / client-egress), deploys the egress-locked deny-prober, and churns
// svc-forbidden (pod-kill all). It samples BOTH targets; the positive-control / proof-of-fire /
// INCONCLUSIVE bookkeeping stays in the shell driver (one level up). This adapter owns only the
// VERDICT on the negative invariant, routed through the singular engine (runDeny), and probes the
// SAME forbidden action the scenario does: can the locked prober curl svc-forbidden?

import (
	"testing"
	"time"
)

// denyAccess is the security-deny workload accessor — the single injectable seam. It exposes only
// the one operation the verdict needs: from the egress-locked prober, is the forbidden destination
// reachable? Live = kubectl exec curl; a fake drives the unit tests so the verdict is provable
// RED/GREEN with no cluster.
type denyAccess interface {
	// ForbiddenReachable reports whether the egress-locked client can reach the forbidden target.
	// true = the fence failed open (a leak); false = the connection was denied (the fence held).
	ForbiddenReachable() bool
}

// denyOracle is a ContinuousOracle whose Probe is one sample of the negative invariant. Probe
// returns ok=TRUE when the forbidden action is BLOCKED and ok=FALSE (a leak) when it unexpectedly
// SUCCEEDS — exactly the signal runDeny grades with zero tolerance.
type denyOracle struct {
	a denyAccess
}

func (o *denyOracle) Name() string { return "security-deny" }

func (o *denyOracle) Probe() (bool, string) {
	if o.a.ForbiddenReachable() {
		return false, "egress fence LEAKED — the locked client reached svc-forbidden (fail-open)"
	}
	return true, ""
}

// ---- live accessor (kubectl exec curl from the egress-locked prober) ----

type liveDeny struct {
	ns      string
	prober  string
	url     string // the forbidden target the fence must deny
	timeout string // curl -m; a denied connect just hangs to this deadline, so keep it short
}

func (l liveDeny) ForbiddenReachable() bool {
	return kubectlOK("-n", l.ns, "exec", l.prober, "--",
		"curl", "-sf", "-m", l.timeout, "-o", "/dev/null", l.url)
}

// TestSecurityDeny — LIVE. The shell provisions the deny chain and churns svc-forbidden; this
// samples the forbidden action continuously from the egress-locked prober and grades zero-tolerance
// via runDeny (the first leak is red).
func TestSecurityDeny(t *testing.T) {
	o := &denyOracle{a: liveDeny{
		ns:      envOr("CHAOS_SANDBOX_NS", "chaos-sandbox"),
		prober:  envOr("DENY_PROBER", "deny-prober"),
		url:     envOr("FORBIDDEN_URL", "http://svc-forbidden/"),
		timeout: envOr("DENY_FORBIDDEN_TIMEOUT", "1"),
	}}
	runDeny(t, o) // zero-tolerance: any success reaching the forbidden target is an immediate red
}

// ---- prove-red (no cluster) ----

// fakeDeny replays a scripted reachability sequence: reach[i] is whether the forbidden target was
// reachable on probe i (true = the fence leaked on that sample).
type fakeDeny struct {
	reach []bool
	i     int
}

func (f *fakeDeny) ForbiddenReachable() bool {
	r := false
	if f.i < len(f.reach) {
		r = f.reach[f.i]
	}
	f.i++
	return r
}

// TestSecurityDenyRedGreen — PROVE-RED (no cluster). The adapter must go both green and red: a fence
// that denies every probe passes; a fence that reaches the forbidden target even ONCE reds. The red
// is genuine — a single reachable sample is exactly a fail-open, the real product failure this plane
// exists to catch — not a tautology.
func TestSecurityDenyRedGreen(t *testing.T) {
	far := time.Now().Add(time.Hour)

	// GREEN: the forbidden target is never reachable across the whole window — the fence held.
	green := &denyOracle{a: &fakeDeny{reach: repeat(false, 20)}}
	if pass, msg := gradeContinuous(sampleContinuous(green, true, far, 0, 20), 1.0, 0, true); !pass {
		t.Fatalf("a holding egress fence should PASS: %s", msg)
	}

	// RED: the fence held for a stretch but leaked once mid-churn — a single fail-open is red under
	// zero tolerance. sampleContinuous (fail-fast) stops at that first leak and marks it leaked.
	leaky := repeat(false, 20)
	leaky[7] = true // the locked client reached svc-forbidden on probe 8
	if pass, _ := gradeContinuous(sampleContinuous(&denyOracle{a: &fakeDeny{reach: leaky}}, true, far, 0, 20), 1.0, 0, true); pass {
		t.Fatal("a single leak (the fence failing open once during the churn) MUST RED")
	}
}
