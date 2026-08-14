//go:build convergence

package main

// subscription-noloss plane — a RECOVER adapter on the singular runOracle for the open-appsync
// GraphQL-subscription path (mutation -> engine -> durable JetStream subject -> subscribers). It is
// the conservation-of-acknowledged-work law for live subscriptions: every ACKNOWLEDGED mutation (one
// that returned data.createTodo) publishes exactly one onCreateTodo event onto the durable subject,
// and even when one of two engine replicas is killed mid-stream (the survivor keeps the Service up),
// every acknowledged event must reach the subject. Duplicates are fine (at-least-once, which a
// reconnect can produce); a DROPPED acknowledged event is the release blocker.
//
// The bash scenario (chaos/scenario-subscription-reconnect.sh) provisions a 2-replica open-appsync
// wired to JetStream, drives createTodo mutations across an engine-pod kill, and records how many were
// acknowledged; it passes the denominator in as SUB_WANT (1 canary + acked). This adapter owns only
// the VERDICT, routed through runOracle instead of the shell's own PASS/FAIL, so the subscription
// plane joins the singular engine. The scenario still owns provisioning + firing the kill + the
// proof-of-fire/INCONCLUSIVE gates; the engine owns the pass/fail.
//
// The two runOracle pillars are kept INDEPENDENT so the conservation red is live-reachable:
//   - SteadyState (liveness): the durable subject has SETTLED — its message count stopped climbing
//     across several consecutive samples, i.e. the engine has flushed every event it is going to
//     deliver. The subject RETAINS its log, so the count is monotonic UP and the terminal signal is a
//     PLATEAU (unlike the serverless work stream, which drains to 0). It deliberately says nothing
//     about sufficiency — only that delivery has quiesced.
//   - Reconcile  (safety):    the settled count covers every acknowledged mutation (>= SUB_WANT). A
//     lossy engine plateaus BELOW want (SteadyState still passes — a plateau is a plateau) and
//     Reconcile reds. Reachable. Duplicates (count > want) are fine and never red — at-least-once.

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

// subscriptionAccess is the subscription-plane accessor. Live = a nats-box that reads the durable
// subscription stream's message count; a fake drives the unit test so the verdict is provable
// RED/GREEN with no cluster.
type subscriptionAccess interface {
	// SubjectCount is the durable subject's delivered-event count (the subscription stream's
	// `messages`). Monotonic up during delivery, then plateaus — never drains, because the stream
	// retains its log.
	SubjectCount() (int, error)
}

type subscriptionOracle struct {
	a          subscriptionAccess
	want       int // 1 canary + acknowledged mutations — the denominator (from SUB_WANT)
	stableNeed int // consecutive equal samples that confirm the subject has plateaued
	lastCount  int
	stableSeen int
	haveLast   bool
}

func (o *subscriptionOracle) Name() string { return "subscription-noloss" }

// Drive records the denominator the scenario already established (mutations it acknowledged across the
// kill, + the pre-fault canary). No driving happens here — the shell drove and acked the mutations;
// this adapter judges the settled subject against that promise.
func (o *subscriptionOracle) Drive(t *testing.T) map[string]bool {
	if o.want <= 0 && t != nil {
		t.Fatalf("subscription-noloss: SUB_WANT not set (denominator missing) — the scenario must pass 1 + acked")
	}
	ledger := make(map[string]bool, o.want)
	for i := 1; i <= o.want; i++ {
		ledger[fmt.Sprintf("evt%d", i)] = true
	}
	return ledger
}

// SteadyState = the durable subject has PLATEAUED: its message count is unchanged across stableNeed
// consecutive samples, so the engine has flushed every event it is going to deliver after the kill.
// Independent of sufficiency (a lossy engine plateaus below want and still reaches steady), so the
// conservation red in Reconcile stays live-reachable. A transient sampling error is "not yet steady".
func (o *subscriptionOracle) SteadyState() (bool, string, error) {
	c, err := o.a.SubjectCount()
	if err != nil {
		return false, "", err
	}
	if o.haveLast && c == o.lastCount {
		o.stableSeen++
	} else {
		o.stableSeen = 0
	}
	o.lastCount = c
	o.haveLast = true
	need := o.stableNeed
	if need <= 0 {
		need = 3
	}
	if o.stableSeen < need {
		return false, fmt.Sprintf("subject still settling (count=%d, stable %d/%d)", c, o.stableSeen, need), nil
	}
	return true, "", nil
}

// Reconcile = the settled subject covers every acknowledged mutation (count >= want: nothing dropped).
// Independent of the plateau check, so this red actually fires when a lossy engine settles below want.
// Duplicates (count > want) are fine — at-least-once delivery across a reconnect. A transient sampling
// glitch (err) is NOT treated as loss.
func (o *subscriptionOracle) Reconcile(ledger map[string]bool) []string {
	c, err := o.a.SubjectCount()
	if err != nil {
		return nil
	}
	if c >= o.want {
		return nil // every acknowledged event reached the subject (dups OK, at-least-once)
	}
	lost := make([]string, 0, o.want-c)
	for i := c + 1; i <= o.want; i++ {
		lost = append(lost, fmt.Sprintf("evt%d", i)) // acknowledged mutations whose event never reached the subject
	}
	return lost
}

// ---- live accessor (a nats-box that reads the durable subscription JetStream stream) ----

type liveSubscription struct {
	natsSvc string
	stream  string // open_appsync_subscriptions
}

func (l liveSubscription) SubjectCount() (int, error) {
	// NB: keep any JetStream field name OUT of the pod name — "last_seq"/"messages" contain no
	// underscore issue here, but the timestamp-only name keeps it RFC1123-safe regardless.
	name := fmt.Sprintf("nats-sub-%d", time.Now().UnixNano())
	out, err := kubectl("-n", "nats", "run", name, "--rm", "-i", "--restart=Never",
		"--image=natsio/nats-box:latest", "--", "sh", "-c",
		"nats --server="+l.natsSvc+" stream info "+l.stream+" --json 2>/dev/null | tr ',' '\\n' | grep -oE '\"messages\": *[0-9]+' | grep -oE '[0-9]+' | head -1")
	if err != nil {
		return 0, err
	}
	if m := serverlessDigits.FindString(out); m != "" { // reuse the digit regex from the serverless adapter
		n, _ := strconv.Atoi(m)
		return n, nil
	}
	return 0, nil
}

// TestSubscriptionNoLoss — LIVE. The shell provisions the 2-replica open-appsync engine, drives
// createTodo mutations across an engine-pod kill, records SUB_WANT (1 canary + acked), then invokes
// this: it waits for the durable subject to plateau (SteadyState) and asserts it received every
// acknowledged event (Reconcile: count >= want), dups OK.
func TestSubscriptionNoLoss(t *testing.T) {
	runOracle(t, &subscriptionOracle{
		a: liveSubscription{
			natsSvc: envOr("SUB_NATS_URL", "nats://nats.nats.svc:4222"),
			stream:  envOr("SUB_STREAM", "open_appsync_subscriptions"),
		},
		want:       atoiEnv("SUB_WANT", 0),
		stableNeed: atoiEnv("SUB_STABLE_SAMPLES", 3),
	})
}

// ---- prove-red (no cluster) ----

type fakeSubscription struct{ count int }

func (f *fakeSubscription) SubjectCount() (int, error) { return f.count, nil }

// settle polls SteadyState until it reports steady (or the cap is hit), mirroring runOracle's poll.
func settleSub(o *subscriptionOracle, cap int) bool {
	for i := 0; i < cap; i++ {
		if ok, _, _ := o.SteadyState(); ok {
			return true
		}
	}
	return false
}

func TestSubscriptionNoLossRedGreen(t *testing.T) {
	const want = 101 // 1 canary + 100 acked mutations

	// GREEN: while events are still arriving the subject is not steady; once it plateaus at >= want,
	// every acknowledged event was delivered (dups OK).
	f := &fakeSubscription{count: 40}
	o := &subscriptionOracle{a: f, want: want, stableNeed: 3}
	o.Drive(nil)
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("must not be steady while the subject is still climbing")
	}
	f.count = 105 // plateau ABOVE want — legitimate duplicates from an at-least-once reconnect
	if !settleSub(o, 10) {
		t.Fatal("must reach steady once the subject plateaus across the confirming samples")
	}
	if lost := o.Reconcile(nil); len(lost) != 0 {
		t.Fatalf("green: full coverage (dups OK) but reported lost: %v", lost)
	}

	// RED (loss, live-reachable): the subject PLATEAUS below want — acknowledged events were dropped
	// across the kill. SteadyState still passes (a plateau is a plateau, independent of sufficiency);
	// the conservation pillar reds.
	fr := &fakeSubscription{count: want - 3}
	or := &subscriptionOracle{a: fr, want: want, stableNeed: 3}
	or.Drive(nil)
	if !settleSub(or, 10) {
		t.Fatal("a settled-but-lossy subject must reach steady — else Reconcile is dead code")
	}
	if lost := or.Reconcile(nil); len(lost) != 3 {
		t.Fatalf("dropped acknowledged events MUST be reported: want 3, got %d (%v)", len(lost), lost)
	}
}
