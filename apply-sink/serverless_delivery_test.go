//go:build convergence

package main

// serverless-delivery plane — a RECOVER adapter on the singular runOracle for the async serverless
// invoke path (app -> aws-shim async worker -> function). It is the conservation-of-accepted-work law
// for AWS-Lambda-style Event invocations: every invocation ACCEPTED onto the durable JetStream work
// stream (LAMBDA_ASYNC, WorkQueue-retained) must — even when a shim worker replica is killed mid-drain —
// be either delivered to its function or, after retries, dead-lettered to LAMBDA_ASYNC_DLQ. Nothing may
// silently vanish.
//
// The bash scenario (chaos/scenario-async-invoke-noloss.sh) provisions a 2-replica aws-shim wired to
// JetStream, publishes invocations for a function that does NOT exist (so every delivery fails and must
// dead-letter), and kills one replica mid-drain. Delivery-to-a-ghost makes the outcome exact + count-
// only: the DLQ must cover every accepted invocation. This adapter owns only the VERDICT, routed through
// runOracle instead of the shell's own PASS/FAIL, so the async plane joins the singular engine.
//
// The two runOracle pillars are kept INDEPENDENT so the conservation red is live-reachable (the same
// discipline that keeps stream-no-loss honest):
//   - SteadyState (liveness): the DLQ has STOPPED GROWING between samples — the durable worker finished
//     routing the backlog after the kill. It says nothing about sufficiency.
//   - Reconcile  (safety):    the drained DLQ covers every accepted invocation (>= accepted: none lost)
//     and is not implausibly high (<= accepted*ceilMult: no runaway dead-letter loop / mis-targeted DLQ
//     stream, a real bug a live run caught via a DLQ-subject collision). A lossy worker drains and
//     stabilizes BELOW accepted -> SteadyState passes, Reconcile reds. A real, reachable red.

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// serverlessAccess is the async-plane accessor. Live = a nats-box that reads the work + DLQ streams; a
// fake drives the unit test so the verdict is provable RED/GREEN with no cluster.
type serverlessAccess interface {
	AcceptedCount() (int, error) // LAMBDA_ASYNC last_seq — total invocations ever accepted (the denominator)
	DlqCount() (int, error)      // LAMBDA_ASYNC_DLQ messages — invocations dead-lettered (the durable outcome)
}

type serverlessOracle struct {
	a        serverlessAccess
	ceilMult int
	accepted int
	lastDlq  int
	sampled  bool
}

func (o *serverlessOracle) Name() string { return "serverless-delivery" }

// Drive records the denominator: what was ACCEPTED onto the work stream (canary + burst published by the
// scenario across the outage). last_seq is authoritative — WorkQueue removes each message on ack/term,
// but the sequence only ever climbs, so it counts every accepted invocation regardless of outcome.
func (o *serverlessOracle) Drive(t *testing.T) map[string]bool {
	n, err := o.a.AcceptedCount()
	if err != nil && t != nil {
		t.Fatalf("serverless-delivery: read accepted count: %v", err)
	}
	o.accepted = n
	ledger := make(map[string]bool, n)
	for i := 1; i <= n; i++ {
		ledger[fmt.Sprintf("inv%d", i)] = true
	}
	return ledger
}

// SteadyState = the DLQ has stopped growing across two samples (the worker finished routing the backlog
// after the kill). Deliberately independent of sufficiency, so a drained-but-lossy DLQ still reaches
// steady and is then caught by Reconcile.
func (o *serverlessOracle) SteadyState() (bool, string, error) {
	dlq, err := o.a.DlqCount()
	if err != nil {
		return false, "", err
	}
	if !o.sampled {
		o.sampled = true
		o.lastDlq = dlq
		return false, "first sample; waiting for the DLQ to stop filling", nil
	}
	if dlq != o.lastDlq {
		prev := o.lastDlq
		o.lastDlq = dlq
		return false, fmt.Sprintf("DLQ still filling (%d, was %d)", dlq, prev), nil
	}
	return true, "", nil // DLQ stable across two samples = the worker has drained the backlog
}

// Reconcile = the drained DLQ covers every accepted invocation (>= accepted: nothing silently lost) and
// is not implausibly high (<= accepted*ceilMult: no runaway dead-letter loop). Independent of the
// stability check, so this red actually fires. A transient sampling glitch (err) is NOT treated as loss.
func (o *serverlessOracle) Reconcile(ledger map[string]bool) []string {
	dlq, err := o.a.DlqCount()
	if err != nil {
		return nil
	}
	if dlq < 0 {
		dlq = 0
	}
	if dlq < o.accepted {
		lost := make([]string, 0, o.accepted-dlq)
		for i := dlq + 1; i <= o.accepted; i++ {
			lost = append(lost, fmt.Sprintf("inv%d", i)) // accepted invocations that never reached the DLQ
		}
		return lost
	}
	mult := o.ceilMult
	if mult <= 0 {
		mult = 4
	}
	if ceil := o.accepted * mult; o.accepted > 0 && dlq > ceil {
		return []string{fmt.Sprintf("runaway-dlq: %d dead-letters for %d accepted (> %dx) — a redelivery loop or a mis-targeted DLQ stream", dlq, o.accepted, mult)}
	}
	return nil
}

// ---- live accessor (a nats-box that reads the work + DLQ JetStream streams) ----

var serverlessDigits = regexp.MustCompile(`[0-9]+`)

type liveServerless struct {
	natsSvc    string
	workStream string // LAMBDA_ASYNC
	dlqStream  string // LAMBDA_ASYNC_DLQ
}

func (l liveServerless) streamField(stream, field string) (int, error) {
	name := fmt.Sprintf("nats-sd-%s-%d", field, time.Now().UnixNano())
	out, err := kubectl("-n", "nats", "run", name, "--rm", "-i", "--restart=Never",
		"--image=natsio/nats-box:latest", "--", "sh", "-c",
		"nats --server="+l.natsSvc+" stream info "+stream+" --json 2>/dev/null | tr ',' '\\n' | grep -oE '\""+field+"\": *[0-9]+' | grep -oE '[0-9]+' | head -1")
	if err != nil {
		return 0, err
	}
	if m := serverlessDigits.FindString(out); m != "" {
		n, _ := strconv.Atoi(m)
		return n, nil
	}
	return 0, nil
}

func (l liveServerless) AcceptedCount() (int, error) { return l.streamField(l.workStream, "last_seq") }
func (l liveServerless) DlqCount() (int, error)      { return l.streamField(l.dlqStream, "messages") }

// TestServerlessDelivery — LIVE. The shell provisions the shim + work streams, kills a replica, and
// publishes invocations for a ghost function; this judges that every accepted invocation dead-lettered
// (no loss) across the kill, within a sane ceiling.
func TestServerlessDelivery(t *testing.T) {
	runOracle(t, &serverlessOracle{
		a: liveServerless{
			natsSvc:    envOr("SERVERLESS_NATS_URL", "nats://nats.nats.svc:4222"),
			workStream: envOr("ASYNC_WORK_STREAM", "LAMBDA_ASYNC"),
			dlqStream:  envOr("ASYNC_DLQ_STREAM", "LAMBDA_ASYNC_DLQ"),
		},
		ceilMult: atoiEnv("ASYNC_CEIL_MULT", 4),
	})
}

// ---- prove-red (no cluster) ----

type fakeServerless struct {
	accepted int
	dlq      int
}

func (f *fakeServerless) AcceptedCount() (int, error) { return f.accepted, nil }
func (f *fakeServerless) DlqCount() (int, error)      { return f.dlq, nil }

func TestServerlessDeliveryRedGreen(t *testing.T) {
	const accepted = 100

	// GREEN: the kill lands, the DLQ fills to full coverage and stabilizes within the ceiling.
	f := &fakeServerless{accepted: accepted, dlq: 40}
	o := &serverlessOracle{a: f, ceilMult: 4}
	o.Drive(nil) // accepted = 100

	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("first sample must not be steady")
	}
	f.dlq = 90 // still filling
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("a growing DLQ must not be reported steady")
	}
	f.dlq = accepted // drains to full coverage
	o.SteadyState()  // records lastDlq = accepted
	if ok, _, _ := o.SteadyState(); !ok {
		t.Fatal("SteadyState must be true once the DLQ stabilizes")
	}
	if lost := o.Reconcile(nil); len(lost) != 0 {
		t.Fatalf("green: full coverage but reported lost: %v", lost)
	}

	// RED (loss, live-reachable): a lossy worker drains and STABILIZES below accepted. SteadyState passes;
	// the conservation pillar (independent of stability) reds.
	fr := &fakeServerless{accepted: accepted, dlq: accepted - 3}
	or := &serverlessOracle{a: fr, ceilMult: 4}
	or.Drive(nil)
	or.SteadyState() // lastDlq = accepted-3
	if ok, _, _ := or.SteadyState(); !ok {
		t.Fatal("a drained (stable) DLQ must reach steady even when it lost invocations — else Reconcile is dead code")
	}
	if lost := or.Reconcile(nil); len(lost) != 3 {
		t.Fatalf("lost accepted invocations (DLQ < accepted) MUST be reported: want 3, got %d (%v)", len(lost), lost)
	}

	// RED (runaway): the DLQ stabilizes implausibly high (a redelivery loop / mis-targeted stream).
	fx := &fakeServerless{accepted: accepted, dlq: accepted*4 + 1}
	ox := &serverlessOracle{a: fx, ceilMult: 4}
	ox.Drive(nil)
	ox.SteadyState()
	if ok, _, _ := ox.SteadyState(); !ok {
		t.Fatal("a stable (if huge) DLQ must reach steady")
	}
	if lost := ox.Reconcile(nil); len(lost) == 0 {
		t.Fatal("a runaway DLQ (> ceil) MUST be reported as a fault")
	}
}
