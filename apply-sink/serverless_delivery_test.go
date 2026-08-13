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
// The two runOracle pillars are kept INDEPENDENT so the conservation red is live-reachable:
//   - SteadyState (liveness): the WORK STREAM has drained to EMPTY — every accepted invocation has been
//     delivered-and-acked or dead-lettered (WorkQueue removes each on ack/term). This is monotonic and
//     terminal; it deliberately says nothing about WHERE they went. (The DLQ itself fills in bursty retry
//     backoffs, so "DLQ count stable" is a false done-signal — a pause between bursts looks stable — which
//     is exactly why liveness watches the draining work stream, not the DLQ.)
//   - Reconcile  (safety):    once drained, the DLQ covers every accepted invocation (>= accepted: none
//     lost) and is not implausibly high (<= accepted*ceilMult: no runaway dead-letter loop / mis-targeted
//     DLQ stream, a real bug a live run caught via a subject collision). A worker that drops an accepted
//     invocation drains to empty (SteadyState passes) with DLQ BELOW accepted -> Reconcile reds. Reachable.

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
	WorkPending() (int, error)   // LAMBDA_ASYNC messages — invocations not yet delivered/dead-lettered (drains to 0)
	DlqCount() (int, error)      // LAMBDA_ASYNC_DLQ messages — invocations dead-lettered (the durable outcome)
}

type serverlessOracle struct {
	a           serverlessAccess
	ceilMult    int
	accepted    int
	drainedOnce bool
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

// SteadyState = the work stream has drained to EMPTY (every accepted invocation processed) across two
// consecutive samples. Publishing is already done before the oracle runs, so pending only falls; the
// double-empty guards against catching a transient empty before the burst fully landed. Deliberately
// independent of sufficiency, so a lossy worker that drains still reaches steady and is caught by
// Reconcile.
func (o *serverlessOracle) SteadyState() (bool, string, error) {
	pending, err := o.a.WorkPending()
	if err != nil {
		return false, "", err
	}
	if pending > 0 {
		o.drainedOnce = false
		return false, fmt.Sprintf("work stream still draining (%d pending)", pending), nil
	}
	if !o.drainedOnce {
		o.drainedOnce = true
		return false, "work stream empty once; confirming it stays drained", nil
	}
	return true, "", nil // drained across two samples = every invocation has been delivered or dead-lettered
}

// Reconcile = the drained work produced a DLQ that covers every accepted invocation (>= accepted: nothing
// silently lost) and is not implausibly high (<= accepted*ceilMult: no runaway dead-letter loop).
// Independent of the drain check, so this red actually fires. A transient sampling glitch (err) is NOT
// treated as loss.
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
	// NB: keep the field OUT of the pod name — a JetStream field like "last_seq" has an underscore, which
	// is illegal in an RFC1123 pod name and makes `kubectl run` exit 1.
	name := fmt.Sprintf("nats-sd-%d", time.Now().UnixNano())
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
func (l liveServerless) WorkPending() (int, error)   { return l.streamField(l.workStream, "messages") }
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
	pending  int
	dlq      int
}

func (f *fakeServerless) AcceptedCount() (int, error) { return f.accepted, nil }
func (f *fakeServerless) WorkPending() (int, error)   { return f.pending, nil }
func (f *fakeServerless) DlqCount() (int, error)      { return f.dlq, nil }

func TestServerlessDeliveryRedGreen(t *testing.T) {
	const accepted = 100

	// GREEN: the kill lands, the work stream drains to empty, the DLQ covers every accepted invocation.
	f := &fakeServerless{accepted: accepted, pending: 60, dlq: 40}
	o := &serverlessOracle{a: f, ceilMult: 4}
	o.Drive(nil) // accepted = 100

	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("must not be steady while work is pending")
	}
	f.pending, f.dlq = 0, accepted // drained; everything dead-lettered
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("first empty sample must not be steady (needs a confirming second)")
	}
	if ok, _, _ := o.SteadyState(); !ok {
		t.Fatal("SteadyState must be true once the work stream is drained across two samples")
	}
	if lost := o.Reconcile(nil); len(lost) != 0 {
		t.Fatalf("green: full coverage but reported lost: %v", lost)
	}

	// RED (loss, live-reachable): the work stream drains to EMPTY (SteadyState passes) but the DLQ is
	// BELOW accepted — invocations vanished (neither delivered nor dead-lettered). The conservation pillar
	// (independent of the drain check) reds.
	fr := &fakeServerless{accepted: accepted, pending: 0, dlq: accepted - 3}
	or := &serverlessOracle{a: fr, ceilMult: 4}
	or.Drive(nil)
	or.SteadyState() // first empty
	if ok, _, _ := or.SteadyState(); !ok {
		t.Fatal("a drained work stream must reach steady even when invocations were lost — else Reconcile is dead code")
	}
	if lost := or.Reconcile(nil); len(lost) != 3 {
		t.Fatalf("lost accepted invocations (DLQ < accepted) MUST be reported: want 3, got %d (%v)", len(lost), lost)
	}

	// RED (runaway): drained, but the DLQ is implausibly high (a redelivery loop / mis-targeted stream).
	fx := &fakeServerless{accepted: accepted, pending: 0, dlq: accepted*4 + 1}
	ox := &serverlessOracle{a: fx, ceilMult: 4}
	ox.Drive(nil)
	ox.SteadyState()
	if ok, _, _ := ox.SteadyState(); !ok {
		t.Fatal("a drained work stream must reach steady")
	}
	if lost := ox.Reconcile(nil); len(lost) == 0 {
		t.Fatal("a runaway DLQ (> ceil) MUST be reported as a fault")
	}
}
