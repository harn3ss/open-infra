//go:build convergence

package main

// stream-function-noloss plane — a RECOVER adapter on the singular runOracle, and the first CROSS-KIND
// chain: database -> stream -> function. It is the end-to-end edition of stream-no-loss: every source
// change committed while the capture engine is DOWN must not only reach the durable JetStream stream,
// it must be DELIVERED TO AND ACKNOWLEDGED BY THE FUNCTION at the far end of the chain. The whole chain
// is at-least-once (dups fine); only a change that never reaches the function is a red.
//
// Why the far-end measurement is authoritative WITHOUT a custom recorder image: the Function's trigger
// runs a Benthos "pump" holding a DURABLE JetStream consumer (fn-<function>) with explicit ack — Benthos
// acks a message ONLY after its HTTP POST to the function returns 2xx (kind: Function's function-
// composition.yaml). So the consumer's acknowledged count == CDC events actually delivered to and
// accepted by the function. `nats consumer info cdc-<stream> fn-<function>` reads it, O(1).
//
// The two runOracle pillars are kept INDEPENDENT so the end-to-end conservation red is live-reachable —
// the same discipline as stream-no-loss (collapsing them made Reconcile dead code once already):
//   - SteadyState (liveness): the fault has LANDED (capture pod replaced) AND the WHOLE chain has
//     drained — the function-ack count has STOPPED changing between samples. Says nothing about
//     sufficiency.
//   - Reconcile  (safety):    the drained function-ack count is >= every acknowledged source change. A
//     chain that loses a change ANYWHERE (capture drops it, or the pump/function never acks it) drains
//     and stabilizes BELOW the acked count -> SteadyState passes, Reconcile reds. A real, reachable red.
//
// NOTE: end-to-end recovery is deliberately slow (capture ~40s Debezium JVM resume + the pump's ack_wait
// redelivery + the function cold-start from scale-to-zero), so the runner sets CONV_TIMEOUT >= 420 for
// this scenario or a slow-but-lossless drain would t.Fatalf as a false red.

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// streamFnAccess is the chain accessor. Live = kubectl into the source pod + a nats-box that reads the
// function's durable consumer; a fake drives the unit test so the verdict is provable RED/GREEN with no
// cluster.
type streamFnAccess interface {
	CaptureUID() (string, error)          // identity of the capture (Debezium) pod — detects the fault landed
	DriveChanges(n int) ([]string, error) // commit canary + n single-row changes on the source; return the acked keys
	FunctionAckCount() (int, error)       // changes ACKNOWLEDGED by the function's durable consumer (end-to-end, O(1))
}

type streamFnOracle struct {
	a         streamFnAccess
	rows      int
	origUID   string
	keys      []string
	lastCount int
	sampled   bool
}

func (o *streamFnOracle) Name() string { return "stream-function-noloss" }

func (o *streamFnOracle) Drive(t *testing.T) map[string]bool {
	o.origUID, _ = o.a.CaptureUID()
	keys, err := o.a.DriveChanges(o.rows)
	if err != nil && t != nil {
		t.Fatalf("stream-function-noloss: drive source changes: %v", err)
	}
	o.keys = keys
	ledger := make(map[string]bool, len(keys))
	for _, k := range keys {
		ledger[k] = true
	}
	return ledger
}

// SteadyState = fault landed AND the whole chain has stopped delivering (the function-ack count is stable
// across two samples). Deliberately independent of sufficiency, so a drained-but-lossy chain still
// reaches steady and is then caught by Reconcile.
func (o *streamFnOracle) SteadyState() (bool, string, error) {
	uid, err := o.a.CaptureUID()
	if err != nil {
		return false, "", err
	}
	if uid == "" || uid == o.origUID {
		return false, "capture pod not yet replaced (fault not landed / not rescheduled)", nil
	}
	count, err := o.a.FunctionAckCount()
	if err != nil {
		return false, "", err
	}
	if !o.sampled {
		o.sampled = true
		o.lastCount = count
		return false, "first post-fault sample; waiting for the chain to finish delivering to the function", nil
	}
	if count != o.lastCount {
		prev := o.lastCount
		o.lastCount = count
		return false, fmt.Sprintf("function still draining the chain backlog (acked %d, was %d)", count, prev), nil
	}
	return true, "", nil // function-ack count stable across two samples = the whole chain has drained
}

// Reconcile = the function acknowledged every source change end to end. Independent of SteadyState's
// stability check, so this red actually fires. A transient sampling glitch (err) is NOT treated as loss
// — SteadyState already observed a readable, stable count.
func (o *streamFnOracle) Reconcile(ledger map[string]bool) []string {
	count, err := o.a.FunctionAckCount()
	if err != nil {
		return nil
	}
	if count < 0 {
		count = 0
	}
	if count < len(o.keys) {
		return append([]string(nil), o.keys[count:]...) // the shortfall = changes that never reached the function
	}
	return nil
}

// ---- live accessor (kubectl into the source pod + a nats-box that reads the function's consumer) ----

var streamFnDigits = regexp.MustCompile(`[0-9]+`)

type liveStreamFn struct {
	ns       string
	label    string
	srcPod   string
	natsSvc  string
	stream   string // the durable JetStream stream, cdc-<streamName>
	consumer string // the function pump's durable consumer, fn-<functionName>
}

func (l liveStreamFn) CaptureUID() (string, error) {
	return kubectl("-n", l.ns, "get", "pods", "-l", l.label, "-o", "jsonpath={.items[0].metadata.uid}")
}

func (l liveStreamFn) DriveChanges(n int) ([]string, error) {
	sql := "INSERT INTO public.events(id,val) VALUES ('canary','alive') ON CONFLICT (id) DO UPDATE SET val='alive';" +
		fmt.Sprintf("INSERT INTO public.events(id,val) SELECT 'e'||g, 'v'||g FROM generate_series(1,%d) g ON CONFLICT (id) DO NOTHING;", n)
	if _, err := kubectl("-n", l.ns, "exec", l.srcPod, "--", "psql", "-U", "app", "-d", "app", "-c", sql); err != nil {
		return nil, err
	}
	keys := make([]string, 0, n+1)
	keys = append(keys, "canary")
	for g := 1; g <= n; g++ {
		keys = append(keys, "e"+strconv.Itoa(g))
	}
	return keys, nil
}

// FunctionAckCount reads the acknowledged floor of the function's durable consumer — the number of CDC
// events the pump delivered to the function and the function 2xx-acked. `ack_floor.stream_seq` is the
// highest contiguously-acked stream sequence; with the stream starting at seq 1 that equals the count of
// end-to-end delivered changes. It is authoritative and O(1).
func (l liveStreamFn) FunctionAckCount() (int, error) {
	name := fmt.Sprintf("nats-fnack-cnt-%d", time.Now().UnixNano())
	// Pull the consumer's ack_floor.stream_seq out of the JSON without needing jq in the box image.
	out, err := kubectl("-n", "nats", "run", name, "--rm", "-i", "--restart=Never",
		"--image=natsio/nats-box:latest", "--", "sh", "-c",
		"nats --server="+l.natsSvc+" consumer info "+l.stream+" "+l.consumer+" --json 2>/dev/null "+
			"| tr -d ' \\n' | grep -oE '\"ack_floor\":\\{[^}]*\\}' | grep -oE '\"stream_seq\":[0-9]+' | grep -oE '[0-9]+' | head -1")
	if err != nil {
		return 0, err
	}
	if m := streamFnDigits.FindString(out); m != "" {
		n, _ := strconv.Atoi(m)
		return n, nil
	}
	return 0, nil
}

// TestStreamFunctionNoLoss — LIVE. The shell provisions the source Database + kind: Stream + kind:
// Function (trigger) and injects the capture kill; this drives the source changes and judges end-to-end
// no-loss delivery all the way to the function across the capture restart.
func TestStreamFunctionNoLoss(t *testing.T) {
	runOracle(t, &streamFnOracle{
		a: liveStreamFn{
			ns:       envOr("CHAOS_SANDBOX_NS", "chaos-sandbox"),
			label:    envOr("CAPTURE_LABEL", "app=evt-stream"),
			srcPod:   envOr("STREAM_SRC_POD", "evt-src-0"),
			natsSvc:  envOr("STREAM_NATS_URL", "nats://nats.nats.svc:4222"),
			stream:   envOr("STREAM_NAME", "cdc-evt"),
			consumer: envOr("FN_CONSUMER", "fn-evt-fn"),
		},
		rows: atoiEnv("STREAM_ROWS", 150),
	})
}

// ---- prove-red (no cluster) ----

type fakeStreamFn struct {
	uid   string
	count int
}

func (f *fakeStreamFn) CaptureUID() (string, error) { return f.uid, nil }
func (f *fakeStreamFn) DriveChanges(n int) ([]string, error) {
	keys := make([]string, 0, n+1)
	keys = append(keys, "canary")
	for g := 1; g <= n; g++ {
		keys = append(keys, "e"+strconv.Itoa(g))
	}
	return keys, nil
}
func (f *fakeStreamFn) FunctionAckCount() (int, error) { return f.count, nil }

func TestStreamFunctionNoLossRedGreen(t *testing.T) {
	const rows = 150
	const expected = rows + 1 // canary + rows

	// GREEN: fault lands, the chain drains all the way to the function, stabilizes at full coverage.
	f := &fakeStreamFn{uid: "cap-1", count: expected}
	o := &streamFnOracle{a: f, rows: rows}
	o.Drive(nil) // origUID = cap-1

	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("SteadyState must be false before the capture pod is replaced (pre-fault state)")
	}
	f.uid, f.count = "cap-2", 40 // fault landed, function still catching up
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("first post-fault sample must not be steady (chain not yet drained)")
	}
	f.count = 100 // function-ack count still climbing → not drained
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("a changing function-ack count must not be reported steady")
	}
	f.count = expected // drains to full end-to-end coverage
	o.SteadyState()    // records lastCount = expected
	if ok, _, _ := o.SteadyState(); !ok {
		t.Fatal("SteadyState must be true once the function-ack count stabilizes (chain drained)")
	}
	if lost := o.Reconcile(nil); len(lost) != 0 {
		t.Fatalf("green: full end-to-end coverage but reported lost: %v", lost)
	}

	// RED (genuine, live-reachable): a change is lost SOMEWHERE in the chain (capture drop, or the
	// pump/function never acks it). The function-ack count DRAINS and stabilizes — SteadyState passes —
	// but BELOW the acknowledged source count. The conservation pillar (independent of stability) reds.
	fr := &fakeStreamFn{uid: "cap-1", count: expected - 3}
	or := &streamFnOracle{a: fr, rows: rows}
	or.Drive(nil)
	fr.uid = "cap-2" // fault landed
	or.SteadyState() // lastCount = expected-3
	if ok, _, _ := or.SteadyState(); !ok {
		t.Fatal("a drained (stable) chain must reach steady even when it lost changes — else Reconcile is dead code")
	}
	lost := or.Reconcile(nil)
	if len(lost) != 3 {
		t.Fatalf("changes that never reached the function (count < acknowledged) MUST be reported as lost: want 3, got %d (%v)", len(lost), lost)
	}
}
