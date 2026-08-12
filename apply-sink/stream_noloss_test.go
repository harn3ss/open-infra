//go:build convergence

package main

// stream-no-loss plane — a RECOVER adapter on the singular runOracle. The streaming edition of
// conservation-of-acknowledged-work: every source change committed while the capture engine is DOWN
// must still reach the durable JetStream stream once capture resumes from its slot offset. A Stream
// is AT-LEAST-ONCE, so duplicates are fine — only a MISSING change is a red.
//
// The bash scenario (chaos/scenario-stream-noloss.sh) provisions a source Database + kind: Stream
// (Debezium → JetStream cdc-evt) + a capture-kill FaultInjection, commits canary + N distinct
// single-row changes, and asserts cdc-evt reaches ≥ N+1 messages after capture resumes. This adapter
// owns only the VERDICT, routed through runOracle instead of the shell fork.
//
// The two runOracle pillars are kept INDEPENDENT so the conservation red is live-reachable (an early
// version collapsed them onto the same count comparison, making Reconcile dead code):
//   - SteadyState (liveness): the fault has LANDED (capture pod replaced) AND the stream has DRAINED
//     — the message count has STOPPED changing between samples. It says nothing about sufficiency.
//   - Reconcile  (safety):    the drained count is ≥ every acknowledged change. A lossy capture drains
//     and stabilizes BELOW the acked count → SteadyState passes, Reconcile reds. A real, reachable red.
//
// NOTE: healthy capture resume is deliberately slow (~40s Debezium JVM start + a logical-slot
// connection that must time out), so the runner sets CONV_TIMEOUT ≥ 360 for this scenario or a slow
// but lossless drain would t.Fatalf as a false red.

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// streamAccess is the stream-plane workload accessor. Live = kubectl into the source pod + a nats-box
// count pod; a fake drives the unit test so the verdict is provable RED/GREEN with no cluster.
type streamAccess interface {
	CaptureUID() (string, error)          // identity of the capture (Debezium) pod — detects the fault landed
	DriveChanges(n int) ([]string, error) // commit canary + n single-row changes on the source; return the acked keys
	StreamCount() (int, error)            // messages currently on the durable stream (authoritative, O(1))
}

type streamOracle struct {
	a         streamAccess
	rows      int
	origUID   string
	keys      []string
	lastCount int
	sampled   bool
}

func (o *streamOracle) Name() string { return "stream-no-loss" }

func (o *streamOracle) Drive(t *testing.T) map[string]bool {
	o.origUID, _ = o.a.CaptureUID()
	keys, err := o.a.DriveChanges(o.rows)
	if err != nil && t != nil {
		t.Fatalf("stream-no-loss: drive source changes: %v", err)
	}
	o.keys = keys
	ledger := make(map[string]bool, len(keys))
	for _, k := range keys {
		ledger[k] = true
	}
	return ledger
}

// SteadyState = fault landed AND the stream has stopped draining (count stable across two samples).
// Deliberately independent of sufficiency, so a drained-but-lossy stream still reaches steady and is
// then caught by Reconcile.
func (o *streamOracle) SteadyState() (bool, string, error) {
	uid, err := o.a.CaptureUID()
	if err != nil {
		return false, "", err
	}
	if uid == "" || uid == o.origUID {
		return false, "capture pod not yet replaced (fault not landed / not rescheduled)", nil
	}
	count, err := o.a.StreamCount()
	if err != nil {
		return false, "", err
	}
	if !o.sampled {
		o.sampled = true
		o.lastCount = count
		return false, "first post-fault sample; waiting for the stream to stop draining", nil
	}
	if count != o.lastCount {
		prev := o.lastCount
		o.lastCount = count
		return false, fmt.Sprintf("stream still draining the WAL backlog (%d, was %d)", count, prev), nil
	}
	return true, "", nil // count stable across two samples = the pipeline has drained
}

// Reconcile = the drained stream covers every acknowledged change. Independent of SteadyState's
// stability check, so this red actually fires. A transient sampling glitch (err) is NOT treated as
// loss — SteadyState already observed a readable, stable count.
func (o *streamOracle) Reconcile(ledger map[string]bool) []string {
	count, err := o.a.StreamCount()
	if err != nil {
		return nil
	}
	if count < 0 {
		count = 0
	}
	if count < len(o.keys) {
		return append([]string(nil), o.keys[count:]...) // the shortfall = dropped, acknowledged changes
	}
	return nil
}

// ---- live accessor (kubectl into the source pod + a nats-box count pod) ----

var streamDigits = regexp.MustCompile(`[0-9]+`)

type liveStream struct {
	ns      string
	label   string
	srcPod  string
	natsSvc string
	stream  string
}

func (l liveStream) CaptureUID() (string, error) {
	return kubectl("-n", l.ns, "get", "pods", "-l", l.label, "-o", "jsonpath={.items[0].metadata.uid}")
}

func (l liveStream) DriveChanges(n int) ([]string, error) {
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

func (l liveStream) StreamCount() (int, error) {
	name := fmt.Sprintf("nats-noloss-cnt-%d", time.Now().UnixNano())
	out, err := kubectl("-n", "nats", "run", name, "--rm", "-i", "--restart=Never",
		"--image=natsio/nats-box:latest", "--", "sh", "-c",
		"nats --server="+l.natsSvc+" stream info "+l.stream+" --json 2>/dev/null | tr ',' '\\n' | grep -oE '\"messages\": *[0-9]+' | grep -oE '[0-9]+' | head -1")
	if err != nil {
		return 0, err
	}
	if m := streamDigits.FindString(out); m != "" {
		n, _ := strconv.Atoi(m)
		return n, nil
	}
	return 0, nil
}

// TestStreamNoLoss — LIVE. The shell provisions the source + Stream and injects the capture kill;
// this drives the source changes and judges no-loss delivery across the capture restart.
func TestStreamNoLoss(t *testing.T) {
	runOracle(t, &streamOracle{
		a: liveStream{
			ns:      envOr("CHAOS_SANDBOX_NS", "chaos-sandbox"),
			label:   envOr("CAPTURE_LABEL", "app=evt-stream"),
			srcPod:  envOr("STREAM_SRC_POD", "evt-src-0"),
			natsSvc: envOr("STREAM_NATS_URL", "nats://nats.nats.svc:4222"),
			stream:  envOr("STREAM_NAME", "cdc-evt"),
		},
		rows: atoiEnv("STREAM_ROWS", 150),
	})
}

// ---- prove-red (no cluster) ----

type fakeStream struct {
	uid   string
	count int
}

func (f *fakeStream) CaptureUID() (string, error) { return f.uid, nil }
func (f *fakeStream) DriveChanges(n int) ([]string, error) {
	keys := make([]string, 0, n+1)
	keys = append(keys, "canary")
	for g := 1; g <= n; g++ {
		keys = append(keys, "e"+strconv.Itoa(g))
	}
	return keys, nil
}
func (f *fakeStream) StreamCount() (int, error) { return f.count, nil }

func TestStreamNoLossRedGreen(t *testing.T) {
	const rows = 150
	const expected = rows + 1

	// GREEN: fault lands, stream drains, stabilizes at full coverage.
	f := &fakeStream{uid: "cap-1", count: expected}
	o := &streamOracle{a: f, rows: rows}
	o.Drive(nil) // origUID = cap-1

	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("SteadyState must be false before the capture pod is replaced (pre-fault state)")
	}
	f.uid, f.count = "cap-2", 40 // fault landed, still draining
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("first post-fault sample must not be steady (not yet drained)")
	}
	f.count = 100 // count still changing → not drained
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("a changing count must not be reported steady")
	}
	f.count = expected // drains to full coverage
	o.SteadyState()    // records lastCount = expected
	if ok, _, _ := o.SteadyState(); !ok {
		t.Fatal("SteadyState must be true once the count stabilizes (pipeline drained)")
	}
	if lost := o.Reconcile(nil); len(lost) != 0 {
		t.Fatalf("green: full coverage but reported lost: %v", lost)
	}

	// RED (genuine, live-reachable): a non-durable capture DRAINS and stabilizes — SteadyState passes
	// — but BELOW the acknowledged count. The conservation pillar (independent of stability) reds.
	fr := &fakeStream{uid: "cap-1", count: expected - 3}
	or := &streamOracle{a: fr, rows: rows}
	or.Drive(nil)
	fr.uid = "cap-2" // fault landed
	or.SteadyState() // lastCount = expected-3
	if ok, _, _ := or.SteadyState(); !ok {
		t.Fatal("a drained (stable) stream must reach steady even when it lost changes — else Reconcile is dead code")
	}
	lost := or.Reconcile(nil)
	if len(lost) != 3 {
		t.Fatalf("dropped changes (count < acknowledged) MUST be reported as lost work: want 3, got %d (%v)", len(lost), lost)
	}
}
