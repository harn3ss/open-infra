package cfn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// memSignals is a SignalSource the test feeds.
type memSignals struct {
	mu   sync.Mutex
	sigs map[string][]Signal // logical id -> signals
	// onRead, if set, runs on every read (to deliver a signal "later").
	onRead func(id string, reads int)
	reads  map[string]int
}

func (m *memSignals) Signals(_ context.Context, _, id string) ([]Signal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reads == nil {
		m.reads = map[string]int{}
	}
	m.reads[id]++
	if m.onRead != nil {
		m.mu.Unlock()
		m.onRead(id, m.reads[id])
		m.mu.Lock()
	}
	return append([]Signal(nil), m.sigs[id]...), nil
}

func (m *memSignals) send(id string, s Signal) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sigs == nil {
		m.sigs = map[string][]Signal{}
	}
	m.sigs[id] = append(m.sigs[id], s)
}

func fastSignals(t *testing.T) {
	t.Helper()
	prev := signalPollInterval
	signalPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { signalPollInterval = prev })
}

const signalInstanceTmpl = `
Resources:
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: web }
  Web:
    Type: AWS::EC2::Instance
    CreationPolicy: { ResourceSignal: { Count: 2, Timeout: PT1M } }
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref SG ] }
  After:
    Type: AWS::SSM::Parameter
    DependsOn: Web
    Properties: { Name: /after, Type: String, Value: x }
`

// A CreationPolicy ResourceSignal holds the resource (and everything after it) until Count SUCCESS
// signals with distinct UniqueIds arrive.
func TestSignals_CreationPolicyWaitsForCount(t *testing.T) {
	fastSignals(t)
	sigs := &memSignals{}
	var f *fakeApplier
	sigs.onRead = func(id string, reads int) {
		if id != "Web" {
			return
		}
		for _, a := range f.applied {
			if strings.Contains(a, "s-after") {
				t.Errorf("a resource after the signaled one was applied before the signals arrived: %v", f.applied)
			}
		}
		switch reads {
		case 2:
			sigs.send("Web", Signal{UniqueID: "i-1", Status: "SUCCESS"})
			sigs.send("Web", Signal{UniqueID: "i-1", Status: "SUCCESS"}) // same instance twice counts once
		case 4:
			sigs.send("Web", Signal{UniqueID: "i-2", Status: "SUCCESS"})
		}
	}
	f = &fakeApplier{}
	opts := deployOpts()
	opts.Signals = sigs
	rec, err := Deploy(context.Background(), []byte(signalInstanceTmpl), opts, f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" || sigs.reads["Web"] < 4 {
		t.Fatalf("the create completes once both distinct signals arrive (reads=%d): %s", sigs.reads["Web"], rec.Status)
	}
	if !hasEvent(rec, "Web", "CREATE_COMPLETE") || !hasEvent(rec, "After", "CREATE_COMPLETE") {
		t.Fatalf("events: %+v", rec.Events)
	}
}

// A FAILURE signal fails the resource at once and rolls the stack back; so does the timeout.
func TestSignals_FailureAndTimeoutRollBack(t *testing.T) {
	fastSignals(t)
	sigs := &memSignals{}
	sigs.send("Web", Signal{UniqueID: "i-1", Status: "FAILURE", Reason: "bootstrap failed"})
	f := &fakeApplier{}
	opts := deployOpts()
	opts.Signals = sigs
	rec, err := Deploy(context.Background(), []byte(signalInstanceTmpl), opts, f)
	if err == nil || !strings.Contains(err.Error(), "FAILURE signal with UniqueId i-1 (bootstrap failed)") {
		t.Fatalf("a FAILURE signal must fail the create with its reason: %v", err)
	}
	if rec.Status != "CREATE_FAILED" || len(f.deleted) == 0 || !hasEvent(rec, "Web", "CREATE_FAILED") {
		t.Fatalf("the failed create rolls back: %s deleted=%v events=%+v", rec.Status, f.deleted, rec.Events)
	}

	short := strings.Replace(signalInstanceTmpl, "PT1M", "PT0H0M1S", 1)
	f2 := &fakeApplier{}
	opts.Signals = &memSignals{}
	start := time.Now()
	_, err = Deploy(context.Background(), []byte(short), opts, f2)
	if err == nil || !strings.Contains(err.Error(), "failed to receive 2 resource signal(s) within the specified duration") {
		t.Fatalf("the timeout must fail the create: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the timeout was not honored (%s)", time.Since(start))
	}
}

// A path that cannot receive signals (the CLI) refuses such a stack before creating anything.
func TestSignals_RefusedWithoutASource(t *testing.T) {
	f := &fakeApplier{}
	_, err := Deploy(context.Background(), []byte(signalInstanceTmpl), deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "cannot receive") || len(f.applied) != 0 {
		t.Fatalf("want a refusal before anything is applied: %v applied=%v", err, f.applied)
	}
}

// A WaitCondition waits for its handle's signals; the handle's Ref (used in UserData) is the signal URL;
// Fn::GetAtt Data in an Output is the signals' data by UniqueId.
func TestSignals_WaitConditionAndHandle(t *testing.T) {
	fastSignals(t)
	tmpl := `
Resources:
  Handle:
    Type: AWS::CloudFormation::WaitConditionHandle
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: web }
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      SecurityGroupIds: [ !Ref SG ]
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          curl -X PUT -H 'Content-Type:' --data-binary '{"Status":"SUCCESS","UniqueId":"web","Data":"ready","Reason":"ok"}' "${Handle}"
  Wait:
    Type: AWS::CloudFormation::WaitCondition
    DependsOn: Web
    Properties: { Handle: !Ref Handle, Timeout: "60" }
Outputs:
  Data: { Value: !GetAtt Wait.Data }
  Url:  { Value: !Ref Handle }
`
	sigs := &memSignals{}
	sigs.onRead = func(id string, reads int) {
		if id == "Handle" && reads == 2 {
			sigs.send("Handle", Signal{UniqueID: "web", Status: "SUCCESS", Data: "ready"})
		}
	}
	f := &fakeApplier{}
	opts := deployOpts()
	opts.Signals = sigs
	opts.SignalURL = func(stack, id string) string { return "https://shim.example/cfn-signal/" + stack + "/" + id + "?sig=x" }
	rec, err := Deploy(context.Background(), []byte(tmpl), opts, f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	out := outputMap(rec)
	if out["Data"].OutputValue != `{"web":"ready"}` || out["Url"].OutputValue != "https://shim.example/cfn-signal/s/Handle?sig=x" {
		t.Fatalf("outputs: %+v", rec.Outputs)
	}
	// The instance's UserData carries the handle URL (resolved at translate time).
	js, _ := json.Marshal(f.liveSpecs["VirtualMachine/s-web"])
	found := strings.Contains(string(js), "cfn-signal/s/Handle")
	for _, m := range regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`).FindAllString(string(js), -1) {
		if b, err := base64.StdEncoding.DecodeString(m); err == nil && strings.Contains(string(b), "cfn-signal/s/Handle") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the instance's UserData must carry the handle URL: %s", js)
	}
	// The wait condition is not an object: nothing was applied or would be deleted for it.
	for _, a := range f.applied {
		if strings.Contains(a, "SignalWait") {
			t.Fatalf("a wait condition must not be applied: %v", f.applied)
		}
	}
	if _, err := Destroy(context.Background(), deployOpts(), f); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	for _, d := range f.deleted {
		if strings.Contains(d, "SignalWait") {
			t.Fatalf("a wait condition must not be deleted as an object: %v", f.deleted)
		}
	}
}

// An Fn::GetAtt WaitCondition.Data in another resource's properties is refused: there is no value to
// translate before the wait completes.
func TestSignals_WaitDataInPropertiesRefused(t *testing.T) {
	tmpl := `
Resources:
  Handle: { Type: AWS::CloudFormation::WaitConditionHandle }
  Wait:
    Type: AWS::CloudFormation::WaitCondition
    Properties: { Handle: !Ref Handle, Timeout: "60" }
  P:
    Type: AWS::SSM::Parameter
    Properties: { Name: /p, Type: String, Value: !GetAtt Wait.Data }
`
	plan, err := BuildPlan([]byte(tmpl), nil, "s")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Verdict != Rejected || !strings.Contains(strings.Join(plan.Blockers, "\n"), "resolves only once the wait condition completes") {
		t.Fatalf("want a refusal: %v", plan.Blockers)
	}
}

func TestParseISODuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"PT15M": 15 * time.Minute, "PT1H30M": 90 * time.Minute, "PT45S": 45 * time.Second, "pt2h": 2 * time.Hour} {
		if got, err := parseISODuration(in); err != nil || got != want {
			t.Errorf("%s = %v (%v), want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"15M", "PT", "P1D", "PTxM"} {
		if _, err := parseISODuration(bad); err == nil {
			t.Errorf("%s must not parse", bad)
		}
	}
}

// The stack's events record every transition, oldest first; the newest-first view is what
// DescribeStackEvents returns.
func TestEvents_CreateRecordsEveryTransition(t *testing.T) {
	tmpl := `
Resources:
  A: { Type: AWS::SSM::Parameter, Properties: { Name: /a, Type: String, Value: x } }
  B: { Type: AWS::SSM::Parameter, DependsOn: A, Properties: { Name: /b, Type: String, Value: y } }
`
	f := &fakeApplier{}
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err != nil {
		t.Fatal(err)
	}
	var seq []string
	for _, e := range rec.Events {
		seq = append(seq, e.LogicalID+":"+e.Status)
	}
	want := "s:CREATE_IN_PROGRESS,A:CREATE_IN_PROGRESS,A:CREATE_COMPLETE,B:CREATE_IN_PROGRESS,B:CREATE_COMPLETE,s:CREATE_COMPLETE"
	if strings.Join(seq, ",") != want {
		t.Fatalf("events = %s\nwant     %s", strings.Join(seq, ","), want)
	}
	newest := EventsNewestFirst(rec)
	if newest[0].Status != "CREATE_COMPLETE" || newest[0].Type != StackTypeName || newest[1].Type != "AWS::SSM::Parameter" {
		t.Fatalf("newest first: %+v", newest[:2])
	}
	for _, r := range rec.Resources {
		if r.Status != "CREATE_COMPLETE" || r.Type != "AWS::SSM::Parameter" || r.PhysicalID == "" {
			t.Fatalf("each resource records its type, status and physical id: %+v", r)
		}
	}
	// An update keeps the history and adds its own transitions.
	v2 := strings.Replace(tmpl, "Value: y", "Value: z", 1)
	rec2, err := Update(context.Background(), []byte(v2), deployOpts(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec2.Events) <= len(rec.Events) || !hasEvent(rec2, "B", "UPDATE_COMPLETE") || !hasEvent(rec2, "s", "UPDATE_COMPLETE") {
		t.Fatalf("update events: %+v", rec2.Events)
	}
}

// eventsApplier records what the engine flushes for DescribeStackEvents/ListStackResources to read.
type eventsApplier struct {
	*fakeApplier
	mu      sync.Mutex
	flushed []StackEvent
}

func (e *eventsApplier) PutEvents(_ context.Context, _ string, events []StackEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flushed = append([]StackEvent(nil), events...)
	return nil
}

func (e *eventsApplier) latest(id string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := ""
	for _, ev := range e.flushed {
		if ev.LogicalID == id {
			st = ev.Status
		}
	}
	return st
}

// While a WaitCondition waits, its CREATE_IN_PROGRESS has already been flushed, so DescribeStackEvents and
// ListStackResources show it in progress (as AWS does), not only once it completes.
func TestSignals_WaitingResourceShowsInProgress(t *testing.T) {
	fastSignals(t)
	tmpl := `
Resources:
  P: { Type: AWS::SSM::Parameter, Properties: { Name: /p, Type: String, Value: x } }
  W:
    Type: AWS::CloudFormation::WaitCondition
    DependsOn: P
    CreationPolicy: { ResourceSignal: { Count: 1, Timeout: PT1M } }
`
	ap := &eventsApplier{fakeApplier: &fakeApplier{}}
	sigs := &memSignals{}
	var whileWaiting string
	sigs.onRead = func(id string, reads int) {
		if id == "W" && reads == 1 {
			whileWaiting = ap.latest("W")
			sigs.send("W", Signal{UniqueID: "u", Status: "SUCCESS"})
		}
	}
	opts := deployOpts()
	opts.Signals = sigs
	if _, err := Deploy(context.Background(), []byte(tmpl), opts, ap); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if whileWaiting != "CREATE_IN_PROGRESS" {
		t.Fatalf("while waiting for its signal, W's flushed status = %q, want CREATE_IN_PROGRESS", whileWaiting)
	}
}
