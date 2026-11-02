package cfn

import (
	"context"
	"strings"
	"testing"
	"time"
)

const resizeTmpl = `
Parameters:
  Type: { Type: String, Default: t3.small }
  Script: { Type: String, Default: "#!/bin/bash\necho one" }
  Public: { Type: String, Default: "false" }
Conditions:
  IsPublic: !Equals [!Ref Public, "true"]
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      InstanceType: !Ref Type
      UserData: !Base64 { Ref: Script }
      NetworkInterfaces:
        - DeviceIndex: "0"
          AssociatePublicIpAddress: !If [IsPublic, true, false]
Outputs:
  Ip: { Value: !GetAtt Web.PrivateIp }
`

// powerApplier is a fakeApplier with a VM that behaves as KubeVirt does: a spec change it reads at start
// makes it RestartRequired; spec.running false stops it (after stopAfter status reads), true starts it on
// its current spec (after startAfter reads). neverStops keeps it Running whatever it is told.
type powerApplier struct {
	*fakeApplier
	calls                 []bool // SetRunning calls, in order
	state                 string // Running | Stopping | Stopped | Starting
	restartRequired       bool
	runningSpec           map[string]any // the spec the running VM started with
	stopAfter, startAfter int
	countdown             int
	neverStops            bool
}

func newPowerApplier() *powerApplier {
	p := &powerApplier{fakeApplier: &fakeApplier{}, state: "Running", stopAfter: 2, startAfter: 2}
	p.statusFn = p.status
	return p
}

const webKey = "VirtualMachine/s-web"

func (p *powerApplier) Apply(ctx context.Context, y []byte) error {
	if err := p.fakeApplier.Apply(ctx, y); err != nil {
		return err
	}
	if idOf(y) == webKey {
		spec := p.liveSpecs[webKey]
		if p.runningSpec == nil {
			p.runningSpec = spec
		}
		p.restartRequired = len(restartFields(p.runningSpec, spec)) > 0
	}
	return nil
}

func (p *powerApplier) SetRunning(_ context.Context, _, kind, name string, running bool) error {
	p.calls = append(p.calls, running)
	if spec := p.liveSpecs[kind+"/"+name]; spec != nil {
		spec["running"] = running
	}
	switch {
	case p.neverStops:
	case !running && p.state != "Stopped":
		p.state, p.countdown = "Stopping", p.stopAfter
	case running && p.state != "Running":
		p.state, p.countdown = "Starting", p.startAfter
	}
	return nil
}

func (p *powerApplier) status(key string) (map[string]any, bool) {
	if key != webKey {
		return nil, false
	}
	if p.countdown > 0 {
		p.countdown--
	} else {
		switch p.state {
		case "Stopping":
			p.state = "Stopped"
		case "Starting":
			p.state = "Running"
			p.runningSpec = p.liveSpecs[webKey]
			p.restartRequired = false
		}
	}
	ip := ""
	if p.state == "Running" {
		ip = "10.16.0.9"
	}
	return map[string]any{"powerState": p.state, "restartRequired": p.restartRequired, "ip": ip}, true
}

func fastRestart(t *testing.T) {
	t.Helper()
	fastOutputs(t)
	prev := restartPollInterval
	restartPollInterval = time.Millisecond
	t.Cleanup(func() { restartPollInterval = prev })
}

func deployResize(t *testing.T, p *powerApplier) {
	t.Helper()
	if _, err := Deploy(context.Background(), []byte(resizeTmpl), deployOpts(), p); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	p.calls = nil
}

func withParams(opts DeployOptions, kv ...string) DeployOptions {
	opts.Params = map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		opts.Params[kv[i]] = kv[i+1]
	}
	return opts
}

func hasEventReason(rec *StackRecord, sub string) bool {
	for _, e := range rec.Events {
		if strings.Contains(e.Reason, sub) {
			return true
		}
	}
	return false
}

// A new InstanceType stops and starts the instance, and the update completes once it runs at the new size.
func TestUpdate_InstanceTypeRestartsTheInstance(t *testing.T) {
	fastRestart(t)
	p := newPowerApplier()
	deployResize(t, p)
	rec, err := Update(context.Background(), []byte(resizeTmpl), withParams(deployOpts(), "Type", "t3.medium"), p)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if rec.Status != "UPDATE_COMPLETE" {
		t.Fatalf("status = %s, want UPDATE_COMPLETE", rec.Status)
	}
	if len(p.calls) != 2 || p.calls[0] || !p.calls[1] {
		t.Fatalf("SetRunning calls = %v, want [false true] (stop, then start)", p.calls)
	}
	if p.state != "Running" || p.restartRequired {
		t.Fatalf("the VM is %s with restartRequired=%v, want Running on its new spec", p.state, p.restartRequired)
	}
	if got := p.runningSpec["memory"]; got != "4Gi" {
		t.Fatalf("the VM runs with memory %v, want the t3.medium's 4Gi", got)
	}
	if !hasEventReason(rec, "Stopping and starting the instance to apply its new memory") {
		t.Fatalf("no event says the instance is stopped and started: %+v", rec.Events)
	}
	if len(rec.Restarting) != 0 {
		t.Fatalf("a completed update keeps Restarting = %v", rec.Restarting)
	}
}

// New UserData is read only at start, so it restarts the instance too (AWS: some interruptions).
func TestUpdate_UserDataRestartsTheInstance(t *testing.T) {
	fastRestart(t)
	p := newPowerApplier()
	deployResize(t, p)
	rec, err := Update(context.Background(), []byte(resizeTmpl), withParams(deployOpts(), "Script", "#!/bin/bash\necho two"), p)
	if err != nil || rec.Status != "UPDATE_COMPLETE" {
		t.Fatalf("update: %v (%v)", err, rec)
	}
	if len(p.calls) != 2 {
		t.Fatalf("SetRunning calls = %v, want a stop and a start", p.calls)
	}
}

// A change a running VM takes live (here its LAN exposure) restarts nothing, as on AWS.
func TestUpdate_LiveChangeDoesNotRestart(t *testing.T) {
	fastRestart(t)
	p := newPowerApplier()
	deployResize(t, p)
	rec, err := Update(context.Background(), []byte(resizeTmpl), withParams(deployOpts(), "Public", "true"), p)
	if err != nil || rec.Status != "UPDATE_COMPLETE" {
		t.Fatalf("update: %v (%v)", err, rec)
	}
	if len(p.calls) != 0 {
		t.Fatalf("a live change stopped/started the instance: SetRunning calls = %v", p.calls)
	}
}

// A stopped instance is left stopped: the new size applies when it is next started.
func TestUpdate_StoppedInstanceStaysStopped(t *testing.T) {
	fastRestart(t)
	p := newPowerApplier()
	deployResize(t, p)
	p.state = "Stopped"
	p.liveSpecs[webKey]["running"] = false
	// The cfn manifest never sets spec.running; the live object keeps what the console set.
	// (A stopped VM has no address, so this stack names no PrivateIp Output.)
	noOutputs := resizeTmpl[:strings.Index(resizeTmpl, "Outputs:")]
	rec, err := Update(context.Background(), []byte(noOutputs), withParams(deployOpts(), "Type", "t3.medium"), &keepRunning{p})
	if err != nil || rec.Status != "UPDATE_COMPLETE" {
		t.Fatalf("update: %v (%v)", err, rec)
	}
	if len(p.calls) != 0 {
		t.Fatalf("a stopped instance was started: SetRunning calls = %v", p.calls)
	}
}

// keepRunning is a powerApplier whose Apply keeps the live spec.running, as a server-side apply that
// does not set the field does.
type keepRunning struct{ *powerApplier }

func (k *keepRunning) Apply(ctx context.Context, y []byte) error {
	run, had := k.liveSpecs[webKey]["running"]
	if err := k.powerApplier.Apply(ctx, y); err != nil {
		return err
	}
	if had && idOf(y) == webKey {
		k.liveSpecs[webKey]["running"] = run
	}
	return nil
}

// An instance that never stops fails the update, which rolls back — and the instance is never left
// stopped: the last thing it is told is to run.
func TestUpdate_RestartThatNeverStopsRollsBack(t *testing.T) {
	fastRestart(t)
	p := newPowerApplier()
	deployResize(t, p)
	p.neverStops = true
	opts := withParams(deployOpts(), "Type", "t3.medium")
	opts.Timeout = 50 * time.Millisecond
	rec, err := Update(context.Background(), []byte(resizeTmpl), opts, p)
	if err == nil || rec.Status != "UPDATE_ROLLBACK_COMPLETE" {
		t.Fatalf("status = %v (err %v), want UPDATE_ROLLBACK_COMPLETE", rec.Status, err)
	}
	if !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("err = %v, want it to say the instance did not stop", err)
	}
	if len(p.calls) == 0 || !p.calls[len(p.calls)-1] {
		t.Fatalf("SetRunning calls = %v: the instance must be told to run last", p.calls)
	}
	if got := p.liveSpecs[webKey]["memory"]; got != "2Gi" {
		t.Fatalf("rollback left memory %v, want the prior t3.small's 2Gi", got)
	}
}

// A failure after the restart rolls back and restarts the instance onto its prior spec.
func TestUpdate_RollbackRestartsOntoThePriorSpec(t *testing.T) {
	fastRestart(t)
	p := newPowerApplier()
	deployResize(t, p)
	// The update also adds a key, created after the instance, whose apply fails.
	withKey := strings.Replace(resizeTmpl, "Outputs:", `  Later:
    Type: AWS::KMS::Key
    DependsOn: Web
    Properties: { Description: later }
Outputs:`, 1)
	p.failOn = "EncryptionKey/s-later"
	rec, err := Update(context.Background(), []byte(withKey), withParams(deployOpts(), "Type", "t3.medium"), p)
	if err == nil || rec.Status != "UPDATE_ROLLBACK_COMPLETE" {
		t.Fatalf("status = %v (err %v), want UPDATE_ROLLBACK_COMPLETE", rec.Status, err)
	}
	if len(p.calls) != 4 || p.calls[0] || !p.calls[1] || p.calls[2] || !p.calls[3] {
		t.Fatalf("SetRunning calls = %v, want stop/start onto the new spec, then stop/start onto the prior", p.calls)
	}
	if p.state != "Running" || p.restartRequired {
		t.Fatalf("after rollback the VM is %s, restartRequired=%v; want Running on its prior spec", p.state, p.restartRequired)
	}
	if got := p.runningSpec["memory"]; got != "2Gi" {
		t.Fatalf("after rollback the VM runs with memory %v, want the prior 2Gi", got)
	}
}

// An update whose process died mid-restart is recovered by starting the instance on its prior spec.
func TestRecover_InterruptedRestartStartsTheInstance(t *testing.T) {
	fastRestart(t)
	p := newPowerApplier()
	deployResize(t, p)
	// The update recorded its restart, applied the new size and stopped the VM, then the process died.
	rec := *p.stored
	rec.Status = "UPDATE_IN_PROGRESS"
	rec.Restarting = []string{"Web"}
	p.stored = &rec
	p.liveSpecs[webKey]["memory"] = "4Gi"
	p.liveSpecs[webKey]["running"] = false
	p.state = "Stopped"
	out, err := RecoverInterrupted(context.Background(), deployOpts(), p, "the front door restarted")
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if out.Status != "UPDATE_ROLLBACK_COMPLETE" || len(out.Restarting) != 0 {
		t.Fatalf("status = %s, restarting = %v; want UPDATE_ROLLBACK_COMPLETE with none left", out.Status, out.Restarting)
	}
	if p.state != "Running" || !p.calls[len(p.calls)-1] {
		t.Fatalf("the instance is %s (calls %v), want it running", p.state, p.calls)
	}
	if got := p.runningSpec["memory"]; got != "2Gi" {
		t.Fatalf("the recovered VM runs with memory %v, want the prior 2Gi", got)
	}
}

func TestRestartFields(t *testing.T) {
	prior := map[string]any{"cpu": 2, "memory": "2Gi", "securityGroups": []any{"a"}, "expose": false}
	cases := []struct {
		name string
		next map[string]any
		want string
	}{
		{"memory", map[string]any{"cpu": 2, "memory": "4Gi", "securityGroups": []any{"a"}, "expose": false}, "memory"},
		{"live only", map[string]any{"cpu": 2, "memory": "2Gi", "securityGroups": []any{"b"}, "expose": true, "ports": []any{80}}, ""},
		{"added userData", map[string]any{"cpu": 2, "memory": "2Gi", "securityGroups": []any{"a"}, "expose": false, "userData": "x"}, "userData"},
		{"int vs float", map[string]any{"cpu": 2.0, "memory": "2Gi", "securityGroups": []any{"a"}, "expose": false}, ""},
	}
	for _, c := range cases {
		if got := strings.Join(restartFields(prior, c.next), ","); got != c.want {
			t.Errorf("%s: restartFields = %q, want %q", c.name, got, c.want)
		}
	}
}
