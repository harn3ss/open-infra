package cfn

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// fastVMWaits shortens the VM power-state polling and the error grace for a test.
func fastVMWaits(t *testing.T, grace time.Duration) {
	t.Helper()
	prevPoll, prevGrace := restartPollInterval, vmErrorGrace
	restartPollInterval, vmErrorGrace = 5*time.Millisecond, grace
	t.Cleanup(func() { restartPollInterval, vmErrorGrace = prevPoll, prevGrace })
}

// eventIndex is the position of a resource's first event with status (-1 when there is none).
func eventIndex(rec *StackRecord, logicalID, status string) int {
	for i, e := range rec.Events {
		if e.LogicalID == logicalID && e.Status == status {
			return i
		}
	}
	return -1
}

// #350 W: a WaitCondition with no DependsOn, ahead of the instance whose UserData signals it, waits while
// the instance is created (as AWS creates them in parallel) instead of blocking it until its timeout.
func TestReadiness_WaitConditionWithoutDependsOnDoesNotBlockTheInstance(t *testing.T) {
	fastSignals(t)
	tmpl := `
Resources:
  AWait:
    Type: AWS::CloudFormation::WaitCondition
    Properties: { Handle: !Ref Handle, Timeout: "2" }
  Handle:
    Type: AWS::CloudFormation::WaitConditionHandle
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          curl -X PUT --data-binary '{"Status":"SUCCESS","UniqueId":"web","Data":"up","Reason":"ok"}' "${Handle}"
Outputs:
  Data: { Value: !GetAtt AWait.Data }
`
	f := &fakeApplier{}
	sigs := &memSignals{}
	sigs.onRead = func(id string, _ int) {
		// The instance "boots" and signals the handle — but only once it has been created.
		for _, a := range f.applied {
			if a == "VirtualMachine/s-web" {
				sigs.send("Handle", Signal{UniqueID: "web", Status: "SUCCESS", Data: "up"})
				return
			}
		}
	}
	opts := deployOpts()
	opts.Signals = sigs
	opts.SignalURL = func(stack, id string) string { return "https://shim.example/cfn-signal/" + stack + "/" + id }
	start := time.Now()
	rec, err := Deploy(context.Background(), []byte(tmpl), opts, f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" || outputMap(rec)["Data"].OutputValue != `{"web":"up"}` {
		t.Fatalf("want CREATE_COMPLETE with the signal's data: %s %+v", rec.Status, rec.Outputs)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("the wait condition blocked the instance (took %s)", time.Since(start))
	}
	if eventIndex(rec, "Web", "CREATE_IN_PROGRESS") > eventIndex(rec, "AWait", "CREATE_COMPLETE") {
		t.Fatalf("the instance must be created while the wait condition waits: %+v", rec.Events)
	}
}

// #347 item 25 / #350 U: an instance is complete only once its VM runs; what depends on it is created
// after that. A VM that never starts fails the stack (rolled back), and one that stays in an error state
// fails it without waiting out the timeout.
func TestReadiness_InstanceCompletesWhenItsVMRuns(t *testing.T) {
	fastVMWaits(t, time.Hour)
	tmpl := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
  After:
    Type: AWS::SSM::Parameter
    DependsOn: Web
    Properties: { Name: /after, Type: String, Value: x }
`
	var mu sync.Mutex
	reads := 0
	var f *fakeApplier
	f = &fakeApplier{statusFn: func(key string) (map[string]any, bool) {
		if key != "VirtualMachine/s-web" {
			return map[string]any{}, true
		}
		mu.Lock()
		defer mu.Unlock()
		reads++
		for _, a := range f.applied {
			if strings.Contains(a, "s-after") {
				t.Errorf("a resource depending on the instance was created before its VM ran: %v", f.applied)
			}
		}
		switch {
		case reads < 3:
			return map[string]any{"powerState": ""}, true
		case reads < 6:
			return map[string]any{"powerState": "Starting"}, true
		}
		return map[string]any{"powerState": "Running"}, true
	}}
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" || reads < 6 {
		t.Fatalf("the instance completes once its VM runs (reads=%d): %s", reads, rec.Status)
	}
	if eventIndex(rec, "Web", "CREATE_COMPLETE") > eventIndex(rec, "After", "CREATE_IN_PROGRESS") {
		t.Fatalf("the dependent must start after the instance completes: %+v", rec.Events)
	}

	// A VM that never starts (its pod's network never comes up): the stack fails at the timeout.
	stuck := &fakeApplier{statusFn: func(key string) (map[string]any, bool) {
		return map[string]any{"powerState": "Starting"}, true
	}}
	opts := deployOpts()
	opts.Timeout = 100 * time.Millisecond
	rec, err = Deploy(context.Background(), []byte(tmpl), opts, stuck)
	if err == nil || !strings.Contains(err.Error(), "did not start running") || !strings.Contains(err.Error(), `state Starting`) {
		t.Fatalf("a VM that never runs must fail the create: %v", err)
	}
	if !hasEvent(rec, "Web", "CREATE_FAILED") || len(stuck.deleted) == 0 || stuck.appliedHas("s-after") {
		t.Fatalf("the failed create rolls back, and nothing after the instance is created: deleted=%v applied=%v", stuck.deleted, stuck.applied)
	}
}

func (f *fakeApplier) appliedHas(sub string) bool {
	for _, a := range f.applied {
		if strings.Contains(a, sub) {
			return true
		}
	}
	return false
}

func TestReadiness_VMErrorStateFailsFast(t *testing.T) {
	fastVMWaits(t, 30*time.Millisecond)
	tmpl := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
`
	f := &fakeApplier{statusFn: func(string) (map[string]any, bool) {
		return map[string]any{"powerState": "ErrorUnschedulable"}, true
	}}
	opts := deployOpts()
	opts.Timeout = time.Minute
	start := time.Now()
	_, err := Deploy(context.Background(), []byte(tmpl), opts, f)
	if err == nil || !strings.Contains(err.Error(), "cannot run: its VM has been ErrorUnschedulable") {
		t.Fatalf("a VM stuck in an error state must fail the create: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the error state must fail the create before the timeout (took %s)", time.Since(start))
	}
	// A status with no power state (a composition that does not report it) is not waited for.
	plain := &fakeApplier{statusFn: func(string) (map[string]any, bool) { return map[string]any{"ip": "10.0.0.1"}, true }}
	if rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), plain); err != nil || rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("no power state reported: %v", err)
	}
}

// keyFirstApplier is a cluster where an encrypted Volume becomes ready only once its EncryptionKey exists.
type keyFirstApplier struct{ *fakeApplier }

func (k keyFirstApplier) WaitReady(ctx context.Context, apiVersion, kind, name string, timeout time.Duration) error {
	if kind == "Volume" {
		key, _ := k.liveSpecs["Volume/"+name]["encryptionKey"].(string)
		if key != "" {
			if _, ok := k.liveSpecs["EncryptionKey/"+key]; !ok {
				return errFake("Volume " + name + " never became ready: its key " + key + " does not exist")
			}
		}
	}
	return k.fakeApplier.WaitReady(ctx, apiVersion, kind, name, timeout)
}

// #350 V: an encrypted standalone volume with no KmsKeyId is keyed by the stack's default key, which it
// carries as a companion: the key is created before the volume is waited for, so the volume becomes ready.
func TestReadiness_EncryptedVolumeDefaultKeyCreatedBeforeItsWait(t *testing.T) {
	tmpl := `
Resources:
  Data:
    Type: AWS::EC2::Volume
    Properties: { Size: 10, Encrypted: true }
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04 }
  Attach:
    Type: AWS::EC2::VolumeAttachment
    Properties: { InstanceId: !Ref Web, VolumeId: !Ref Data, Device: /dev/sdf }
`
	f := keyFirstApplier{&fakeApplier{}}
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" || !f.appliedHas("EncryptionKey/s-ebs-default") {
		t.Fatalf("want CREATE_COMPLETE with the default key created: %s %v", rec.Status, f.applied)
	}
}

// A resource that fails while others are still being created cancels them (CREATE_FAILED "Resource
// creation cancelled", as on AWS) and the stack rolls back without waiting them out.
func TestReadiness_FailureCancelsWhatIsStillBeingCreated(t *testing.T) {
	fastSignals(t)
	tmpl := `
Resources:
  AWait:
    Type: AWS::CloudFormation::WaitCondition
    Properties: { Handle: !Ref Handle, Timeout: "600" }
  Handle:
    Type: AWS::CloudFormation::WaitConditionHandle
  K:
    Type: AWS::KMS::Key
`
	f := &fakeApplier{notReady: "s-k"}
	opts := deployOpts()
	opts.Signals = &memSignals{}
	start := time.Now()
	rec, err := Deploy(context.Background(), []byte(tmpl), opts, f)
	if err == nil || !strings.Contains(err.Error(), "s-k never became Ready") {
		t.Fatalf("want the key's failure: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the failure must not wait out the wait condition (took %s)", time.Since(start))
	}
	if rec.Status != "ROLLBACK_COMPLETE" || !hasEvent(rec, "K", "CREATE_FAILED") {
		t.Fatalf("status %s, events %+v", rec.Status, rec.Events)
	}
	cancelled := false
	for _, e := range rec.Events {
		if e.LogicalID == "AWait" && e.Status == "CREATE_FAILED" && e.Reason == "Resource creation cancelled" {
			cancelled = true
		}
	}
	if !cancelled {
		t.Fatalf("the wait condition must be cancelled: %+v", rec.Events)
	}
}

// The update path: a WaitCondition added with no DependsOn waits alongside the instance added with it.
func TestReadiness_UpdateAddsWaitConditionBesideItsInstance(t *testing.T) {
	fastSignals(t)
	v1 := `
Resources:
  K:
    Type: AWS::KMS::Key
`
	v2 := `
Resources:
  K:
    Type: AWS::KMS::Key
  AWait:
    Type: AWS::CloudFormation::WaitCondition
    Properties: { Handle: !Ref Handle, Timeout: "2" }
  Handle:
    Type: AWS::CloudFormation::WaitConditionHandle
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      UserData: { "Fn::Base64": !Sub "#!/bin/bash\ncurl -X PUT '${Handle}'\n" }
`
	f := &fakeApplier{}
	sigs := &memSignals{}
	sigs.onRead = func(string, int) {
		if f.appliedHas("VirtualMachine/s-web") {
			sigs.send("Handle", Signal{UniqueID: "web", Status: "SUCCESS"})
		}
	}
	opts := deployOpts()
	opts.Signals = sigs
	opts.SignalURL = func(stack, id string) string { return "https://shim.example/cfn-signal/" + stack + "/" + id }
	if _, err := Deploy(context.Background(), []byte(v1), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	rec, err := Update(context.Background(), []byte(v2), opts, f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if rec.Status != "UPDATE_COMPLETE" {
		t.Fatalf("want UPDATE_COMPLETE: %s", rec.Status)
	}
}

func TestAncestorsFollowFoldedResources(t *testing.T) {
	deps := map[string][]string{"Inst": {"Route"}, "Route": {"Gw"}, "Gw": {"Vpc"}, "Vpc": nil}
	got := ancestors(deps, "Inst")
	for _, id := range []string{"Route", "Gw", "Vpc"} {
		if !got[id] {
			t.Fatalf("ancestors(Inst) = %v, missing %s", got, id)
		}
	}
	if got["Inst"] {
		t.Fatalf("a resource is not its own ancestor: %v", got)
	}
}
