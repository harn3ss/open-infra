package cfn

import (
	"context"
	"strings"
	"testing"
	"time"
)

const encryptedRootTmpl = `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      BlockDeviceMappings:
        - DeviceName: /dev/sda1
          Ebs: { VolumeSize: 30, Encrypted: true }
Outputs:
  Ip:  { Value: !GetAtt Web.PrivateIp }
  Dns: { Value: !GetAtt Web.PrivateDnsName }
`

// bootWait shortens the waits: the ordinary bound is opts.Timeout (base), the encrypted-root bound boot.
func bootWait(t *testing.T, boot time.Duration) {
	t.Helper()
	fastOutputs(t)
	prev := outputBootWaitCap
	outputBootWaitCap = boot
	t.Cleanup(func() { outputBootWaitCap = prev })
}

// vmTimeline is a VM's status over time since the deploy began: copying its root until copied, then
// started (no address) until addressed, then its address.
func vmTimeline(copied, addressed time.Duration) func(string) (map[string]any, bool) {
	start := time.Now()
	return func(key string) (map[string]any, bool) {
		if key != "VirtualMachine/s-web" {
			return nil, false
		}
		el := time.Since(start)
		switch {
		case el < copied:
			return map[string]any{"rootPopulated": false, "ip": ""}, true
		case el < addressed:
			return map[string]any{"rootPopulated": true, "ip": ""}, true
		default:
			return map[string]any{"rootPopulated": true, "ip": "10.16.0.9"}, true
		}
	}
}

// An instance with an encrypted root starts only once its OS image is copied onto the encrypted disk,
// minutes after its resource completed: the stack waits past the ordinary bound while it copies and
// starts, and completes with its address.
func TestOutputs_EncryptedRootWaitsWhileItCopiesAndStarts(t *testing.T) {
	bootWait(t, 5*time.Second)
	opts := deployOpts()
	opts.Timeout = 100 * time.Millisecond
	// Copied at 400ms (past the ordinary 100ms bound), addressed 60ms later.
	f := &fakeApplier{statusFn: vmTimeline(400*time.Millisecond, 460*time.Millisecond)}
	start := time.Now()
	rec, err := Deploy(context.Background(), []byte(encryptedRootTmpl), opts, f)
	if err != nil {
		t.Fatalf("an encrypted-root instance that copies, starts and reports its address must complete the stack: %v", err)
	}
	out := outputMap(rec)
	if out["Ip"].OutputValue != "10.16.0.9" || out["Dns"].OutputValue != "ip-10-16-0-9.ec2.internal" {
		t.Fatalf("outputs = %+v", out)
	}
	if el := time.Since(start); el < 460*time.Millisecond {
		t.Fatalf("returned after %s, before the address existed", el)
	}
}

// Still copying at the encrypted-root bound: the create fails (rolled back), saying the VM had not
// started because it was still copying its image.
func TestOutputs_EncryptedRootStillCopyingFailsAtTheLongerBound(t *testing.T) {
	bootWait(t, 500*time.Millisecond)
	opts := deployOpts()
	opts.Timeout = 100 * time.Millisecond
	f := &fakeApplier{statusFn: vmTimeline(time.Hour, time.Hour)}
	start := time.Now()
	rec, err := Deploy(context.Background(), []byte(encryptedRootTmpl), opts, f)
	el := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "still copying its OS image onto its encrypted root") {
		t.Fatalf("the create must fail, saying the VM was still copying its root: %v", err)
	}
	if el < 500*time.Millisecond || el > 3*time.Second {
		t.Fatalf("waited %s, want the encrypted-root bound (500ms)", el)
	}
	if rec.Status != "CREATE_FAILED" || len(f.deleted) == 0 {
		t.Fatalf("the failed create must be rolled back: status=%s deleted=%v", rec.Status, f.deleted)
	}
}

// Copied but never addressed: once its copy is done the VM gets the ordinary bound to report its
// address, not the rest of the encrypted-root bound.
func TestOutputs_EncryptedRootCopiedGetsTheOrdinaryBoundToStart(t *testing.T) {
	bootWait(t, 5*time.Second)
	opts := deployOpts()
	opts.Timeout = 100 * time.Millisecond
	f := &fakeApplier{statusFn: vmTimeline(300*time.Millisecond, time.Hour)}
	start := time.Now()
	_, err := Deploy(context.Background(), []byte(encryptedRootTmpl), opts, f)
	el := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "the OS image was copied onto its encrypted root, and the VM had not reported it") {
		t.Fatalf("the create must fail, saying the copied VM never reported its address: %v", err)
	}
	if el < 400*time.Millisecond || el > 2*time.Second {
		t.Fatalf("waited %s, want the copy (300ms) plus the ordinary bound (100ms), far short of the encrypted-root bound", el)
	}
}

// An instance without an encrypted root gets the ordinary bound only.
func TestOutputs_UnencryptedRootGetsTheOrdinaryBound(t *testing.T) {
	bootWait(t, 5*time.Second)
	opts := deployOpts()
	opts.Timeout = 100 * time.Millisecond
	tmpl := strings.Replace(encryptedRootTmpl, ", Encrypted: true", "", 1)
	f := &fakeApplier{statusFn: vmTimeline(time.Hour, time.Hour)}
	start := time.Now()
	_, err := Deploy(context.Background(), []byte(tmpl), opts, f)
	if err == nil || !strings.Contains(err.Error(), "private IP was not assigned before the stack completed") {
		t.Fatalf("the create must fail, saying the IP was not assigned: %v", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("an unencrypted root waited %s, past the ordinary bound", el)
	}
}

// The longer wait still stops a reserve short of the operation's deadline, so the failed create's record
// is written.
func TestOutputs_EncryptedRootWaitLeavesTimeForTheRecord(t *testing.T) {
	bootWait(t, time.Minute)
	prev := outputRecordReserve
	outputRecordReserve = 300 * time.Millisecond
	t.Cleanup(func() { outputRecordReserve = prev })
	opts := deployOpts()
	opts.Timeout = 100 * time.Millisecond
	f := &fakeApplier{statusFn: vmTimeline(time.Hour, time.Hour)}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	start := time.Now()
	rec, err := Deploy(ctx, []byte(encryptedRootTmpl), opts, ctxApplier{f})
	if err == nil || !strings.Contains(err.Error(), "still copying") {
		t.Fatalf("the create fails, saying the VM was still copying: %v", err)
	}
	if rec.Status != "CREATE_FAILED" || f.stored == nil || f.stored.Status != "CREATE_FAILED" {
		t.Fatalf("want a stored CREATE_FAILED record (written before the deadline): %+v / %+v", rec, f.stored)
	}
	if el := time.Since(start); el > 700*time.Millisecond {
		t.Fatalf("the wait ran into the record's reserve (%s)", el)
	}
}
