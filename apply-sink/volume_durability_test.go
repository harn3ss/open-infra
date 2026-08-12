//go:build convergence

package main

// volume-durability plane — a RECOVER reference adapter on the singular runOracle. Conservation of
// acknowledged work on the block-storage plane: a raw-block signature written before the fault must
// read back identical after the attached pod is killed and a new pod re-attaches the volume.
//
// The timing subtlety every recover-durability adapter must handle: SteadyState must NOT pass on the
// pre-fault state (the device is attached before the kill too), or runOracle would reconcile before
// the fault even landed. So SteadyState requires the fault to have LANDED — a NEW pod replaced the
// original — before it will report steady. The adapter records the pre-fault identity in Drive.

import (
	"strconv"
	"testing"
)

const volSig = "CHAOSVOL-PERSIST-OK"

// volAccess is the block-volume workload accessor. Live = kubectl exec into the writer pod; a fake
// drives the unit tests, so the verdict is provable RED/GREEN with no cluster.
type volAccess interface {
	WriterUID() (string, error) // identity of the attached pod (to detect the fault landed)
	WriteSig() error            // write the signature to the raw block device (the acked work)
	Readable() bool             // the block device is attached + readable in the current pod
	ReadSig() (string, error)   // read the signature back
}

type volOracle struct {
	a       volAccess
	origUID string
}

func (o *volOracle) Name() string { return "volume-durability" }

func (o *volOracle) Drive(t *testing.T) map[string]bool {
	o.origUID, _ = o.a.WriterUID()
	if err := o.a.WriteSig(); err != nil && t != nil {
		t.Fatalf("volume-durability: write signature: %v", err)
	}
	return map[string]bool{"block-signature": true}
}

func (o *volOracle) SteadyState() (bool, string, error) {
	uid, err := o.a.WriterUID()
	if err != nil {
		return false, "", err
	}
	if uid == "" || uid == o.origUID {
		return false, "attached pod not yet replaced (fault not landed / not rescheduled)", nil
	}
	if !o.a.Readable() {
		return false, "replacement pod has not re-attached the block device", nil
	}
	return true, "", nil
}

func (o *volOracle) Reconcile(ledger map[string]bool) []string {
	got, err := o.a.ReadSig()
	if err != nil || got != volSig {
		return []string{"block-signature"}
	}
	return nil
}

// ---- live accessor (kubectl exec into the writer pod) ----

type liveVol struct {
	ns  string
	dev string
}

func (l liveVol) WriterUID() (string, error) {
	return kubectl("-n", l.ns, "get", "pods", "-l", "app=vol-writer",
		"-o", "jsonpath={.items[0].metadata.uid}")
}
func (l liveVol) WriteSig() error {
	_, err := kubectl("-n", l.ns, "exec", "deploy/vol-writer", "--", "sh", "-c",
		"printf %s '"+volSig+"' | dd of="+l.dev+" bs=512 seek=0 conv=notrunc 2>/dev/null; sync")
	return err
}
func (l liveVol) Readable() bool {
	return kubectlOK("-n", l.ns, "exec", "deploy/vol-writer", "--", "test", "-b", l.dev)
}
func (l liveVol) ReadSig() (string, error) {
	return kubectl("-n", l.ns, "exec", "deploy/vol-writer", "--", "sh", "-c",
		"dd if="+l.dev+" bs=1 count="+strconv.Itoa(len(volSig))+" 2>/dev/null")
}

// TestVolumeDurability — LIVE. The shell provisions the Volume + writer and injects the pod kill;
// this drives the signature and judges conservation across the reschedule.
func TestVolumeDurability(t *testing.T) {
	runOracle(t, &volOracle{a: liveVol{ns: envOr("CHAOS_SANDBOX_NS", "chaos-sandbox"), dev: envOr("VOL_DEV", "/dev/xvda")}})
}

// ---- prove-red (no cluster) ----

type fakeVol struct {
	uid, sig string
	readable bool
}

func (f *fakeVol) WriterUID() (string, error) { return f.uid, nil }
func (f *fakeVol) WriteSig() error            { return nil }
func (f *fakeVol) Readable() bool             { return f.readable }
func (f *fakeVol) ReadSig() (string, error)   { return f.sig, nil }

func TestVolumeDurabilityRedGreen(t *testing.T) {
	f := &fakeVol{uid: "u1", sig: volSig, readable: true}
	o := &volOracle{a: f}
	o.Drive(nil) // records origUID = u1

	// Must NOT be steady while the pod hasn't been replaced (guards the pre-fault race).
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("SteadyState must be false before the attached pod is replaced (pre-fault state)")
	}

	// Fault lands: a new pod re-attaches the device.
	f.uid = "u2"
	if ok, _, _ := o.SteadyState(); !ok {
		t.Fatal("SteadyState must be true once a replacement pod has re-attached the device")
	}

	// GREEN: signature intact across the reschedule.
	if lost := o.Reconcile(nil); len(lost) != 0 {
		t.Fatalf("green: signature intact but reported lost: %v", lost)
	}

	// RED: replacement re-attached but the signature is gone — lost acknowledged work.
	f.sig = "GARBAGE"
	if lost := o.Reconcile(nil); len(lost) == 0 {
		t.Fatal("a lost block signature MUST be reported as lost work (RED)")
	}
}
