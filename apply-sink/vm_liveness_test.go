//go:build convergence

package main

// vm-liveness plane — a RECOVER (liveness) adapter on the singular runOracle for the compute/virt
// plane. The bash scenario (chaos/scenario-vm-resilience.sh) provisions a kind: VirtualMachine, waits
// for the VMI to reach Running, kills its virt-launcher pod, and asserts KubeVirt brings the VMI back
// to Running (runStrategy: Always). The invariant is LIVENESS — does the VM come back? — so this
// adapter judges exactly that, routed through the singular engine instead of a bash-forked PASS/FAIL.
//
// It is deliberately a pure liveness oracle. An earlier version "conserved" the root-PVC claim NAME,
// but a virt-launcher kill reschedules onto the SAME deterministically-named PVC, so that red could
// never fire live (it was a fake red manufactured in the test). The genuine, live-reachable red here
// is a VM that does NOT return to Running: SteadyState never reports steady → runOracle times out as
// a liveness failure. (Conserving the guest's persisted BYTES — a disk marker written in Drive and
// read back post-reboot — would strengthen this beyond the bash; it needs guest-console access and is
// left as a deliberate follow-up. Reconcile is a no-op: there is no acked data unit on this plane.)
//
// The recover timing guard (see volume_durability): SteadyState must NOT pass on the PRE-fault state
// — the VMI is Running before the kill too. It requires the fault to have LANDED (the launcher pod
// identity changed) AND the VMI to be Running again. Drive records the pre-fault launcher identity.

import "testing"

// vmAccess is the virt-plane workload accessor — only what the liveness verdict needs, behind an
// injectable seam. Live = kubectl against the VMI + its launcher pod; a fake drives the unit test.
type vmAccess interface {
	LauncherUID() (string, error) // identity of the virt-launcher pod (to detect the fault landed)
	Running() bool                // the VMI is in phase Running (the guest is back up)
}

type vmOracle struct {
	a       vmAccess
	origUID string
}

func (o *vmOracle) Name() string { return "vm-liveness" }

func (o *vmOracle) Drive(t *testing.T) map[string]bool {
	o.origUID, _ = o.a.LauncherUID()
	return map[string]bool{"vm-running": true} // the "acked unit" is a live VM; conserved by SteadyState
}

func (o *vmOracle) SteadyState() (bool, string, error) {
	uid, err := o.a.LauncherUID()
	if err != nil {
		return false, "", err
	}
	if uid == "" || uid == o.origUID {
		return false, "virt-launcher not yet replaced (fault not landed / not rescheduled)", nil
	}
	if !o.a.Running() {
		return false, "VMI has not returned to Running after the virt-launcher kill", nil
	}
	return true, "", nil
}

// Reconcile is a no-op: on the liveness plane the invariant is "the VM came back", which SteadyState
// already gates (a VM that never returns keeps SteadyState false → runOracle reds on the timeout).
func (o *vmOracle) Reconcile(ledger map[string]bool) []string { return nil }

// ---- live accessor (kubectl against the VMI + its virt-launcher pod) ----

type liveVM struct {
	ns       string
	vmi      string
	selector string
}

func (l liveVM) LauncherUID() (string, error) {
	return kubectl("-n", l.ns, "get", "pods", "-l", l.selector, "-o", "jsonpath={.items[0].metadata.uid}")
}
func (l liveVM) Running() bool {
	ph, err := kubectl("-n", l.ns, "get", "vmi", l.vmi, "-o", "jsonpath={.status.phase}")
	return err == nil && ph == "Running"
}

// TestVmLiveness — LIVE. The shell provisions the VM + injects the virt-launcher kill; this records
// the pre-fault launcher identity and judges that the VMI returns to Running through runOracle.
func TestVmLiveness(t *testing.T) {
	runOracle(t, &vmOracle{a: liveVM{
		ns:       envOr("CHAOS_SANDBOX_NS", "chaos-sandbox"),
		vmi:      envOr("VM_NAME", "vm"),
		selector: envOr("VM_LAUNCHER_SELECTOR", "kubevirt.io/domain=vm"),
	}})
}

// ---- prove-red (no cluster) ----

type fakeVM struct {
	uid     string
	running bool
}

func (f *fakeVM) LauncherUID() (string, error) { return f.uid, nil }
func (f *fakeVM) Running() bool                { return f.running }

func TestVmLivenessRedGreen(t *testing.T) {
	f := &fakeVM{uid: "launcher-1", running: true}
	o := &vmOracle{a: f}
	o.Drive(nil) // records origUID = launcher-1

	// Must NOT be steady on the pre-fault state (the VMI is Running before the kill too).
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("SteadyState must be false before the virt-launcher is replaced (pre-fault state)")
	}

	// RED (genuine, live-reachable): the fault landed (a new launcher was scheduled) but the VMI did
	// NOT return to Running — the VM did not recover. SteadyState stays false, so runOracle reds on
	// the liveness timeout. This is the real product failure on this plane.
	f.uid, f.running = "launcher-2", false
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("a VM that did not return to Running MUST NOT be steady (this is the liveness red)")
	}

	// GREEN: the VMI came back to Running under a replaced launcher.
	f.running = true
	if ok, _, _ := o.SteadyState(); !ok {
		t.Fatal("SteadyState must be true once a new launcher is up and the VMI is Running")
	}
	if lost := o.Reconcile(nil); len(lost) != 0 {
		t.Fatalf("liveness plane has no acked data unit; Reconcile must be empty, got %v", lost)
	}
}
