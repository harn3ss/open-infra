//go:build convergence

package main

// fileshare-durability plane — a RECOVER adapter on the singular runOracle. Conservation of
// acknowledged work on the FILE plane: a file written over SMB before the Samba server is killed
// must still be readable after the share restarts, and the recovered share must accept a NEW write
// (fully functional, not read-only-stale). This replaces the bash verdict in
// chaos/scenario-fileshare-durable.sh with a verdict routed through the shared engine.
//
// The recover timing subtlety (identical to volume-durability): the share answers SMB before the
// kill too, so SteadyState must NOT report steady on the pre-fault state — it requires the fault to
// have LANDED (the Samba pod's identity changed) AND the restarted share to serve SMB again. The
// adapter records the pre-fault pod identity in Drive.

import (
	"encoding/base64"
	"strings"
	"testing"
)

const fsProbePayload = "chaos-probe-payload"

// fsAccess is the SMB workload accessor — only the operations the adapter needs, behind a seam.
// Live = kubectl exec smbclient into the probe pod over the Service; a fake drives the unit tests,
// so the verdict is provable RED/GREEN with no cluster.
type fsAccess interface {
	SmbUID() (string, error) // identity of the Samba pod (to detect the kill landed)
	WriteProbe() error       // write the probe file over SMB (the acked work)
	Serving() bool           // the share answers SMB right now (ls succeeds)
	HasProbe() bool          // the probe file is still present on the share
	AcceptsWrite() bool      // the share accepts a NEW write (not read-only-stale)
}

type fsOracle struct {
	a       fsAccess
	origUID string
}

func (o *fsOracle) Name() string { return "fileshare-durability" }

func (o *fsOracle) Drive(t *testing.T) map[string]bool {
	o.origUID, _ = o.a.SmbUID()
	if err := o.a.WriteProbe(); err != nil && t != nil {
		t.Fatalf("fileshare-durability: write probe file: %v", err)
	}
	return map[string]bool{"probe-file": true}
}

func (o *fsOracle) SteadyState() (bool, string, error) {
	uid, err := o.a.SmbUID()
	if err != nil {
		return false, "", err
	}
	if uid == "" || uid == o.origUID {
		return false, "Samba pod not yet replaced (fault not landed / not rescheduled)", nil
	}
	if !o.a.Serving() {
		return false, "restarted share not answering SMB yet", nil
	}
	return true, "", nil
}

func (o *fsOracle) Reconcile(ledger map[string]bool) []string {
	if !o.a.HasProbe() {
		return []string{"probe-file"} // file data lost across the kill
	}
	if !o.a.AcceptsWrite() {
		return []string{"probe-file"} // recovered with data but read-only-stale
	}
	return nil
}

// ---- live accessor (kubectl exec smbclient into the fs-client probe pod) ----

type liveFS struct {
	ns       string
	pass     string
	selector string
}

// smb runs one smbclient command against the share over the Service and returns its stdout.
// smbclient (dperson/samba) commonly exits non-zero even on a successful listing, so the error is
// ignored and only the OUTPUT is judged — a real failure just yields empty output.
func (l liveFS) smb(cmd string) string {
	out, _ := kubectl("-n", l.ns, "exec", "fs-client", "--", "smbclient",
		"//fs."+l.ns+".svc.cluster.local/fs", "-U", "openinfra%"+l.pass, "-c", cmd)
	return out
}

func (l liveFS) SmbUID() (string, error) {
	return kubectl("-n", l.ns, "get", "pods", "-l", l.selector,
		"-o", "jsonpath={.items[0].metadata.uid}")
}

func (l liveFS) WriteProbe() error {
	if _, err := kubectl("-n", l.ns, "exec", "fs-client", "--", "sh", "-c",
		"echo "+fsProbePayload+" > /tmp/probe.txt"); err != nil {
		return err
	}
	l.smb("put /tmp/probe.txt probe.txt")
	return nil
}

func (l liveFS) Serving() bool { return strings.Contains(l.smb("ls"), ".") }

func (l liveFS) HasProbe() bool { return strings.Contains(l.smb("ls"), "probe.txt") }

func (l liveFS) AcceptsWrite() bool {
	l.smb("put /tmp/probe.txt probe2.txt")
	return strings.Contains(l.smb("ls"), "probe2.txt")
}

// TestFileshareDurability — LIVE. The shell provisions the kind: FileShare + smbclient probe pod and
// injects the Samba pod kill; this drives the probe file and judges conservation across the restart.
func TestFileshareDurability(t *testing.T) {
	ns := envOr("CHAOS_SANDBOX_NS", "chaos-sandbox")
	enc, err := kubectl("-n", ns, "get", "secret", envOr("FS_SECRET", "fs-fileshare"),
		"-o", "jsonpath={.data.PASSWORD}")
	if err != nil {
		t.Fatalf("fileshare-durability: read password secret: %v", err)
	}
	pw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		t.Fatalf("fileshare-durability: decode password secret: %v", err)
	}
	runOracle(t, &fsOracle{a: liveFS{
		ns:       ns,
		pass:     string(pw),
		selector: envOr("FS_SELECTOR", "app=fs-smb"),
	}})
}

// ---- prove-red (no cluster) ----

type fakeFS struct {
	uid      string
	serving  bool
	hasProbe bool
	accepts  bool
}

func (f *fakeFS) SmbUID() (string, error) { return f.uid, nil }
func (f *fakeFS) WriteProbe() error       { return nil }
func (f *fakeFS) Serving() bool           { return f.serving }
func (f *fakeFS) HasProbe() bool          { return f.hasProbe }
func (f *fakeFS) AcceptsWrite() bool      { return f.accepts }

func TestFileshareDurabilityRedGreen(t *testing.T) {
	f := &fakeFS{uid: "p1", serving: true, hasProbe: true, accepts: true}
	o := &fsOracle{a: f}
	o.Drive(nil) // records origUID = p1, writes the probe file

	// Must NOT be steady while the Samba pod hasn't been replaced (guards the pre-fault race —
	// the share answers SMB before the kill too, so a bare "serving?" check would false-green).
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("SteadyState must be false before the Samba pod is replaced (pre-fault state)")
	}

	// Fault lands: a new Samba pod restarts the share.
	f.uid = "p2"
	if ok, _, _ := o.SteadyState(); !ok {
		t.Fatal("SteadyState must be true once a replacement Samba pod serves SMB again")
	}

	// GREEN: probe file intact and the share accepts new writes across the restart.
	if lost := o.Reconcile(nil); len(lost) != 0 {
		t.Fatalf("green: probe file survived but reported lost: %v", lost)
	}

	// RED: the share recovered but the probe file is GONE — lost acknowledged work.
	f.hasProbe = false
	if lost := o.Reconcile(nil); len(lost) == 0 {
		t.Fatal("a lost probe file MUST be reported as lost work (RED)")
	}

	// RED: file present but the recovered share is read-only-stale (won't accept a new write).
	f.hasProbe = true
	f.accepts = false
	if lost := o.Reconcile(nil); len(lost) == 0 {
		t.Fatal("a recovered-but-read-only share MUST be reported as lost work (RED)")
	}
}
