//go:build convergence

package main

// directory-auth plane — a RECOVER adapter on the singular runOracle. Conservation of acknowledged
// work on the IDENTITY plane: an account created before the fault must still exist after the Samba AD
// Domain Controller is killed and restarts from its stable domain-database PVC. If the account is
// gone, every domain-joined machine that trusted it has lost authentication — a release blocker.
//
// This owns only the VERDICT; chaos/scenario-directory-recover.sh provisions the kind: Directory DC,
// waits for the domain to actually serve (samba-tool answers), and injects the pod-scoped DC kill.
//
// The recover timing subtlety (identical to volume-durability): the DC serves BEFORE the kill too, so
// SteadyState must NOT report steady on the pre-fault state — otherwise runOracle would reconcile
// before the fault ever landed and bless a directory that was never disrupted. SteadyState therefore
// requires the fault to have LANDED (the DC pod uid changed — the kill replaced it) AND the restarted
// DC to serve again. Drive records the pre-fault pod identity.

import "testing"

// probe user is the acknowledged work — an AD account created before the fault that must survive it.
const dirProbeUser = "chaosprobe"

// dirAccess is the directory workload accessor. Live = kubectl exec into the DC pod (samba-tool); a
// fake drives the unit tests, so the verdict is provable RED/GREEN with no cluster.
type dirAccess interface {
	DCUID() (string, error) // identity of the DC pod (to detect the kill actually landed)
	CreateUser() error      // create the probe account (the acked work)
	Serving() bool          // the domain answers (samba-tool responds) in the current DC pod
	HasUser() (bool, error) // the probe account is still present in the directory
}

type dirOracle struct {
	a       dirAccess
	origUID string
}

func (o *dirOracle) Name() string { return "directory-auth" }

func (o *dirOracle) Drive(t *testing.T) map[string]bool {
	o.origUID, _ = o.a.DCUID()
	if err := o.a.CreateUser(); err != nil && t != nil {
		t.Fatalf("directory-auth: create probe account: %v", err)
	}
	return map[string]bool{"identity:" + dirProbeUser: true}
}

func (o *dirOracle) SteadyState() (bool, string, error) {
	uid, err := o.a.DCUID()
	if err != nil {
		return false, "", err
	}
	if uid == "" || uid == o.origUID {
		return false, "DC pod not yet replaced (fault not landed / not rescheduled)", nil
	}
	if !o.a.Serving() {
		return false, "restarted DC is not serving the domain again yet", nil
	}
	return true, "", nil
}

func (o *dirOracle) Reconcile(ledger map[string]bool) []string {
	has, err := o.a.HasUser()
	if err != nil || !has {
		return []string{"identity:" + dirProbeUser}
	}
	return nil
}

// ---- live accessor (kubectl exec into the DC pod) ----

type liveDir struct {
	ns   string
	pod  string
	user string
	pass string
}

func (l liveDir) DCUID() (string, error) {
	return kubectl("-n", l.ns, "get", "pod", l.pod, "-o", "jsonpath={.metadata.uid}")
}

func (l liveDir) CreateUser() error {
	// Tolerate an account left over from a prior run: create, and if that fails, treat it as OK only
	// when the account is already present (anything else is a genuine setup error).
	if kubectlOK("-n", l.ns, "exec", l.pod, "--", "samba-tool", "user", "create", l.user, l.pass) {
		return nil
	}
	if has, _ := l.HasUser(); has {
		return nil
	}
	// surface the real error from the create attempt
	_, err := kubectl("-n", l.ns, "exec", l.pod, "--", "samba-tool", "user", "create", l.user, l.pass)
	return err
}

func (l liveDir) Serving() bool {
	return kubectlOK("-n", l.ns, "exec", l.pod, "--", "samba-tool", "user", "list")
}

func (l liveDir) HasUser() (bool, error) {
	out, err := kubectl("-n", l.ns, "exec", l.pod, "--", "samba-tool", "user", "list")
	if err != nil {
		return false, err
	}
	for _, line := range splitLines(out) {
		if line == l.user {
			return true, nil
		}
	}
	return false, nil
}

// TestDirectoryAuth — LIVE. The shell provisions the Directory DC + injects the DC pod kill; this
// records the probe account and judges identity conservation across the DC restart.
func TestDirectoryAuth(t *testing.T) {
	runOracle(t, &dirOracle{a: liveDir{
		ns:   envOr("CHAOS_SANDBOX_NS", "chaos-sandbox"),
		pod:  envOr("DIR_DC_POD", "dir-dc-0"),
		user: envOr("DIR_PROBE_USER", dirProbeUser),
		pass: envOr("DIR_PROBE_PASS", "Aa1!chaosprobe99"),
	}})
}

// ---- prove-red (no cluster) ----

type fakeDir struct {
	uid     string
	serving bool
	hasUser bool
}

func (f *fakeDir) DCUID() (string, error) { return f.uid, nil }
func (f *fakeDir) CreateUser() error      { f.hasUser = true; return nil }
func (f *fakeDir) Serving() bool          { return f.serving }
func (f *fakeDir) HasUser() (bool, error) { return f.hasUser, nil }

func TestDirectoryAuthRedGreen(t *testing.T) {
	f := &fakeDir{uid: "u1", serving: true, hasUser: false}
	o := &dirOracle{a: f}
	o.Drive(nil) // records origUID = u1 and creates the probe account

	// Must NOT be steady while the DC pod hasn't been replaced (guards the pre-fault race — the DC
	// serves before the kill too, and reconciling here would bless a fault that never landed).
	if ok, _, _ := o.SteadyState(); ok {
		t.Fatal("SteadyState must be false before the DC pod is replaced (pre-fault state)")
	}

	// Fault lands: the kill replaced the DC pod and the restarted DC serves again.
	f.uid = "u2"
	if ok, _, _ := o.SteadyState(); !ok {
		t.Fatal("SteadyState must be true once the restarted DC serves the domain again")
	}

	// GREEN: the probe account survived the DC restart (domain database intact).
	if lost := o.Reconcile(nil); len(lost) != 0 {
		t.Fatalf("green: probe account intact but reported lost: %v", lost)
	}

	// RED: the DC recovered and serves, but the probe account is GONE — acknowledged identity lost
	// across the kill (the domain database did not survive; every joined machine loses auth).
	f.hasUser = false
	if lost := o.Reconcile(nil); len(lost) == 0 {
		t.Fatal("a lost directory account MUST be reported as lost work (RED)")
	}
}

// splitLines splits samba-tool output into trimmed non-empty lines (exact-match account lookup).
func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' || s[i] == '\r' {
			line := s[start:i]
			// trim surrounding spaces/tabs
			for len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				line = line[1:]
			}
			for len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
				line = line[:len(line)-1]
			}
			if line != "" {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	return out
}
