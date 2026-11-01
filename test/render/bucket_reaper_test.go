package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const bucketReaperPath = "../../platform/abstraction/bucket-reaper.yaml"

// The reaper's stubs: claims and composites are files ($STUB/claims/<plural>/<ns>/<name> holds the
// composite name, $STUB/xrs/<name> its creation time); secrets come from $STUB/creds.tsv and
// $STUB/recs.tsv; every mutation is appended to $STUB/actions.log.
const reaperStubKubectl = `#!/bin/sh
case "$*" in
  "get secrets -n openinfra-bucket-creds -l openinfra.dev/scoped-creds=true -o jsonpath="*) cat "$STUB/creds.tsv" 2>/dev/null; exit 0 ;;
  "get secrets -n openinfra-bucket-creds -l openinfra.dev/bucket-owner=true -o jsonpath="*) cat "$STUB/recs.tsv" 2>/dev/null; exit 0 ;;
  "get x"*".openinfra.dev "*" -o jsonpath={.metadata.creationTimestamp}")
    [ -f "$STUB/fail-get" ] && { echo "stub: apiserver unavailable" >&2; exit 1; }
    [ -f "$STUB/xrs/$3" ] && { cat "$STUB/xrs/$3"; exit 0; }
    echo "Error from server (NotFound): $2 \"$3\" not found" >&2; exit 1 ;;
  "get "*".openinfra.dev "*" -n "*" -o jsonpath={.spec.resourceRef.name}")
    [ -f "$STUB/fail-get" ] && { echo "stub: apiserver unavailable" >&2; exit 1; }
    pl=${2%.openinfra.dev}
    [ -f "$STUB/claims/$pl/$5/$3" ] && { cat "$STUB/claims/$pl/$5/$3"; exit 0; }
    echo "Error from server (NotFound): $2 \"$3\" not found" >&2; exit 1 ;;
  "delete secret "*) echo "delete-secret $3" >> "$STUB/actions.log" ;;
  "patch secret "*) echo "patch $3 $9" >> "$STUB/actions.log" ;;
  "label secret "*) echo "label $3 $6" >> "$STUB/actions.log" ;;
  *) echo "stub kubectl: unhandled: $*" >&2; exit 99 ;;
esac
`

const reaperStubMc = `#!/bin/sh
case "$1 $2 $3" in
  "alias set m") : ;;
  "admin user rm") echo "user-rm $5" >> "$STUB/actions.log" ;;
  "admin policy rm") echo "policy-rm $5" >> "$STUB/actions.log" ;;
  "rb m/"*) echo "rb ${2#m/}" >> "$STUB/actions.log" ;;
  *) case "$1" in rb) echo "rb ${2#m/}" >> "$STUB/actions.log" ;; *) echo "stub mc: unhandled: $*" >&2; exit 99 ;; esac ;;
esac
`

const reaperStubAws = `#!/bin/sh
[ "$1" = "--endpoint-url" ] && shift 2
case "$1 $2" in
  "s3api list-buckets")
    b=${4#*Name==\'}; b=${b%%\'*}
    if [ -f "$STUB/buckets/$b" ]; then cat "$STUB/buckets/$b"; else echo None; fi ;;
  "s3api list-object-versions")
    [ -f "$STUB/fail-list/$4" ] && { echo "stub: cannot list" >&2; exit 1; }
    [ -f "$STUB/objects/$4" ] && echo '{"Versions":[{"Key":"k"}]}' || echo '{}' ;;
  *) echo "stub aws: unhandled: $*" >&2; exit 99 ;;
esac
`

type reaperEnv struct {
	dir, bin string
	creds    []string // user \t owner \t instance
	recs     []string // record \t owner \t instance \t orphaned
}

func newReaperEnv(t *testing.T) *reaperEnv {
	t.Helper()
	root := t.TempDir()
	e := &reaperEnv{dir: filepath.Join(root, "stub"), bin: filepath.Join(root, "bin")}
	for _, d := range []string{e.dir, e.bin, filepath.Join(e.dir, "xrs"), filepath.Join(e.dir, "buckets"), filepath.Join(e.dir, "objects"), filepath.Join(e.dir, "fail-list")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"kubectl": reaperStubKubectl, "mc": reaperStubMc, "aws": reaperStubAws} {
		writeFileMode(t, filepath.Join(e.bin, name), body, 0o755)
	}
	return e
}

func writeFileMode(t *testing.T, p, s string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), mode); err != nil {
		t.Fatal(err)
	}
}

// claim makes a live claim (plural/ns/name) whose composite xr was created at made.
func (e *reaperEnv) claim(t *testing.T, plural, ns, name, xr, made string) {
	writeFileMode(t, filepath.Join(e.dir, "claims", plural, ns, name), xr, 0o644)
	writeFileMode(t, filepath.Join(e.dir, "xrs", xr), made, 0o644)
}

func (e *reaperEnv) run(t *testing.T, sh []string) (string, string) {
	t.Helper()
	writeFileMode(t, filepath.Join(e.dir, "creds.tsv"), strings.Join(e.creds, "\n")+"\n", 0o644)
	writeFileMode(t, filepath.Join(e.dir, "recs.tsv"), strings.Join(e.recs, "\n")+"\n", 0o644)
	own := filepath.Join(e.dir, "bucket-ownership.sh")
	writeFileMode(t, own, extractDataScript(t, providerSetupPath, "bucket-ownership.sh"), 0o644)
	script := setupScript(t, mustRead(t, bucketReaperPath), "name: reaper")
	env := bktEnv{dir: e.dir, path: e.bin + string(os.PathListSeparator) + os.Getenv("PATH"), tmp: t.TempDir()}
	out, err := env.run(t, sh, script, "OWNERSHIP_SH="+own, "MC="+filepath.Join(e.bin, "mc"), "WATCH_SECONDS=0")
	if err != nil {
		t.Fatalf("reaper exited non-zero: %v\n%s", err, out)
	}
	return out, env.read("actions.log")
}

const live, earlier = "2026-10-23T02:55:58Z", "2026-09-01T00:00:00Z"

func TestBucketReaper_Credentials(t *testing.T) {
	for _, sh := range posixShells(t) {
		e := newReaperEnv(t)
		e.claim(t, "buckets", "team-a", "live", "live-x1", live)
		e.claim(t, "buckets", "team-a", "again", "again-x2", live) // re-created: a newer composite
		e.creds = []string{
			"app-dead\tBucket/team-a/dead\t" + live,      // claim deleted → reaped
			"app-live\tBucket/team-a/live\t" + live,      // same instance → kept
			"app-again\tBucket/team-a/again\t" + earlier, // an earlier instance → reaped
			"app-odd\tWidget/team-a/thing\t" + live,      // unknown kind → kept
			"app-noinst\tStaticSite/team-a/live-site\t",  // claim gone, no instance → reaped
			"app-unmarked\t\t",                           // no owner yet → kept
		}
		_, acts := e.run(t, sh)
		for _, want := range []string{"user-rm app-dead", "delete-secret app-dead", "user-rm app-again", "delete-secret app-again", "user-rm app-noinst"} {
			if !strings.Contains(acts, want+"\n") {
				t.Errorf("%s: missing %q in actions:\n%s", shellName(sh), want, acts)
			}
		}
		for _, keep := range []string{"app-live", "app-odd", "app-unmarked"} {
			if strings.Contains(acts, keep+"\n") {
				t.Errorf("%s: %s should be kept; actions:\n%s", shellName(sh), keep, acts)
			}
		}
	}
}

func TestBucketReaper_ApiErrorsNeverReap(t *testing.T) {
	for _, sh := range posixShells(t) {
		e := newReaperEnv(t)
		writeFileMode(t, filepath.Join(e.dir, "fail-get"), "", 0o644)
		e.creds = []string{"app-x\tBucket/team-a/x\t" + live}
		e.recs = []string{"bucket-owner-x\t" + b64("Bucket/team-a/x") + "\t" + b64(live) + "\t"}
		writeFileMode(t, filepath.Join(e.dir, "buckets", "x"), "2026-09-01T00:00:00+00:00\n", 0o644)
		_, acts := e.run(t, sh)
		if strings.TrimSpace(acts) != "" {
			t.Errorf("%s: an API error must reap nothing; actions:\n%s", shellName(sh), acts)
		}
	}
}

func TestBucketReaper_Buckets(t *testing.T) {
	for _, sh := range posixShells(t) {
		e := newReaperEnv(t)
		e.claim(t, "buckets", "team-a", "live", "live-x1", live)
		e.claim(t, "buckets", "team-a", "legacy", "legacy-x1", live)
		rec := func(b, owner, inst, orphan string) string {
			return "bucket-owner-" + b + "\t" + b64(owner) + "\t" + b64(inst) + "\t" + orphan
		}
		e.recs = []string{
			rec("empty", "Bucket/team-a/gone1", live, ""),    // deleted claim, empty bucket → rb + record
			rec("full", "Bucket/team-a/gone2", live, ""),     // deleted claim, data → kept, labelled
			rec("vanished", "Bucket/team-a/gone3", live, ""), // deleted claim, bucket already gone → record
			rec("listfail", "Bucket/team-a/gone4", live, ""), // can't list it → skipped
			rec("live", "Bucket/team-a/live", live, ""),      // live → kept
			rec("legacy", "Bucket/team-a/legacy", "", ""),    // live, no instance → instance recorded
			rec("velero", "Bucket/team-a/gone5", live, ""),   // platform bucket → never
			"bucket-owner-nsonly\t\t\t",                      // legacy namespace-only record → skipped
			rec("orph", "Bucket/team-a/gone6", live, "true"), // already labelled → not relabelled
		}
		for _, b := range []string{"empty", "full", "listfail", "live", "legacy", "velero", "orph"} {
			writeFileMode(t, filepath.Join(e.dir, "buckets", b), "2026-09-01T00:00:00+00:00\n", 0o644)
		}
		writeFileMode(t, filepath.Join(e.dir, "objects", "full"), "k", 0o644)
		writeFileMode(t, filepath.Join(e.dir, "objects", "orph"), "k", 0o644)
		writeFileMode(t, filepath.Join(e.dir, "fail-list", "listfail"), "", 0o644)
		_, acts := e.run(t, sh)
		for _, want := range []string{
			"rb empty", "delete-secret bucket-owner-empty",
			"label bucket-owner-full openinfra.dev/orphaned=true",
			"delete-secret bucket-owner-vanished",
			`patch bucket-owner-legacy {"stringData":{"instance":"` + live + `"}}`,
		} {
			if !strings.Contains(acts, want+"\n") {
				t.Errorf("%s: missing %q in actions:\n%s", shellName(sh), want, acts)
			}
		}
		for _, never := range []string{"rb full", "bucket-owner-full\n", "listfail", "bucket-owner-live", "velero", "nsonly", "bucket-owner-orph", "rb orph"} {
			if strings.Contains(acts, never) {
				t.Errorf("%s: unexpected action matching %q:\n%s", shellName(sh), never, acts)
			}
		}
	}
}
