package render

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A setup pod can outlive its claim: provider-kubernetes deletes a setup Job without a propagation
// policy, batch/v1 then orphans the Job's pod, and an orphan keeps retrying (restartPolicy OnFailure).
// The setup re-checks its claim instance before it records, creates or mints anything, and creates
// nothing — successfully — once that instance is certainly gone. Doubt (a missing grant, another kind)
// changes nothing.
func TestBucketOwnership_SetupOfAGoneClaimCreatesNothing(t *testing.T) {
	needJQ(t)
	cases := []struct {
		name    string
		flag    string // a stub flag file
		content string
		env     []string
		gone    bool
	}{
		{name: "claim deleted", flag: "claim-gone", gone: true},
		{name: "composite deleted", flag: "xr-gone", gone: true},
		{name: "claim created again (a later composite)", flag: "xr-created", content: "2026-11-02T05:40:14Z", gone: true},
		{name: "the same instance", gone: false},
		{name: "the claim cannot be read (a missing grant)", flag: "claim-forbidden", gone: false},
		{name: "a kind with no claim check", flag: "claim-gone", env: []string{"OWNER_NS=team-a", "OWNER_REF=Widget/team-a/data", "XR_CREATED=" + xrCreated}, gone: false},
		{name: "no composite time", flag: "xr-created", content: "2026-11-02T05:40:14Z", env: []string{"OWNER_NS=team-a", "OWNER_REF=Bucket/team-a/data", "XR_CREATED="}, gone: false},
	}
	for _, sh := range posixShells(t) {
		for _, c := range cases {
			t.Run(shellName(sh)+"/"+c.name, func(t *testing.T) {
				e := newBktEnv(t, nil, nil)
				if c.flag != "" {
					writeFile(t, filepath.Join(e.dir, c.flag), c.content)
				}
				env := ownerEnv
				if c.env != nil {
					env = c.env
				}
				out, err := e.run(t, sh, claimScript(t, "data"), env...)
				if err != nil {
					t.Fatalf("setup failed: %v\n%s", err, out)
				}
				if c.gone {
					if strings.Contains(out, "CLAIMED") || !strings.Contains(out, "this setup creates nothing") {
						t.Errorf("a gone claim's setup must stop, successfully, before claiming:\n%s", out)
					}
					if got := e.read("records/bucket-owner-data"); got != "" {
						t.Errorf("a gone claim's setup recorded an owner: %q", got)
					}
					return
				}
				if !strings.Contains(out, "CLAIMED") {
					t.Errorf("the setup must carry on:\n%s", out)
				}
			})
		}
	}
}

// The rendered Bucket setup Job of a deleted claim, run as an orphaned pod would run it: no bucket, no
// configuration, no MinIO user, no credentials.
func TestBucketComposition_OrphanedSetupCreatesNothing(t *testing.T) {
	needJQ(t)
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	out := render(t, tmpl, bucketOwnCtx("open-infra-cfn", "stk-configbucket", map[string]any{"bucketName": "named-bucket", "versioning": true}))
	script := setupScript(t, out, "kind: Job")
	env := []string{"OWNER_NS=open-infra-cfn", "OWNER_REF=Bucket/open-infra-cfn/stk-configbucket", "XR_CREATED=" + xrCreated}
	for _, sh := range posixShells(t) {
		e := newBktEnv(t, nil, nil)
		writeFile(t, filepath.Join(e.dir, "claim-gone"), "")
		res, err := e.run(t, sh, runnable(t, script, e.tmp), env...)
		if err != nil {
			t.Fatalf("%s: an orphaned setup must end successfully (a failure is retried forever): %v\n%s", shellName(sh), err, res)
		}
		for _, f := range []string{"records/bucket-owner-named-bucket", "made.txt", "configured.txt", "users.txt", "applied.txt"} {
			if got := e.read(f); got != "" {
				t.Errorf("%s: %s written by a deleted claim's setup: %q", shellName(sh), f, got)
			}
		}
	}
}

// A stack deleted and created again within seconds (the bucket has an explicit name): the stack delete
// removed the bucket, but the earlier instance's owner record is still there (the reaper never removes
// it once the claim exists again). The new instance takes the record over and creates the bucket — and a
// bucket that disappears between the two reads counts as empty.
func TestBucketOwnership_GoneBucketOfAnEarlierInstanceIsTakenOver(t *testing.T) {
	needJQ(t)
	const earlier = "2026-09-01T00:00:00Z"
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh)+"/bucket gone", func(t *testing.T) {
			e := newBktEnv(t, map[string]string{"bucket-owner-data": "team-a|Bucket/team-a/data|" + earlier}, nil)
			out, err := e.run(t, sh, claimScript(t, "data"), ownerEnv...)
			if err != nil || !strings.Contains(out, "CLAIMED") {
				t.Fatalf("the re-created claim must take over the record of its gone bucket: %v\n%s", err, out)
			}
			if !strings.Contains(out, "no longer exists; its record is taken over") {
				t.Errorf("output does not say why:\n%s", out)
			}
			if got := e.read("records/bucket-owner-data.instance"); got != xrCreated {
				t.Errorf("record instance = %q, want %q", got, xrCreated)
			}
		})
		t.Run(shellName(sh)+"/bucket removed between the reads", func(t *testing.T) {
			e := newBktEnv(t, map[string]string{"bucket-owner-data": "team-a|Bucket/team-a/data|" + earlier},
				map[string]string{"data": "2026-09-01T00:00:00+00:00"})
			writeFileMode(t, filepath.Join(e.dir, "nosuchbucket", "data"), "", 0o644)
			out, err := e.run(t, sh, claimScript(t, "data"), ownerEnv...)
			if err != nil || !strings.Contains(out, "CLAIMED") {
				t.Fatalf("NoSuchBucket must count as empty: %v\n%s", err, out)
			}
			if got := e.read("records/bucket-owner-data.instance"); got != xrCreated {
				t.Errorf("record instance = %q, want %q", got, xrCreated)
			}
		})
	}
}

// The full Bucket setup of a fast same-name re-create, end to end: the earlier instance's record is
// still there, its bucket is gone; the new setup takes the record over and creates the bucket (the
// earlier credentials' rotation: bucket_creds_rotation_test.go).
func TestBucketComposition_FastSameNameRecreate(t *testing.T) {
	needJQ(t)
	const earlier = "2026-09-01T00:00:00Z"
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	out := render(t, tmpl, bucketOwnCtx("open-infra-cfn", "stk-configbucket", map[string]any{"bucketName": "named-bucket", "versioning": true}))
	script := setupScript(t, out, "kind: Job")
	env := []string{"OWNER_NS=open-infra-cfn", "OWNER_REF=Bucket/open-infra-cfn/stk-configbucket", "XR_CREATED=" + xrCreated}
	for _, sh := range posixShells(t) {
		e := newBktEnv(t, map[string]string{"bucket-owner-named-bucket": "open-infra-cfn|Bucket/open-infra-cfn/stk-configbucket|" + earlier}, nil)
		res, err := e.run(t, sh, runnable(t, script, e.tmp), env...)
		if err != nil {
			t.Fatalf("%s: the re-create's setup failed: %v\n%s", shellName(sh), err, res)
		}
		if !strings.Contains(e.read("made.txt"), "named-bucket") {
			t.Errorf("%s: the bucket was not created again:\n%s", shellName(sh), res)
		}
		if got := e.read("records/bucket-owner-named-bucket.instance"); got != xrCreated {
			t.Errorf("%s: record instance = %q, want %q", shellName(sh), got, xrCreated)
		}
	}
}

// mint_scoped_user of a deleted claim (an orphaned pod past claim_bucket) mints nothing.
func TestMintScopedUser_GoneClaimMintsNothing(t *testing.T) {
	lib := extractDataScript(t, providerSetupPath, "bucket-ownership.sh")
	stubs := `
LOG="$STUB/calls"
kubectl() {
  echo "kubectl $*" >> "$LOG"
  case "$*" in
    *"jsonpath={.spec.resourceRef.name}"*) echo "Error from server (NotFound): buckets.openinfra.dev \"data\" not found" >&2; return 1 ;;
  esac
  return 0
}
MC_() { echo "mc $*" >> "$LOG"; return 0; }
MC=MC_
OWN_NS=openinfra-bucket-creds
OWNER_REF=Bucket/team-a/data
`
	for _, sh := range posixShells(t) {
		dir := t.TempDir()
		script := lib + "\n" + stubs + "\nmint_scoped_user app-team-a-data /dev/null\necho MINTED\n"
		cmd := exec.Command(sh[0], append(append([]string{}, sh[1:]...), "-c", script)...)
		cmd.Env = append(os.Environ(), "STUB="+dir, "XR_CREATED="+xrCreated, "TMPDIR="+dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", shellName(sh), err, out)
		}
		calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
		if strings.Contains(string(out), "MINTED") || strings.Contains(string(calls), "mc ") || strings.Contains(string(calls), "MINIO_SECRET_KEY") {
			t.Errorf("%s: a gone claim's credentials were touched:\n%s\ncalls:\n%s", shellName(sh), out, calls)
		}
	}
}
