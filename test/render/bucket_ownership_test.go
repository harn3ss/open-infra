package render

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Bucket ownership (provider-setup.yaml's openinfra-bucket-ownership script, sourced by every
// bucket-setup Job). These tests run the script, and the rendered Bucket setup Job, against stub
// kubectl / aws / mc binaries under every POSIX shell available (busybox ash first: the alpine/k8s
// image's shell), and check the compositions all call it before they create or grant anything.

const (
	providerSetupPath     = "../../platform/abstraction/provider-setup.yaml"
	bucketCompositionPath = "../../platform/abstraction/bucket-composition.yaml"
)

// extractDataScript returns the `<key>: |` block scalar of a ConfigMap manifest, dedented.
func extractDataScript(t *testing.T, path, key string) string {
	t.Helper()
	lines := strings.Split(mustRead(t, path), "\n")
	start, keyIndent := -1, 0
	for i, ln := range lines {
		if strings.TrimSpace(ln) == key+": |" {
			start, keyIndent = i+1, len(ln)-len(strings.TrimLeft(ln, " "))
			break
		}
	}
	if start < 0 {
		t.Fatalf("no %q block in %s", key, filepath.Base(path))
	}
	return dedentBlock(lines[start:], keyIndent)
}

// dedentBlock returns the block scalar lines (indented deeper than keyIndent), dedented.
func dedentBlock(lines []string, keyIndent int) string {
	contentIndent := -1
	var out []string
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			out = append(out, "")
			continue
		}
		ind := len(ln) - len(strings.TrimLeft(ln, " "))
		if ind <= keyIndent {
			break
		}
		if contentIndent < 0 {
			contentIndent = ind
		}
		if ind < contentIndent {
			break
		}
		out = append(out, ln[contentIndent:])
	}
	return strings.Join(out, "\n") + "\n"
}

// setupScript returns the first `args: - |` script after the line containing marker, in rendered output.
func setupScript(t *testing.T, rendered, marker string) string {
	t.Helper()
	lines := strings.Split(rendered, "\n")
	at := -1
	for i, ln := range lines {
		if strings.Contains(ln, marker) {
			at = i
			break
		}
	}
	if at < 0 {
		t.Fatalf("no %q in rendered output", marker)
	}
	for i := at; i+1 < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "args:" && strings.TrimSpace(lines[i+1]) == "- |" {
			ln := lines[i+1]
			return dedentBlock(lines[i+2:], len(ln)-len(strings.TrimLeft(ln, " ")))
		}
	}
	t.Fatalf("no args script after %q", marker)
	return ""
}

const bktStubKubectl = `#!/bin/sh
echo "kubectl $*" >> "$STUB/calls.log"
case "$*" in
  "get secret bucket-owner-"*" -n openinfra-bucket-creds --ignore-not-found -o jsonpath={.data.namespace}")
    [ -f "$STUB/fail-get" ] && { echo "stub: apiserver unavailable" >&2; exit 1; }
    [ -f "$STUB/records/$3" ] && printf '%s' "$(cat "$STUB/records/$3")" | base64 | tr -d '\n'
    exit 0 ;;
  "get secret bucket-owner-"*" -n openinfra-bucket-creds --ignore-not-found -o jsonpath={.data.owner}")
    [ -f "$STUB/fail-get" ] && { echo "stub: apiserver unavailable" >&2; exit 1; }
    [ -f "$STUB/records/$3.owner" ] && printf '%s' "$(cat "$STUB/records/$3.owner")" | base64 | tr -d '\n'
    exit 0 ;;
  "create secret generic bucket-owner-"*" --dry-run=client -o yaml")
    ns=""; ow=""; for a in "$@"; do case "$a" in --from-literal=namespace=*) ns=${a#--from-literal=namespace=} ;; --from-literal=owner=*) ow=${a#--from-literal=owner=} ;; esac; done
    printf 'name=%s\nowner-namespace=%s\nowner-ref=%s\n' "$4" "$ns" "$ow" ;;
  "label --local -f - openinfra.dev/bucket-owner=true -o yaml") cat; echo "label=openinfra.dev/bucket-owner" ;;
  "create -f -")
    obj=$(cat); name=$(printf '%s\n' "$obj" | sed -n 's/^name=//p'); ns=$(printf '%s\n' "$obj" | sed -n 's/^owner-namespace=//p'); ow=$(printf '%s\n' "$obj" | sed -n 's/^owner-ref=//p')
    [ -f "$STUB/race/$name" ] && cp "$STUB/race/$name" "$STUB/records/$name"
    if [ -f "$STUB/records/$name" ]; then echo "Error from server (AlreadyExists): secrets \"$name\" already exists" >&2; exit 1; fi
    printf '%s' "$ns" > "$STUB/records/$name"
    printf '%s' "$ow" > "$STUB/records/$name.owner"
    printf '%s\n' "$obj" >> "$STUB/created.txt" ;;
  # The platform-side scoped-credentials Secret (openinfra-bucket-creds/<user>): read its key (empty
  # unless a test seeded $STUB/pcreds/<user>), and record a write by emitting its literals for apply.
  "get secret "*" -n openinfra-bucket-creds -o jsonpath={.data.MINIO_SECRET_KEY}")
    [ -f "$STUB/pcreds/$3" ] && printf '%s' "$(cat "$STUB/pcreds/$3")" | base64 | tr -d '\n'
    exit 0 ;;
  "create secret generic "*"-n openinfra-bucket-creds --from-literal=MINIO_ACCESS_KEY="*"--dry-run=client -o yaml")
    printf 'pcreds-secret %s\n' "$4"; printf '%s\n' "$@" | tr ' ' '\n' | grep -- '--from-literal=MINIO_' ;;
  # Legacy path (compositions not yet on the scoped model): the Job writes the claim Secret directly.
  "get secret "*"-minio -n "*" -o jsonpath={.data.MINIO_SECRET_KEY}") exit 1 ;;
  "create secret generic "*"-minio -n "*" --dry-run=client -o yaml") printf 'secret %s\n' "$4"; printf '%s\n' "$@" | grep -- '--from-literal=MINIO_ACCESS_KEY=' ;;
  "apply -f -") cat >> "$STUB/applied.txt" ;;
  *) echo "stub kubectl: unhandled: $*" >&2; exit 99 ;;
esac
`

const bktStubAws = `#!/bin/sh
echo "aws $*" >> "$STUB/calls.log"
[ "$1" = "--endpoint-url" ] && shift 2
case "$1 $2" in
  "s3api list-buckets")
    [ -f "$STUB/fail-list" ] && { echo "stub: minio unreachable" >&2; exit 255; }
    b=${4#*Name==\'}; b=${b%%\'*}
    if [ -f "$STUB/buckets/$b" ]; then cat "$STUB/buckets/$b"; else echo None; fi ;;
  "s3 mb") b=${3#s3://}; echo "$b" >> "$STUB/made.txt"; echo "make_bucket: $b" ;;
  "s3api "*) echo "$*" >> "$STUB/configured.txt" ;;
  *) echo "stub aws: unhandled: $*" >&2; exit 99 ;;
esac
`

const bktStubMc = `#!/bin/sh
echo "mc $*" >> "$STUB/calls.log"
mkdir -p "$STUB/miniousers"
case "$1 $2 $3" in
  "alias set m") : ;;
  "mb --ignore-existing"*) echo "${3#m/}" >> "$STUB/made.txt" ;;
  "admin user add") echo "$5" >> "$STUB/users.txt"; : > "$STUB/miniousers/$5" ;;  # add <alias> <user> <key>
  "admin user info") [ -f "$STUB/miniousers/$5" ] || { echo "user $5 not found" >&2; exit 1; } ;;  # info <alias> <user>
  "admin policy "*) : ;;
  *) echo "stub mc: unhandled: $*" >&2; exit 99 ;;
esac
`

type bktEnv struct{ dir, path, tmp string }

// newBktEnv: records maps an owner-record name to its namespace; buckets maps a bucket to its
// creation time (existing buckets).
func newBktEnv(t *testing.T, records, buckets map[string]string) bktEnv {
	t.Helper()
	root := t.TempDir()
	e := bktEnv{dir: filepath.Join(root, "stub"), tmp: filepath.Join(root, "tmp")}
	bin := filepath.Join(root, "bin")
	for _, d := range []string{e.dir, e.tmp, bin, filepath.Join(e.dir, "records"), filepath.Join(e.dir, "buckets"), filepath.Join(e.dir, "race")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stubs := map[string]string{"kubectl": bktStubKubectl, "aws": bktStubAws, "mc": bktStubMc}
	// Exercise busybox's date (the runtime one) when it's here.
	if _, err := exec.LookPath("busybox"); err == nil {
		stubs["date"] = "#!/bin/sh\nexec busybox date \"$@\"\n"
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A record value is the owning namespace, or "namespace|owner-ref" to also seed the modern owner
	// field (a value with no "|" is a legacy record with no owner, exercising the namespace fallback).
	for k, v := range records {
		ns, owner, modern := strings.Cut(v, "|")
		writeFile(t, filepath.Join(e.dir, "records", k), ns)
		if modern {
			writeFile(t, filepath.Join(e.dir, "records", k+".owner"), owner)
		}
	}
	for k, v := range buckets {
		writeFile(t, filepath.Join(e.dir, "buckets", k), v+"\n")
	}
	e.path = bin + string(os.PathListSeparator) + os.Getenv("PATH")
	return e
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e bktEnv) run(t *testing.T, sh []string, script string, env ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), reconcilerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh[0], append(sh[1:], "-c", script)...)
	cmd.Env = append([]string{"PATH=" + e.path, "STUB=" + e.dir, "TMPDIR=" + e.tmp, "HOME=" + e.tmp,
		"E=http://minio.test:9000", "AWS_ACCESS_KEY_ID=root", "AWS_SECRET_ACCESS_KEY=rootpw"}, env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (e bktEnv) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(e.dir, name))
	return string(b)
}

// ownerEnv is a claim in team-a whose composite was created at xrCreated.
const xrCreated = "2026-10-23T02:55:58Z"

var ownerEnv = []string{"OWNER_NS=team-a", "OWNER_REF=Bucket/team-a/data", "XR_CREATED=" + xrCreated}

func claimScript(t *testing.T, bucket string) string {
	return extractDataScript(t, providerSetupPath, "bucket-ownership.sh") + "claim_bucket " + bucket + "\necho CLAIMED\n"
}

func TestBucketOwnership_ScriptParses(t *testing.T) {
	script := extractDataScript(t, providerSetupPath, "bucket-ownership.sh")
	for _, sh := range posixShells(t) {
		if out, err := exec.Command(sh[0], append(sh[1:], "-n", "-c", script)...).CombinedOutput(); err != nil {
			t.Errorf("bucket-ownership.sh does not parse under %s: %v\n%s", shellName(sh), err, out)
		}
	}
}

func TestBucketOwnership_Claim(t *testing.T) {
	needJQ(t)
	cases := []struct {
		name          string
		bucket        string
		records       map[string]string // owner record -> namespace
		buckets       map[string]string // existing bucket -> creation time
		race          string            // namespace that records the bucket between our read and our create
		env           []string
		wantOK        bool
		wantRecord    string // namespace the record holds afterwards ("" = no record)
		wantOutSubstr string
	}{
		{name: "new bucket is recorded to this namespace", bucket: "data",
			wantOK: true, wantRecord: "team-a", wantOutSubstr: "recorded as owned by Bucket/team-a/data"},
		{name: "own bucket is used (legacy record, namespace fallback)", bucket: "data", records: map[string]string{"bucket-owner-data": "team-a"},
			buckets: map[string]string{"data": "2026-09-01T00:00:00+00:00"}, wantOK: true, wantRecord: "team-a"},
		{name: "own bucket is used (modern record, identity match)", bucket: "data", records: map[string]string{"bucket-owner-data": "team-a|Bucket/team-a/data"},
			buckets: map[string]string{"data": "2026-09-01T00:00:00+00:00"}, wantOK: true, wantRecord: "team-a"},
		{name: "another namespace's bucket is refused", bucket: "data", records: map[string]string{"bucket-owner-data": "team-b"},
			buckets: map[string]string{"data": "2026-10-24T00:00:00+00:00"}, wantRecord: "team-b",
			wantOutSubstr: "BucketAlreadyExists: bucket data belongs to another namespace (team-b)"},
		// The CloudFormation case: another claim in the SAME namespace (every stack lives in
		// open-infra-cfn) must not adopt this claim's bucket by naming it. Identity, not namespace.
		{name: "same namespace, different claim is refused", bucket: "data",
			records: map[string]string{"bucket-owner-data": "team-a|Bucket/team-a/other"},
			buckets: map[string]string{"data": "2026-10-24T00:00:00+00:00"}, wantRecord: "team-a",
			wantOutSubstr: "BucketAlreadyExists: bucket data belongs to another claim (Bucket/team-a/other)"},
		// A claim that uses a bucket rather than being one — a StaticSite (a CloudFront origin) serving a
		// bucket its stack's kind: Bucket created — may use it within the owning namespace, and only there.
		{name: "a StaticSite serves a bucket another claim in its namespace owns", bucket: "data",
			records: map[string]string{"bucket-owner-data": "team-a|Bucket/team-a/data"},
			buckets: map[string]string{"data": "2026-10-24T00:00:00+00:00"}, wantOK: true, wantRecord: "team-a",
			env:           []string{"OWNER_NS=team-a", "OWNER_REF=StaticSite/team-a/site", "XR_CREATED=" + xrCreated},
			wantOutSubstr: "StaticSite/team-a/site uses it from the same namespace"},
		{name: "a StaticSite cannot serve another namespace's bucket", bucket: "data",
			records: map[string]string{"bucket-owner-data": "team-b|Bucket/team-b/data"},
			buckets: map[string]string{"data": "2026-10-24T00:00:00+00:00"}, wantRecord: "team-b",
			env:           []string{"OWNER_NS=team-a", "OWNER_REF=StaticSite/team-a/site", "XR_CREATED=" + xrCreated},
			wantOutSubstr: "belongs to another claim (Bucket/team-b/data)"},
		{name: "unrecorded bucket made by this claim is adopted", bucket: "data",
			buckets: map[string]string{"data": "2026-10-23T02:56:10.123000+00:00"}, wantOK: true, wantRecord: "team-a"},
		{name: "unrecorded bucket made in the same second is adopted", bucket: "data",
			buckets: map[string]string{"data": "2026-10-23T02:55:58+00:00"}, wantOK: true, wantRecord: "team-a"},
		{name: "unrecorded bucket older than the claim is refused", bucket: "data",
			buckets:       map[string]string{"data": "2026-09-01T00:00:00+00:00"},
			wantOutSubstr: "kubectl -n openinfra-bucket-creds create secret generic bucket-owner-data --from-literal=namespace=team-a"},
		{name: "unrecorded existing bucket with no composite time is refused", bucket: "data",
			buckets:       map[string]string{"data": "2026-10-24T00:00:00+00:00"},
			env:           []string{"OWNER_NS=team-a", "OWNER_REF=Bucket/team-a/data", "XR_CREATED="},
			wantOutSubstr: "predates Bucket/team-a/data"},
		{name: "losing a race to another namespace is refused", bucket: "data", race: "team-b", wantRecord: "team-b",
			wantOutSubstr: "belongs to another namespace (team-b)"},
		{name: "losing a race to this namespace is fine", bucket: "data", race: "team-a", wantOK: true, wantRecord: "team-a"},
		{name: "platform buckets are refused", bucket: "db-snapshots", wantOutSubstr: "db-snapshots is a platform bucket"},
		{name: "a name with shell characters is refused", bucket: "'x;id'", wantOutSubstr: "invalid bucket name"},
		{name: "no owner identity fails", bucket: "data", env: []string{"OWNER_NS=", "OWNER_REF="},
			wantOutSubstr: "OWNER_NS and OWNER_REF must be set"},
	}
	for _, sh := range posixShells(t) {
		for _, c := range cases {
			t.Run(shellName(sh)+"/"+c.name, func(t *testing.T) {
				e := newBktEnv(t, c.records, c.buckets)
				if c.race != "" {
					writeFile(t, filepath.Join(e.dir, "race", "bucket-owner-"+c.bucket), c.race)
				}
				env := ownerEnv
				if c.env != nil {
					env = c.env
				}
				out, err := e.run(t, sh, claimScript(t, c.bucket), env...)
				if c.wantOK != (err == nil) || c.wantOK != strings.Contains(out, "CLAIMED") {
					t.Fatalf("ok=%v, want %v; output:\n%s", err == nil, c.wantOK, out)
				}
				if c.wantOutSubstr != "" && !strings.Contains(out, c.wantOutSubstr) {
					t.Errorf("output lacks %q:\n%s", c.wantOutSubstr, out)
				}
				if got := e.read("records/bucket-owner-" + strings.Trim(c.bucket, "'")); got != c.wantRecord {
					t.Errorf("owner record = %q, want %q", got, c.wantRecord)
				}
			})
		}
	}
}

// A read failure (API server or MinIO) fails the Job rather than treating the bucket as unowned.
func TestBucketOwnership_ReadFailuresFailClosed(t *testing.T) {
	for _, flag := range []string{"fail-get", "fail-list"} {
		for _, sh := range posixShells(t) {
			e := newBktEnv(t, nil, nil)
			writeFile(t, filepath.Join(e.dir, flag), "")
			out, err := e.run(t, sh, claimScript(t, "data"), ownerEnv...)
			if err == nil || strings.Contains(out, "CLAIMED") {
				t.Errorf("%s/%s: claim succeeded despite a read failure:\n%s", shellName(sh), flag, out)
			}
			if e.read("records/bucket-owner-data") != "" {
				t.Errorf("%s/%s: recorded an owner despite a read failure", shellName(sh), flag)
			}
		}
	}
}

func bucketOwnCtx(ns, name string, spec map[string]any) map[string]any {
	return map[string]any{"observed": map[string]any{"composite": map[string]any{"resource": map[string]any{
		"spec": spec,
		"metadata": map[string]any{
			"name":              name + "-x7k2p",
			"uid":               "00000000-0000-0000-0000-000000000abc",
			"creationTimestamp": xrCreated,
			"labels": map[string]any{
				"crossplane.io/claim-name":      name,
				"crossplane.io/claim-namespace": ns,
			},
		},
	}}}}
}

// runnable turns a rendered setup script into one the stubs can run.
func runnable(t *testing.T, script, tmp string) string {
	t.Helper()
	own := filepath.Join(tmp, "bucket-ownership.sh")
	writeFile(t, own, extractDataScript(t, providerSetupPath, "bucket-ownership.sh"))
	if !strings.Contains(script, ". /opt/openinfra/bucket-ownership.sh") {
		t.Fatalf("the setup script does not source the ownership script:\n%s", script)
	}
	script = strings.ReplaceAll(script, ". /opt/openinfra/bucket-ownership.sh", ". "+own)
	script = strings.ReplaceAll(script, "MC=/mc/mc", "MC=mc")
	return strings.ReplaceAll(script, "/tmp/pol.json", tmp+"/pol.json")
}

// The rendered Bucket setup Job, end to end: another namespace's bucket stops the Job before it
// creates, configures or grants anything; a new bucket is recorded first, then made, and the MinIO
// user is this claim's own.
func TestBucketComposition_SetupRefusesForeignBucket(t *testing.T) {
	needJQ(t)
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	out := render(t, tmpl, bucketOwnCtx("team-b", "data", map[string]any{"bucketName": "shared", "versioning": true}))
	script := setupScript(t, out, "kind: Job")
	env := []string{"OWNER_NS=team-b", "OWNER_REF=Bucket/team-b/data", "XR_CREATED=" + xrCreated}
	for _, sh := range posixShells(t) {
		t.Run(shellName(sh)+"/foreign", func(t *testing.T) {
			e := newBktEnv(t, map[string]string{"bucket-owner-shared": "team-a"}, map[string]string{"shared": "2026-10-01T00:00:00+00:00"})
			res, err := e.run(t, sh, runnable(t, script, e.tmp), env...)
			if err == nil {
				t.Fatalf("setup succeeded on another namespace's bucket:\n%s", res)
			}
			for _, f := range []string{"made.txt", "configured.txt", "users.txt", "applied.txt"} {
				if got := e.read(f); got != "" {
					t.Errorf("%s written before the refusal: %q", f, got)
				}
			}
		})
		t.Run(shellName(sh)+"/new", func(t *testing.T) {
			e := newBktEnv(t, nil, nil)
			res, err := e.run(t, sh, runnable(t, script, e.tmp), env...)
			if err != nil {
				t.Fatalf("setup of a new bucket failed: %v\n%s", err, res)
			}
			if e.read("records/bucket-owner-shared") != "team-b" {
				t.Errorf("new bucket not recorded to team-b")
			}
			calls := e.read("calls.log")
			if i, j := strings.Index(calls, "create -f -"), strings.Index(calls, "s3 mb"); i < 0 || j < 0 || i > j {
				t.Errorf("the owner record must be created before the bucket; calls:\n%s", calls)
			}
			user := strings.TrimSpace(e.read("users.txt"))
			if user == "app-data" || !strings.HasPrefix(user, "app-team-b-data-") {
				t.Errorf("MinIO user = %q, want a per-namespace app-team-b-data-<hash>", user)
			}
			// The Job writes the key to the platform-side Secret (openinfra-bucket-creds/<user>), NOT the
			// claim namespace — a provider Object copies it to the claim later.
			if !strings.Contains(e.read("applied.txt"), "MINIO_ACCESS_KEY="+user) {
				t.Errorf("the platform-side creds Secret does not carry the scoped user %q:\n%s", user, e.read("applied.txt"))
			}
			if !strings.Contains(e.read("calls.log"), "-n openinfra-bucket-creds") {
				t.Errorf("the Job did not write the platform-side creds Secret in openinfra-bucket-creds:\n%s", e.read("calls.log"))
			}
		})
	}
}

// Every bucket-setup Job, in every composition that makes one: it mounts the ownership script and
// claims each bucket before it creates one or mints a user; its MinIO user and its Job name differ
// between two namespaces' same-named claims; and an invalid bucket name fails the render.
func TestBucketSetup_AllCompositionsClaimFirst(t *testing.T) {
	type comp struct {
		kind, path, jobMarker string
		spec                  func(bucket string) map[string]any
	}
	comps := []comp{
		{"Bucket", bucketCompositionPath, "-bucket-", func(b string) map[string]any { return map[string]any{"bucketName": b} }},
		{"StaticSite", staticsiteCompositionPath, "-site-", func(b string) map[string]any {
			return map[string]any{"domain": "app.example.com", "bucket": b}
		}},
		{"Application", "../../platform/abstraction/composition.yaml", "-bucket-", func(b string) map[string]any {
			return map[string]any{"storage": map[string]any{"buckets": []any{b, "second-" + b}}}
		}},
		{"Model", "../../platform/abstraction/model-composition.yaml", "-model-bucket-", func(b string) map[string]any {
			return map[string]any{"serve": map[string]any{"image": "ghcr.io/x/serve:1", "artifact": map[string]any{"bucket": b, "key": "m.bin"}}}
		}},
		{"TrainingJob", "../../platform/abstraction/trainingjob-composition.yaml", "-tj-bucket-", func(b string) map[string]any {
			return map[string]any{"image": "ghcr.io/x/train:1", "dataset": map[string]any{"bucket": b}, "output": map[string]any{"bucket": "out-" + b}}
		}},
		{"ProcessingJob", "../../platform/abstraction/processingjob-composition.yaml", "-proc-bucket-", func(b string) map[string]any {
			return map[string]any{"image": "ghcr.io/x/proc:1",
				"inputs":  []any{map[string]any{"name": "in", "bucket": b}},
				"outputs": []any{map[string]any{"name": "out", "bucket": "out-" + b}}}
		}},
		{"BatchTransform", "../../platform/abstraction/batchtransform-composition.yaml", "-bt-bucket-", func(b string) map[string]any {
			return map[string]any{"image": "ghcr.io/x/bt:1",
				"input": map[string]any{"bucket": b}, "output": map[string]any{"bucket": "out-" + b}}
		}},
		{"ModelMonitor", "../../platform/abstraction/modelmonitor-composition.yaml", "-mon-bucket-", func(b string) map[string]any {
			return map[string]any{"image": "ghcr.io/x/mon:1",
				"baseline": map[string]any{"bucket": b, "key": "base.csv"},
				"current":  map[string]any{"bucket": b, "key": "cur.csv"},
				"output":   map[string]any{"bucket": "out-" + b}}
		}},
	}
	for _, c := range comps {
		t.Run(c.kind, func(t *testing.T) {
			tmpl := extractInlineTemplate(t, c.path)
			a := render(t, tmpl, bucketOwnCtx("team-a", "data", c.spec("shared")))
			b := render(t, tmpl, bucketOwnCtx("team-b", "data", c.spec("shared")))
			script := setupScript(t, a, c.jobMarker)
			claim := strings.Index(script, "claim_bucket")
			if claim < 0 {
				t.Fatalf("setup script never claims its bucket:\n%s", script)
			}
			for _, act := range []string{" mb ", "create-bucket", "admin user add", "admin policy", "kubectl create secret generic"} {
				if i := strings.Index(script, act); i >= 0 && i < claim {
					t.Errorf("%q runs before claim_bucket", act)
				}
			}
			if strings.Contains(script, `APPUSER="app-data"`) {
				t.Errorf("MinIO user is the bare claim name, shared with every same-named claim")
			}
			for _, want := range []string{"name: openinfra-bucket-ownership", "mountPath: /opt/openinfra", `name: OWNER_NS, value: "team-a"`,
				`name: OWNER_REF, value: "` + c.kind + `/team-a/data"`, `name: XR_CREATED, value: "` + xrCreated + `"`} {
				if !strings.Contains(a, want) {
					t.Errorf("rendered Job lacks %q", want)
				}
			}
			if jobName(t, a, c.jobMarker) == jobName(t, b, c.jobMarker) {
				t.Errorf("two namespaces' same-named claims share setup Job %s", jobName(t, a, c.jobMarker))
			}
			if userOf(script) == userOf(setupScript(t, b, c.jobMarker)) {
				t.Errorf("two namespaces' same-named claims share MinIO user %s", userOf(script))
			}
			if err := renderErr(tmpl, bucketOwnCtx("team-a", "data", c.spec("$(id)"))); err == nil || !strings.Contains(err.Error(), "not a valid S3 bucket name") {
				t.Errorf("an invalid bucket name rendered (err=%v)", err)
			}
		})
	}
}

func jobName(t *testing.T, rendered, marker string) string {
	t.Helper()
	for _, ln := range strings.Split(rendered, "\n") {
		if strings.Contains(ln, "metadata: { name: ") && strings.Contains(ln, marker) && strings.Contains(ln, "namespace: minio") {
			return strings.TrimSpace(ln)
		}
	}
	t.Fatalf("no minio-namespace Job matching %q", marker)
	return ""
}

func userOf(script string) string {
	for _, ln := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "APPUSER=") {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}
