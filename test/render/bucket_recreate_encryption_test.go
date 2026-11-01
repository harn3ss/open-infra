package render

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func bucketCtxUID(spec map[string]any, uid string) map[string]any {
	ctx := bucketCtx(spec)
	ctx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["metadata"].(map[string]any)["uid"] = uid
	return ctx
}

// A re-created claim (same name, same spec, a new composite) gets a fresh setup Job, so it never collides
// with the finished Job of the claim before it; and the Job is composed under a hash-qualified resource
// name, so a spec change makes Crossplane delete the superseded Job rather than leave it behind.
func TestBucketComposition_RecreateGetsAFreshSetupJob(t *testing.T) {
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	spec := map[string]any{"versioning": true}
	first := render(t, tmpl, bucketCtxUID(spec, "0b6f1c2e-0000-4000-8000-000000000001"))
	again := render(t, tmpl, bucketCtxUID(spec, "0b6f1c2e-0000-4000-8000-000000000002"))
	if bucketJobName(first) == "" || bucketJobName(first) == bucketJobName(again) {
		t.Fatalf("a re-created claim must get a new setup Job name: %q vs %q", bucketJobName(first), bucketJobName(again))
	}
	same := render(t, tmpl, bucketCtxUID(spec, "0b6f1c2e-0000-4000-8000-000000000001"))
	if bucketJobName(first) != bucketJobName(same) {
		t.Fatal("the same composite and spec must keep its setup Job name (no re-run on every reconcile)")
	}
	// metadata: { name: data-bucket-<hash>, namespace: minio } -> <hash>
	ln := bucketJobName(first)
	i := strings.Index(ln, "data-bucket-")
	if i < 0 {
		t.Fatalf("unexpected setup Job line %q", ln)
	}
	hash := strings.SplitN(ln[i+len("data-bucket-"):], ",", 2)[0]
	if !strings.Contains(first, "composition-resource-name: bucket-setup-"+hash) {
		t.Fatalf("the setup Job must be composed per hash (bucket-setup-%s):\n%s", hash, grepCtx(first, "composition-resource-name: bucket-setup"))
	}
	changed := render(t, tmpl, bucketCtxUID(map[string]any{"versioning": false}, "0b6f1c2e-0000-4000-8000-000000000001"))
	if strings.Contains(changed, "composition-resource-name: bucket-setup-"+hash) {
		t.Fatal("a spec change must compose the setup under a new resource name, so the superseded Job is deleted")
	}
}

// The setup reads the platform's default encryption from the optional switch ConfigMap, never from
// the claim.
func TestBucketComposition_DefaultEncryptionFromThePlatformSwitch(t *testing.T) {
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	out := render(t, tmpl, bucketCtxUID(map[string]any{}, "0b6f1c2e-0000-4000-8000-000000000003"))
	if !strings.Contains(out, "configMapKeyRef: { name: openinfra-object-encryption, key: default, optional: true }") {
		t.Fatalf("OBJECT_ENCRYPTION_DEFAULT must come from the optional platform switch:\n%s", grepCtx(out, "OBJECT_ENCRYPTION"))
	}
}

// The default-encryption step, run under the shells the setup image has: only a bucket created here, or
// one still empty with no encryption, gets default encryption; a bucket holding objects is left as is;
// nothing happens while the platform switch is off.
func TestBucketComposition_DefaultEncryptionStep(t *testing.T) {
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	out := render(t, tmpl, bucketCtxUID(map[string]any{"versioning": true}, "0b6f1c2e-0000-4000-8000-000000000004"))
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatal(err)
	}
	var scripts []string
	for _, d := range docs {
		scriptTexts(d, "bucket", &scripts)
	}
	var setup string
	for _, s := range scripts {
		if strings.Contains(s, "OBJECT_ENCRYPTION_DEFAULT") {
			setup = strings.TrimPrefix(s, "bucket: ")
		}
	}
	a := strings.Index(setup, "if [ -n \"${OBJECT_ENCRYPTION_DEFAULT:-}\" ]; then")
	b := strings.Index(setup, "aws --endpoint-url $E s3api put-bucket-versioning")
	if a < 0 || b < a {
		t.Fatalf("default-encryption step not found in the setup script:\n%s", setup)
	}
	step := setup[a:b]
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	stub := `
aws() {
  echo "$*" >> "$LOG"
  case "$*" in
    *get-bucket-encryption*) [ "$HAS_ENC" = 1 ] && return 0; return 254 ;;
    *list-object-versions*) if [ "$HAS_OBJ" = 1 ]; then echo '{"Versions":[{"Key":"a","VersionId":"null"}]}'; fi; return 0 ;;
    *put-bucket-encryption*) return 0 ;;
  esac
  return 1
}
set -e
E=http://minio.invalid:9000
`
	cases := []struct {
		name                         string
		def, created, hasEnc, hasObj string
		want                         bool
	}{
		{"switch off", "", "1", "0", "0", false},
		{"created here", "AES256", "1", "0", "0", true},
		{"existing, empty, unencrypted (a retried setup)", "AES256", "0", "0", "0", true},
		{"existing, holding objects", "AES256", "0", "0", "1", false},
		{"existing, already encrypted", "AES256", "0", "1", "0", false},
	}
	for _, sh := range []string{"sh", "dash", "busybox"} {
		bin, err := exec.LookPath(sh)
		if err != nil {
			continue
		}
		for _, c := range cases {
			log := filepath.Join(t.TempDir(), "calls")
			args := []string{"-c", stub + "created=" + c.created + "\n" + step}
			if sh == "busybox" {
				args = append([]string{"sh"}, args...)
			}
			cmd := exec.Command(bin, args...)
			cmd.Env = append(os.Environ(), "LOG="+log, "OBJECT_ENCRYPTION_DEFAULT="+c.def, "HAS_ENC="+c.hasEnc, "HAS_OBJ="+c.hasObj)
			if o, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s/%s: step failed: %v\n%s", sh, c.name, err, o)
			}
			calls, _ := os.ReadFile(log)
			got := strings.Contains(string(calls), "put-bucket-encryption")
			if got != c.want {
				t.Errorf("%s/%s: put-bucket-encryption called = %v, want %v (calls: %q)", sh, c.name, got, c.want, calls)
			}
		}
	}
	// An unknown default fails the setup loudly instead of creating an unencrypted bucket.
	cmd := exec.Command("sh", "-c", stub+"created=1\n"+step)
	cmd.Env = append(os.Environ(), "LOG="+filepath.Join(t.TempDir(), "calls"), "OBJECT_ENCRYPTION_DEFAULT=rot13")
	if err := cmd.Run(); err == nil {
		t.Error("an unsupported default encryption must fail the setup")
	}
}
