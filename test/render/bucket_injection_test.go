package render

import (
	"strings"
	"testing"
)

// The bucket policy, lifecycle JSON and object-lock JSON are tenant-controlled documents. They must
// reach the setup Job as env VALUES and be used as "$VAR", never pasted into the shell script — a
// single quote in spec.policy once reached a root-credentialed shell (the #347 bucket-Job injection).
func TestBucketComposition_PolicyAndLifecycleRideEnv(t *testing.T) {
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	out := render(t, tmpl, bucketOwnCtx("team-b", "data", map[string]any{
		"bucketName":     "shared",
		"versioning":     true,
		"policy":         `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::shared/*"}]}`,
		"lifecycleRules": []any{map[string]any{"id": "expire-tmp", "prefix": "tmp/", "expireDays": int64(7)}},
		"objectLock":     map[string]any{"mode": "GOVERNANCE", "days": int64(30)},
	}))
	script := setupScript(t, out, "kind: Job")
	// Used from the environment, not interpolated.
	for _, want := range []string{
		`--policy "$BUCKET_POLICY"`,
		`--lifecycle-configuration "$LIFECYCLE_JSON"`,
		`--object-lock-configuration "$LOCK_JSON"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("setup script must use %q (from env); got:\n%s", want, script)
		}
	}
	// The documents themselves appear only in the env block, never in the script body.
	if strings.Contains(script, "s3:GetObject") {
		t.Errorf("the bucket policy was pasted into the script body:\n%s", script)
	}
	env := collectEnv(t, out)
	if !strings.Contains(env["BUCKET_POLICY"], "s3:GetObject") {
		t.Errorf("BUCKET_POLICY env missing the policy; got %q", env["BUCKET_POLICY"])
	}
	if !strings.Contains(env["LIFECYCLE_JSON"], "expire-tmp") {
		t.Errorf("LIFECYCLE_JSON env missing the rule; got %q", env["LIFECYCLE_JSON"])
	}
	if !strings.Contains(env["LOCK_JSON"], "GOVERNANCE") {
		t.Errorf("LOCK_JSON env missing the lock; got %q", env["LOCK_JSON"])
	}
}

// A policy that is not a JSON object fails the render loudly (fromYaml guard), rather than being
// written out and applied as something MinIO silently ignores or mis-parses.
func TestBucketComposition_RejectsNonJSONPolicy(t *testing.T) {
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	for _, bad := range []string{"not json at all", `["an","array"]`, `"a string"`, "42"} {
		ctx := bucketOwnCtx("team-b", "data", map[string]any{"bucketName": "shared", "policy": bad})
		if err := renderErr(tmpl, ctx); err == nil {
			t.Errorf("policy %q should fail the render (must be a JSON object)", bad)
		}
	}
	// A valid JSON object renders.
	ok := bucketOwnCtx("team-b", "data", map[string]any{"bucketName": "shared", "policy": `{"Version":"2012-10-17"}`})
	if err := renderErr(tmpl, ok); err != nil {
		t.Errorf("a valid JSON-object policy must render: %v", err)
	}
}
