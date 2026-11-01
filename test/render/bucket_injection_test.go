package render

import (
	"strings"
	"testing"
)

// The Application db-backup (PITR) WAL-archive user also moves onto the scoped model: the Job mints via
// the shared helper, and the claim's <name>-db-backup-creds Secret (keys ak/sk) is a composed copy with
// sk patched from the platform Secret's MINIO_SECRET_KEY.
func TestApplicationDBBackup_ScopedCredentialDelivery(t *testing.T) {
	tmpl := extractInlineTemplate(t, compositionPath)
	mk := func(observed map[string]any) map[string]any {
		return map[string]any{"observed": map[string]any{
			"composite": map[string]any{"resource": map[string]any{
				"spec": map[string]any{"image": "ghcr.io/x/app:latest", "database": map[string]any{
					"engine": "postgres", "pointInTimeRecovery": true,
				}},
				"metadata": map[string]any{"uid": "00000000-0000-0000-0000-00000000d0d0",
					"labels": map[string]any{"crossplane.io/claim-name": "app", "crossplane.io/claim-namespace": "team"}},
			}},
			"resources": observed,
		}}
	}
	// The setup Job mints via the shared helper (no inline user add / claim-Secret write) and Observes
	// the platform Secret.
	base := render(t, tmpl, mk(map[string]any{}))
	for _, want := range []string{
		`mint_scoped_user "$BKPUSER"`,
		"composition-resource-name: db-backup-pcreds",
		". /opt/openinfra/bucket-ownership.sh", // the Job sources the shared helpers (mint_scoped_user)
	} {
		if !strings.Contains(base, want) {
			t.Errorf("db-backup setup missing %q:\n%s", want, grepCtx(base, "db-backup"))
		}
	}
	if strings.Contains(base, "composition-resource-name: db-backup-creds") {
		t.Errorf("the db-backup claim-creds copy must not render before the platform Secret is observed")
	}
	// Once the platform Secret is observed, the claim Secret copy renders: ak is the scoped user, sk is
	// patched from the platform Secret's MINIO_SECRET_KEY.
	seeded := render(t, tmpl, mk(map[string]any{
		"db-backup-pcreds": map[string]any{"resource": map[string]any{
			"status": map[string]any{"atProvider": map[string]any{"manifest": map[string]any{
				"metadata": map[string]any{"uid": "33333333-3333-3333-3333-333333333333"},
			}}},
		}},
	}))
	for _, want := range []string{
		"composition-resource-name: db-backup-creds",
		"name: app-db-backup-creds, namespace: team",
		"fieldPath: data.MINIO_SECRET_KEY",
		"toFieldPath: data.sk",
		"ak: bkp-team-app",
	} {
		if !strings.Contains(seeded, want) {
			t.Errorf("db-backup scoped copy missing %q:\n%s", want, grepCtx(seeded, "db-backup-creds"))
		}
	}
}

// Scoped-credential delivery (the #347 SA-scoping redesign). The setup Job writes the scoped key to a
// platform Secret (openinfra-bucket-creds/<user>); a provider Object copies it into the claim's
// <name>-minio Secret ONLY once that platform Secret is observed. A legacy claim (platform Secret not
// yet seeded) renders no copy, so its existing Secret is left alone and it stays Ready via the gate.
func TestBucketComposition_ScopedCredentialDelivery(t *testing.T) {
	tmpl := extractInlineTemplate(t, bucketCompositionPath)
	appUser := func(out string) string { // the pcreds Observe names the Secret after the MinIO user
		for _, ln := range strings.Split(out, "\n") {
			if strings.Contains(ln, "name: app-") && strings.Contains(ln, "namespace: openinfra-bucket-creds") {
				return strings.TrimSpace(ln)
			}
		}
		return ""
	}
	mk := func(observed map[string]any) map[string]any {
		return map[string]any{"observed": map[string]any{
			"composite": map[string]any{"resource": map[string]any{
				"spec": map[string]any{"bucketName": "shared"},
				"metadata": map[string]any{
					"name": "data-x7k2p", "creationTimestamp": xrCreated,
					"labels": map[string]any{"crossplane.io/claim-name": "data", "crossplane.io/claim-namespace": "team-b"},
				},
			}},
			"resources": observed,
		}}
	}

	// Legacy / pre-seed: the platform Secret is not observed. No claim-creds copy Object; the pcreds
	// Observe is always present.
	legacy := render(t, tmpl, mk(map[string]any{}))
	if strings.Contains(legacy, "composition-resource-name: bucket-creds") {
		t.Errorf("no claim-creds copy must render before the platform Secret exists:\n%s", grepCtx(legacy, "bucket-creds"))
	}
	if !strings.Contains(legacy, "composition-resource-name: bucket-pcreds") || appUser(legacy) == "" {
		t.Errorf("the pcreds Observe Object must always render:\n%s", grepCtx(legacy, "pcreds"))
	}

	// Seeded: the platform Secret is observed (uid present). The claim-creds Object renders and copies
	// MINIO_SECRET_KEY from it via patchesFrom; the non-secret fields are rendered directly.
	seeded := render(t, tmpl, mk(map[string]any{
		"bucket-pcreds": map[string]any{"resource": map[string]any{
			"status": map[string]any{"atProvider": map[string]any{"manifest": map[string]any{
				"metadata": map[string]any{"uid": "11111111-1111-1111-1111-111111111111"},
			}}},
		}},
	}))
	for _, want := range []string{
		"composition-resource-name: bucket-creds",
		"fieldPath: data.MINIO_SECRET_KEY",
		"toFieldPath: data.MINIO_SECRET_KEY",
		"namespace: openinfra-bucket-creds",
		"name: data-minio, namespace: team-b",
		"MINIO_ACCESS_KEY: app-team-b-data-",
	} {
		if !strings.Contains(seeded, want) {
			t.Errorf("seeded render missing %q:\n%s", want, grepCtx(seeded, "bucket-creds"))
		}
	}
	// The claim Secret's key is never written literally — only patched from the platform Secret.
	if strings.Contains(seeded, "MINIO_SECRET_KEY: ") {
		t.Errorf("the claim Secret must not carry a literal secret key; it is patched from the platform Secret:\n%s", grepCtx(seeded, "MINIO_SECRET_KEY"))
	}
}

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
