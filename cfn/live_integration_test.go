//go:build integration

// Live apply-path verification for the CFN engine (#119): drives real templates through the REAL
// kubectlApplier into a live cluster and observes the three facts a fake applier structurally
// cannot test — a real create reconciling to ready, a real failed-create leaving ZERO orphans
// (rollback), and real drift detection against an out-of-band edit. "Supported" means "deploys and
// runs", not "translates".
//
//	KUBECONFIG=/etc/rancher/k3s/k3s.yaml go test -tags integration -run TestLive ./...
//
// Requires the platform's backing services (MinIO for Bucket, Knative for Function) on the target
// cluster. Each test cleans up its own stack.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func liveNS(t *testing.T) string {
	t.Helper()
	if os.Getenv("KUBECONFIG") == "" {
		t.Skip("set KUBECONFIG to run the live apply-path tests")
	}
	ns := "cfn-live"
	_ = exec.Command("kubectl", "create", "namespace", ns).Run() // idempotent; ignore "already exists"
	return ns
}

func liveOpts(ns, stack string, timeout time.Duration) DeployOptions {
	return DeployOptions{StackName: stack, Namespace: ns, Wait: true, Timeout: timeout}
}

// 1. REAL CREATE — a Bucket (MinIO-backed) driven through the engine into the real API server,
// admitted, reconciled to ready. Not the fake applier.
func TestLive_RealCreate(t *testing.T) {
	ns := liveNS(t)
	ap := kubectlApplier{namespace: ns}
	opts := liveOpts(ns, "live-create", 90*time.Second)
	tmpl := []byte(`
Resources:
  Assets:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: cfn-live-assets
      VersioningConfiguration: { Status: Enabled }
`)
	defer Destroy(context.Background(), opts, ap)

	rec, err := Deploy(context.Background(), tmpl, opts, ap)
	if err != nil {
		t.Fatalf("live deploy failed: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("status = %s, want CREATE_COMPLETE", rec.Status)
	}
	// The real object exists + is ready (observed through the real applier, not asserted on a double).
	if err := ap.WaitReady(context.Background(), "openinfra.dev/v1", "Bucket", "assets", 60*time.Second); err != nil {
		t.Fatalf("the created Bucket did not reach ready on the real cluster: %v", err)
	}
	t.Logf("observed: kind: Bucket assets created + ready on the live cluster")
}

// 2. REAL FAILED-CREATE WITH ZERO ORPHANS — a valid first resource, then a second the real API
// server rejects at apply; the deploy fails and rolls back, leaving the first resource GONE. This
// is the property a fake applier cannot exercise (a double never runs real admission/validation).
func TestLive_FailedCreateZeroOrphans(t *testing.T) {
	ns := liveNS(t)
	ap := kubectlApplier{namespace: ns}
	opts := liveOpts(ns, "live-fail", 60*time.Second)
	// Good is created first; Bad (ordered after it via DependsOn) has a logical id whose k8s name
	// exceeds the 253-char limit, so the API server REJECTS it at apply. The engine must then roll
	// back and delete Good — the zero-orphans property.
	tooLong := strings.Repeat("Overlong", 40) // 320 chars -> metadata.name too long
	tmpl := []byte(fmt.Sprintf(`
Resources:
  Good:
    Type: AWS::S3::Bucket
    Properties: { BucketName: cfn-live-good }
  %s:
    Type: AWS::S3::Bucket
    DependsOn: [Good]
    Properties: { BucketName: cfn-live-toolong }
`, tooLong))
	defer Destroy(context.Background(), opts, ap)

	rec, err := Deploy(context.Background(), tmpl, opts, ap)
	if err == nil {
		t.Fatalf("expected the deploy to FAIL (second resource rejected at apply), got status %s", rec.Status)
	}
	if rec == nil || rec.Status != "CREATE_FAILED" {
		t.Fatalf("status = %v, want CREATE_FAILED", rec)
	}
	// Zero orphans: the first, successfully-created Bucket must have been rolled back.
	if err := ap.WaitGone(context.Background(), "openinfra.dev/v1", "Bucket", "good", 60*time.Second); err != nil {
		t.Fatalf("ORPHAN: the rolled-back Bucket is still present — rollback left an orphan: %v", err)
	}
	t.Logf("observed: partial-failure rollback left zero orphans (the Good Bucket was deleted)")
}

// 3. REAL DRIFT DETECTION — deploy, edit the live object out-of-band, and observe the engine
// detecting the drift against the real cluster (not against a double).
func TestLive_DriftDetection(t *testing.T) {
	ns := liveNS(t)
	ap := kubectlApplier{namespace: ns}
	opts := liveOpts(ns, "live-drift", 90*time.Second)
	tmpl := []byte(`
Resources:
  Drifty:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: cfn-live-drifty
      VersioningConfiguration: { Status: Enabled }
`)
	defer Destroy(context.Background(), opts, ap)

	if _, err := Deploy(context.Background(), tmpl, opts, ap); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	// Before the edit: no drift.
	rep, err := DetectDrift(context.Background(), opts, ap)
	if err != nil {
		t.Fatalf("drift (pre-edit): %v", err)
	}
	if !rep.InSync {
		t.Fatalf("unexpected drift before any edit: %+v", rep)
	}
	// Edit a declared field out-of-band.
	if err := exec.Command("kubectl", "-n", ns, "patch", "bucket.openinfra.dev", "drifty",
		"--type=merge", "-p", `{"spec":{"versioning":false}}`).Run(); err != nil {
		t.Fatalf("out-of-band patch failed: %v", err)
	}
	// After the edit: drift is detected against the real cluster.
	rep, err = DetectDrift(context.Background(), opts, ap)
	if err != nil {
		t.Fatalf("drift (post-edit): %v", err)
	}
	if rep.InSync {
		t.Fatalf("engine did NOT detect the out-of-band edit as drift: %+v", rep)
	}
	t.Logf("observed: out-of-band spec edit detected as drift on the live cluster")
}
