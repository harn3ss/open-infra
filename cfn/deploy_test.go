package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// fakeApplier records what the engine would do to a cluster, and can be told to fail a
// specific apply or readiness wait — so ordering, state, and rollback are tested with no
// cluster.
type fakeApplier struct {
	applied  []string // "Kind/name" in apply order (ConfigMap included)
	deleted  []string // "Kind/name" in delete order
	failOn   string   // fail Apply for this "Kind/name"
	notReady string   // fail WaitReady for this name
}

func idOf(y []byte) string {
	var m map[string]any
	_ = yaml.Unmarshal(y, &m)
	kind, _ := m["kind"].(string)
	meta, _ := m["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	return kind + "/" + name
}

func (f *fakeApplier) Apply(_ context.Context, y []byte) error {
	id := idOf(y)
	if id == f.failOn {
		return errFake("apply refused for " + id)
	}
	f.applied = append(f.applied, id)
	return nil
}

func (f *fakeApplier) Delete(_ context.Context, apiVersion, kind, name string) error {
	f.deleted = append(f.deleted, kind+"/"+name)
	return nil
}

func (f *fakeApplier) WaitReady(_ context.Context, _, _, name string, _ time.Duration) error {
	if name == f.notReady {
		return errFake(name + " never became Ready")
	}
	return nil
}

type errFake string

func (e errFake) Error() string { return string(e) }

func (f *fakeApplier) appliedNonCM() []string {
	var out []string
	for _, a := range f.applied {
		if !strings.HasPrefix(a, "ConfigMap/") {
			out = append(out, a)
		}
	}
	return out
}

func deployOpts() DeployOptions {
	return DeployOptions{StackName: "s", Namespace: "cfn-test", Params: map[string]string{}, Wait: true, Timeout: time.Second}
}

// The cardinal rule at deploy time: a template with an unsupported resource type provisions
// NOTHING — not even the stack record.
func TestDeploy_Unsupported_NothingApplied(t *testing.T) {
	f := &fakeApplier{}
	_, err := Deploy(context.Background(), readFixture(t, "unsupported.yaml"), deployOpts(), f)
	if err == nil {
		t.Fatal("expected deploy to be refused")
	}
	if len(f.applied) != 0 {
		t.Fatalf("unsupported template must apply nothing, applied: %v", f.applied)
	}
}

// A type that PLANS as supported but has no create translator is refused at the translate
// gate — plan-supported is not create-faithful — and still applies nothing.
func TestDeploy_NoTranslator_NothingApplied(t *testing.T) {
	tmpl := []byte(`
Resources:
  R:
    Type: AWS::IAM::Role
    Properties: { Path: / }
`)
	// sanity: it plans clean (IAM::Role is plan-supported)
	if p := mustPlan(t, tmpl, nil, ""); p.Verdict == Rejected {
		t.Fatalf("precondition: IAM::Role should plan supported, got %s", p.Verdict)
	}
	f := &fakeApplier{}
	_, err := Deploy(context.Background(), tmpl, deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "no create translator") {
		t.Fatalf("expected a no-translator refusal, got %v", err)
	}
	if len(f.applied) != 0 {
		t.Fatalf("no-translator template must apply nothing, applied: %v", f.applied)
	}
}

func TestDeploy_Success_OrderedAndComplete(t *testing.T) {
	tmpl := []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    Properties: { Description: a }
  KeyB:
    Type: AWS::KMS::Key
    DependsOn: KeyA
    Properties: { Description: b }
`)
	f := &fakeApplier{}
	rec, err := Deploy(context.Background(), tmpl, deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("status = %s, want CREATE_COMPLETE", rec.Status)
	}
	got := f.appliedNonCM()
	want := []string{"EncryptionKey/keya", "EncryptionKey/keyb"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("apply order = %v, want %v (DependsOn must be honored)", got, want)
	}
	// the stack record was persisted (a ConfigMap apply happened).
	sawCM := false
	for _, a := range f.applied {
		if a == "ConfigMap/cfn-stack-s" {
			sawCM = true
		}
	}
	if !sawCM {
		t.Fatal("stack record ConfigMap was never persisted")
	}
}

// No orphans: if a create fails midway, everything created THIS deploy is deleted.
func TestDeploy_Rollback_NoOrphans(t *testing.T) {
	tmpl := []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    Properties: { Description: a }
  KeyB:
    Type: AWS::KMS::Key
    DependsOn: KeyA
    Properties: { Description: b }
`)
	f := &fakeApplier{failOn: "EncryptionKey/keyb"}
	rec, err := Deploy(context.Background(), tmpl, deployOpts(), f)
	if err == nil {
		t.Fatal("expected the deploy to fail")
	}
	if rec == nil || rec.Status != "CREATE_FAILED" {
		t.Fatalf("status = %v, want CREATE_FAILED", rec)
	}
	// keya was applied then rolled back; keyb never applied.
	if len(f.deleted) != 1 || f.deleted[0] != "EncryptionKey/keya" {
		t.Fatalf("rollback should have deleted exactly keya, deleted: %v", f.deleted)
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("error should say it rolled back: %v", err)
	}
}

// A resource that applies but never becomes Ready is also rolled back (with -wait).
func TestDeploy_NotReady_RollsBack(t *testing.T) {
	tmpl := []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    Properties: { Description: a }
`)
	f := &fakeApplier{notReady: "keya"}
	rec, err := Deploy(context.Background(), tmpl, deployOpts(), f)
	if err == nil || rec.Status != "CREATE_FAILED" {
		t.Fatalf("a never-ready resource should CREATE_FAILED, got status=%v err=%v", rec, err)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "EncryptionKey/keya" {
		t.Fatalf("not-ready resource should be rolled back, deleted: %v", f.deleted)
	}
}

func TestDeploy_RequiresNamespace(t *testing.T) {
	o := deployOpts()
	o.Namespace = ""
	if _, err := Deploy(context.Background(), []byte(`Resources: {K: {Type: AWS::KMS::Key}}`), o, &fakeApplier{}); err == nil {
		t.Fatal("deploy without a namespace must be refused")
	}
}
