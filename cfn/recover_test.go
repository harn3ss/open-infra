package cfn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const interruptedReason = "The stack operation was interrupted before it finished."

// Both live appliers can read labels, so a rollback of write-ahead entries is label-guarded on each path.
var (
	_ LabelReader = kubectlApplier{}
	_ LabelReader = (*fakeApplier)(nil)
)

// threeKeys: KeyA is Retain (the shared-key shape), then KeyB, then KeyC — created in that order.
var threeKeys = []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    DeletionPolicy: Retain
    Properties: { Description: a }
  KeyB:
    Type: AWS::KMS::Key
    DependsOn: KeyA
    Properties: { Description: b }
  KeyC:
    Type: AWS::KMS::Key
    DependsOn: KeyB
    Properties: { Description: c }
`)

// A create whose process dies mid-flight leaves CREATE_IN_PROGRESS listing every planned resource
// (write-ahead). Recovery rolls back exactly what this stack created — keeping the Retain resource, never
// touching a planned-but-never-applied name that belongs to someone else — and ends ROLLBACK_COMPLETE
// with the interruption as the reason.
func TestRecover_CreateInterrupted_RolledBackHonoringRetain(t *testing.T) {
	f := &fakeApplier{dieAfter: 3} // record write, KeyA, KeyB — then the process is gone
	// keyc is NOT this stack's: an object of that name already exists, labeled for another stack.
	f.liveLabels = map[string]map[string]string{"EncryptionKey/keyc": {labelStack: "other"}}
	if _, err := Deploy(context.Background(), threeKeys, deployOpts(), f); err == nil {
		t.Fatal("the dying deploy must not succeed")
	}
	if f.stored == nil || f.stored.Status != "CREATE_IN_PROGRESS" || len(f.stored.Resources) != 3 {
		t.Fatalf("a killed create must leave CREATE_IN_PROGRESS listing all 3 planned resources, got %+v", f.stored)
	}
	if len(f.deleted) != 0 {
		t.Fatalf("a dead process rolls nothing back itself, deleted=%v", f.deleted)
	}

	f.dieAfter = 0 // a new front door
	rec, err := RecoverInterrupted(context.Background(), deployOpts(), f, interruptedReason)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Status != "ROLLBACK_COMPLETE" || rec.Message != interruptedReason {
		t.Fatalf("want ROLLBACK_COMPLETE naming the interruption, got %s %q", rec.Status, rec.Message)
	}
	if strings.Join(f.deleted, ",") != "EncryptionKey/keyb" {
		t.Fatalf("only keyb (created by this stack, not Retain) is deleted; deleted=%v", f.deleted)
	}
	if _, ok := f.liveLabels["EncryptionKey/keya"]; !ok {
		t.Fatal("the Retain resource must survive the rollback")
	}
	if _, ok := f.liveLabels["EncryptionKey/keyc"]; !ok {
		t.Fatal("a same-named object that is not this stack's must survive the rollback")
	}
	if len(rec.Resources) != 1 || rec.Resources[0].LogicalID != "KeyA" || len(rec.Pending) != 0 {
		t.Fatalf("the rolled-back record lists only the retained KeyA, no Pending: %+v", rec)
	}
	if f.stored.Status != "ROLLBACK_COMPLETE" {
		t.Fatalf("the persisted record must be ROLLBACK_COMPLETE, got %s", f.stored.Status)
	}

	// Idempotent: recovering a settled stack touches nothing.
	f.applied, f.deleted = nil, nil
	again, err := RecoverInterrupted(context.Background(), deployOpts(), f, interruptedReason)
	if err != nil || again.Status != "ROLLBACK_COMPLETE" || len(f.applied)+len(f.deleted) != 0 {
		t.Fatalf("a settled stack is untouched: %v %v applied=%v deleted=%v", again.Status, err, f.applied, f.deleted)
	}
}

// A recovery that is itself interrupted leaves ROLLBACK_IN_PROGRESS, which the next recovery finishes.
func TestRecover_RollbackInProgressIsContinued(t *testing.T) {
	f := &fakeApplier{dieAfter: 3}
	_, _ = Deploy(context.Background(), threeKeys, deployOpts(), f)
	f.dieAfter, f.mutations = 1, 0 // the recovering process dies right after recording ROLLBACK_IN_PROGRESS
	if _, err := RecoverInterrupted(context.Background(), deployOpts(), f, interruptedReason); err == nil {
		t.Fatal("the dying recovery must not succeed")
	}
	if f.stored.Status != "ROLLBACK_IN_PROGRESS" {
		t.Fatalf("want ROLLBACK_IN_PROGRESS left behind, got %s", f.stored.Status)
	}
	f.dieAfter = 0
	rec, err := RecoverInterrupted(context.Background(), deployOpts(), f, interruptedReason)
	if err != nil || rec.Status != "ROLLBACK_COMPLETE" || !contains(f.deleted, "EncryptionKey/keyb") {
		t.Fatalf("the next recovery finishes the rollback: %v %v deleted=%v", rec, err, f.deleted)
	}
}

// A delete that fails during recovery ends ROLLBACK_FAILED with what remains (AWS: delete the stack).
func TestRecover_CreateRollbackFailure_RollbackFailed(t *testing.T) {
	f := &fakeApplier{dieAfter: 4} // record, KeyA, KeyB, KeyC
	_, _ = Deploy(context.Background(), threeKeys, deployOpts(), f)
	f.dieAfter = 0
	f.failDelete = "EncryptionKey/keyb"
	rec, err := RecoverInterrupted(context.Background(), deployOpts(), f, interruptedReason)
	if err == nil || rec.Status != "ROLLBACK_FAILED" {
		t.Fatalf("want ROLLBACK_FAILED, got %v %v", rec, err)
	}
	if !strings.HasPrefix(rec.Message, interruptedReason) || !strings.Contains(rec.Message, "keyb") {
		t.Fatalf("the reason names the interruption and the failure: %q", rec.Message)
	}
	var ids []string
	for _, r := range rec.Resources {
		ids = append(ids, r.LogicalID)
	}
	if strings.Join(ids, ",") != "KeyA,KeyB" { // keyc was deleted; keyb failed; keya is retained
		t.Fatalf("remaining = %v, want KeyA,KeyB", ids)
	}
}

// An update whose process dies mid-flight leaves UPDATE_IN_PROGRESS with the prior stack in Resources and
// its Adds in Pending (write-ahead). Recovery deletes the add, restores the modified spec, re-creates
// nothing extra, and ends UPDATE_ROLLBACK_COMPLETE — the prior stack exactly.
func TestRecover_UpdateInterrupted_PriorStackRestored(t *testing.T) {
	f := deployInitial(t) // KeyA (description a), KeyB
	prior := *f.stored
	priorA := f.liveSpecs["EncryptionKey/keya"]["description"]
	f.applied, f.deleted = nil, nil
	f.dieAfter, f.mutations = 3, 0 // UPDATE_IN_PROGRESS record, KeyA (modify), KeyC (add) — then gone
	if _, err := Update(context.Background(), updatedStack, deployOpts(), f); err == nil {
		t.Fatal("the dying update must not succeed")
	}
	if f.stored.Status != "UPDATE_IN_PROGRESS" {
		t.Fatalf("want UPDATE_IN_PROGRESS left behind, got %s", f.stored.Status)
	}
	if len(f.stored.Pending) != 1 || f.stored.Pending[0].LogicalID != "KeyC" {
		t.Fatalf("the in-progress update must record its Add (KeyC) as Pending, got %+v", f.stored.Pending)
	}
	if got := f.liveSpecs["EncryptionKey/keya"]["description"]; got == priorA {
		t.Fatalf("precondition: the interrupted update had modified KeyA")
	}

	f.dieAfter = 0
	rec, err := RecoverInterrupted(context.Background(), deployOpts(), f, interruptedReason)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Status != "UPDATE_ROLLBACK_COMPLETE" || rec.Message != interruptedReason || len(rec.Pending) != 0 {
		t.Fatalf("want UPDATE_ROLLBACK_COMPLETE naming the interruption, got %+v", rec)
	}
	if !contains(f.deleted, "EncryptionKey/keyc") {
		t.Fatalf("the update's add (keyc) must be deleted, deleted=%v", f.deleted)
	}
	if got := f.liveSpecs["EncryptionKey/keya"]["description"]; got != priorA {
		t.Fatalf("KeyA's prior spec must be restored: description=%v want %v", got, priorA)
	}
	if _, ok := f.liveSpecs["EncryptionKey/keyb"]; !ok {
		t.Fatal("KeyB (never removed, but re-applied either way) must be present")
	}
	pj, _ := json.Marshal(prior.Resources)
	rj, _ := json.Marshal(rec.Resources)
	if string(pj) != string(rj) {
		t.Fatalf("the record must be the prior stack's resources:\n got %s\nwant %s", rj, pj)
	}
}

// A delete whose process dies mid-flight is resumed to completion (deletes are idempotent).
func TestRecover_DeleteInterrupted_Completed(t *testing.T) {
	f := deployTemplate(t, []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    Properties: { Description: a }
  KeyB:
    Type: AWS::KMS::Key
    DependsOn: KeyA
    Properties: { Description: b }
  Shared:
    Type: AWS::KMS::Key
    DeletionPolicy: Retain
    Properties: { Description: shared }
`))
	f.dieAfter, f.mutations = 2, 0 // DELETE_IN_PROGRESS record, then one delete — then gone
	if _, err := Destroy(context.Background(), deployOpts(), f); err == nil {
		t.Fatal("the dying destroy must not succeed")
	}
	if f.stored == nil || f.stored.Status != "DELETE_IN_PROGRESS" {
		t.Fatalf("want DELETE_IN_PROGRESS left behind, got %+v", f.stored)
	}
	f.dieAfter = 0
	rec, err := RecoverInterrupted(context.Background(), deployOpts(), f, interruptedReason)
	if err != nil || rec == nil || rec.Status != "DELETE_COMPLETE" {
		t.Fatalf("the resumed delete completes: %+v %v", rec, err)
	}
	if f.stored != nil {
		t.Fatal("the stack record must be removed")
	}
	for _, k := range []string{"EncryptionKey/keya", "EncryptionKey/keyb"} {
		if _, live := f.liveLabels[k]; live {
			t.Fatalf("%s must be deleted", k)
		}
	}
	if _, ok := f.liveLabels["EncryptionKey/shared"]; !ok {
		t.Fatal("the Retain resource survives the resumed delete")
	}
}

// The interleaved create (custom resources) records each resource as Pending before creating it, so a
// create killed mid-way is rolled back — including a Delete event to the custom resource's Function.
func TestRecover_InterleavedCreate_WriteAhead(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/handler:latest } }
  Setup:
    Type: Custom::Setup
    Properties: { ServiceToken: !GetAtt Fn.Arn }
  Consumer:
    Type: AWS::Lambda::Function
    DependsOn: Setup
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/consumer:latest } }
`
	var events []string
	opts := deployOpts()
	opts.Invoke = func(_ context.Context, _, _ string, event []byte) (map[string]any, error) {
		var e map[string]any
		_ = json.Unmarshal(event, &e)
		events = append(events, e["RequestType"].(string)+":"+e["LogicalResourceId"].(string))
		return map[string]any{"Status": "SUCCESS"}, nil
	}
	// Writes: IN_PROGRESS, Pending[Fn], Fn, Pending[Setup] (then Setup is invoked) — the process dies
	// before recording Setup as created.
	f := &fakeApplier{dieAfter: 4}
	if _, err := Deploy(context.Background(), []byte(tmpl), opts, f); err == nil {
		t.Fatal("the dying deploy must not succeed")
	}
	if f.stored.Status != "CREATE_IN_PROGRESS" || len(f.stored.Resources) != 1 || len(f.stored.Pending) != 1 ||
		f.stored.Pending[0].LogicalID != "Setup" {
		t.Fatalf("the record must hold Fn as created and Setup as Pending: %+v", f.stored)
	}
	events = nil
	f.dieAfter = 0
	rec, err := RecoverInterrupted(context.Background(), opts, f, interruptedReason)
	if err != nil || rec.Status != "ROLLBACK_COMPLETE" {
		t.Fatalf("recover: %+v %v", rec, err)
	}
	if len(f.deleted) != 1 || !strings.HasPrefix(f.deleted[0], "Function/") {
		t.Fatalf("the created Function must be deleted, deleted=%v", f.deleted)
	}
	if strings.Join(events, ",") != "Delete:Setup" {
		t.Fatalf("the Pending custom resource gets its Delete event, events=%v", events)
	}
}

// The engine's own create rollback honors Retain too (AWS retains a Retain resource on rollback).
func TestDeploy_Rollback_HonorsRetain(t *testing.T) {
	f := &fakeApplier{failOn: "EncryptionKey/keyc"}
	if _, err := Deploy(context.Background(), threeKeys, deployOpts(), f); err == nil {
		t.Fatal("deploy must fail")
	}
	if strings.Join(f.deleted, ",") != "EncryptionKey/keyb" {
		t.Fatalf("rollback deletes keyb, keeps the Retain keya: deleted=%v", f.deleted)
	}
}

// A record settled *_FAILED without the operation's authority keeps its Pending write-ahead entries; a
// later Destroy removes those too — but only objects carrying this stack's label (an entry may never have
// been applied, and a same-named object may be someone else's).
func TestDestroy_PendingIsLabelGuarded(t *testing.T) {
	f := &fakeApplier{
		stored: &StackRecord{Name: "s", Namespace: "cfn-test", Status: "UPDATE_ROLLBACK_FAILED",
			Resources: []StackResource{{LogicalID: "KeyA", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: "keya"}},
			Pending: []StackResource{
				{LogicalID: "Mine", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: "mine"},
				{LogicalID: "Theirs", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: "theirs"},
				{LogicalID: "Never", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: "never"},
			}},
		liveLabels: map[string]map[string]string{
			"EncryptionKey/keya":   {labelStack: "s"},
			"EncryptionKey/mine":   {labelStack: "s"},
			"EncryptionKey/theirs": {labelStack: "other"},
		},
	}
	rec, err := Destroy(context.Background(), deployOpts(), f)
	if err != nil || rec.Status != "DELETE_COMPLETE" {
		t.Fatalf("destroy: %+v %v", rec, err)
	}
	if strings.Join(f.deleted, ",") != "EncryptionKey/mine,EncryptionKey/keya,ConfigMap/cfn-stack-s" {
		t.Fatalf("Pending objects of this stack, then Resources, then the record; never another stack's: deleted=%v", f.deleted)
	}
	if _, ok := f.liveLabels["EncryptionKey/theirs"]; !ok {
		t.Fatal("another stack's same-named object must survive")
	}
}

// RecoveryFailedStatus maps each interrupted state to its terminal failure.
func TestRecoveryFailedStatus(t *testing.T) {
	for in, want := range map[string]string{
		"CREATE_IN_PROGRESS": "ROLLBACK_FAILED", "ROLLBACK_IN_PROGRESS": "ROLLBACK_FAILED",
		"UPDATE_IN_PROGRESS": "UPDATE_ROLLBACK_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS": "UPDATE_ROLLBACK_FAILED",
		"DELETE_IN_PROGRESS": "DELETE_FAILED", "CREATE_COMPLETE": "",
	} {
		if got := RecoveryFailedStatus(in); got != want {
			t.Errorf("RecoveryFailedStatus(%s) = %q, want %q", in, got, want)
		}
	}
}
