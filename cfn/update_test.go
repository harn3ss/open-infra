package cfn

import (
	"context"
	"strings"
	"testing"
)

var initialStack = []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    Properties: { Description: a }
  KeyB:
    Type: AWS::KMS::Key
    DependsOn: KeyA
    Properties: { Description: b }
`)

// KeyA modified, KeyC added, KeyB removed.
var updatedStack = []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    Properties: { Description: a-changed }
  KeyC:
    Type: AWS::KMS::Key
    DependsOn: KeyA
    Properties: { Description: c }
`)

func deployInitial(t *testing.T) *fakeApplier {
	t.Helper()
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), initialStack, deployOpts(), f); err != nil {
		t.Fatalf("initial deploy: %v", err)
	}
	return f
}

func actionOf(cs *ChangeSet, id string) ChangeAction {
	for _, c := range cs.Changes {
		if c.LogicalID == id {
			return c.Action
		}
	}
	return ""
}

func TestChangeSet_AddModifyRemove(t *testing.T) {
	f := deployInitial(t)
	cs, _, _, err := BuildChangeSet(context.Background(), updatedStack, deployOpts(), f)
	if err != nil {
		t.Fatalf("changeset: %v", err)
	}
	if !cs.Exists || !cs.hasChanges() {
		t.Fatal("expected an existing stack with changes")
	}
	if a := actionOf(cs, "KeyA"); a != Modify {
		t.Errorf("KeyA action = %s, want Modify", a)
	}
	if a := actionOf(cs, "KeyC"); a != Add {
		t.Errorf("KeyC action = %s, want Add", a)
	}
	if a := actionOf(cs, "KeyB"); a != Remove {
		t.Errorf("KeyB action = %s, want Remove", a)
	}
}

func TestChangeSet_NoChanges(t *testing.T) {
	f := deployInitial(t)
	cs, _, _, err := BuildChangeSet(context.Background(), initialStack, deployOpts(), f)
	if err != nil {
		t.Fatalf("changeset: %v", err)
	}
	if cs.hasChanges() {
		t.Fatalf("re-applying the same template should show no changes, got %+v", cs.Changes)
	}
}

func TestUpdate_Success(t *testing.T) {
	f := deployInitial(t)
	f.applied = nil // focus on what the update does
	f.deleted = nil
	rec, err := Update(context.Background(), updatedStack, deployOpts(), f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if rec.Status != "UPDATE_COMPLETE" {
		t.Fatalf("status = %s, want UPDATE_COMPLETE", rec.Status)
	}
	// KeyC added and KeyA re-applied (modify); KeyB deleted.
	gotApplied := f.appliedNonCM()
	if !contains(gotApplied, "EncryptionKey/s-keyc") || !contains(gotApplied, "EncryptionKey/s-keya") {
		t.Errorf("update should apply keya(modify)+keyc(add), applied: %v", gotApplied)
	}
	if !contains(f.deleted, "EncryptionKey/s-keyb") {
		t.Errorf("update should delete keyb, deleted: %v", f.deleted)
	}
	// final resource set is exactly the desired one.
	ids := map[string]bool{}
	for _, r := range rec.Resources {
		ids[r.LogicalID] = true
	}
	if !ids["KeyA"] || !ids["KeyC"] || ids["KeyB"] {
		t.Errorf("final stack should be {KeyA,KeyC}, got %v", ids)
	}
}

// Rollback fidelity: if an added resource never becomes ready, the update rolls back to the
// EXACT prior stack — the add is deleted, the prior resources are restored, no orphans.
func TestUpdate_Rollback_RestoresPriorStack(t *testing.T) {
	f := deployInitial(t)
	f.applied = nil
	f.deleted = nil
	f.notReady = "s-keyc" // the newly-added key never comes ready
	rec, err := Update(context.Background(), updatedStack, deployOpts(), f)
	if err == nil {
		t.Fatal("expected the update to fail")
	}
	if rec.Status != "UPDATE_ROLLBACK_COMPLETE" {
		t.Fatalf("status = %s, want UPDATE_ROLLBACK_COMPLETE", rec.Status)
	}
	// the add was rolled back (deleted).
	if !contains(f.deleted, "EncryptionKey/s-keyc") {
		t.Errorf("rollback should delete the added keyc, deleted: %v", f.deleted)
	}
	// the prior stack is restored exactly: KeyA and KeyB, not KeyC.
	ids := map[string]bool{}
	for _, r := range rec.Resources {
		ids[r.LogicalID] = true
	}
	if !ids["KeyA"] || !ids["KeyB"] || ids["KeyC"] {
		t.Errorf("rollback should restore {KeyA,KeyB}, got %v", ids)
	}
	// KeyB was never actually removed (removal happens after adds; the add failed first).
	if contains(f.deleted, "EncryptionKey/s-keyb") {
		t.Errorf("keyb should not have been deleted before the failing add: %v", f.deleted)
	}
}

// #347 review item 3: the shared default EncryptionKey is Retain — removing the disk that created
// it (here the whole encrypted Volume) must NOT delete the key, since a sibling disk in the
// namespace may still use it. The Volume itself IS deleted.
func TestUpdate_RetainedDefaultKey_SurvivesRemoval(t *testing.T) {
	initial := []byte(`
Resources:
  Data:
    Type: AWS::EC2::Volume
    Properties: { Size: 10, Encrypted: true }
  Keep:
    Type: AWS::KMS::Key
    Properties: { Description: keep }
`)
	updated := []byte(`
Resources:
  Keep:
    Type: AWS::KMS::Key
    Properties: { Description: keep }
`)
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), initial, deployOpts(), f); err != nil {
		t.Fatalf("initial deploy: %v", err)
	}
	f.applied, f.deleted = nil, nil
	rec, err := Update(context.Background(), updated, deployOpts(), f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if rec.Status != "UPDATE_COMPLETE" {
		t.Fatalf("status = %s, want UPDATE_COMPLETE", rec.Status)
	}
	if !contains(f.deleted, "Volume/s-data") {
		t.Errorf("the removed Volume must be deleted, deleted: %v", f.deleted)
	}
	// The stack's own default key keyed only the removed disk, so it goes with it.
	if !contains(f.deleted, "EncryptionKey/s-ebs-default") {
		t.Errorf("the stack's default EncryptionKey must go with its last disk, deleted: %v", f.deleted)
	}
}

// A stack's default EncryptionKey is the stack's own (<stack>-ebs-default): another stack's crypto-erase
// of its key never reaches this stack's disks. Removing one of two default-encrypted disks keeps the key
// the other still uses.
func TestUpdate_StackDefaultKey_PerStackAndKeptWhileUsed(t *testing.T) {
	two := []byte(`
Resources:
  Data:
    Type: AWS::EC2::Volume
    Properties: { Size: 10, Encrypted: true }
  Logs:
    Type: AWS::EC2::Volume
    Properties: { Size: 10, Encrypted: "true" }
`)
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), two, deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	for _, v := range []string{"Volume/s-data", "Volume/s-logs"} {
		if got := f.liveSpecs[v]["encryptionKey"]; got != "s-ebs-default" {
			t.Fatalf("%s is keyed by %v, want the stack's own s-ebs-default", v, got)
		}
	}
	o := deployOpts()
	o.StackName = "other"
	fo := &fakeApplier{} // the fake keeps one stack record; the other stack gets its own
	if _, err := Deploy(context.Background(), two, o, fo); err != nil {
		t.Fatalf("deploy other: %v", err)
	}
	if got := fo.liveSpecs["Volume/other-data"]["encryptionKey"]; got != "other-ebs-default" {
		t.Fatalf("another stack's disk is keyed by %v, want its own other-ebs-default", got)
	}
	f.deleted = nil
	one := []byte("Resources:\n  Logs:\n    Type: AWS::EC2::Volume\n    Properties: { Size: 10, Encrypted: \"true\" }\n")
	if _, err := Update(context.Background(), one, deployOpts(), f); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !contains(f.deleted, "Volume/s-data") || contains(f.deleted, "EncryptionKey/s-ebs-default") {
		t.Fatalf("removing one disk must delete it and keep the key the other uses, deleted: %v", f.deleted)
	}
}

// A stack created when disks were keyed by the shared namespace key keeps that key: its disks are keyed
// by it, and switching an existing disk's key is not possible. A disk it adds uses the same key.
func TestUpdate_LegacyStackKeepsSharedDefaultKey(t *testing.T) {
	f := &fakeApplier{stored: &StackRecord{Name: "s", Namespace: "cfn-test", Status: "CREATE_COMPLETE", Resources: []StackResource{
		{LogicalID: "Data", APIVersion: "openinfra.dev/v1", Kind: "Volume", Name: "s-data", Spec: map[string]any{"size": "10Gi", "encrypted": true, "encryptionKey": defaultEBSKeyName}},
		{LogicalID: "Data/" + defaultEBSKeyName, APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: defaultEBSKeyName, DeletionPolicy: "Retain",
			Spec: defaultEBSEncryptionKey().Spec},
	}}, liveLabels: map[string]map[string]string{"Volume/s-data": {labelStack: "s"}, "EncryptionKey/" + defaultEBSKeyName: {labelStack: "s"}}}
	two := []byte(`
Resources:
  Data:
    Type: AWS::EC2::Volume
    Properties: { Size: 10, Encrypted: true }
  More:
    Type: AWS::EC2::Volume
    Properties: { Size: 5, Encrypted: true }
`)
	cs, _, _, err := BuildChangeSet(context.Background(), two, deployOpts(), f)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs.Changes {
		if c.LogicalID == "Data" && c.Action != Unchanged {
			t.Fatalf("the existing disk must keep its key (Unchanged), got %s", c.Action)
		}
	}
	rec, err := Update(context.Background(), two, deployOpts(), f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, r := range rec.Resources {
		if r.Kind == "Volume" && r.Spec["encryptionKey"] != defaultEBSKeyName {
			t.Errorf("%s is keyed by %v, want the shared %s the stack already uses", r.LogicalID, r.Spec["encryptionKey"], defaultEBSKeyName)
		}
	}
}

func TestUpdate_NoStack_Refused(t *testing.T) {
	if _, err := Update(context.Background(), initialStack, deployOpts(), &fakeApplier{}); err == nil ||
		!strings.Contains(err.Error(), "no stack") {
		t.Fatalf("updating a nonexistent stack should be refused, got %v", err)
	}
}

func TestUpdate_NoChanges_NoOp(t *testing.T) {
	f := deployInitial(t)
	f.applied = nil
	rec, err := Update(context.Background(), initialStack, deployOpts(), f)
	if err != nil {
		t.Fatalf("no-op update: %v", err)
	}
	if len(f.applied) != 0 || len(f.deleted) != 0 {
		t.Fatalf("a no-change update must touch nothing, applied=%v deleted=%v", f.applied, f.deleted)
	}
	_ = rec
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
