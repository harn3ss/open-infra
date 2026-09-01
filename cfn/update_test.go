package main

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
	if !contains(gotApplied, "EncryptionKey/keyc") || !contains(gotApplied, "EncryptionKey/keya") {
		t.Errorf("update should apply keya(modify)+keyc(add), applied: %v", gotApplied)
	}
	if !contains(f.deleted, "EncryptionKey/keyb") {
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
	f.notReady = "keyc" // the newly-added key never comes ready
	rec, err := Update(context.Background(), updatedStack, deployOpts(), f)
	if err == nil {
		t.Fatal("expected the update to fail")
	}
	if rec.Status != "UPDATE_ROLLBACK_COMPLETE" {
		t.Fatalf("status = %s, want UPDATE_ROLLBACK_COMPLETE", rec.Status)
	}
	// the add was rolled back (deleted).
	if !contains(f.deleted, "EncryptionKey/keyc") {
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
	if contains(f.deleted, "EncryptionKey/keyb") {
		t.Errorf("keyb should not have been deleted before the failing add: %v", f.deleted)
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
