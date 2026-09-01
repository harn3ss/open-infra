package main

import (
	"context"
	"strings"
	"testing"
)

func deployTemplate(t *testing.T, tmpl []byte) *fakeApplier {
	t.Helper()
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), tmpl, deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	f.applied = nil
	f.deleted = nil
	return f
}

func TestDestroy_ReverseOrder(t *testing.T) {
	f := deployTemplate(t, initialStack) // KeyA, then KeyB (depends on KeyA)
	rec, err := Destroy(context.Background(), deployOpts(), f)
	if err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if rec.Status != "DELETE_COMPLETE" {
		t.Fatalf("status = %s, want DELETE_COMPLETE", rec.Status)
	}
	// KeyB (last created) deleted before KeyA; the record ConfigMap removed too.
	want := []string{"EncryptionKey/keyb", "EncryptionKey/keya", "ConfigMap/cfn-stack-s"}
	if strings.Join(f.deleted, ",") != strings.Join(want, ",") {
		t.Fatalf("delete order = %v, want %v", f.deleted, want)
	}
	if len(rec.Resources) != 0 {
		t.Fatalf("nothing should remain, got %v", rec.Resources)
	}
	// the stored record is gone.
	if _, found, _ := f.GetStack(context.Background(), "s"); found {
		t.Fatal("stack record should be deleted")
	}
}

func TestDestroy_RetainKeepsResource(t *testing.T) {
	tmpl := []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    Properties: { Description: a }
  KeyB:
    Type: AWS::KMS::Key
    DeletionPolicy: Retain
    Properties: { Description: b }
`)
	f := deployTemplate(t, tmpl)
	rec, err := Destroy(context.Background(), deployOpts(), f)
	if err != nil {
		t.Fatalf("destroy: %v", err)
	}
	// KeyA deleted; KeyB retained (never deleted).
	if contains(f.deleted, "EncryptionKey/keyb") {
		t.Errorf("retained KeyB must not be deleted, deleted: %v", f.deleted)
	}
	if !contains(f.deleted, "EncryptionKey/keya") {
		t.Errorf("KeyA should be deleted, deleted: %v", f.deleted)
	}
	// the retained resource is reported (now unmanaged).
	if len(rec.Resources) != 1 || rec.Resources[0].LogicalID != "KeyB" {
		t.Fatalf("KeyB should be reported as retained, got %v", rec.Resources)
	}
}

func TestDestroy_SnapshotRefused(t *testing.T) {
	tmpl := []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    DeletionPolicy: Snapshot
    Properties: { Description: a }
`)
	f := deployTemplate(t, tmpl)
	_, err := Destroy(context.Background(), deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "Snapshot") {
		t.Fatalf("Snapshot policy should refuse destroy, got %v", err)
	}
	// nothing deleted.
	if len(f.deleted) != 0 {
		t.Fatalf("a refused destroy must delete nothing, deleted: %v", f.deleted)
	}
}

func TestDestroy_NoStack_Refused(t *testing.T) {
	if _, err := Destroy(context.Background(), deployOpts(), &fakeApplier{}); err == nil ||
		!strings.Contains(err.Error(), "no stack") {
		t.Fatalf("destroying a nonexistent stack should be refused, got %v", err)
	}
}

// Deletes are not reversible: a failed delete leaves DELETE_FAILED with what remains, and the
// record is kept (not removed).
func TestDestroy_DeleteFails(t *testing.T) {
	f := deployTemplate(t, initialStack) // KeyA, KeyB
	f.failDelete = "EncryptionKey/keyb"  // the first to be deleted (reverse order)
	rec, err := Destroy(context.Background(), deployOpts(), f)
	if err == nil {
		t.Fatal("expected destroy to fail")
	}
	if rec.Status != "DELETE_FAILED" {
		t.Fatalf("status = %s, want DELETE_FAILED", rec.Status)
	}
	// both remain (keyb failed, keya never reached), and the record was NOT removed.
	if len(rec.Resources) != 2 {
		t.Fatalf("both resources should remain, got %v", rec.Resources)
	}
	if _, found, _ := f.GetStack(context.Background(), "s"); !found {
		t.Fatal("a failed destroy must keep the stack record")
	}
}
