package cfn

import (
	"context"
	"errors"
	"testing"
)

// #350 Y: a delete records each resource's DELETE_IN_PROGRESS / DELETE_COMPLETE / DELETE_FAILED, so after a
// DELETE_FAILED the resource that failed shows DELETE_FAILED and the ones deleted show DELETE_COMPLETE
// (they kept their old CREATE_COMPLETE).
func TestDestroy_ResourceDeleteStatuses(t *testing.T) {
	f := &fakeApplier{}
	tmpl := "Resources:\n  A: { Type: AWS::KMS::Key, Properties: { Description: a } }\n  B: { Type: AWS::KMS::Key, DependsOn: A, Properties: { Description: b } }\n"
	if _, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	f.failDelete = "EncryptionKey/s-a"
	rec, err := Destroy(context.Background(), deployOpts(), f)
	if err == nil || rec.Status != "DELETE_FAILED" {
		t.Fatalf("want DELETE_FAILED: %v %+v", err, rec)
	}
	if len(rec.Resources) != 1 || rec.Resources[0].LogicalID != "A" || rec.Resources[0].Status != "DELETE_FAILED" {
		t.Fatalf("the resource that failed must show DELETE_FAILED: %+v", rec.Resources)
	}
	if !hasEvent(rec, "B", "DELETE_COMPLETE") || !hasEvent(rec, "A", "DELETE_FAILED") {
		t.Fatalf("events: %+v", rec.Events)
	}
}

// #348: an update whose rollback cannot restore the prior stack ends UPDATE_ROLLBACK_FAILED (it said
// UPDATE_ROLLBACK_COMPLETE), keeping what it added recorded so a delete removes it.
func TestUpdate_RollbackFailure(t *testing.T) {
	f := &fakeApplier{}
	v1 := "Resources:\n  A: { Type: AWS::KMS::Key, Properties: { Description: a } }\n"
	if _, err := Deploy(context.Background(), []byte(v1), deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	v2 := v1 + "  B: { Type: AWS::KMS::Key, Properties: { Description: b } }\n  C: { Type: AWS::KMS::Key, DependsOn: B, Properties: { Description: c } }\n"
	f.failOn, f.failDelete = "EncryptionKey/s-c", "EncryptionKey/s-b"
	rec, err := Update(context.Background(), []byte(v2), deployOpts(), f)
	if err == nil || rec.Status != "UPDATE_ROLLBACK_FAILED" {
		t.Fatalf("want UPDATE_ROLLBACK_FAILED: %v %+v", err, rec)
	}
	if len(rec.Pending) != 1 || rec.Pending[0].LogicalID != "B" {
		t.Fatalf("what the update added and could not delete must stay recorded: %+v", rec.Pending)
	}
}

// A stack created with termination protection refuses its delete (nothing is deleted), and keeps the
// protection across an update, as on AWS.
func TestTerminationProtection(t *testing.T) {
	f := &fakeApplier{}
	opts := deployOpts()
	opts.TerminationProtection = true
	if _, err := Deploy(context.Background(), []byte("Resources:\n  K: { Type: AWS::KMS::Key, Properties: { Description: a } }\n"), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	opts.TerminationProtection = false // an update does not take it from its options
	if _, err := Update(context.Background(), []byte("Resources:\n  K: { Type: AWS::KMS::Key, Properties: { Description: b } }\n"), opts, f); err != nil {
		t.Fatalf("update: %v", err)
	}
	if f.stored == nil || !f.stored.TerminationProtection {
		t.Fatalf("the update must keep termination protection: %+v", f.stored)
	}
	_, err := Destroy(context.Background(), opts, f)
	var tp *TerminationProtectedError
	if !errors.As(err, &tp) || len(f.deleted) != 0 {
		t.Fatalf("a protected stack's delete must be refused with nothing deleted: %v %v", err, f.deleted)
	}
}
