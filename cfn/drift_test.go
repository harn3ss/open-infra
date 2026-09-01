package main

import (
	"context"
	"strings"
	"testing"
)

func driftOf(r *DriftReport, id string) ResourceDrift {
	for _, rd := range r.Resources {
		if rd.LogicalID == id {
			return rd
		}
	}
	return ResourceDrift{}
}

func TestDrift_InSync(t *testing.T) {
	f := deployTemplate(t, initialStack) // KeyA, KeyB; liveSpecs mirror what was applied
	r, err := DetectDrift(context.Background(), deployOpts(), f)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if !r.InSync {
		t.Fatalf("a freshly-deployed stack should be in sync, got %+v", r.Resources)
	}
	for _, rd := range r.Resources {
		if rd.Status != InSync {
			t.Errorf("%s should be IN_SYNC, got %s %v", rd.LogicalID, rd.Status, rd.DriftedFields)
		}
	}
}

func TestDrift_ModifiedField(t *testing.T) {
	f := deployTemplate(t, initialStack)
	// Someone edits the live object out of band.
	f.liveSpecs["EncryptionKey/keya"]["description"] = "hand-edited"
	r, err := DetectDrift(context.Background(), deployOpts(), f)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if r.InSync {
		t.Fatal("expected drift to be detected")
	}
	kd := driftOf(r, "KeyA")
	if kd.Status != Modified || len(kd.DriftedFields) != 1 || kd.DriftedFields[0] != "description" {
		t.Fatalf("KeyA should be MODIFIED on description, got %s %v", kd.Status, kd.DriftedFields)
	}
	if driftOf(r, "KeyB").Status != InSync {
		t.Errorf("KeyB was not touched and should be in sync")
	}
}

func TestDrift_DeletedOutOfBand(t *testing.T) {
	f := deployTemplate(t, initialStack)
	delete(f.liveSpecs, "EncryptionKey/keyb") // someone deleted it
	r, err := DetectDrift(context.Background(), deployOpts(), f)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if driftOf(r, "KeyB").Status != Deleted {
		t.Fatalf("KeyB should be DELETED, got %s", driftOf(r, "KeyB").Status)
	}
	if r.InSync {
		t.Fatal("a deleted resource is drift")
	}
}

// A default the CRD/composition filled in that the stack never declared is NOT drift — drift
// only compares the fields the stack owns.
func TestDrift_IgnoresLiveDefaults(t *testing.T) {
	f := deployTemplate(t, initialStack)
	f.liveSpecs["EncryptionKey/keya"]["vaultKeyPath"] = "transit/keys/keya" // a composition-filled default
	r, err := DetectDrift(context.Background(), deployOpts(), f)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if !r.InSync {
		t.Fatalf("an extra defaulted field is not drift, got %+v", r.Resources)
	}
}

func TestDrift_NoStack_Refused(t *testing.T) {
	if _, err := DetectDrift(context.Background(), deployOpts(), &fakeApplier{}); err == nil ||
		!strings.Contains(err.Error(), "no stack") {
		t.Fatalf("drift on a nonexistent stack should be refused, got %v", err)
	}
}
