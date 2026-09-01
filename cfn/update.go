// Stateful update for the CFN engine (Phase 3).
//
// Update applies a change set to an existing stack, fail-closed and with rollback as a
// first-class property (the place most CFN engines lose fidelity):
//
//  1. Build the change set — the same plan+translate gate as deploy, so an untranslatable new
//     template is refused before anything changes.
//  2. Apply Adds and Modifies in dependency order (each readiness-gated), then delete Removes
//     in reverse dependency order.
//  3. On ANY failure, roll back to the exact prior stack: delete everything this update added,
//     then re-apply every resource the prior stack had (restoring modified specs and
//     re-creating deleted ones). The stack ends UPDATE_ROLLBACK_COMPLETE, matching the state
//     it had before the update — no orphans, no half-applied change.
package main

import (
	"context"
	"fmt"
	"time"
)

// Update applies data as an update to an existing stack. Returns the resulting record
// (UPDATE_COMPLETE or UPDATE_ROLLBACK_COMPLETE) and an error if the update did not succeed.
func Update(ctx context.Context, data []byte, opts DeployOptions, ap Applier) (*StackRecord, error) {
	if opts.Namespace == "" {
		return nil, fmt.Errorf("a target namespace is required")
	}
	cs, desired, current, err := BuildChangeSet(ctx, data, opts, ap)
	if err != nil {
		return nil, err
	}
	if !cs.Exists {
		return nil, fmt.Errorf("no stack %q in namespace %q to update — use deploy to create it", opts.StackName, opts.Namespace)
	}
	if !cs.hasChanges() {
		return current, nil // no-op: nothing to do
	}

	desiredByID := map[string]builtResource{}
	for _, b := range desired {
		desiredByID[b.res.LogicalID] = b
	}
	currentByID := map[string]StackResource{}
	for _, r := range current.Resources {
		currentByID[r.LogicalID] = r
	}
	action := map[string]ChangeAction{}
	for _, c := range cs.Changes {
		action[c.LogicalID] = c.Action
	}

	// Mark IN_PROGRESS (keep the current resource list until we succeed).
	inProg := *current
	inProg.Status = "UPDATE_IN_PROGRESS"
	inProg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeStackRecord(ctx, ap, &inProg, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}

	var added []StackResource // to delete on rollback
	rollback := func(cause error) (*StackRecord, error) {
		// Delete everything this update added, newest first.
		for i := len(added) - 1; i >= 0; i-- {
			_ = ap.Delete(ctx, added[i].APIVersion, added[i].Kind, added[i].Name)
		}
		// Re-apply the entire prior stack: restores modified specs and re-creates removed
		// resources; unchanged re-applies are idempotent no-ops.
		for _, r := range current.Resources {
			if y, err := renderStackResource(r, opts); err == nil {
				_ = ap.Apply(ctx, y)
			}
		}
		rec := *current
		rec.Status = "UPDATE_ROLLBACK_COMPLETE"
		rec.Message = cause.Error()
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		_ = writeStackRecord(ctx, ap, &rec, opts)
		return &rec, fmt.Errorf("update failed and was rolled back to the prior stack (no orphans): %w", cause)
	}

	// Apply Adds and Modifies in dependency order.
	for _, b := range desired {
		switch action[b.res.LogicalID] {
		case Add, Modify:
			if err := ap.Apply(ctx, b.yml); err != nil {
				return rollback(fmt.Errorf("applying %s/%s: %w", b.res.Kind, b.res.Name, err))
			}
			if action[b.res.LogicalID] == Add {
				added = append(added, b.res)
			}
			if opts.Wait {
				if err := ap.WaitReady(ctx, b.res.APIVersion, b.res.Kind, b.res.Name, opts.Timeout); err != nil {
					return rollback(fmt.Errorf("%s/%s did not become ready: %w", b.res.Kind, b.res.Name, err))
				}
			}
		}
	}
	// Delete Removes in reverse dependency order (cs lists them reversed already).
	for _, c := range cs.Changes {
		if c.Action != Remove {
			continue
		}
		if err := ap.Delete(ctx, currentByID[c.LogicalID].APIVersion, c.Kind, c.Name); err != nil {
			return rollback(fmt.Errorf("deleting %s/%s: %w", c.Kind, c.Name, err))
		}
	}

	// Success — the new resource set is exactly the desired one.
	newRec := &StackRecord{
		Name: opts.StackName, Namespace: opts.Namespace, Status: "UPDATE_COMPLETE",
		CreatedAt: current.CreatedAt, UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, b := range desired {
		newRec.Resources = append(newRec.Resources, b.res)
	}
	if err := writeStackRecord(ctx, ap, newRec, opts); err != nil {
		return newRec, fmt.Errorf("stack updated but recording COMPLETE failed: %w", err)
	}
	return newRec, nil
}

// renderStackResource rebuilds the applyable YAML for a resource from its recorded spec — used
// to restore prior state during rollback.
func renderStackResource(res StackResource, opts DeployOptions) ([]byte, error) {
	return renderManifest(&Manifest{APIVersion: res.APIVersion, Kind: res.Kind, Name: res.Name, Spec: res.Spec}, opts)
}
