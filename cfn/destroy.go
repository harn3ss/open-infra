// Stateful teardown for the CFN engine (Phase 4).
//
// Destroy deletes a stack: its resources in reverse dependency order (the record is stored in
// create order), then the stack record itself. It honors CloudFormation's DeletionPolicy —
// `Retain` leaves a resource in the cluster (now unmanaged), `Delete` (the default) removes
// it. `Snapshot` is refused up front: open-infra has no generic pre-delete snapshot for an
// arbitrary kind, and deleting a resource that asked to be snapshotted first would be exactly
// the silent data loss the cardinal rule forbids — so a Snapshot policy fails loud rather than
// deleting without the snapshot.
//
// Deletes are not reversible, so there is no rollback: a delete that fails leaves the stack
// DELETE_FAILED with the resources that remain, and stops.
package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Destroy tears down a stack. It returns the resulting record (DELETE_COMPLETE — with any
// retained resources listed — or DELETE_FAILED) and an error if teardown did not complete.
func Destroy(ctx context.Context, opts DeployOptions, ap Applier) (*StackRecord, error) {
	if opts.Namespace == "" {
		return nil, fmt.Errorf("a target namespace is required")
	}
	rec, found, err := ap.GetStack(ctx, opts.StackName)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("no stack %q in namespace %q to destroy", opts.StackName, opts.Namespace)
	}

	// Fail-closed on DeletionPolicy: Snapshot — we cannot honor the snapshot it asked for.
	var snapshot []string
	for _, r := range rec.Resources {
		if strings.EqualFold(r.DeletionPolicy, "Snapshot") {
			snapshot = append(snapshot, r.LogicalID+" ("+r.Kind+")")
		}
	}
	if len(snapshot) > 0 {
		return rec, fmt.Errorf("refusing to destroy: DeletionPolicy: Snapshot is not supported, and deleting without the snapshot it asked for would lose data — %s. Remove the policy or delete these manually.",
			strings.Join(snapshot, ", "))
	}

	now := func() string { return time.Now().UTC().Format(time.RFC3339) }
	prog := *rec
	prog.Status = "DELETE_IN_PROGRESS"
	prog.UpdatedAt = now()
	if err := writeStackRecord(ctx, ap, &prog, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}

	gone := map[string]bool{}
	remaining := func() []StackResource {
		var out []StackResource
		for _, r := range rec.Resources {
			if !gone[r.LogicalID] {
				out = append(out, r)
			}
		}
		return out
	}
	fail := func(cause error) (*StackRecord, error) {
		out := *rec
		out.Status = "DELETE_FAILED"
		out.Message = cause.Error()
		out.Resources = remaining()
		out.UpdatedAt = now()
		_ = writeStackRecord(ctx, ap, &out, opts)
		return &out, fmt.Errorf("destroy failed (deletes are not reversible; %d resource(s) remain): %w", len(out.Resources), cause)
	}

	// Reverse dependency order.
	for i := len(rec.Resources) - 1; i >= 0; i-- {
		r := rec.Resources[i]
		if strings.EqualFold(r.DeletionPolicy, "Retain") {
			continue // left in place, intentionally unmanaged
		}
		if err := ap.Delete(ctx, r.APIVersion, r.Kind, r.Name); err != nil {
			return fail(fmt.Errorf("deleting %s/%s: %w", r.Kind, r.Name, err))
		}
		if opts.Wait {
			if err := ap.WaitGone(ctx, r.APIVersion, r.Kind, r.Name, opts.Timeout); err != nil {
				return fail(err)
			}
		}
		gone[r.LogicalID] = true
	}

	// All deletable resources are gone — remove the stack record. Any retained resources are
	// reported and now unmanaged.
	_ = ap.Delete(ctx, "v1", "ConfigMap", "cfn-stack-"+opts.StackName)
	out := *rec
	out.Status = "DELETE_COMPLETE"
	out.Resources = remaining() // the retained ones, if any
	out.UpdatedAt = now()
	return &out, nil
}
