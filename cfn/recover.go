// Recovery of a stack operation interrupted mid-flight (#347).
//
// A stack operation runs inside the process that started it. If that process dies before the operation
// finishes — a rolling update replaces the pod running it — the operation dies with it, and the stack
// record is left *_IN_PROGRESS with nothing left to finish it: partially-created resources sit without the
// rollback the engine would have run, and the stack reports "in progress" forever. AWS never strands a
// stack: an interrupted operation fails and rolls back. RecoverInterrupted is that resolution, run by
// whoever notices the orphaned record (the aws-shim front door's recovery pass), from the record alone.
//
// That works because every operation records what it may create BEFORE creating it (write-ahead):
//
//   - Deploy lists every planned resource in Resources before its first apply; the interleaved create
//     (custom resources / REST v1) records the resource it is about to create as Pending;
//   - Update keeps the prior stack in Resources (with each resource's applied spec) and records the
//     resources it adds as Pending;
//   - Destroy keeps the stack's resources in Resources until the stack record itself is removed.
//
// Resolution per interrupted state — the rollback the engine runs when an operation fails:
//
//	CREATE_IN_PROGRESS / ROLLBACK_IN_PROGRESS
//	    → ROLLBACK_IN_PROGRESS → tear down Resources+Pending newest-first, honoring DeletionPolicy: Retain
//	    → ROLLBACK_COMPLETE (the retained resources stay listed), or ROLLBACK_FAILED with what remains
//	UPDATE_IN_PROGRESS / UPDATE_ROLLBACK_IN_PROGRESS
//	    → UPDATE_ROLLBACK_IN_PROGRESS → delete the Pending adds (honoring Retain), re-apply every prior
//	      resource from its recorded spec → UPDATE_ROLLBACK_COMPLETE, or UPDATE_ROLLBACK_FAILED
//	DELETE_IN_PROGRESS
//	    → resume the delete (Destroy is idempotent) → the record is removed (DELETE_COMPLETE), or DELETE_FAILED
//
// Every path is idempotent: a recovery that is itself interrupted leaves ROLLBACK_IN_PROGRESS /
// UPDATE_ROLLBACK_IN_PROGRESS / DELETE_IN_PROGRESS, which the next recovery continues. The reason passed in
// becomes the stack's StackStatusReason, so DescribeStacks names the interruption.
//
// Why fail-and-roll-back rather than resume an interrupted create or update: it is AWS's behavior for an
// operation that cannot finish; it needs only the record (resuming would need the template, parameters,
// exports and a custom resource's returned Data, none of which the record holds); and it can never apply
// something the caller did not see validated against the current state. A delete is the exception — it is
// resumed, because deletes are not reversible and finishing one is what the caller asked for.
//
// A write-ahead entry may never have been applied (the process died first), and a same-named object may
// belong to someone else. So the rollback deletes an object only when it carries THIS stack's label
// (every object the engine applies does) — read through the optional LabelReader capability.
package cfn

import (
	"context"
	"fmt"
	"time"
)

// RecoverInterrupted resolves a stack whose operation was interrupted (its process died) — see the file
// comment. It returns the resulting record (nil when the stack record is gone, e.g. a resumed delete that
// completed) and an error when the recovery did not fully succeed; a stack that is not *_IN_PROGRESS is
// returned untouched. The Applier must carry the authority the interrupted operation ran under (the
// aws-shim impersonates the operation's recorded caller).
func RecoverInterrupted(ctx context.Context, opts DeployOptions, ap Applier, reason string) (*StackRecord, error) {
	if opts.Namespace == "" {
		return nil, fmt.Errorf("a target namespace is required")
	}
	rec, found, err := ap.GetStack(ctx, opts.StackName)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	switch rec.Status {
	case "CREATE_IN_PROGRESS", "ROLLBACK_IN_PROGRESS":
		return recoverCreate(ctx, opts, ap, rec, reason)
	case "UPDATE_IN_PROGRESS", "UPDATE_ROLLBACK_IN_PROGRESS":
		return recoverUpdate(ctx, opts, ap, rec, reason)
	case "DELETE_IN_PROGRESS":
		return recoverDelete(ctx, opts, ap, reason)
	default:
		return rec, nil // settled: nothing to recover
	}
}

// RecoveryFailedStatus is the terminal status an interrupted operation in `status` ends in when it cannot
// be rolled back (e.g. no authority to run the rollback under): ROLLBACK_FAILED, UPDATE_ROLLBACK_FAILED or
// DELETE_FAILED. "" for a status that is not an interrupted operation.
func RecoveryFailedStatus(status string) string {
	switch status {
	case "CREATE_IN_PROGRESS", "ROLLBACK_IN_PROGRESS":
		return "ROLLBACK_FAILED"
	case "UPDATE_IN_PROGRESS", "UPDATE_ROLLBACK_IN_PROGRESS":
		return "UPDATE_ROLLBACK_FAILED"
	case "DELETE_IN_PROGRESS":
		return "DELETE_FAILED"
	}
	return ""
}

func recoverNow() string { return time.Now().UTC().Format(time.RFC3339) }

func recoverCreate(ctx context.Context, opts DeployOptions, ap Applier, rec *StackRecord, reason string) (*StackRecord, error) {
	prog := *rec
	prog.Status = "ROLLBACK_IN_PROGRESS"
	prog.Message = reason
	prog.UpdatedAt = recoverNow()
	if err := writeStackRecord(ctx, ap, &prog, opts); err != nil {
		return rec, fmt.Errorf("could not record ROLLBACK_IN_PROGRESS: %w", err)
	}
	remaining, terr := teardown(ctx, opts, ap, unionResources(rec.Resources, rec.Pending), true, true)
	out := *rec
	out.Pending = nil
	out.Outputs, out.OutputsOmitted = nil, nil
	out.Resources = remaining // the retained resources (and, on failure, what could not be deleted)
	out.UpdatedAt = recoverNow()
	if terr != nil {
		out.Status = "ROLLBACK_FAILED"
		out.Message = reason + " Rollback failed: " + terr.Error()
		_ = writeStackRecord(ctx, ap, &out, opts)
		return &out, fmt.Errorf("rolling back the interrupted create failed (%d resource(s) remain): %w", len(remaining), terr)
	}
	out.Status = "ROLLBACK_COMPLETE"
	out.Message = reason
	if err := writeStackRecord(ctx, ap, &out, opts); err != nil {
		return &out, fmt.Errorf("interrupted create rolled back but recording ROLLBACK_COMPLETE failed: %w", err)
	}
	return &out, nil
}

func recoverUpdate(ctx context.Context, opts DeployOptions, ap Applier, rec *StackRecord, reason string) (*StackRecord, error) {
	prog := *rec // keeps Pending, so a recovery interrupted in turn still knows the update's adds
	prog.Status = "UPDATE_ROLLBACK_IN_PROGRESS"
	prog.Message = reason
	prog.UpdatedAt = recoverNow()
	if err := writeStackRecord(ctx, ap, &prog, opts); err != nil {
		return rec, fmt.Errorf("could not record UPDATE_ROLLBACK_IN_PROGRESS: %w", err)
	}
	rerr := restorePrior(ctx, opts, ap, rec.Resources, rec.Pending, true)
	out := *rec // the prior stack: its resources, specs and Outputs
	out.Pending = nil
	out.UpdatedAt = recoverNow()
	if rerr != nil {
		out.Status = "UPDATE_ROLLBACK_FAILED"
		out.Message = reason + " Restoring the prior stack failed: " + rerr.Error()
		_ = writeStackRecord(ctx, ap, &out, opts)
		return &out, fmt.Errorf("rolling back the interrupted update failed: %w", rerr)
	}
	out.Status = "UPDATE_ROLLBACK_COMPLETE"
	out.Message = reason
	if err := writeStackRecord(ctx, ap, &out, opts); err != nil {
		return &out, fmt.Errorf("interrupted update rolled back but recording UPDATE_ROLLBACK_COMPLETE failed: %w", err)
	}
	return &out, nil
}

func recoverDelete(ctx context.Context, opts DeployOptions, ap Applier, reason string) (*StackRecord, error) {
	out, err := Destroy(ctx, opts, ap)
	if err == nil {
		return out, nil
	}
	// Destroy records DELETE_FAILED itself once it is under way, and a refusal before it starts (a
	// Snapshot policy on a record written by an older engine) would leave DELETE_IN_PROGRESS. Either way,
	// settle the record as DELETE_FAILED naming the interruption.
	if cur, found, gerr := ap.GetStack(ctx, opts.StackName); gerr == nil && found &&
		(cur.Status == "DELETE_IN_PROGRESS" || cur.Status == "DELETE_FAILED") {
		cur.Status = "DELETE_FAILED"
		cur.Message = reason + " Resuming the delete failed: " + err.Error()
		cur.UpdatedAt = recoverNow()
		_ = writeStackRecord(ctx, ap, cur, opts)
		return cur, err
	}
	return out, err
}

// unionResources is a then b, minus any b entry naming an object already listed (an interleaved create's
// Pending may repeat what it just appended to Resources). Out-of-band entries (custom resources, REST v1
// APIs) are identified by their logical id.
func unionResources(a, b []StackResource) []StackResource {
	seen := map[string]bool{}
	out := make([]StackResource, 0, len(a)+len(b))
	for _, list := range [][]StackResource{a, b} {
		for _, r := range list {
			k := r.APIVersion + "/" + r.Kind + "/" + r.Name
			if isOutOfBand(r) {
				k = "logical/" + r.LogicalID
			}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}
