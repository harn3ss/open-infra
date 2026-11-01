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
package cfn

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Update applies data as an update to an existing stack. Returns the resulting record
// (UPDATE_COMPLETE or UPDATE_ROLLBACK_COMPLETE) and an error if the update did not succeed.
func Update(ctx context.Context, data []byte, opts DeployOptions, ap Applier) (*StackRecord, error) {
	if opts.Namespace == "" {
		return nil, fmt.Errorf("a target namespace is required")
	}
	// Fail-closed: a stack with custom resources can't be UPDATEd (v1, #269) — a custom resource runs
	// deploy-time logic (an invoke) with no diffable desired state, so an in-place update can't honor it.
	// Destroy + recreate instead. (Create + delete are supported; update is the bounded carve-out.)
	if pt, perr := Parse(data); perr == nil && hasCustomResources(pt) {
		return nil, fmt.Errorf("updating a stack that contains a custom resource is not supported (#269): a custom resource runs deploy-time logic that has no diffable state — destroy and recreate the stack instead")
	}
	cs, desired, current, err := BuildChangeSet(ctx, data, opts, ap)
	if err != nil {
		return nil, err
	}
	if !cs.Exists {
		return nil, fmt.Errorf("no stack %q in namespace %q to update — use deploy to create it", opts.StackName, opts.Namespace)
	}
	// Also refuse if the EXISTING stack was created with custom resources (removing one via update would
	// need a Delete-event invoke the diff path doesn't run) — destroy + recreate.
	for _, r := range current.Resources {
		if r.APIVersion == customResourceAPIVersion && r.Kind == customResourceKind {
			return nil, fmt.Errorf("updating a stack that was created with a custom resource is not supported (#269) — destroy and recreate the stack instead")
		}
		if r.APIVersion == apigwRestV1APIVersion && r.Kind == apigwRestV1Kind {
			return nil, fmt.Errorf("updating a stack that was created with an API Gateway REST v1 API is not supported yet (#295) — the diff path does not re-provision the API; destroy and recreate the stack, or change the API via the apigateway API")
		}
	}
	if !cs.hasChanges() {
		// No resource changes — but the template's Outputs (or their live values) may have changed; an
		// Outputs-only change is still an update. Otherwise a true no-op: nothing is written.
		next := *current
		setOutputs(ctx, data, opts, &next, ap, nil)
		if outputsEqual(&next, current) {
			return current, nil
		}
		next.Status = "UPDATE_COMPLETE"
		next.Message = ""
		next.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := writeStackRecord(ctx, ap, &next, opts); err != nil {
			return &next, fmt.Errorf("stack outputs updated but recording COMPLETE failed: %w", err)
		}
		return &next, nil
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
	var removed []StackResource
	for _, c := range cs.Changes {
		action[c.LogicalID] = c.Action
		if c.Action == Remove {
			removed = append(removed, currentByID[c.LogicalID])
		}
	}
	// Removing a resource with deletion protection is refused before anything changes, as on AWS.
	if p := protectedOf(removed); len(p) > 0 {
		return nil, fmt.Errorf("refusing to update: it would remove %s, which has deletion protection on — turn DeletionProtection off in an update first", strings.Join(p, ", "))
	}

	// Mark IN_PROGRESS (keep the current resource list until we succeed). The resources this update
	// will ADD are recorded as Pending before any is applied (write-ahead), so an update whose process
	// dies mid-flight can be rolled back to exactly this prior stack from the record (RecoverInterrupted).
	inProg := *current
	inProg.Status = "UPDATE_IN_PROGRESS"
	inProg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	inProg.Pending = nil
	for _, b := range desired {
		if action[b.res.LogicalID] == Add {
			inProg.Pending = append(inProg.Pending, b.res)
		}
	}
	if err := writeStackRecord(ctx, ap, &inProg, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}

	var added []StackResource // to delete on rollback
	rollback := func(cause error) (*StackRecord, error) {
		// Delete everything this update added (honoring Retain), then re-apply the entire prior stack.
		_ = restorePrior(ctx, opts, ap, current.Resources, added, false)
		rec := *current
		rec.Pending = nil
		rec.Status = "UPDATE_ROLLBACK_COMPLETE"
		rec.Message = cause.Error()
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		_ = writeStackRecord(ctx, ap, &rec, opts)
		return &rec, fmt.Errorf("update failed and was rolled back to the prior stack (no orphans): %w", cause)
	}

	// Apply Adds and Modifies in dependency order. The stack owns what its record names (and what this
	// update creates); another object carrying its label was left by an earlier stack of the same name.
	owned := ownedFrom(current.Resources)
	for _, b := range desired {
		switch action[b.res.LogicalID] {
		case Add, Modify:
			if err := applyOwned(ctx, ap, b, opts.StackName, owned); err != nil {
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
	// Delete Removes in reverse dependency order (cs lists them reversed already). Honor Retain: a
	// Retain resource is left in place (now unmanaged), matching destroy's behavior — e.g. removing
	// one disk must not delete a shared default EncryptionKey another disk still uses (#347 review item 3).
	// An object the new stack still names (a companion another resource also carries, such as the stack's
	// default EncryptionKey of a disk that stays) is not deleted either: only that record entry goes.
	stillNamed := map[string]bool{}
	for _, b := range desired {
		stillNamed[b.res.APIVersion+"/"+b.res.Kind+"/"+b.res.Name] = true
	}
	for _, c := range cs.Changes {
		if c.Action != Remove {
			continue
		}
		if r := currentByID[c.LogicalID]; isRetain(r) || stillNamed[r.APIVersion+"/"+r.Kind+"/"+r.Name] {
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
		Template: string(data), Owner: current.Owner,
	}
	newRec.setParams(data, opts.Params)
	for _, b := range desired {
		newRec.Resources = append(newRec.Resources, b.res)
	}
	setOutputs(ctx, data, opts, newRec, ap, nil)
	if err := writeStackRecord(ctx, ap, newRec, opts); err != nil {
		return newRec, fmt.Errorf("stack updated but recording COMPLETE failed: %w", err)
	}
	return newRec, nil
}

// restorePrior rolls an update back to the prior stack. It deletes what the update added, newest first —
// honoring Retain (a Retain resource such as the shared default EncryptionKey survives rollback: a sibling
// may already use it and it may pre-date this update, #347 review item 3), and never an object the prior
// stack itself names (re-applying it below restores it; deleting it first would lose its data). Then it
// re-applies every prior resource from its recorded spec: restoring modified specs and re-creating removed
// resources; unchanged re-applies are idempotent no-ops. ownedOnly (recovery) deletes an added object only
// if it carries this stack's label (an Add recorded ahead of applying may never have been applied). Every
// step is attempted; the first error is returned.
func restorePrior(ctx context.Context, opts DeployOptions, ap Applier, prior, added []StackResource, ownedOnly bool) error {
	inPrior := map[string]bool{}
	for _, r := range prior {
		inPrior[r.APIVersion+"/"+r.Kind+"/"+r.Name] = true
	}
	var first error
	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	lr, canReadLabels := ap.(LabelReader)
	for i := len(added) - 1; i >= 0; i-- {
		r := added[i]
		if keptOnRollback(r) || isOutOfBand(r) || inPrior[r.APIVersion+"/"+r.Kind+"/"+r.Name] {
			continue
		}
		if ownedOnly && canReadLabels {
			labels, found, err := lr.GetLabels(ctx, r.APIVersion, r.Kind, r.Name)
			if err != nil {
				note(fmt.Errorf("reading %s/%s: %w", r.Kind, r.Name, err))
				continue
			}
			if !found || labels[labelStack] != opts.StackName {
				continue // never applied, or not this stack's object
			}
		}
		if err := ap.Delete(ctx, r.APIVersion, r.Kind, r.Name); err != nil {
			note(fmt.Errorf("deleting added %s/%s: %w", r.Kind, r.Name, err))
		}
	}
	for _, r := range prior {
		if isOutOfBand(r) {
			continue // not a k8s object (an update never runs on a stack holding one)
		}
		y, err := renderStackResource(r, opts)
		if err == nil {
			err = ap.Apply(ctx, y)
		}
		if err != nil {
			note(fmt.Errorf("restoring %s/%s: %w", r.Kind, r.Name, err))
		}
	}
	return first
}

// renderStackResource rebuilds the applyable YAML for a resource from its recorded spec — used
// to restore prior state during rollback.
func renderStackResource(res StackResource, opts DeployOptions) ([]byte, error) {
	return renderManifest(&Manifest{APIVersion: res.APIVersion, Kind: res.Kind, Name: res.Name, Spec: res.Spec}, opts)
}
