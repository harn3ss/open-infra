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
	opts.adoptStackID(current) // the stack instance's own StackId, as its create resolved AWS::StackId
	// An update runs only while it leaves every nested stack as it is (nested_stacks.go); its resources and
	// Outputs read the nested stacks' current Outputs.
	if msg := nestedUpdateRefusal(ctx, opts, desired, current); msg != "" {
		return nil, fmt.Errorf("%s", msg)
	}
	nestedData, err := nestedOutputsOf(ctx, opts, current.Resources)
	if err != nil {
		return nil, err
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
		next.Resources = append([]StackResource(nil), current.Resources...)
		setOutputs(ctx, data, opts, &next, ap, nestedData)
		if err := outputFailure(&next); err != nil {
			return current, fmt.Errorf("update refused (nothing changed): %w", err)
		}
		if outputsEqual(&next, current) {
			return current, nil
		}
		next.Status = "UPDATE_COMPLETE"
		next.Message = ""
		next.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		next.Events = append([]StackEvent(nil), current.Events...)
		next.stackEvent("UPDATE_IN_PROGRESS", startReason(opts))
		next.stackEvent("UPDATE_COMPLETE", "")
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
	inProg.Resources = append([]StackResource(nil), current.Resources...)
	inProg.Events = append([]StackEvent(nil), current.Events...)
	for _, b := range desired {
		if action[b.res.LogicalID] == Add {
			inProg.Pending = append(inProg.Pending, b.res)
		}
	}
	inProg.stackEvent("UPDATE_IN_PROGRESS", startReason(opts))
	if err := writeStackRecord(ctx, ap, &inProg, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}

	var added []StackResource // to delete on rollback
	var restarted []string    // instances this update stopped and started, by logical id: restarted again on rollback
	var waits waitQueue       // resources this update creates that are not yet complete (readiness.go)
	rollback := func(cause error) (*StackRecord, error) {
		for _, p := range waits.all() { // still being created when another resource failed: cancelled, as on AWS
			inProg.addEvent(p.res.LogicalID, p.res.Name, typeOr(p.res), "CREATE_FAILED", "Resource creation cancelled")
		}
		inProg.stackEvent("UPDATE_ROLLBACK_IN_PROGRESS", cause.Error())
		// Delete everything this update added (honoring Retain), then re-apply the entire prior stack.
		rerr := restorePrior(ctx, opts, ap, current.Resources, added, false)
		// An instance restarted onto the new spec is restarted onto its prior spec, as AWS's rollback does
		// (best-effort: its prior spec is restored either way, and applies at its next start).
		for _, id := range restarted {
			if prior, ok := currentByID[id]; ok {
				_ = restartInstance(ctx, opts, ap, prior)
			}
		}
		rec := *current
		rec.Pending = nil
		rec.Status = "UPDATE_ROLLBACK_COMPLETE"
		rec.Message = cause.Error()
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		rec.Events = inProg.Events
		if rerr != nil {
			// As on AWS, a rollback that could not restore the prior stack ends UPDATE_ROLLBACK_FAILED. What
			// the update added stays recorded (Pending), so deleting the stack removes it too.
			rec.Status = "UPDATE_ROLLBACK_FAILED"
			rec.Message = cause.Error() + " Rollback failed: " + rerr.Error()
			rec.Pending = append([]StackResource(nil), added...)
			rec.stackEvent("UPDATE_ROLLBACK_FAILED", rerr.Error())
			_ = writeStackRecord(ctx, ap, &rec, opts)
			return &rec, fmt.Errorf("update failed and its rollback could not restore the prior stack (UPDATE_ROLLBACK_FAILED): %w", cause)
		}
		rec.stackEvent("UPDATE_ROLLBACK_COMPLETE", "")
		_ = writeStackRecord(ctx, ap, &rec, opts)
		return &rec, fmt.Errorf("update failed and was rolled back to the prior stack (no orphans): %w", cause)
	}
	event := func(r StackResource, status, reason string) {
		inProg.addEvent(r.LogicalID, r.Name, typeOr(r), status, reason)
		flushEvents(ctx, ap, &inProg)
	}

	// Apply Adds and Modifies in dependency order. The stack owns what its record names (and what this
	// update creates); another object carrying its label was left by an earlier stack of the same name.
	owned := ownedFrom(current.Resources)
	// A resource this update creates is complete once its wait passes (readiness.go): before anything
	// that depends on it is changed, or at the end — so a new WaitCondition waits alongside the instance
	// that signals it.
	completed := map[string]bool{}
	complete := func(b builtResource, sigs []Signal) {
		if IsSignalWait(b.res) {
			b.res.SignalData = signalData(sigs)
			desiredByID[b.res.LogicalID] = b
		}
		completed[b.res.LogicalID] = true
		event(b.res, "CREATE_COMPLETE", "")
	}
	settle := func(set []builtResource) error {
		fb, err := settleWaits(ctx, opts, ap, set, complete)
		if err != nil {
			event(fb.res, "CREATE_FAILED", err.Error())
			for _, b := range set { // what had not completed is cancelled by the rollback
				if b.res.LogicalID != fb.res.LogicalID && !completed[b.res.LogicalID] {
					waits.add(b)
				}
			}
		}
		return err
	}
	for _, b := range desired {
		act := action[b.res.LogicalID]
		if act != Add && act != Modify {
			continue
		}
		if err := settle(waits.due(b.after)); err != nil {
			return rollback(err)
		}
		verb := "UPDATE"
		if act == Add {
			verb = "CREATE"
		}
		event(b.res, verb+"_IN_PROGRESS", "")
		if IsNestedStack(b.res) {
			// Only reachable when the nested stack itself is unchanged (nestedUpdateRefusal): what changed is
			// recorded on the parent alone (its TimeoutInMinutes), and the child stack is left as it is.
			event(b.res, verb+"_COMPLETE", "")
			continue
		}
		if IsSignalWait(b.res) {
			if act == Add { // a wait condition waits when it is created, never on an update
				waits.add(b)
				continue
			}
			event(b.res, verb+"_COMPLETE", "")
			continue
		}
		if act == Add {
			if err := tableTaken(ctx, opts, b.res); err != nil {
				event(b.res, verb+"_FAILED", err.Error())
				return rollback(err)
			}
		}
		if err := applyOwned(ctx, ap, b, opts.StackName, owned); err != nil {
			event(b.res, verb+"_FAILED", err.Error())
			return rollback(fmt.Errorf("applying %s/%s: %w", b.res.Kind, b.res.Name, err))
		}
		if act == Add {
			added = append(added, b.res)
			waits.add(b)
			continue
		}
		if opts.Wait {
			if err := ap.WaitReady(ctx, b.res.APIVersion, b.res.Kind, b.res.Name, opts.Timeout); err != nil {
				event(b.res, verb+"_FAILED", err.Error())
				return rollback(fmt.Errorf("%s/%s did not become ready: %w", b.res.Kind, b.res.Name, err))
			}
		}
		// An instance whose change it reads only when it starts (its InstanceType, UserData…) is stopped and
		// started, and the update waits until it runs on the new spec (instance_restart.go).
		if isStackVM(b.res) {
			if fields := restartFields(currentByID[b.res.LogicalID].Spec, b.res.Spec); len(fields) > 0 {
				if !opts.Wait {
					event(b.res, verb+"_IN_PROGRESS", "the instance runs its earlier "+strings.Join(fields, ", ")+" until it is next stopped and started (this update does not wait)")
				} else {
					restarted = append(restarted, b.res.LogicalID)
					inProg.Restarting = append([]string(nil), restarted...)
					if err := writeStackRecord(ctx, ap, &inProg, opts); err != nil {
						event(b.res, verb+"_FAILED", err.Error())
						return rollback(fmt.Errorf("could not record the restart of %s: %w", b.res.LogicalID, err))
					}
					event(b.res, verb+"_IN_PROGRESS", restartReason(fields))
					if err := restartInstance(ctx, opts, ap, b.res); err != nil {
						event(b.res, verb+"_FAILED", err.Error())
						return rollback(err)
					}
				}
			}
		}
		event(b.res, verb+"_COMPLETE", "")
	}
	if err := settle(waits.all()); err != nil {
		return rollback(err)
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
	// The stack's Outputs must resolve against what it is about to become (an Output that does not resolve
	// fails the update, which rolls back) — checked before anything is removed.
	newRec := &StackRecord{
		Name: opts.StackName, Namespace: opts.Namespace, StackID: current.StackID, Status: "UPDATE_COMPLETE",
		CreatedAt: current.CreatedAt, UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Template: string(data), Owner: current.Owner, Description: templateDescription(data), Fidelity: opts.Fidelity, TerminationProtection: current.TerminationProtection,
	}
	newRec.setParams(data, opts.Params)
	for _, b := range desired {
		r := desiredByID[b.res.LogicalID].res
		switch action[r.LogicalID] {
		case Add:
			r.Status = "CREATE_COMPLETE"
		case Modify:
			r.Status = "UPDATE_COMPLETE"
		default: // unchanged: keeps its status, and a wait condition its data
			if cur, ok := currentByID[r.LogicalID]; ok {
				r.Status, r.StatusReason, r.Timestamp, r.SignalData = cur.Status, cur.StatusReason, cur.Timestamp, cur.SignalData
				if IsNestedStack(r) { // a nested stack keeps the stack it is (its StackId and name)
					r.Name, r.PhysicalID, r.ProvisionedID = cur.Name, cur.PhysicalID, cur.ProvisionedID
				}
			}
		}
		if r.Timestamp == "" || action[r.LogicalID] == Add || action[r.LogicalID] == Modify {
			r.Timestamp = eventTime(time.Now())
		}
		newRec.Resources = append(newRec.Resources, r)
	}
	setOutputs(ctx, data, opts, newRec, ap, nestedData)
	if err := outputFailure(newRec); err != nil {
		return rollback(err)
	}

	inProg.stackEvent("UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", "")
	for _, c := range cs.Changes {
		if c.Action != Remove {
			continue
		}
		r := currentByID[c.LogicalID]
		if isRetain(r) || stillNamed[r.APIVersion+"/"+r.Kind+"/"+r.Name] || isOutOfBand(r) {
			if isRetain(r) {
				inProg.addEvent(r.LogicalID, r.Name, typeOr(r), "DELETE_SKIPPED", "")
			}
			continue
		}
		// A dropped S3 bucket that still holds data is kept, unmanaged, as AWS's cleanup leaves it (the
		// resource's DELETE_FAILED event says so; the update still completes).
		noWait := opts
		noWait.Wait = false // as before: an update does not wait for a removed object to go
		event(r, "DELETE_IN_PROGRESS", "")
		kept, err := deleteStackObject(ctx, noWait, ap, r, false)
		if err != nil {
			event(r, "DELETE_FAILED", err.Error())
			return rollback(err)
		}
		if kept {
			event(r, "DELETE_FAILED", (&BucketNotEmptyError{LogicalID: r.LogicalID, Bucket: bucketNameOf(r)}).Error())
			continue
		}
		event(r, "DELETE_COMPLETE", "")
	}

	// Success — the new resource set is exactly the desired one.
	newRec.Events = inProg.Events
	newRec.stackEvent("UPDATE_COMPLETE", "")
	if err := writeStackRecord(ctx, ap, newRec, opts); err != nil {
		return newRec, fmt.Errorf("stack updated but recording COMPLETE failed: %w", err)
	}
	return newRec, nil
}

// typeOr is a recorded resource's CloudFormation type, or its kind on a record from before types were kept.
func typeOr(r StackResource) string {
	if r.Type != "" {
		return r.Type
	}
	return r.Kind
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
			continue
		}
		note(removeTableData(ctx, opts, r))
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
