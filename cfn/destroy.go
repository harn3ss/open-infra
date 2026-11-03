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
package cfn

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
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

	// Termination protection refuses the delete, as on AWS.
	if rec.TerminationProtection {
		return rec, &TerminationProtectedError{Stack: opts.StackName}
	}
	// Fail-closed on DeletionPolicy: Snapshot — we cannot honor the snapshot it asked for.
	var snapshot []string
	for _, r := range append(append([]StackResource{}, rec.Resources...), rec.Pending...) {
		if strings.EqualFold(r.DeletionPolicy, "Snapshot") {
			snapshot = append(snapshot, r.LogicalID+" ("+r.Kind+")")
		}
	}
	if len(snapshot) > 0 {
		return rec, fmt.Errorf("refusing to destroy: DeletionPolicy: Snapshot is not supported, and deleting without the snapshot it asked for would lose data — %s. Remove the policy or delete these manually.",
			strings.Join(snapshot, ", "))
	}
	// Deletion protection (RDS DeletionProtection), as AWS refuses to delete a protected instance.
	if p := protectedOf(append(append([]StackResource{}, rec.Resources...), rec.Pending...)); len(p) > 0 {
		return rec, fmt.Errorf("refusing to destroy: %s has deletion protection on — update the stack to turn DeletionProtection off first", strings.Join(p, ", "))
	}

	now := func() string { return time.Now().UTC().Format(time.RFC3339) }
	prog := *rec
	prog.Status = "DELETE_IN_PROGRESS"
	prog.UpdatedAt = now()
	prog.Resources = append([]StackResource(nil), rec.Resources...)
	prog.Events = append([]StackEvent(nil), rec.Events...)
	prog.stackEvent("DELETE_IN_PROGRESS", "User Initiated")
	if err := writeStackRecord(ctx, ap, &prog, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}
	// Each resource's delete is an event, and its own status, as on AWS (DescribeStackEvents,
	// ListStackResources of a DELETE_FAILED stack).
	ev := func(r StackResource, status, reason string) {
		prog.resourceEvent(r, status, reason)
		flushEvents(ctx, ap, &prog)
	}

	fail := func(resources, pending []StackResource, cause error) (*StackRecord, error) {
		out := *rec
		out.Status = "DELETE_FAILED"
		out.Message = cause.Error()
		out.Resources, out.Pending = withStatuses(resources, prog.Resources), pending
		out.UpdatedAt = now()
		out.Events = prog.Events
		out.stackEvent("DELETE_FAILED", cause.Error())
		_ = writeStackRecord(ctx, ap, &out, opts)
		return &out, fmt.Errorf("destroy failed (deletes are not reversible; %d resource(s) remain): %w", len(resources)+len(pending), cause)
	}
	// Pending — an interrupted operation's write-ahead, kept only on a record that recovery had to settle
	// without the operation's authority — may never have been applied: those are deleted only where the
	// object carries this stack's label (newest first: they come after Resources in create order).
	pendingLeft, perr := teardown(ctx, opts, ap, rec.Pending, true, false, ev)
	if perr != nil {
		return fail(rec.Resources, pendingLeft, perr)
	}
	remaining, terr := teardown(ctx, opts, ap, rec.Resources, false, false, ev)
	if terr != nil {
		return fail(remaining, pendingLeft, terr)
	}

	// All deletable resources are gone — remove the stack record. Any retained resources are
	// reported and now unmanaged.
	_ = ap.Delete(ctx, "v1", "ConfigMap", "cfn-stack-"+opts.StackName)
	out := *rec
	out.Status = "DELETE_COMPLETE"
	out.Resources = withStatuses(append(remaining, pendingLeft...), prog.Resources) // the retained ones, if any
	out.Pending = nil
	out.UpdatedAt = now()
	out.Events = prog.Events
	out.stackEvent("DELETE_COMPLETE", "")
	return &out, nil
}

// LabelReader is an optional Applier capability: a live object's metadata.labels (found=false when the
// object is absent). Recovery (recover.go) uses it to delete only objects that carry THIS stack's label: a
// resource an interrupted operation recorded ahead of applying it may never have been applied, and a
// same-named object that is not this stack's must survive.
type LabelReader interface {
	GetLabels(ctx context.Context, apiVersion, kind, name string) (labels map[string]string, found bool, err error)
}

// withStatuses gives each resource of rs the status its entry in from has (by logical id) — the status
// a teardown's events set.
func withStatuses(rs, from []StackResource) []StackResource {
	byID := map[string]StackResource{}
	for _, r := range from {
		byID[r.LogicalID] = r
	}
	out := make([]StackResource, len(rs))
	for i, r := range rs {
		if f, ok := byID[r.LogicalID]; ok && f.Status != "" {
			r.Status, r.StatusReason, r.Timestamp = f.Status, f.StatusReason, f.Timestamp
		}
		out[i] = r
	}
	return out
}

// TerminationProtectedError is a delete refused because the stack has termination protection on.
type TerminationProtectedError struct{ Stack string }

func (e *TerminationProtectedError) Error() string {
	return "Stack [" + e.Stack + "] cannot be deleted while TerminationProtection is enabled"
}

// customResourceDelete sends a custom resource's Function AWS's Delete event (RequestType=Delete), as a
// stack delete and a rolled-back create do. Nothing is sent where functions cannot be invoked (the CLI).
func customResourceDelete(ctx context.Context, opts DeployOptions, r StackResource) (map[string]any, error) {
	if opts.Invoke == nil {
		return nil, nil
	}
	fnName, _ := r.Spec["function"].(string)
	resType, _ := r.Spec["resourceType"].(string)
	props, _ := r.Spec["properties"].(map[string]any)
	event, _ := json.Marshal(map[string]any{
		"RequestType": "Delete", "ResponseURL": "", "StackId": awsidentity.Current().StackID(opts.StackName),
		"RequestId": opts.StackName + "/" + r.LogicalID, "ResourceType": resType,
		"LogicalResourceId": r.LogicalID, "ResourceProperties": props,
	})
	return opts.Invoke(ctx, opts.Namespace, fnName, event)
}

// rollbackCreate undoes a failed create: everything it created, newest first, honoring Retain — a Retain
// resource (e.g. the shared default EncryptionKey, which may pre-date this stack and key a sibling's
// disks) survives, as AWS retains it on rollback. A custom resource gets its Function's Delete event; a
// DynamoDB table goes with its data. Each step is a resource event. It reports whether every delete
// succeeded: the stack then ends ROLLBACK_COMPLETE, else ROLLBACK_FAILED, as on AWS.
func rollbackCreate(ctx context.Context, opts DeployOptions, ap Applier, rec *StackRecord, applied []StackResource) bool {
	ok := true
	for i := len(applied) - 1; i >= 0; i-- {
		a := applied[i]
		if keptOnRollback(a) {
			rec.resourceEvent(a, "DELETE_SKIPPED", "")
			continue
		}
		rec.resourceEvent(a, "DELETE_IN_PROGRESS", "")
		var err error
		if IsCustomResource(a) {
			if resp, ierr := customResourceDelete(ctx, opts, a); ierr != nil {
				err = ierr
			} else if st, _ := resp["Status"].(string); resp != nil && !strings.EqualFold(st, "SUCCESS") {
				reason, _ := resp["Reason"].(string)
				err = fmt.Errorf("the custom resource's Function answered the Delete with %s: %s", st, reason)
			}
		} else if err = ap.Delete(ctx, a.APIVersion, a.Kind, a.Name); err == nil {
			err = removeTableData(ctx, opts, a)
		}
		if err != nil {
			rec.resourceEvent(a, "DELETE_FAILED", err.Error())
			ok = false
			continue
		}
		rec.resourceEvent(a, "DELETE_COMPLETE", "")
	}
	return ok
}

// rolledBackStatus is a rolled-back create's final status.
func rolledBackStatus(ok bool) string {
	if ok {
		return "ROLLBACK_COMPLETE"
	}
	return "ROLLBACK_FAILED"
}

// isRetain reports whether a resource's DeletionPolicy keeps it through a stack delete and through
// removal by an update: Retain and RetainExceptOnCreate. A rollback of the operation that created it uses
// keptOnRollback instead.
func isRetain(r StackResource) bool {
	return strings.EqualFold(r.DeletionPolicy, "Retain") || strings.EqualFold(r.DeletionPolicy, "RetainExceptOnCreate")
}

// protectedOf names the resources a delete would remove that have deletion protection on (a retained
// resource is not deleted, so it does not count).
func protectedOf(rs []StackResource) []string {
	var out []string
	for _, r := range rs {
		if r.Protected && !isRetain(r) {
			out = append(out, r.LogicalID+" ("+r.Kind+")")
		}
	}
	return out
}

// keptOnRollback reports whether a resource survives the rollback of the operation that created it:
// Retain only. RetainExceptOnCreate exists to delete a resource whose own creation is being rolled back.
func keptOnRollback(r StackResource) bool { return strings.EqualFold(r.DeletionPolicy, "Retain") }

// IsRetained reports whether a recorded resource survives a stack delete (DeletionPolicy: Retain).
func IsRetained(r StackResource) bool { return isRetain(r) }

// IsCustomResource reports whether a recorded resource is a custom resource (its teardown is a Delete
// event to its Function, not an object delete).
func IsCustomResource(r StackResource) bool {
	return r.APIVersion == customResourceAPIVersion && r.Kind == customResourceKind
}

// IsRestV1API reports whether a recorded resource is a REST v1 API provisioned out of band.
func IsRestV1API(r StackResource) bool {
	return r.APIVersion == apigwRestV1APIVersion && r.Kind == apigwRestV1Kind
}

// isOutOfBand reports whether a recorded resource is not a Kubernetes object: a custom resource (#269,
// invoked) or a provisioned REST v1 API (#295). Neither is applied or deleted as an object.
func isOutOfBand(r StackResource) bool {
	return (r.APIVersion == customResourceAPIVersion && r.Kind == customResourceKind) ||
		(r.APIVersion == apigwRestV1APIVersion && r.Kind == apigwRestV1Kind) || IsSignalWait(r)
}

// teardown deletes resources newest-first (the record is in create order), honoring DeletionPolicy:
// Retain. A custom resource gets its Function's Delete event and a REST v1 API is deprovisioned by its
// recorded id — both best-effort, so a failed out-of-band delete never wedges the rest of the teardown.
// With opts.Wait each deleted object is waited for until it is actually gone. ownedOnly (recovery) first
// reads each object's labels and deletes it only if it carries this stack's label; an absent object, or
// one that is not this stack's, is simply not part of the stack. rollback (undoing an interrupted
// create) keeps only Retain resources, not RetainExceptOnCreate ones. ev, when set, records each
// template resource's DELETE_IN_PROGRESS / DELETE_COMPLETE / DELETE_FAILED / DELETE_SKIPPED, as AWS
// reports them (a companion object is part of its resource and records none). It returns the resources
// still present (retained, the one that failed, and any not reached) and the first error.
func teardown(ctx context.Context, opts DeployOptions, ap Applier, resources []StackResource, ownedOnly, rollback bool,
	ev func(r StackResource, status, reason string)) ([]StackResource, error) {
	gone := make([]bool, len(resources))
	remaining := func() []StackResource {
		var out []StackResource
		for i, r := range resources {
			if !gone[i] {
				out = append(out, r)
			}
		}
		return out
	}
	event := func(r StackResource, status, reason string) {
		if ev != nil && !strings.Contains(r.LogicalID, "/") {
			ev(r, status, reason)
		}
	}
	failed := func(r StackResource, err error) ([]StackResource, error) {
		event(r, "DELETE_FAILED", err.Error())
		return remaining(), err
	}
	lr, canReadLabels := ap.(LabelReader)
	for i := len(resources) - 1; i >= 0; i-- {
		r := resources[i]
		if (rollback && keptOnRollback(r)) || (!rollback && isRetain(r)) {
			event(r, "DELETE_SKIPPED", "")
			continue // left in place, intentionally unmanaged
		}
		if IsSignalWait(r) { // a wait condition: there is nothing to delete
			event(r, "DELETE_COMPLETE", "")
			gone[i] = true
			continue
		}
		if ownedOnly && canReadLabels && !isOutOfBand(r) {
			labels, found, err := lr.GetLabels(ctx, r.APIVersion, r.Kind, r.Name)
			if err != nil {
				return remaining(), fmt.Errorf("reading %s/%s: %w", r.Kind, r.Name, err)
			}
			if !found || labels[labelStack] != opts.StackName {
				gone[i] = true // never applied, or not this stack's object: not ours to delete
				continue
			}
		}
		event(r, "DELETE_IN_PROGRESS", "")
		switch {
		// A custom resource (#269) has no k8s object to delete — instead send its Function a Delete event
		// (AWS's RequestType=Delete), best-effort: a failed custom-resource Delete must not wedge teardown
		// (it would otherwise leave the whole stack undeletable), so it is not fatal. A refusal because the
		// caller may not invoke the Function is: the resource stays and the teardown fails.
		case r.APIVersion == customResourceAPIVersion && r.Kind == customResourceKind:
			if _, err := customResourceDelete(ctx, opts, r); IsUnauthorized(err) {
				return failed(r, fmt.Errorf("custom resource %s: %w", r.LogicalID, err))
			}
		// A REST v1 API (#295) has no k8s object — tear it down via the apigateway hook, by the id
		// recorded at provision time. Best-effort like a custom-resource Delete: a failed/absent
		// deprovision (or a CLI destroy with no hook) must not wedge teardown of the rest of the stack.
		// A refusal because the caller may not delete the API is fatal, as for a custom resource.
		case r.APIVersion == apigwRestV1APIVersion && r.Kind == apigwRestV1Kind:
			if opts.DeprovisionRestAPI != nil && r.ProvisionedID != "" {
				if err := opts.DeprovisionRestAPI(ctx, r.ProvisionedID); IsUnauthorized(err) {
					return failed(r, fmt.Errorf("REST API %s: %w", r.LogicalID, err))
				}
			}
		default:
			// An S3 bucket is deleted as AWS deletes one: refused while it still holds data (BucketNotEmpty —
			// the stack goes DELETE_FAILED and the bucket and its data stay), removed with its claim when empty.
			if _, err := deleteStackObject(ctx, opts, ap, r, true); err != nil {
				return failed(r, err)
			}
		}
		event(r, "DELETE_COMPLETE", "")
		gone[i] = true
	}
	return remaining(), nil
}
