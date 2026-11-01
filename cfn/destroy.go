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
	for _, r := range append(append([]StackResource{}, rec.Resources...), rec.Pending...) {
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

	fail := func(resources, pending []StackResource, cause error) (*StackRecord, error) {
		out := *rec
		out.Status = "DELETE_FAILED"
		out.Message = cause.Error()
		out.Resources, out.Pending = resources, pending
		out.UpdatedAt = now()
		_ = writeStackRecord(ctx, ap, &out, opts)
		return &out, fmt.Errorf("destroy failed (deletes are not reversible; %d resource(s) remain): %w", len(resources)+len(pending), cause)
	}
	// Pending — an interrupted operation's write-ahead, kept only on a record that recovery had to settle
	// without the operation's authority — may never have been applied: those are deleted only where the
	// object carries this stack's label (newest first: they come after Resources in create order).
	pendingLeft, perr := teardown(ctx, opts, ap, rec.Pending, true)
	if perr != nil {
		return fail(rec.Resources, pendingLeft, perr)
	}
	remaining, terr := teardown(ctx, opts, ap, rec.Resources, false)
	if terr != nil {
		return fail(remaining, pendingLeft, terr)
	}

	// All deletable resources are gone — remove the stack record. Any retained resources are
	// reported and now unmanaged.
	_ = ap.Delete(ctx, "v1", "ConfigMap", "cfn-stack-"+opts.StackName)
	out := *rec
	out.Status = "DELETE_COMPLETE"
	out.Resources = append(remaining, pendingLeft...) // the retained ones, if any
	out.Pending = nil
	out.UpdatedAt = now()
	return &out, nil
}

// LabelReader is an optional Applier capability: a live object's metadata.labels (found=false when the
// object is absent). Recovery (recover.go) uses it to delete only objects that carry THIS stack's label: a
// resource an interrupted operation recorded ahead of applying it may never have been applied, and a
// same-named object that is not this stack's must survive.
type LabelReader interface {
	GetLabels(ctx context.Context, apiVersion, kind, name string) (labels map[string]string, found bool, err error)
}

// isRetain reports whether a resource's DeletionPolicy keeps it through destroy, update removal and
// rollback (AWS honors Retain on rollback too — RetainExceptOnCreate is its opt-out).
func isRetain(r StackResource) bool { return strings.EqualFold(r.DeletionPolicy, "Retain") }

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
		(r.APIVersion == apigwRestV1APIVersion && r.Kind == apigwRestV1Kind)
}

// teardown deletes resources newest-first (the record is in create order), honoring DeletionPolicy:
// Retain. A custom resource gets its Function's Delete event and a REST v1 API is deprovisioned by its
// recorded id — both best-effort, so a failed out-of-band delete never wedges the rest of the teardown.
// With opts.Wait each deleted object is waited for until it is actually gone. ownedOnly (recovery) first
// reads each object's labels and deletes it only if it carries this stack's label; an absent object, or
// one that is not this stack's, is simply not part of the stack. It returns the resources still present
// (retained, the one that failed, and any not reached) and the first error.
func teardown(ctx context.Context, opts DeployOptions, ap Applier, resources []StackResource, ownedOnly bool) ([]StackResource, error) {
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
	lr, canReadLabels := ap.(LabelReader)
	for i := len(resources) - 1; i >= 0; i-- {
		r := resources[i]
		if isRetain(r) {
			continue // left in place, intentionally unmanaged
		}
		// A custom resource (#269) has no k8s object to delete — instead send its Function a Delete event
		// (AWS's RequestType=Delete), best-effort: a failed custom-resource Delete must not wedge teardown
		// (it would otherwise leave the whole stack undeletable), so it is not fatal.
		if r.APIVersion == customResourceAPIVersion && r.Kind == customResourceKind {
			if opts.Invoke != nil {
				fnName, _ := r.Spec["function"].(string)
				resType, _ := r.Spec["resourceType"].(string)
				props, _ := r.Spec["properties"].(map[string]any)
				event, _ := json.Marshal(map[string]any{
					"RequestType": "Delete", "ResponseURL": "", "StackId": opts.StackName,
					"RequestId": opts.StackName + "/" + r.LogicalID, "ResourceType": resType,
					"LogicalResourceId": r.LogicalID, "ResourceProperties": props,
				})
				_, _ = opts.Invoke(ctx, opts.Namespace, fnName, event)
			}
			gone[i] = true
			continue
		}
		// A REST v1 API (#295) has no k8s object — tear it down via the apigateway hook, by the id
		// recorded at provision time. Best-effort like a custom-resource Delete: a failed/absent
		// deprovision (or a CLI destroy with no hook) must not wedge teardown of the rest of the stack.
		if r.APIVersion == apigwRestV1APIVersion && r.Kind == apigwRestV1Kind {
			if opts.DeprovisionRestAPI != nil && r.ProvisionedID != "" {
				_ = opts.DeprovisionRestAPI(ctx, r.ProvisionedID)
			}
			gone[i] = true
			continue
		}
		if ownedOnly && canReadLabels {
			labels, found, err := lr.GetLabels(ctx, r.APIVersion, r.Kind, r.Name)
			if err != nil {
				return remaining(), fmt.Errorf("reading %s/%s: %w", r.Kind, r.Name, err)
			}
			if !found || labels[labelStack] != opts.StackName {
				gone[i] = true // never applied, or not this stack's object: not ours to delete
				continue
			}
		}
		if err := ap.Delete(ctx, r.APIVersion, r.Kind, r.Name); err != nil {
			return remaining(), fmt.Errorf("deleting %s/%s: %w", r.Kind, r.Name, err)
		}
		if opts.Wait {
			if err := ap.WaitGone(ctx, r.APIVersion, r.Kind, r.Name, opts.Timeout); err != nil {
				return remaining(), err
			}
		}
		gone[i] = true
	}
	return remaining(), nil
}
