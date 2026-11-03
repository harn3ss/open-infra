// Stateful create for the CFN engine (Phase 2).
//
// Deploy provisions a stack LIVE, fail-closed by construction:
//
//  1. Plan gate — run the Phase-1 plan. A REJECTED plan (unsupported type/intrinsic, macro,
//     missing param, broken ref, cycle) refuses the deploy before anything is applied.
//  2. Translate gate — every included resource must have a create translator AND every one of
//     its properties must translate. A single blocking finding refuses the whole deploy. There
//     is no partial stack: nothing is applied until everything translates.
//  3. Apply in dependency order, recording each applied resource in a persisted stack record.
//  4. Rollback on failure — if any apply (or readiness wait) fails, the resources already
//     created THIS deploy are deleted in reverse order (a DeletionPolicy: Retain resource is
//     kept, as AWS keeps it), and the stack is marked CREATE_FAILED. A failed create leaves no
//     orphans. A create whose PROCESS dies mid-flight is rolled back from the record by
//     RecoverInterrupted (recover.go).
//
// Stack state is persisted as a ConfigMap (cfn-stack-<name>) so later phases (update, delete,
// drift) have a record of what was created; every applied resource is labeled with its stack.
package cfn

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	labelStack     = "cfn.openinfra.dev/stack"
	labelLogicalID = "cfn.openinfra.dev/logical-id"
	labelManagedBy = "app.kubernetes.io/managed-by"
	managedBy      = "cfn"
)

// Applier performs the live cluster operations. Abstracted so the engine's ordering / state /
// rollback logic is tested against a fake, and the live path shells out to kubectl.
type Applier interface {
	Apply(ctx context.Context, manifestYAML []byte) error
	Delete(ctx context.Context, apiVersion, kind, name string) error
	WaitReady(ctx context.Context, apiVersion, kind, name string, timeout time.Duration) error
	// WaitGone blocks until the resource no longer exists (for teardown).
	WaitGone(ctx context.Context, apiVersion, kind, name string, timeout time.Duration) error
	// GetStack reads a persisted stack record, if one exists (found=false when absent).
	GetStack(ctx context.Context, stackName string) (rec *StackRecord, found bool, err error)
	// GetSpec reads a live resource's .spec (found=false when the object is absent).
	GetSpec(ctx context.Context, apiVersion, kind, name string) (spec map[string]any, found bool, err error)
}

// NoEchoStore is an Applier that keeps a stack's NoEcho parameter values somewhere safer than the plain
// stack record. PutNoEcho replaces the stack's stored values (an empty map removes them). An Applier
// without one does not keep NoEcho values at all.
type NoEchoStore interface {
	PutNoEcho(ctx context.Context, stackName string, values map[string]string) error
}

type StackResource struct {
	LogicalID      string         `json:"logicalId"`
	APIVersion     string         `json:"apiVersion"`
	Kind           string         `json:"kind"`
	Name           string         `json:"name"`
	DeletionPolicy string         `json:"deletionPolicy,omitempty"` // Delete (default) | Retain | Snapshot
	Spec           map[string]any `json:"spec,omitempty"`           // the applied spec — enables diff (update) and faithful rollback
	ProvisionedID  string         `json:"provisionedId,omitempty"`  // out-of-band id of a non-k8s resource (e.g. a REST v1 API id), for teardown
	Protected      bool           `json:"protected,omitempty"`      // deletion protection: a delete/removal of the stack's resource is refused
	// Type is the resource's CloudFormation type (AWS::S3::Bucket); "" on a record from before it was kept.
	// A companion object a resource emits (an inline policy) carries its parent's type.
	Type string `json:"type,omitempty"`
	// PhysicalID is the resource's physical id — its Ref value (resource_attrs.go), set when the stack
	// completes; "" until then, or when the Ref does not resolve.
	PhysicalID string `json:"physicalId,omitempty"`
	// Status, StatusReason and Timestamp are the resource's own last status (CREATE_COMPLETE, …), what
	// DescribeStackResources reports.
	Status       string `json:"status,omitempty"`
	StatusReason string `json:"statusReason,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
	// SignalData is a wait condition's received signals' data (its Fn::GetAtt Data), set when it completes.
	SignalData string `json:"signalData,omitempty"`
}

// builtResource is one translated, ready-to-apply resource plus its identity/spec record.
type builtResource struct {
	res      StackResource
	yml      []byte
	cav      []string
	shared   bool          // applied by several stacks on purpose (Manifest.Shared): no ownership check
	requires []Requirement // objects outside the stack that must exist first (Manifest.Requires)
	signals  *signalSpec   // signals the resource waits for once Ready (signals.go); nil = none
	// after is the template logical ids of every resource this one depends on (directly or through
	// others): each must be complete before this one is applied (readiness.go).
	after map[string]bool
}

// Creator is an optional Applier capability: create an object only if none of that kind and name exists
// (created=false, err=nil when one does). A resource's first apply goes through it, so two operations
// racing for one name cannot both take it: the existence check and the write are one step.
type Creator interface {
	Create(ctx context.Context, manifestYAML []byte) (created bool, err error)
}

// Lister is an optional Applier capability: the objects of a kind in the stack's namespace, with their
// labels and spec — how a resource's explicit physical name (a BucketName) is checked against the others.
type Lister interface {
	List(ctx context.Context, apiVersion, kind string) ([]LiveObject, error)
}

// LiveObject is one listed object.
type LiveObject struct {
	Name   string
	Labels map[string]string
	Spec   map[string]any
}

// physicalNameField names, per kind, the spec field that carries a resource's AWS name when the template
// sets one (BucketName, QueueName / TopicName, TableName, an SSM parameter's Name). That name, not the
// object's, is what the platform creates: two objects with the same one share one bucket, stream, table
// or parameter. With the field unset the object's own name is used (except a Parameter, which has none).
var physicalNameField = map[string]string{
	"openinfra.dev/v1/Bucket":    "bucketName",
	"openinfra.dev/v1/Queue":     "queueName",
	"openinfra.dev/v1/Table":     "tableName",
	"openinfra.dev/v1/Parameter": "path",
}

// physicalName is an object's effective physical name ("" when its kind has none, or it sets none).
func physicalName(apiVersion, kind, name string, spec map[string]any) (field, value string) {
	field, ok := physicalNameField[apiVersion+"/"+kind]
	if !ok {
		return "", ""
	}
	if v, _ := spec[field].(string); v != "" {
		return field, v
	}
	if kind == "Parameter" {
		return field, ""
	}
	return field, name
}

// ownedObjects is what one stack operation may write to: the objects its stack record names (an update's
// current resources) and those the operation itself created. Any other object carrying the stack's label
// was left by an earlier stack of the same name — a retained resource, kept unmanaged — and is not taken
// back: adopting it would let this stack's rollback or delete remove data the template asked to keep.
type ownedObjects map[string]bool

func ownedFrom(rs []StackResource) ownedObjects {
	o := ownedObjects{}
	for _, r := range rs {
		o[r.APIVersion+"/"+r.Kind+"/"+r.Name] = true
	}
	return o
}

// applyOwned applies a built resource, first refusing to overwrite an object of the same kind and name
// that is not this stack's: another stack's, one no stack created, or one an earlier stack of this name
// left behind (owned says which of the stack's labelled objects are this stack's now). On AWS a create
// whose name is taken fails; taking the object over would silently corrupt the stack that owns it. A
// shared companion (the per-namespace default EncryptionKey) is meant to be applied by several stacks and
// is not checked. An Applier that cannot read labels (LabelReader) is not checked either.
//
// A resource whose explicit physical name (BucketName, QueueName, TableName, an SSM Name) another object
// already uses is refused the same way (Lister), and a resource not yet created is created only if it
// still does not exist (Creator), so two operations racing for a name cannot both take it.
//
// It also refuses a resource while an object outside the stack that it requires does not exist (a
// security group a parameter names): applying it would silently lose what that object provides.
func applyOwned(ctx context.Context, ap Applier, b builtResource, stack string, owned ownedObjects) error {
	for _, rq := range b.requires {
		_, found, err := ap.GetSpec(ctx, rq.APIVersion, rq.Kind, rq.Name)
		if err != nil {
			return fmt.Errorf("checking that %s %s exists: %w", rq.Kind, rq.Name, err)
		}
		if !found {
			return fmt.Errorf("%s %s does not exist — it is %s, named from outside this stack; refusing to apply %s %s without it", rq.Kind, rq.Name, rq.Why, b.res.Kind, b.res.Name)
		}
	}
	key := b.res.APIVersion + "/" + b.res.Kind + "/" + b.res.Name
	lr, ok := ap.(LabelReader)
	if !ok || b.shared {
		return ap.Apply(ctx, b.yml)
	}
	if err := physicalNameFree(ctx, ap, b, stack, owned); err != nil {
		return err
	}
	refuseNotOurs := func(labels map[string]string) error {
		switch owner := labels[labelStack]; {
		case owner == stack && (owned == nil || owned[key]):
			return nil
		case owner == stack:
			return fmt.Errorf("%s %s already exists — an earlier stack named %s left it (a retained resource), and it is not part of this stack; refusing to take it over (delete or rename it, or use another stack name)", b.res.Kind, b.res.Name, stack)
		case owner == "":
			return fmt.Errorf("%s %s already exists and no stack created it — refusing to overwrite it (rename the resource, or remove the existing object)", b.res.Kind, b.res.Name)
		default:
			return fmt.Errorf("%s %s already exists and belongs to stack %s — refusing to overwrite it (two stacks cannot share a resource name)", b.res.Kind, b.res.Name, owner)
		}
	}
	labels, found, err := lr.GetLabels(ctx, b.res.APIVersion, b.res.Kind, b.res.Name)
	if err != nil {
		return fmt.Errorf("checking whether %s %s already exists: %w", b.res.Kind, b.res.Name, err)
	}
	if found {
		if err := refuseNotOurs(labels); err != nil {
			return err
		}
		return ap.Apply(ctx, b.yml)
	}
	if cr, ok := ap.(Creator); ok {
		created, err := cr.Create(ctx, b.yml)
		if err != nil {
			return err
		}
		if !created {
			// Created by someone else since the check above: refuse unless it is, after all, ours.
			labels, _, err := lr.GetLabels(ctx, b.res.APIVersion, b.res.Kind, b.res.Name)
			if err != nil {
				return fmt.Errorf("checking %s %s, created concurrently: %w", b.res.Kind, b.res.Name, err)
			}
			if err := refuseNotOurs(labels); err != nil {
				return fmt.Errorf("%w (it was created while this stack was creating it)", err)
			}
			return ap.Apply(ctx, b.yml)
		}
		if owned != nil {
			owned[key] = true
		}
		return nil
	}
	if err := ap.Apply(ctx, b.yml); err != nil {
		return err
	}
	if owned != nil {
		owned[key] = true
	}
	return nil
}

// physicalNameFree refuses b when another object of its kind in the namespace already has b's physical
// name: on AWS, creating a bucket, queue, table or parameter whose name is taken fails, while here the two
// objects would silently share it (one stack writing the other's data, applying its own policy to it). An
// object of this stack with that name is the same resource (its record names it) or a second resource
// of the stack claiming the name, which AWS refuses too.
func physicalNameFree(ctx context.Context, ap Applier, b builtResource, stack string, owned ownedObjects) error {
	field, value := physicalName(b.res.APIVersion, b.res.Kind, b.res.Name, b.res.Spec)
	if value == "" {
		return nil
	}
	ls, ok := ap.(Lister)
	if !ok {
		return nil
	}
	objs, err := ls.List(ctx, b.res.APIVersion, b.res.Kind)
	if err != nil {
		return fmt.Errorf("checking that no other %s is named %q: %w", b.res.Kind, value, err)
	}
	for _, o := range objs {
		if o.Name == b.res.Name {
			continue
		}
		if _, v := physicalName(b.res.APIVersion, b.res.Kind, o.Name, o.Spec); v != value {
			continue
		}
		owner := o.Labels[labelStack]
		switch {
		case owner == stack && owned != nil && !owned[b.res.APIVersion+"/"+b.res.Kind+"/"+o.Name]:
			// What an earlier stack of this name retained is no longer any stack's: on AWS its name is
			// taken (BucketAlreadyOwnedByYou), so a new resource cannot have it either.
			return fmt.Errorf("%s %s's %s %q is still held by %s %s, which an earlier stack named %s left behind (a retained resource, no longer part of any stack) — refusing to create a second object over it, as AWS refuses a name that is taken (give the resource another %s, or delete the retained one)", b.res.Kind, b.res.Name, field, value, b.res.Kind, o.Name, stack, field)
		case owner == stack:
			owner = "this stack"
		case owner == "":
			owner = "no stack"
		default:
			owner = "stack " + owner
		}
		return fmt.Errorf("%s %s's %s %q is already %s %s's (owned by %s) — refusing to create a second object over it, as AWS refuses a name that is taken (rename it, or drop the explicit name so the stack generates one)", b.res.Kind, b.res.Name, field, value, b.res.Kind, o.Name, owner)
	}
	return nil
}

type StackRecord struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	// StackID is this stack instance's StackId (awsidentity NewStackID), the value AWS::StackId resolves
	// to. "" on a stack created before StackIds were per instance: its StackId is the derived one
	// (awsidentity StackID of its name), which it keeps.
	StackID string `json:"stackId,omitempty"`
	// DeletedAt is when a deleted stack's delete completed (its DeletionTime), set only on the record a
	// front door keeps of a deleted stack.
	DeletedAt string          `json:"deletedAt,omitempty"`
	Status    string          `json:"status"`
	Message   string          `json:"message,omitempty"`
	CreatedAt string          `json:"createdAt"`
	UpdatedAt string          `json:"updatedAt"`
	Resources []StackResource `json:"resources"`
	// Outputs are the template's Outputs evaluated against the deployed stack when it reached *_COMPLETE
	// (outputs.go) — what DescribeStacks returns; an Output with an ExportName is a cross-stack export.
	// OutputsOmitted lists the Outputs left out because their value did not resolve, with the reason.
	Outputs        []StackOutput    `json:"outputs,omitempty"`
	OutputsOmitted []OutputOmission `json:"outputsOmitted,omitempty"`
	// Template and Parameters are the template body and parameter values the stack was last deployed
	// with, as AWS keeps them: GetTemplate / GetTemplateSummary read them, and an update's
	// UsePreviousValue parameters take their values from here.
	// Parameters never holds a NoEcho parameter's value: NoEchoParameters names those, and their values go
	// to the Applier's NoEchoStore (if it has one) instead of the record.
	// Owner is the caller that created the stack (kept across updates); "" on a record from before it
	// was kept.
	Owner string `json:"owner,omitempty"`
	// TerminationProtection refuses the stack's delete while it is on (EnableTerminationProtection, as on
	// AWS); kept across updates.
	TerminationProtection bool              `json:"terminationProtection,omitempty"`
	Template              string            `json:"template,omitempty"`
	Parameters            map[string]string `json:"parameters,omitempty"`
	NoEchoParameters      []string          `json:"noEchoParameters,omitempty"`
	// noEcho is the NoEcho values to store with this write; nil on a record read back (the store is left
	// as it is), non-nil when a create/update sets the stack's parameters.
	noEcho map[string]string
	// Imports are the export names this stack reads through Fn::ImportValue — a stack whose export is
	// imported elsewhere is not deleted (AWS's rule).
	Imports []string `json:"imports,omitempty"`
	// Pending is the write-ahead half of an in-flight operation: resources it is about to create that are
	// not (yet) in Resources — an update's Adds (Resources stays the prior stack until it succeeds), or
	// the resource an interleaved create is applying next. Recorded BEFORE they are created, so an
	// operation interrupted mid-flight (its process died) can be rolled back from the record alone
	// without orphans (RecoverInterrupted). Empty at every terminal status the engine writes; a record a
	// front door had to settle *_FAILED without the operation's authority keeps it, so a later Destroy
	// removes those too (only where the object carries this stack's label — it may never have been applied).
	Pending []StackResource `json:"pending,omitempty"`
	// Restarting is the write-ahead of an in-flight update's instance restarts (instance_restart.go): the
	// logical ids of the instances it stops and starts, recorded before the first is stopped, so recovery
	// of an update whose process died mid-restart starts them again on their prior spec rather than leaving
	// one stopped. Empty at every terminal status.
	Restarting []string `json:"restarting,omitempty"`
	// Events are the stack's status history, oldest first (events.go) — DescribeStackEvents.
	Events []StackEvent `json:"events,omitempty"`
	// Description is the template's Description (DescribeStacks returns it).
	Description string `json:"description,omitempty"`
	// Fidelity is the deploy's one-line fidelity summary — what open-infra accepted but does not emulate —
	// shown by DescribeStacks and the stack's first event of the operation.
	Fidelity string `json:"fidelity,omitempty"`
}

type DeployOptions struct {
	StackName string
	Namespace string
	// StackID is the stack instance's StackId: what AWS::StackId resolves to and the record keeps. "" =
	// the derived StackId of StackName (awsidentity StackID), which every stack created before StackIds
	// were per instance keeps; an update, delete or recovery adopts the one its record names.
	StackID string
	// Owner is the caller a create records as the stack's owner (StackRecord.Owner); "" records none.
	Owner   string
	Params  map[string]string
	Exports map[string]string // cross-stack Exports (export name -> value) for Fn::ImportValue
	Wait    bool
	Timeout time.Duration
	// Invoke synchronously calls an in-stack kind: Function for a Lambda-backed custom resource (#269),
	// returning the parsed response ({Status, Data, Reason}). Nil = custom resources are unsupported on
	// this deploy path (the CLI, which isn't in-cluster): a stack with one refuses rather than guessing.
	// The aws-shim CFN doorway (in-cluster) sets this to an HTTP invoker of the Function's cluster URL.
	Invoke InvokeFunc
	// ProvisionRestAPI materializes a collated API Gateway REST v1 plan (#295) via the aws-shim's
	// apigateway API, returning the created REST API id (for rollback/teardown). DeprovisionRestAPI
	// deletes a provisioned API (rollback on a later failure, and stack destroy). Both nil = REST v1 is
	// unsupported on this deploy path (the CLI): a stack with an AWS::ApiGateway::RestApi refuses rather
	// than guessing. The in-cluster aws-shim doorway sets them to drivers of its own apigateway store.
	ProvisionRestAPI   ProvisionRestAPIFunc
	DeprovisionRestAPI DeprovisionRestAPIFunc
	// BucketData reports whether an S3 bucket exists and whether it is empty (no objects, prior versions
	// or delete markers). RemoveBucket removes an empty bucket. With them, deleting a kind: Bucket is
	// AWS's: a bucket that still holds data fails the delete (BucketNotEmpty), and an empty one is removed
	// with its claim. Nil (the CLI): the claim is deleted and the bucket reaper removes an empty bucket.
	BucketData   func(ctx context.Context, bucket string) (exists, empty bool, err error)
	RemoveBucket func(ctx context.Context, bucket string) error
	// TableExists reports whether a DynamoDB table of that name already exists; RemoveTable deletes a
	// table's items, stream and registry entry. With them a kind: Table is AWS's DynamoDB table: creating
	// one whose name is already a table's is refused ("Table already exists"), and deleting it — a stack
	// delete, an update that removes it, a rolled-back create — deletes the table and its data, so a stack
	// re-created with the same name never sees the earlier stack's items. Nil (the CLI, which has no
	// access to the table data): the claim alone is deleted.
	TableExists func(ctx context.Context, table string) (bool, error)
	RemoveTable func(ctx context.Context, table string) error
	// prior is the existing stack's recorded resources (an update or change set): each keeps the name it
	// was created with (naming.go). Nil for a create.
	prior []StackResource
	// leftovers are names held by objects an earlier stack of this name left behind, which the resources
	// this operation creates are named around (physNamer.leftovers; buildAvoidingLeftovers finds them).
	leftovers []string
	// Caps are deploy-environment facts translators depend on (e.g. whether MinIO has SSE-KMS on).
	// Plan and deploy both evaluate with these, so a PROVISIONABLE* plan still means deploy won't
	// refuse. Zero = fail-closed (the CLI); the in-cluster aws-shim doorway sets them.
	Caps Capabilities
	// Signals reads the resource signals a CreationPolicy or WaitCondition waits for (signals.go). Nil =
	// signals cannot arrive on this path, so a stack that waits for them refuses rather than hangs.
	Signals SignalSource
	// SignalURL returns the URL a WaitConditionHandle's Ref is: where a guest PUTs its signal (nil = no
	// such URL on this path).
	SignalURL func(stackName, handleID string) string
	// Fidelity is the operation's one-line fidelity summary, recorded on the stack (DescribeStacks).
	Fidelity string
	// TerminationProtection is a create's EnableTerminationProtection: the stack's delete is refused while
	// it is on (StackRecord.TerminationProtection).
	TerminationProtection bool
}

// ProvisionRestAPIFunc provisions a collated REST v1 plan (the sentinel's Spec) and returns the created
// REST API id. Parse the plan with ParseRestAPIPlan.
type ProvisionRestAPIFunc func(ctx context.Context, planSpec map[string]any) (apiID string, err error)

// DeprovisionRestAPIFunc deletes a provisioned REST v1 API by id (idempotent — a missing api is not an
// error), for rollback and teardown.
type DeprovisionRestAPIFunc func(ctx context.Context, apiID string) error

// InvokeFunc synchronously invokes a custom resource's backing Function with the CloudFormation
// custom-resource event (JSON) and returns the handler's parsed response: {"Status":"SUCCESS"|"FAILED",
// "Data":{...},"Reason":"..."}. The open-infra adaptation of the ResponseURL callback — the handler
// RETURNS the response rather than PUT-ing it to a pre-signed S3 URL.
type InvokeFunc func(ctx context.Context, namespace, functionName string, event []byte) (map[string]any, error)

// expandManifest renders a translated manifest and any companion manifests it carries (m.Extra — e.g.
// an IAM Role's inline Policies become companion kind: Policy objects) into builtResources in apply
// order: the parent first, then each companion. A companion's LogicalID is namespaced under the parent
// (id/name) so the stack record is unambiguous, and it inherits the parent's DeletionPolicy.
func expandManifest(id string, res Resource, m *Manifest, opts DeployOptions) ([]builtResource, error) {
	all := append([]*Manifest{m}, m.Extra...)
	out := make([]builtResource, 0, len(all))
	for i, mm := range all {
		yml, err := renderManifest(mm, opts)
		if err != nil {
			return nil, err
		}
		lid := id
		if i > 0 {
			lid = id + "/" + mm.Name
		}
		// A companion inherits the parent's DeletionPolicy unless it sets its own override (a SHARED
		// companion like the default EncryptionKey pins Retain so the stack lifecycle can't delete it).
		dp := res.DeletionPolicy
		if mm.DeletionPolicy != "" {
			dp = mm.DeletionPolicy
		}
		out = append(out, builtResource{
			res: StackResource{LogicalID: lid, APIVersion: mm.APIVersion, Kind: mm.Kind, Name: mm.Name,
				DeletionPolicy: dp, Spec: mm.Spec, Protected: mm.Protected, Type: res.Type},
			yml: yml, cav: mm.Caveats, shared: mm.Shared, requires: mm.Requires,
		})
	}
	return out, nil
}

// buildManifests runs the plan gate then the translate gate, returning every included
// resource translated and ordered by dependency. It is the shared fail-closed front half of
// deploy and update: a REJECTED plan, a type with no create translator, or any untranslatable
// property returns an error and no manifests — there is no partial result.
func buildManifests(data []byte, opts DeployOptions) ([]builtResource, error) {
	plan, err := BuildPlanForStack(data, opts.Params, opts.Exports, opts.StackName, opts.StackID, opts.Caps)
	if err != nil {
		return nil, err
	}
	if plan.Verdict == Rejected {
		return nil, fmt.Errorf("plan is REJECTED — refusing:\n  - %s", joinBlockers(plan.Blockers))
	}
	t, err := Parse(data)
	if err != nil {
		return nil, err
	}
	r := newResolver(t, resolveParams(t, opts.Params), strMapToAny(opts.Exports), pseudoParamsFor(opts.StackName, opts.StackID))
	r.evalConditions()
	namer := newPhysNamer(opts.StackName, opts.prior)
	namer.avoid(opts.leftovers)
	ctx := &stackCtx{template: t, resolver: r, caps: opts.Caps, namer: namer, signalURL: opts.SignalURL}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, ctx) }
	r.staticAtt = func(id, attr string) (string, bool) { return serviceAtt(id, attr, ctx) }
	if needsSignals(t) && opts.Signals == nil {
		return nil, fmt.Errorf("the stack waits for resource signals (a CreationPolicy ResourceSignal or a WaitCondition), and this deploy path cannot receive them — deploy it through the aws-shim CloudFormation front door")
	}

	byID := map[string][]builtResource{}
	var findings []Finding
	for _, id := range t.rawOrder {
		res := t.Resources[id]
		if res.Condition != "" && !r.conds[res.Condition] {
			continue // excluded by a false condition
		}
		if !hasTranslator(res.Type) {
			findings = append(findings, Finding{"Resource " + id,
				res.Type + " has no create translator (plan-supported is not create-faithful)"})
			continue
		}
		r.where = "Resource " + id
		resolved, _ := r.resolve(res.Properties).(map[string]any)
		m, fs := translatorFor(res.Type)(id, resolved, ctx)
		if len(fs) > 0 {
			findings = append(findings, fs...)
			continue
		}
		if m == nil {
			continue // a no-op resource (e.g. an ECS Cluster, or a TaskDefinition a Service composes)
		}
		m.Caveats = append(m.Caveats, attributeCaveats(res)...) // so a change set lists them too
		built, err := expandManifest(id, res, m, opts)
		if err != nil {
			return nil, err
		}
		spec, serr := signalSpecOf(res, m, id)
		if serr != nil {
			findings = append(findings, Finding{"Resource " + id, serr.Error()})
			continue
		}
		built[0].signals = spec
		byID[id] = built
	}
	findings = append(findings, r.findings...)
	var order []builtResource
	for _, id := range plan.Order {
		after := ancestors(plan.deps, id)
		for _, b := range byID[id] {
			b.after = after
			order = append(order, b)
		}
	}
	seen := objectSet{}
	for _, b := range order {
		findings = append(findings, seen.add(b)...)
	}
	if len(findings) > 0 {
		return nil, fmt.Errorf("translate gate REJECTED — refusing (nothing applied):\n  - %s", joinFindings(findings))
	}
	return order, nil
}

// maxLeftoverPasses bounds how many times a build is redone to name resources around what earlier stacks
// of the same name left behind (each pass only adds names to avoid, so it settles in a pass or two).
const maxLeftoverPasses = 8

// buildAvoidingLeftovers is buildManifests for an operation against the live cluster: a resource this
// operation creates (one not in owned) whose object name is held by an object an earlier stack of this
// name left behind — a retained resource, kept unmanaged — is renamed (physNamer.fresh) and the stack
// translated again, so the leftover never blocks the stack and is never taken over. On AWS a retained
// resource is simply no longer the stack's: re-creating the stack creates the resource anew. Where a
// name cannot change (an explicit FunctionName) the apply refuses as before (applyOwned), as AWS
// refuses a name that is taken; so does an explicit physical name (a BucketName) the leftover still has.
func buildAvoidingLeftovers(ctx context.Context, data []byte, opts DeployOptions, ap Applier, owned ownedObjects) ([]builtResource, error) {
	for pass := 0; ; pass++ {
		order, err := buildManifests(data, opts)
		if err != nil {
			return nil, err
		}
		hit, err := leftoverHits(ctx, ap, order, opts.StackName, owned, opts.leftovers)
		if err != nil {
			return nil, err
		}
		if len(hit) == 0 || pass+1 >= maxLeftoverPasses {
			return order, nil
		}
		opts.leftovers = append(append([]string(nil), opts.leftovers...), hit...)
	}
}

// leftoverHits names the objects among built that an earlier stack of this name left behind: one that
// exists, carries this stack's label, and is not this operation's (owned). A shared companion (applied
// by several stacks on purpose) and a resource outside Kubernetes are never one; a name already avoided
// is not reported again (it could not be changed). An Applier that cannot read labels finds none.
func leftoverHits(ctx context.Context, ap Applier, built []builtResource, stack string, owned ownedObjects, avoided []string) ([]string, error) {
	lr, ok := ap.(LabelReader)
	if !ok {
		return nil, nil
	}
	skip := map[string]bool{}
	for _, n := range avoided {
		skip[n] = true
	}
	var hit []string
	for _, b := range built {
		if b.shared || isOutOfBand(b.res) || skip[b.res.Name] {
			continue
		}
		if owned[b.res.APIVersion+"/"+b.res.Kind+"/"+b.res.Name] {
			continue
		}
		labels, found, err := lr.GetLabels(ctx, b.res.APIVersion, b.res.Kind, b.res.Name)
		if err != nil {
			return nil, fmt.Errorf("checking whether %s %s already exists: %w", b.res.Kind, b.res.Name, err)
		}
		if found && labels[labelStack] == stack {
			hit = append(hit, b.res.Name)
			skip[b.res.Name] = true
		}
	}
	return hit, nil
}

// objectSet tracks the objects one stack operation applies, by apiVersion, kind and name. Two resources of
// a stack that resolve to one object (an explicit FunctionName equal to another Function's generated name)
// would overwrite each other under one stack label, which no ownership check can see; add refuses the
// second. The one exception is a companion several resources emit identically (the stack's default
// EncryptionKey that each encrypted disk carries) — that is one object applied more than once on purpose.
type objectSet map[string]builtResource

func (s objectSet) add(b builtResource) []Finding {
	key := b.res.APIVersion + "/" + b.res.Kind + "/" + b.res.Name
	prev, dup := s[key]
	if !dup {
		s[key] = b
		return nil
	}
	if prev.res.LogicalID == b.res.LogicalID {
		return nil
	}
	if (b.shared && prev.shared) || (strings.Contains(b.res.LogicalID, "/") && strings.Contains(prev.res.LogicalID, "/") && specEqual(b.res.Spec, prev.res.Spec)) {
		return nil
	}
	return []Finding{{"Resource " + b.res.LogicalID, fmt.Sprintf("%s %q is also %s's name — two resources of one stack cannot be one object (rename one, or drop its explicit name)", b.res.Kind, b.res.Name, prev.res.LogicalID)}}
}

// Deploy runs the full fail-closed create. It returns the final stack record (whose Status is
// CREATE_COMPLETE or CREATE_FAILED) and an error if the deploy did not fully succeed.
func Deploy(ctx context.Context, data []byte, opts DeployOptions, ap Applier) (*StackRecord, error) {
	if opts.Namespace == "" {
		return nil, fmt.Errorf("a target namespace is required (deploy never guesses one)")
	}

	// A stack with Lambda-backed custom resources (#269) OR a REST v1 API (#295) needs the interleaved
	// deploy: a custom resource's Function is invoked, and a REST v1 sentinel is provisioned via the
	// apigateway hook, at its point in dependency order. Stacks WITHOUT either take the exact
	// build-all-then-apply path below, unchanged — the new path is additive and never touches the common case.
	if pt, perr := Parse(data); perr == nil && (hasCustomResources(pt) || hasAPIGatewayRestV1(pt)) {
		return deployInterleaved(ctx, data, opts, ap)
	}

	// 1+2. Plan gate + translate gate — build every manifest up front, in dependency order,
	// refusing (nothing applied) on any blocker or untranslatable property. Named around anything an
	// earlier stack of this name left behind (a new stack owns nothing yet).
	order, err := buildAvoidingLeftovers(ctx, data, opts, ap, ownedObjects{})
	if err != nil {
		return nil, err
	}

	// 3. Persist the stack record (IN_PROGRESS), then apply in order. The record lists EVERY planned
	// resource before the first apply (write-ahead), so a create interrupted mid-flight can be rolled back
	// from the record alone (RecoverInterrupted).
	now := time.Now().UTC().Format(time.RFC3339)
	rec := &StackRecord{
		Name: opts.StackName, Namespace: opts.Namespace, Status: "CREATE_IN_PROGRESS",
		CreatedAt: now, UpdatedAt: now, Template: string(data), Owner: opts.Owner,
		Description: templateDescription(data), Fidelity: opts.Fidelity, TerminationProtection: opts.TerminationProtection,
	}
	rec.setParams(data, opts.Params)
	for _, b := range order {
		rec.Resources = append(rec.Resources, b.res)
	}
	rec.stackEvent("CREATE_IN_PROGRESS", startReason(opts))
	if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}

	var applied []StackResource
	var waits waitQueue // created, not yet complete (readiness.go)
	failed := ""        // the logical id that failed, for its CREATE_FAILED event
	failedRes := order  // looked up by logical id below
	rollback := func(cause error) (*StackRecord, error) {
		for _, b := range failedRes {
			if b.res.LogicalID == failed {
				rec.resourceEvent(b.res, "CREATE_FAILED", cause.Error())
				break
			}
		}
		// What was still being created when another resource failed is cancelled, as on AWS.
		for _, p := range waits.all() {
			if p.res.LogicalID != failed {
				rec.resourceEvent(p.res, "CREATE_FAILED", "Resource creation cancelled")
			}
		}
		rec.stackEvent("ROLLBACK_IN_PROGRESS", rollbackReason(failed))
		// As on AWS, a rolled-back create ends ROLLBACK_COMPLETE (ROLLBACK_FAILED when a delete failed):
		// the stack stays, to be deleted.
		rec.Status = rolledBackStatus(rollbackCreate(ctx, opts, ap, rec, applied))
		rec.Message = cause.Error()
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		rec.stackEvent(rec.Status, "")
		_ = writeStackRecord(ctx, ap, rec, opts)
		if rec.Status == "ROLLBACK_FAILED" {
			return rec, fmt.Errorf("deploy failed and its rollback could not delete everything it created (ROLLBACK_FAILED; delete the stack): %w", cause)
		}
		return rec, fmt.Errorf("deploy failed and was rolled back (no orphans): %w", cause)
	}
	progress := func() { flushEvents(ctx, ap, rec) } // so DescribeStackEvents shows the create as it goes

	// A resource is complete once its wait passes (readiness.go); a WaitCondition's signals data is kept.
	completed := map[string]bool{}
	complete := func(b builtResource, sigs []Signal) {
		if IsSignalWait(b.res) {
			setSignalData(rec, b.res.LogicalID, sigs)
		}
		completed[b.res.LogicalID] = true
		rec.resourceEvent(b.res, "CREATE_COMPLETE", "")
		progress()
	}
	settle := func(set []builtResource) error {
		fb, err := settleWaits(ctx, opts, ap, set, complete)
		if err != nil {
			failed = fb.res.LogicalID
			for _, b := range set { // what had not completed is cancelled by the rollback
				if b.res.LogicalID != failed && !completed[b.res.LogicalID] {
					waits.add(b)
				}
			}
		}
		return err
	}

	owned := ownedObjects{} // a new stack owns only what it creates
	for _, b := range order {
		// Everything b depends on is complete before b is created; what does not depend on what is still
		// being created goes ahead of it, as on AWS.
		if err := settle(waits.due(b.after)); err != nil {
			return rollback(err)
		}
		failed = b.res.LogicalID
		rec.resourceEvent(b.res, "CREATE_IN_PROGRESS", "")
		if !IsSignalWait(b.res) { // a WaitCondition: nothing to apply, only signals to wait for
			if err := tableTaken(ctx, opts, b.res); err != nil {
				return rollback(err)
			}
			if err := applyOwned(ctx, ap, b, opts.StackName, owned); err != nil {
				return rollback(fmt.Errorf("applying %s/%s: %w", b.res.Kind, b.res.Name, err))
			}
			applied = append(applied, b.res)
		}
		progress() // it shows CREATE_IN_PROGRESS while it is created, as on AWS
		waits.add(b)
	}
	if err := settle(waits.all()); err != nil {
		return rollback(err)
	}

	// 4. Complete — with the template's Outputs evaluated against the deployed stack. An Output that
	// does not resolve fails the create, as on AWS (no stack completes with an Output missing).
	failed = ""
	setOutputs(ctx, data, opts, rec, ap, nil)
	if err := outputFailure(rec); err != nil {
		return rollback(err)
	}
	rec.Status = "CREATE_COMPLETE"
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	rec.stackEvent("CREATE_COMPLETE", "")
	if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
		return rec, fmt.Errorf("stack created but recording COMPLETE failed: %w", err)
	}
	return rec, nil
}

// startReason is the reason on an operation's first stack event: AWS's "User Initiated", with the
// operation's fidelity summary when it has one.
func startReason(opts DeployOptions) string {
	if opts.Fidelity == "" {
		return "User Initiated"
	}
	return "User Initiated — open-infra fidelity: " + opts.Fidelity
}

// templateDescription is a template's top-level Description ("" when none).
func templateDescription(data []byte) string {
	t, err := Parse(data)
	if err != nil {
		return ""
	}
	return t.Description
}

// setSignalData stores a wait condition's signals' data on its record entry (its Fn::GetAtt Data).
func setSignalData(rec *StackRecord, id string, sigs []Signal) {
	for i := range rec.Resources {
		if rec.Resources[i].LogicalID == id {
			rec.Resources[i].SignalData = signalData(sigs)
		}
	}
}

// rollbackReason is a rolled-back create's ROLLBACK_IN_PROGRESS reason.
func rollbackReason(failed string) string {
	if failed == "" {
		return "The stack's Outputs did not resolve. Rollback requested by user."
	}
	return "The following resource(s) failed to create: [" + failed + "]. Rollback requested by user."
}

// hasCustomResources reports whether a parsed template contains any Lambda-backed custom resource (#269).
func hasCustomResources(t *Template) bool {
	for _, res := range t.Resources {
		if isCustomResourceType(res.Type) {
			return true
		}
	}
	return false
}

// hasAPIGatewayRestV1 reports whether a parsed template declares a REST v1 API (#295).
func hasAPIGatewayRestV1(t *Template) bool {
	for _, res := range t.Resources {
		if res.Type == "AWS::ApiGateway::RestApi" {
			return true
		}
	}
	return false
}

// deployInterleaved is the create path for a stack containing custom resources (#269). Unlike the
// build-all-then-apply path, it walks resources in dependency order one at a time so a custom resource's
// Function can be invoked at its point in the order, its returned Data recorded, and LATER dependents'
// Fn::GetAtt resolved against it. Same fail-closed rollback as Deploy. A stack with no custom resource
// never reaches here (Deploy branches on hasCustomResources), so the common path is untouched.
func deployInterleaved(ctx context.Context, data []byte, opts DeployOptions, ap Applier) (*StackRecord, error) {
	plan, err := BuildPlanForStack(data, opts.Params, opts.Exports, opts.StackName, opts.StackID, opts.Caps)
	if err != nil {
		return nil, err
	}
	if plan.Verdict == Rejected {
		return nil, fmt.Errorf("plan is REJECTED — refusing:\n  - %s", joinBlockers(plan.Blockers))
	}
	t, err := Parse(data)
	if err != nil {
		return nil, err
	}
	r := newResolver(t, resolveParams(t, opts.Params), strMapToAny(opts.Exports), pseudoParamsFor(opts.StackName, opts.StackID))
	r.evalConditions()
	r.customData = map[string]map[string]any{}
	sctx := &stackCtx{template: t, resolver: r, caps: opts.Caps, namer: newPhysNamer(opts.StackName, nil), signalURL: opts.SignalURL}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, sctx) }
	r.staticAtt = func(id, attr string) (string, bool) { return serviceAtt(id, attr, sctx) }
	if needsSignals(t) && opts.Signals == nil {
		return nil, fmt.Errorf("the stack waits for resource signals (a CreationPolicy ResourceSignal or a WaitCondition), and this deploy path cannot receive them — deploy it through the aws-shim CloudFormation front door")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	rec := &StackRecord{Name: opts.StackName, Namespace: opts.Namespace, Status: "CREATE_IN_PROGRESS", CreatedAt: now, UpdatedAt: now,
		Template: string(data), Owner: opts.Owner, Description: t.Description, Fidelity: opts.Fidelity, TerminationProtection: opts.TerminationProtection}
	rec.setParams(data, opts.Params)
	rec.stackEvent("CREATE_IN_PROGRESS", startReason(opts))
	if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}

	var applied []StackResource
	var provisionedAPIs []string // REST v1 API ids to tear down on rollback
	var waits waitQueue          // created, not yet complete (readiness.go)
	failedID, failedType := "", ""
	rollback := func(cause error) (*StackRecord, error) {
		if failedID != "" {
			rec.addEvent(failedID, "", failedType, "CREATE_FAILED", cause.Error())
		}
		for _, p := range waits.all() { // still being created when another resource failed: cancelled, as on AWS
			if p.res.LogicalID != failedID {
				rec.resourceEvent(p.res, "CREATE_FAILED", "Resource creation cancelled")
			}
		}
		rec.stackEvent("ROLLBACK_IN_PROGRESS", rollbackReason(failedID))
		// Reverse order, honoring Retain (as Deploy does); a created custom resource gets its Delete event.
		ok := rollbackCreate(ctx, opts, ap, rec, applied)
		for i := len(provisionedAPIs) - 1; i >= 0; i-- { // tear down provisioned REST v1 APIs too
			if opts.DeprovisionRestAPI != nil {
				if err := opts.DeprovisionRestAPI(ctx, provisionedAPIs[i]); err != nil {
					ok = false
				}
			}
		}
		rec.Status = rolledBackStatus(ok)
		rec.Message = cause.Error()
		rec.Pending = nil
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		rec.stackEvent(rec.Status, "")
		_ = writeStackRecord(ctx, ap, rec, opts)
		if !ok {
			return rec, fmt.Errorf("deploy failed and its rollback could not delete everything it created (ROLLBACK_FAILED; delete the stack): %w", cause)
		}
		return rec, fmt.Errorf("deploy failed and was rolled back (no orphans): %w", cause)
	}
	// Write-ahead (#347): this path builds the record as it goes, so before creating each resource it
	// records that resource as Pending. A process that dies mid-create then leaves a record naming
	// everything it may have created, which RecoverInterrupted rolls back without orphans.
	intend := func(rs ...StackResource) error {
		rec.Pending = rs
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
			return fmt.Errorf("could not record stack progress (nothing more is created without it): %w", err)
		}
		return nil
	}

	completed := map[string]bool{}
	complete := func(b builtResource, sigs []Signal) {
		if IsSignalWait(b.res) {
			setSignalData(rec, b.res.LogicalID, sigs)
		}
		completed[b.res.LogicalID] = true
		rec.resourceEvent(b.res, "CREATE_COMPLETE", "")
		flushEvents(ctx, ap, rec)
	}
	settle := func(set []builtResource) error {
		fb, err := settleWaits(ctx, opts, ap, set, complete)
		if err != nil {
			failedID, failedType = fb.res.LogicalID, typeOr(fb.res)
			for _, b := range set { // what had not completed is cancelled by the rollback
				if b.res.LogicalID != failedID && !completed[b.res.LogicalID] {
					waits.add(b)
				}
			}
		}
		return err
	}

	seen := objectSet{}
	owned := ownedObjects{} // a new stack owns only what it creates
	for _, id := range plan.Order {
		res := t.Resources[id]
		tr := translatorFor(res.Type)
		if tr == nil {
			return rollback(fmt.Errorf("%s (%s) has no create translator", id, res.Type))
		}
		// Everything this resource depends on is complete before it is translated (a custom resource's
		// Data, a GetAtt) and created; what does not depend on what is still being created goes ahead.
		if err := settle(waits.due(ancestors(plan.deps, id))); err != nil {
			return rollback(err)
		}
		r.where = "Resource " + id
		failedID, failedType = id, res.Type
		resolved, _ := r.resolve(res.Properties).(map[string]any)
		m, fs := tr(id, resolved, sctx)
		if len(fs) > 0 {
			return rollback(fmt.Errorf("translate gate REJECTED:\n  - %s", joinFindings(fs)))
		}
		if m == nil {
			continue // a no-op resource (composes into another kind)
		}
		rec.addEvent(id, "", res.Type, "CREATE_IN_PROGRESS", "")
		// A custom resource is invoked (not applied); its Data feeds later dependents' Fn::GetAtt.
		if m.APIVersion == customResourceAPIVersion && m.Kind == customResourceKind {
			if werr := intend(StackResource{LogicalID: id, APIVersion: m.APIVersion, Kind: m.Kind, Name: m.Name, Spec: m.Spec, Type: res.Type}); werr != nil {
				return rollback(werr)
			}
			sr, cerr := invokeCustomResource(ctx, opts, r, id, m)
			if cerr != nil {
				return rollback(cerr)
			}
			applied = append(applied, sr) // a rollback sends it the Delete event, as AWS does
			rec.Resources = append(rec.Resources, sr)
			rec.Pending = nil
			rec.resourceEvent(sr, "CREATE_COMPLETE", "")
			continue
		}
		// A REST v1 API sentinel is provisioned via the apigateway hook (not applied); its created id is
		// recorded for teardown/rollback — persisted at once, since the id is only known after provisioning.
		if m.APIVersion == apigwRestV1APIVersion && m.Kind == apigwRestV1Kind {
			sr, apiID, perr := provisionRestAPI(ctx, opts, id, m)
			if perr != nil {
				return rollback(perr)
			}
			if apiID != "" {
				provisionedAPIs = append(provisionedAPIs, apiID)
			}
			rec.Resources = append(rec.Resources, sr)
			rec.resourceEvent(sr, "CREATE_COMPLETE", "")
			if werr := intend(); werr != nil {
				return rollback(werr)
			}
			continue
		}
		spec, serr := signalSpecOf(res, m, id)
		if serr != nil {
			return rollback(serr)
		}
		// A wait condition is waited for, not applied — alongside what is created after it that does not
		// depend on it (readiness.go).
		if m.APIVersion == waitAPIVersion && m.Kind == waitKind {
			sr := StackResource{LogicalID: id, APIVersion: m.APIVersion, Kind: m.Kind, Name: m.Name, Spec: m.Spec, Type: res.Type}
			rec.Resources = append(rec.Resources, sr)
			if werr := intend(); werr != nil {
				return rollback(werr)
			}
			flushEvents(ctx, ap, rec) // it shows CREATE_IN_PROGRESS while it waits, as on AWS
			waits.add(builtResource{res: sr, signals: spec})
			continue
		}
		built, berr := expandManifest(id, res, m, opts)
		if berr != nil {
			return rollback(berr)
		}
		// Named around anything an earlier stack of this name left behind (buildAvoidingLeftovers, one
		// resource at a time): translated again under the new name, which later resources then refer to.
		var avoided []string
		for pass := 1; pass < maxLeftoverPasses; pass++ {
			hit, herr := leftoverHits(ctx, ap, built, opts.StackName, owned, avoided)
			if herr != nil {
				return rollback(herr)
			}
			if len(hit) == 0 {
				break
			}
			avoided = append(avoided, hit...)
			sctx.namer.avoid(hit)
			r.where = "Resource " + id
			resolved, _ = r.resolve(res.Properties).(map[string]any)
			if m, fs = tr(id, resolved, sctx); len(fs) > 0 {
				return rollback(fmt.Errorf("translate gate REJECTED:\n  - %s", joinFindings(fs)))
			}
			if built, berr = expandManifest(id, res, m, opts); berr != nil {
				return rollback(berr)
			}
			if spec, serr = signalSpecOf(res, m, id); serr != nil {
				return rollback(serr)
			}
		}
		pending := make([]StackResource, 0, len(built))
		for _, b := range built {
			if fs := seen.add(b); len(fs) > 0 {
				return rollback(fmt.Errorf("translate gate REJECTED:\n  - %s", joinFindings(fs)))
			}
			pending = append(pending, b.res)
		}
		if werr := intend(pending...); werr != nil {
			return rollback(werr)
		}
		for i, b := range built {
			if terr := tableTaken(ctx, opts, b.res); terr != nil {
				return rollback(terr)
			}
			if aerr := applyOwned(ctx, ap, b, opts.StackName, owned); aerr != nil {
				return rollback(fmt.Errorf("applying %s/%s: %w", b.res.Kind, b.res.Name, aerr))
			}
			applied = append(applied, b.res)
			rec.Resources = append(rec.Resources, b.res)
			if i == 0 {
				b.signals = spec // the resource's CreationPolicy signals, waited for once it is ready
			}
			waits.add(b)
		}
		flushEvents(ctx, ap, rec) // the resource shows CREATE_IN_PROGRESS while it is created
		rec.Pending = nil         // now in Resources (written with the next write-ahead, or at COMPLETE)
	}
	if err := settle(waits.all()); err != nil {
		return rollback(err)
	}
	// Outputs may read a custom resource's returned Data (Fn::GetAtt), so evaluate them with it. An Output
	// that does not resolve fails the create.
	failedID, failedType = "", ""
	setOutputs(ctx, data, opts, rec, ap, r.customData)
	if err := outputFailure(rec); err != nil {
		return rollback(err)
	}
	rec.Pending = nil
	rec.Status = "CREATE_COMPLETE"
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	rec.stackEvent("CREATE_COMPLETE", "")
	if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
		return rec, fmt.Errorf("stack created but recording COMPLETE failed: %w", err)
	}
	return rec, nil
}

// invokeCustomResource invokes a custom resource's backing Function with the CloudFormation
// custom-resource event and records its returned Data on the resolver (for dependents' Fn::GetAtt).
// A non-SUCCESS status (or a transport error) fails the deploy, which then rolls back.
func invokeCustomResource(ctx context.Context, opts DeployOptions, r *resolver, id string, m *Manifest) (StackResource, error) {
	sr := StackResource{LogicalID: id, APIVersion: m.APIVersion, Kind: m.Kind, Name: m.Name, Spec: m.Spec}
	if opts.Invoke == nil {
		return sr, fmt.Errorf("custom resource %s requires the in-cluster deploy path (the aws-shim CloudFormation doorway); a CLI deploy cannot invoke a Function", id)
	}
	fnName, _ := m.Spec["function"].(string)
	resType, _ := m.Spec["resourceType"].(string)
	props, _ := m.Spec["properties"].(map[string]any)
	event, _ := json.Marshal(map[string]any{
		"RequestType":        "Create",
		"ResponseURL":        "", // open-infra: the handler returns the response synchronously (no S3 callback)
		"StackId":            opts.stackID(),
		"RequestId":          opts.StackName + "/" + id,
		"ResourceType":       resType,
		"LogicalResourceId":  id,
		"ResourceProperties": props,
	})
	resp, err := opts.Invoke(ctx, opts.Namespace, fnName, event)
	if err != nil {
		return sr, fmt.Errorf("custom resource %s: invoking Function %q failed: %w", id, fnName, err)
	}
	if status := fmt.Sprint(resp["Status"]); status != "SUCCESS" {
		return sr, fmt.Errorf("custom resource %s: Function returned status %q (%s)", id, status, fmt.Sprint(resp["Reason"]))
	}
	if data, ok := resp["Data"].(map[string]any); ok {
		r.customData[id] = data
	} else {
		r.customData[id] = map[string]any{}
	}
	sr.Type = resType
	// The resource's Ref is the PhysicalResourceId its handler returned (AWS's contract); a handler that
	// returns none gets the request's id, as the cfn-response helpers do.
	if pid, ok := resp["PhysicalResourceId"].(string); ok && pid != "" {
		sr.PhysicalID = pid
	} else {
		sr.PhysicalID = opts.StackName + "/" + id
	}
	return sr, nil
}

// provisionRestAPI hands a collated REST v1 plan to the apigateway hook and records the created api id
// on the stack resource (for teardown). Without a hook (a CLI deploy), it refuses rather than guessing —
// the same stance as a custom resource with no Invoke.
func provisionRestAPI(ctx context.Context, opts DeployOptions, id string, m *Manifest) (StackResource, string, error) {
	sr := StackResource{LogicalID: id, APIVersion: m.APIVersion, Kind: m.Kind, Name: m.Name, Spec: m.Spec}
	if opts.ProvisionRestAPI == nil {
		return sr, "", fmt.Errorf("REST API %s requires the in-cluster deploy path (the aws-shim CloudFormation doorway); a CLI deploy cannot provision an API Gateway REST v1 API", id)
	}
	apiID, err := opts.ProvisionRestAPI(ctx, m.Spec)
	if err != nil {
		return sr, "", fmt.Errorf("provisioning REST API %s: %w", id, err)
	}
	sr.ProvisionedID, sr.PhysicalID, sr.Type = apiID, apiID, "AWS::ApiGateway::RestApi"
	return sr, apiID, nil
}

// renderManifest builds the applyable YAML for one resource, with stack labels.
func renderManifest(m *Manifest, opts DeployOptions) ([]byte, error) {
	obj := map[string]any{
		"apiVersion": m.APIVersion,
		"kind":       m.Kind,
		"metadata": map[string]any{
			"name":      m.Name,
			"namespace": opts.Namespace,
			"labels": map[string]any{
				labelStack:     opts.StackName,
				labelManagedBy: managedBy,
			},
		},
		"spec": m.Spec,
	}
	if len(m.Annotations) > 0 {
		ann := map[string]any{}
		for k, v := range m.Annotations {
			ann[k] = v
		}
		obj["metadata"].(map[string]any)["annotations"] = ann
	}
	return yaml.Marshal(obj)
}

// writeStackRecord persists the stack record as a ConfigMap via the applier.
func writeStackRecord(ctx context.Context, ap Applier, rec *StackRecord, opts DeployOptions) error {
	if rec.StackID == "" {
		rec.StackID = opts.StackID // a fresh record of this stack instance carries its StackId
	}
	blob, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	cm := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      "cfn-stack-" + opts.StackName,
			"namespace": opts.Namespace,
			"labels": map[string]any{
				labelStack:     opts.StackName,
				labelManagedBy: managedBy,
			},
		},
		"data": map[string]any{"stack.json": string(blob)},
	}
	y, err := yaml.Marshal(cm)
	if err != nil {
		return err
	}
	if err := ap.Apply(ctx, y); err != nil {
		return err
	}
	if rec.noEcho != nil {
		if st, ok := ap.(NoEchoStore); ok {
			if err := st.PutNoEcho(ctx, opts.StackName, rec.noEcho); err != nil {
				return fmt.Errorf("could not store the NoEcho parameters: %w", err)
			}
		}
	}
	return nil
}

// resolveParams computes the parameter value map (supplied > default) for translation. A
// missing required parameter is already a plan blocker, so by the time Deploy translates, the
// plan gate has passed and every parameter has a value.
func resolveParams(t *Template, params map[string]string) map[string]any {
	out := map[string]any{}
	for name, p := range t.Parameters {
		if v, ok := params[name]; ok {
			out[name] = v
		} else if p.hasDef {
			out[name] = p.Default
		}
	}
	return out
}

func joinBlockers(bs []string) string {
	out := ""
	for i, b := range bs {
		if i > 0 {
			out += "\n  - "
		}
		out += b
	}
	return out
}

func joinFindings(fs []Finding) string {
	out := ""
	for i, f := range fs {
		if i > 0 {
			out += "\n  - "
		}
		out += f.Where + ": " + f.Reason
	}
	return out
}

// setParams records the parameter values a stack is deployed with: the NoEcho ones by name only (their
// values go to the NoEchoStore on write), the rest in Parameters. A template that does not parse treats
// every parameter as NoEcho, so nothing is exposed by mistake.
func (rec *StackRecord) setParams(data []byte, params map[string]string) {
	plain, names, secret := SplitNoEcho(data, params)
	rec.Parameters, rec.NoEchoParameters, rec.noEcho = plain, names, secret
}

// SplitNoEcho separates a template's NoEcho parameter values from the rest. names is sorted; secret is
// never nil, so a caller can tell "no NoEcho values" from "not set". A template that does not parse
// treats every parameter as NoEcho.
func SplitNoEcho(data []byte, params map[string]string) (plain map[string]string, names []string, secret map[string]string) {
	secret = map[string]string{}
	t, err := Parse(data)
	for k, v := range params {
		if err != nil || t.Parameters[k].NoEcho {
			secret[k] = v
			names = append(names, k)
			continue
		}
		if plain == nil {
			plain = map[string]string{}
		}
		plain[k] = v
	}
	sort.Strings(names)
	return plain, names, secret
}

// NoEchoNames is the set of a template's parameters declared NoEcho (empty if it does not parse).
func NoEchoNames(data []byte) map[string]bool {
	out := map[string]bool{}
	t, err := Parse(data)
	if err != nil {
		return out
	}
	for k, p := range t.Parameters {
		if p.NoEcho {
			out[k] = true
		}
	}
	return out
}
