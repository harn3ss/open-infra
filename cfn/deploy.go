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
}

// builtResource is one translated, ready-to-apply resource plus its identity/spec record.
type builtResource struct {
	res StackResource
	yml []byte
	cav []string
}

type StackRecord struct {
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"`
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
	Owner            string            `json:"owner,omitempty"`
	Template         string            `json:"template,omitempty"`
	Parameters       map[string]string `json:"parameters,omitempty"`
	NoEchoParameters []string          `json:"noEchoParameters,omitempty"`
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
}

type DeployOptions struct {
	StackName string
	Namespace string
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
	// Caps are deploy-environment facts translators depend on (e.g. whether MinIO has SSE-KMS on).
	// Plan and deploy both evaluate with these, so a PROVISIONABLE* plan still means deploy won't
	// refuse. Zero = fail-closed (the CLI); the in-cluster aws-shim doorway sets them.
	Caps Capabilities
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
				DeletionPolicy: dp, Spec: mm.Spec},
			yml: yml, cav: mm.Caveats,
		})
	}
	return out, nil
}

// buildManifests runs the plan gate then the translate gate, returning every included
// resource translated and ordered by dependency. It is the shared fail-closed front half of
// deploy and update: a REJECTED plan, a type with no create translator, or any untranslatable
// property returns an error and no manifests — there is no partial result.
func buildManifests(data []byte, opts DeployOptions) ([]builtResource, error) {
	plan, err := BuildPlanWithCaps(data, opts.Params, opts.Exports, opts.StackName, opts.Caps)
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
	r := newResolver(t, resolveParams(t, opts.Params), strMapToAny(opts.Exports), pseudoParams(opts.StackName))
	r.evalConditions()
	ctx := &stackCtx{template: t, resolver: r, caps: opts.Caps}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, ctx) }

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
		built, err := expandManifest(id, res, m, opts)
		if err != nil {
			return nil, err
		}
		byID[id] = built
	}
	findings = append(findings, r.findings...)
	if len(findings) > 0 {
		return nil, fmt.Errorf("translate gate REJECTED — refusing (nothing applied):\n  - %s", joinFindings(findings))
	}
	var order []builtResource
	for _, id := range plan.Order {
		order = append(order, byID[id]...)
	}
	return order, nil
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
	// refusing (nothing applied) on any blocker or untranslatable property.
	order, err := buildManifests(data, opts)
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
	}
	rec.setParams(data, opts.Params)
	for _, b := range order {
		rec.Resources = append(rec.Resources, b.res)
	}
	if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}

	var applied []StackResource
	rollback := func(cause error) (*StackRecord, error) {
		// Reverse order, honoring Retain: a Retain resource (e.g. the shared default EncryptionKey, which
		// may pre-date this stack and key a sibling's disks) survives a failed create — AWS retains it on
		// rollback too.
		for i := len(applied) - 1; i >= 0; i-- {
			a := applied[i]
			if isRetain(a) {
				continue
			}
			_ = ap.Delete(ctx, a.APIVersion, a.Kind, a.Name)
		}
		rec.Status = "CREATE_FAILED"
		rec.Message = cause.Error()
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		_ = writeStackRecord(ctx, ap, rec, opts)
		return rec, fmt.Errorf("deploy failed and was rolled back (no orphans): %w", cause)
	}

	for _, b := range order {
		if err := ap.Apply(ctx, b.yml); err != nil {
			return rollback(fmt.Errorf("applying %s/%s: %w", b.res.Kind, b.res.Name, err))
		}
		applied = append(applied, b.res)
		if opts.Wait {
			if err := ap.WaitReady(ctx, b.res.APIVersion, b.res.Kind, b.res.Name, opts.Timeout); err != nil {
				return rollback(fmt.Errorf("%s/%s did not become ready: %w", b.res.Kind, b.res.Name, err))
			}
		}
	}

	// 4. Complete — with the template's Outputs evaluated against the deployed stack.
	setOutputs(ctx, data, opts, rec, ap, nil)
	rec.Status = "CREATE_COMPLETE"
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
		return rec, fmt.Errorf("stack created but recording COMPLETE failed: %w", err)
	}
	return rec, nil
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
	plan, err := BuildPlanWithCaps(data, opts.Params, opts.Exports, opts.StackName, opts.Caps)
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
	r := newResolver(t, resolveParams(t, opts.Params), strMapToAny(opts.Exports), pseudoParams(opts.StackName))
	r.evalConditions()
	r.customData = map[string]map[string]any{}
	sctx := &stackCtx{template: t, resolver: r, caps: opts.Caps}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, sctx) }

	now := time.Now().UTC().Format(time.RFC3339)
	rec := &StackRecord{Name: opts.StackName, Namespace: opts.Namespace, Status: "CREATE_IN_PROGRESS", CreatedAt: now, UpdatedAt: now,
		Template: string(data), Owner: opts.Owner}
	rec.setParams(data, opts.Params)
	if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}

	var applied []StackResource
	var provisionedAPIs []string // REST v1 API ids to tear down on rollback
	rollback := func(cause error) (*StackRecord, error) {
		for i := len(applied) - 1; i >= 0; i-- { // reverse order, honoring Retain (as Deploy does)
			a := applied[i]
			if isRetain(a) {
				continue
			}
			_ = ap.Delete(ctx, a.APIVersion, a.Kind, a.Name)
		}
		for i := len(provisionedAPIs) - 1; i >= 0; i-- { // tear down provisioned REST v1 APIs too
			if opts.DeprovisionRestAPI != nil {
				_ = opts.DeprovisionRestAPI(ctx, provisionedAPIs[i])
			}
		}
		rec.Status = "CREATE_FAILED"
		rec.Message = cause.Error()
		rec.Pending = nil
		rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		_ = writeStackRecord(ctx, ap, rec, opts)
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

	for _, id := range plan.Order {
		res := t.Resources[id]
		tr := translatorFor(res.Type)
		if tr == nil {
			return rollback(fmt.Errorf("%s (%s) has no create translator", id, res.Type))
		}
		r.where = "Resource " + id
		resolved, _ := r.resolve(res.Properties).(map[string]any)
		m, fs := tr(id, resolved, sctx)
		if len(fs) > 0 {
			return rollback(fmt.Errorf("translate gate REJECTED:\n  - %s", joinFindings(fs)))
		}
		if m == nil {
			continue // a no-op resource (composes into another kind)
		}
		// A custom resource is invoked (not applied); its Data feeds later dependents' Fn::GetAtt.
		if m.APIVersion == customResourceAPIVersion && m.Kind == customResourceKind {
			if werr := intend(StackResource{LogicalID: id, APIVersion: m.APIVersion, Kind: m.Kind, Name: m.Name, Spec: m.Spec}); werr != nil {
				return rollback(werr)
			}
			sr, cerr := invokeCustomResource(ctx, opts, r, id, m)
			if cerr != nil {
				return rollback(cerr)
			}
			rec.Resources = append(rec.Resources, sr)
			rec.Pending = nil
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
			if werr := intend(); werr != nil {
				return rollback(werr)
			}
			continue
		}
		built, berr := expandManifest(id, res, m, opts)
		if berr != nil {
			return rollback(berr)
		}
		pending := make([]StackResource, 0, len(built))
		for _, b := range built {
			pending = append(pending, b.res)
		}
		if werr := intend(pending...); werr != nil {
			return rollback(werr)
		}
		for _, b := range built {
			if aerr := ap.Apply(ctx, b.yml); aerr != nil {
				return rollback(fmt.Errorf("applying %s/%s: %w", b.res.Kind, b.res.Name, aerr))
			}
			applied = append(applied, b.res)
			rec.Resources = append(rec.Resources, b.res)
			if opts.Wait {
				if werr := ap.WaitReady(ctx, b.res.APIVersion, b.res.Kind, b.res.Name, opts.Timeout); werr != nil {
					return rollback(fmt.Errorf("%s/%s did not become ready: %w", b.res.Kind, b.res.Name, werr))
				}
			}
		}
		rec.Pending = nil // now in Resources (written with the next write-ahead, or at COMPLETE)
	}
	// Outputs may read a custom resource's returned Data (Fn::GetAtt), so evaluate them with it.
	setOutputs(ctx, data, opts, rec, ap, r.customData)
	rec.Pending = nil
	rec.Status = "CREATE_COMPLETE"
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
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
		"StackId":            opts.StackName,
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
	sr.ProvisionedID = apiID
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
	return yaml.Marshal(obj)
}

// writeStackRecord persists the stack record as a ConfigMap via the applier.
func writeStackRecord(ctx context.Context, ap Applier, rec *StackRecord, opts DeployOptions) error {
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
