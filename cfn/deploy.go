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
//     created THIS deploy are deleted in reverse order, and the stack is marked CREATE_FAILED.
//     A failed create leaves no orphans.
//
// Stack state is persisted as a ConfigMap (cfn-stack-<name>) so later phases (update, delete,
// drift) have a record of what was created; every applied resource is labeled with its stack.
package main

import (
	"context"
	"encoding/json"
	"fmt"
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
}

type StackResource struct {
	LogicalID  string `json:"logicalId"`
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
}

type StackRecord struct {
	Name      string          `json:"name"`
	Namespace string          `json:"namespace"`
	Status    string          `json:"status"`
	Message   string          `json:"message,omitempty"`
	CreatedAt string          `json:"createdAt"`
	UpdatedAt string          `json:"updatedAt"`
	Resources []StackResource `json:"resources"`
}

type DeployOptions struct {
	StackName string
	Namespace string
	Params    map[string]string
	Wait      bool
	Timeout   time.Duration
}

// Deploy runs the full fail-closed create. It returns the final stack record (whose Status is
// CREATE_COMPLETE or CREATE_FAILED) and an error if the deploy did not fully succeed.
func Deploy(ctx context.Context, data []byte, opts DeployOptions, ap Applier) (*StackRecord, error) {
	if opts.Namespace == "" {
		return nil, fmt.Errorf("a target namespace is required (deploy never guesses one)")
	}

	// 1. Plan gate.
	plan, err := BuildPlan(data, opts.Params, opts.StackName)
	if err != nil {
		return nil, err
	}
	if plan.Verdict == Rejected {
		return nil, fmt.Errorf("plan is REJECTED — refusing to deploy:\n  - %s", joinBlockers(plan.Blockers))
	}

	// 2. Translate gate — build every manifest up front; refuse on any blocking finding.
	t, err := Parse(data)
	if err != nil {
		return nil, err
	}
	r := newResolver(t, resolveParams(t, opts.Params), pseudoParams(opts.StackName))
	r.evalConditions()

	type built struct {
		res StackResource
		yml []byte
		cav []string
	}
	var order []built
	byID := map[string]built{}
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
		m, fs := translators[res.Type](id, resolved)
		if len(fs) > 0 {
			findings = append(findings, fs...)
			continue
		}
		yml, err := renderManifest(m, opts)
		if err != nil {
			return nil, err
		}
		b := built{
			res: StackResource{LogicalID: id, APIVersion: m.APIVersion, Kind: m.Kind, Name: m.Name},
			yml: yml, cav: m.Caveats,
		}
		byID[id] = b
	}
	findings = append(findings, r.findings...)
	if len(findings) > 0 {
		return nil, fmt.Errorf("translate gate REJECTED — refusing to deploy (nothing applied):\n  - %s", joinFindings(findings))
	}
	// Order the built manifests by the plan's provisioning order.
	for _, id := range plan.Order {
		if b, ok := byID[id]; ok {
			order = append(order, b)
		}
	}

	// 3. Persist the stack record (IN_PROGRESS), then apply in order.
	now := time.Now().UTC().Format(time.RFC3339)
	rec := &StackRecord{
		Name: opts.StackName, Namespace: opts.Namespace, Status: "CREATE_IN_PROGRESS",
		CreatedAt: now, UpdatedAt: now,
	}
	for _, b := range order {
		rec.Resources = append(rec.Resources, b.res)
	}
	if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
		return nil, fmt.Errorf("could not persist stack record: %w", err)
	}

	var applied []StackResource
	rollback := func(cause error) (*StackRecord, error) {
		for i := len(applied) - 1; i >= 0; i-- { // reverse order
			a := applied[i]
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

	// 4. Complete.
	rec.Status = "CREATE_COMPLETE"
	rec.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeStackRecord(ctx, ap, rec, opts); err != nil {
		return rec, fmt.Errorf("stack created but recording COMPLETE failed: %w", err)
	}
	return rec, nil
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
	return ap.Apply(ctx, y)
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
