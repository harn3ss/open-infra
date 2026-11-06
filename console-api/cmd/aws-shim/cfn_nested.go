// Nested stacks through the CloudFormation front door: the cfn.NestedStacks driver.
//
// A nested stack (AWS::CloudFormation::Stack) is created as a stack of its own, as AWS creates one: its
// child template is read from its TemplateURL in this shim's own S3 as the caller is allowed to read it
// (cloudformation_templateurl.go — parsed into a bucket and key, never fetched over the network), and it is
// deployed under the caller's authority, by the operation that creates its parent. It has its own record,
// events and Outputs; its record names its parent (ParentId) and root (RootId), DescribeStacks and
// ListStacks report them, and it is recovered and deleted through its parent:
//   - the recovery pass leaves a nested stack's record to its parent's recovery, which rolls it back
//     with the parent;
//   - a nested stack is deleted with its parent (or its parent's rollback), and kept as a deleted stack
//     like any other (cfn_deleted.go); DeleteStack and UpdateTerminationProtection on it directly are
//     refused (its root decides both), while UpdateStack on it runs, as AWS allows.
package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
)

// nestedDriver is cfn.NestedStacks for one operation: its caller (ap) and, for an operation that may create
// nested stacks, the request it started from (whose caller reads the child templates).
type nestedDriver struct {
	h   *cfnDoorway
	ap  *impersonatingApplier
	req *http.Request
}

// withRequest gives an operation's options a nested-stack driver that can create nested stacks, reading
// their templates as the request's caller.
func (h *cfnDoorway) withRequest(o cfn.DeployOptions, ap *impersonatingApplier, r *http.Request) cfn.DeployOptions {
	o.NestedStacks = &nestedDriver{h: h, ap: ap, req: r}
	return o
}

// readTemplateURLAt reads a TemplateURL's object as r's caller, with ctx (an operation that outlives r).
func (h *cfnDoorway) readTemplateURLAt(ctx context.Context, r *http.Request, raw string) (string, error) {
	claims, ok := callerClaimsOf(r)
	if !ok {
		return "", fmt.Errorf("TemplateURL: no caller identity")
	}
	return h.readTemplateURL(withCallerClaims(r.Clone(ctx), claims), raw)
}

func (d *nestedDriver) CreateNested(ctx context.Context, req cfn.NestedStackRequest) (cfn.NestedStackResult, error) {
	h := d.h
	if d.req == nil {
		return cfn.NestedStackResult{}, fmt.Errorf("a nested stack is created only by the operation that creates its parent")
	}
	claims, _ := callerClaimsOf(d.req)
	// The caller creates the nested stack, as on AWS: it needs CreateStack on it as well as on its parent.
	if ok, reason := decide(ctx, d.req, h.authz, claims, "cloudformation:CreateStack", "Stack", req.Name, func() (bool, string) {
		if ok, reason := h.canDo(ctx, claims, "create", req.Name); !ok {
			return false, reason
		}
		return scopedDataPlaneOnly(ctx, d.req, h.authz, claims, "cloudformation:CreateStack", "Stack", req.Name)()
	}); !ok {
		return cfn.NestedStackResult{}, cfn.Unauthorized("not authorized to create nested stack " + req.Name + ": " + reason)
	}
	body, err := h.readTemplateURLAt(ctx, d.req, req.TemplateURL)
	if err != nil {
		return cfn.NestedStackResult{}, err
	}
	if msg := h.parameterRefusal(ctx, body, req.Parameters, nil, nil, d.ap); msg != "" {
		return cfn.NestedStackResult{}, fmt.Errorf("%s", msg)
	}
	if _, found, err := d.ap.GetStack(ctx, req.Name); err != nil {
		return cfn.NestedStackResult{}, err
	} else if found {
		return cfn.NestedStackResult{}, fmt.Errorf("Stack [%s] already exists", req.Name)
	}
	ex := h.exportsFor(ctx, req.Name)
	stackID := h.newStackIDIn(ctx, req.Name) // in the parent stack's account
	plan, perr := cfn.BuildPlanForStack([]byte(body), req.Parameters, ex.values, req.Name, stackID, h.caps(ctx))
	if perr != nil {
		return cfn.NestedStackResult{StackID: stackID}, perr
	}
	if plan.Verdict == cfn.Rejected {
		return cfn.NestedStackResult{StackID: stackID}, fmt.Errorf("template refused (nothing created):\n  - %s", strings.Join(plan.Blockers, "\n  - "))
	}
	opts := h.withRequest(h.asCaller(h.stackOpts(ctx, req.Name, req.Parameters, ex, body), d.ap), d.ap, d.req)
	opts.StackID, opts.ParentID, opts.RootID = stackID, req.ParentID, req.RootID
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	rec, err := cfn.Deploy(ctx, []byte(body), opts, d.ap)
	res := cfn.NestedStackResult{StackID: stackID, Outputs: map[string]string{}}
	if rec != nil {
		for _, o := range rec.Outputs {
			res.Outputs[o.OutputKey] = o.OutputValue
		}
	}
	if err == nil {
		h.logOutputs("CreateStack", req.Name, rec)
	}
	return res, err
}

func (d *nestedDriver) DeleteNested(ctx context.Context, name string) error {
	before, found, err := d.ap.GetStack(ctx, name)
	if err != nil || !found {
		return err // gone already: nothing to delete
	}
	if before.ParentID == "" {
		return fmt.Errorf("stack %s is not a nested stack; it is not deleted with another stack", name)
	}
	out, err := cfn.Destroy(ctx, d.h.asCaller(d.h.opts(ctx, name, nil), d.ap), d.ap)
	if err != nil {
		return err
	}
	d.h.afterDelete(ctx, name, before, out)
	return nil
}

func (d *nestedDriver) NestedOutputs(ctx context.Context, name string) (cfn.NestedStackResult, bool, error) {
	rec, found, err := d.h.getRecord(ctx, name)
	if err != nil || !found {
		return cfn.NestedStackResult{}, false, err
	}
	res := cfn.NestedStackResult{StackID: d.h.idOf(rec), Outputs: map[string]string{}}
	for _, o := range rec.Outputs {
		res.Outputs[o.OutputKey] = o.OutputValue
	}
	return res, true, nil
}

func (d *nestedDriver) NestedUnchanged(ctx context.Context, req cfn.NestedStackRequest) (bool, string, error) {
	if d.req == nil {
		return false, "", fmt.Errorf("its template cannot be read on this path")
	}
	rec, found, err := d.h.getRecord(ctx, req.Name)
	if err != nil {
		return false, "", err
	}
	if !found {
		return false, "it no longer exists", nil
	}
	body, err := d.h.readTemplateURLAt(ctx, d.req, req.TemplateURL)
	if err != nil {
		return false, "", err
	}
	if body != rec.Template {
		return false, "its template changed", nil
	}
	have := describedParams(rec)
	for k, v := range d.h.previousNoEcho(ctx, req.Name)() {
		have[k] = v
	}
	if !sameParams(req.Parameters, have) {
		return false, "its parameters changed", nil
	}
	return true, "", nil
}

// sameParams reports whether two parameter sets are equal (no value and an empty set are the same).
func sameParams(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// afterDelete is what follows a stack's completed delete: as on AWS, the deleted stack is kept (listed, and
// readable by its StackId, for 90 days — cfn_deleted.go), and its change sets, stored NoEcho values, events
// and signals are deleted.
func (h *cfnDoorway) afterDelete(ctx context.Context, name string, before, out *cfn.StackRecord) {
	h.keepDeleted(ctx, before, out)
	h.deleteChangeSetsOf(ctx, name)
	h.deleteStackSide(ctx, name)
	if err := h.noecho.deleteStack(ctx, name); err != nil {
		h.logger.Warn("cfn: could not delete the stack's NoEcho parameters", "stack", name, "error", err.Error())
	}
}

// nestedOf names, for a nested stack's record, the stack its root decides it through ("" = not nested).
func nestedOf(rec *cfn.StackRecord) string {
	if rec == nil || rec.ParentID == "" {
		return ""
	}
	return rec.RootID
}
