// Nested stacks as stacks of their own.
//
// On AWS an AWS::CloudFormation::Stack resource creates a CHILD stack: a stack with its own record,
// events and outputs, named <parent>-<LogicalId>-<suffix>, whose StackId is the resource's physical id
// (its Ref) and whose Outputs the parent reads as Fn::GetAtt <Stack>.Outputs.<Key>. Deleting the parent,
// or rolling back its create, deletes the child. Where a front door can run stacks (the aws-shim, which
// sets DeployOptions.NestedStacks and Capabilities.NestedStacks), a nested stack is exactly that: the
// translator turns the resource into a sentinel the deploy walks in dependency order, handing it to the
// NestedStacks driver, which reads the child template from the TemplateURL, deploys it as its own stack
// and returns its StackId and Outputs. Elsewhere (the cfn CLI, which reads child templates from local
// files) nested stacks are flattened into the parent before planning (FlattenNested).
//
// What is refused rather than approximated:
//   - NotificationARNs (stack event notifications are not sent);
//   - a Parameters value that is not a string, number or boolean (AWS takes only those);
//   - a TemplateURL or parameter value that has not resolved by the time the child is created;
//   - an update of the parent that would add, remove or change a nested stack (its template, as read from
//     the TemplateURL now, or its parameters): such an update is refused, nothing changed. An update that
//     leaves every nested stack as it is runs, its resources reading the children's current Outputs.
package cfn

import (
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	nestedStackAPIVersion = "cfn.openinfra.dev/v1"
	nestedStackKind       = "NestedStack"
)

// NestedStackRequest is one nested stack to create (or compare): what its AWS::CloudFormation::Stack
// resource asks for.
type NestedStackRequest struct {
	// Parent and ParentID are the parent stack's name and StackId; RootID is the top-most stack's StackId
	// (the parent's own when the parent is not nested).
	Parent, ParentID, RootID string
	// LogicalID is the Stack resource's logical id in the parent.
	LogicalID string
	// Name is the child stack's name (nestedStackName).
	Name string
	// TemplateURL is the child template's S3 URL; Parameters the values passed to it.
	TemplateURL string
	Parameters  map[string]string
	// Timeout is TimeoutInMinutes (0 = none).
	Timeout time.Duration
}

// NestedStackResult is a nested stack the driver created or read: its StackId and its Outputs by key.
type NestedStackResult struct {
	StackID string
	Outputs map[string]string
}

// NestedStacks is a front door's driver of nested stacks. CreateNested deploys the child as a stack of its
// own and waits for it (an error: it failed, and was rolled back as a stack); DeleteNested deletes it as a
// stack (a child that is gone is not an error); NestedOutputs reads an existing child (found=false when it
// is gone); NestedUnchanged reports whether updating the child to req would change nothing (and if not,
// what would change).
type NestedStacks interface {
	CreateNested(ctx context.Context, req NestedStackRequest) (NestedStackResult, error)
	DeleteNested(ctx context.Context, name string) error
	NestedOutputs(ctx context.Context, name string) (NestedStackResult, bool, error)
	NestedUnchanged(ctx context.Context, req NestedStackRequest) (unchanged bool, why string, err error)
}

// IsNestedStack reports whether a recorded resource is a nested stack (a stack of its own).
func IsNestedStack(r StackResource) bool {
	return r.APIVersion == nestedStackAPIVersion && r.Kind == nestedStackKind
}

// hasNestedStacks reports whether a parsed template declares a nested stack.
func hasNestedStacks(t *Template) bool {
	for _, res := range t.Resources {
		if res.Type == StackTypeName {
			return true
		}
	}
	return false
}

// nestedStackName is a new child stack's name: <parent>-<logical id>-<12 random letters and digits>, as
// AWS names nested stacks, lowercased (a stack's records are Kubernetes objects named after it) and kept
// within 63 characters (its label value).
func nestedStackName(parent, logicalID string) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		copy(b[:], strconv.FormatInt(time.Now().UnixNano(), 36))
	}
	suffix := make([]byte, len(b))
	for i, c := range b {
		suffix[i] = alphabet[int(c)%len(alphabet)]
	}
	head := k8sName(parent) + "-" + k8sName(logicalID)
	if max := 63 - len(suffix) - 1; len(head) > max {
		head = strings.TrimRight(head[:max], "-")
	}
	return head + "-" + string(suffix)
}

// translateNestedStack maps an AWS::CloudFormation::Stack to the nested-stack sentinel (never applied as an
// object): the child's TemplateURL, its parameters and its timeout.
func translateNestedStack(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	fin := func(msg string) []Finding { return []Finding{{"Resource " + id, msg}} }
	if ctx == nil || !ctx.caps.NestedStacks {
		return nil, fin("a nested stack is created as a stack of its own only through the aws-shim CloudFormation front door; on this path flatten it into its parent (the cfn CLI does, FlattenNested)")
	}
	known := map[string]bool{"TemplateURL": true, "Parameters": true, "TimeoutInMinutes": true, "NotificationARNs": true, "Tags": true}
	var f []Finding
	f = append(f, blockUnknownProps(id, props, known)...)
	url, ok := props["TemplateURL"].(string)
	if !ok || strings.TrimSpace(url) == "" {
		f = append(f, fin("TemplateURL is required, and must resolve to the S3 URL of the child template (a literal, or a Fn::Sub / Fn::Join of parameters and pseudo parameters)")...)
	}
	if raw, present := props["NotificationARNs"]; present {
		if arns, ok := raw.([]any); !ok || len(arns) > 0 {
			f = append(f, fin("NotificationARNs: stack event notifications are not sent on open-infra — remove them")...)
		}
	}
	params := map[string]any{}
	if raw, present := props["Parameters"]; present {
		pm, ok := raw.(map[string]any)
		if !ok {
			f = append(f, fin("Parameters must be an object of parameter names and values")...)
		}
		for k, v := range pm {
			switch val := v.(type) {
			case string:
				params[k] = val
			case bool, int, int64, float64:
				params[k] = scalarString(val)
			default:
				f = append(f, fin(fmt.Sprintf("Parameters.%s must be a string, number or boolean (AWS takes only those — join a list with Fn::Join)", k))...)
			}
		}
	}
	spec := map[string]any{"templateURL": url, "parameters": params}
	if raw, present := props["TimeoutInMinutes"]; present {
		n, err := strconv.Atoi(scalarString(raw))
		if err != nil || n < 1 {
			f = append(f, fin("TimeoutInMinutes must be a whole number of minutes, at least 1")...)
		} else {
			spec["timeoutMinutes"] = int64(n)
		}
	}
	if len(f) > 0 {
		return nil, f
	}
	m := &Manifest{APIVersion: nestedStackAPIVersion, Kind: nestedStackKind, Name: ctx.name(id), Spec: spec}
	if _, tagged := props["Tags"]; tagged {
		m.Caveats = append(m.Caveats, "Tags are not applied to the nested stack's resources (stack tags are not propagated on open-infra)")
	}
	return m, nil
}

// nestedRequest is the request a nested-stack sentinel makes, for a child of that name. It refuses a value
// that has not resolved (a placeholder), which on AWS would be a value the parent cannot pass.
func nestedRequest(opts DeployOptions, id, name string, spec map[string]any) (NestedStackRequest, error) {
	req := NestedStackRequest{Parent: opts.StackName, ParentID: opts.stackID(), RootID: opts.RootID, LogicalID: id, Name: name,
		Parameters: map[string]string{}}
	if req.RootID == "" {
		req.RootID = req.ParentID
	}
	req.TemplateURL, _ = spec["templateURL"].(string)
	if unresolved(req.TemplateURL) {
		return req, fmt.Errorf("%s: TemplateURL %q did not resolve", id, req.TemplateURL)
	}
	if pm, ok := spec["parameters"].(map[string]any); ok {
		for k, v := range pm {
			s := scalarString(v)
			if unresolved(s) {
				return req, fmt.Errorf("%s: Parameters.%s did not resolve (%s)", id, k, s)
			}
			req.Parameters[k] = s
		}
	}
	switch n := spec["timeoutMinutes"].(type) {
	case int64:
		req.Timeout = time.Duration(n) * time.Minute
	case float64:
		req.Timeout = time.Duration(n) * time.Minute
	case int:
		req.Timeout = time.Duration(n) * time.Minute
	}
	return req, nil
}

// unresolved reports whether a resolved value still holds a placeholder the resolver leaves for a value it
// could not resolve.
func unresolved(s string) bool { return strings.Contains(s, "<") && strings.Contains(s, ">") }

// nestedOutputsData is a child's Outputs as the parent's Fn::GetAtt reads them: "Outputs.<Key>" -> value.
func nestedOutputsData(res NestedStackResult) map[string]any {
	data := map[string]any{}
	for k, v := range res.Outputs {
		data["Outputs."+k] = v
	}
	return data
}

// createNestedStack runs one nested-stack sentinel of a create: the child is created as a stack of its
// own, its StackId becomes the resource's physical id, and its Outputs are what later resources'
// Fn::GetAtt read. The resource is returned (for rollback) even when the create failed, since a child that
// failed is a stack the rollback deletes.
func createNestedStack(ctx context.Context, opts DeployOptions, r *resolver, id string, m *Manifest) (StackResource, error) {
	sr := StackResource{LogicalID: id, APIVersion: m.APIVersion, Kind: m.Kind, Name: m.Name, Spec: m.Spec, Type: StackTypeName}
	if opts.NestedStacks == nil {
		return sr, fmt.Errorf("%s: nested stacks cannot be created on this deploy path", id)
	}
	req, err := nestedRequest(opts, id, sr.Name, m.Spec)
	if err != nil {
		return sr, err
	}
	res, err := opts.NestedStacks.CreateNested(ctx, req)
	sr.PhysicalID, sr.ProvisionedID = res.StackID, sr.Name
	if err != nil {
		if res.StackID != "" {
			return sr, fmt.Errorf("Embedded stack %s was not successfully created: %w", res.StackID, err)
		}
		return sr, fmt.Errorf("Embedded stack %s was not successfully created: %w", sr.Name, err)
	}
	r.customData[id] = nestedOutputsData(res)
	return sr, nil
}

// deleteNestedStack deletes a recorded nested stack (a stack delete, a rollback).
func deleteNestedStack(ctx context.Context, opts DeployOptions, r StackResource) error {
	if opts.NestedStacks == nil {
		return fmt.Errorf("nested stack %s (%s) cannot be deleted on this path — delete it through the aws-shim CloudFormation front door", r.LogicalID, r.Name)
	}
	return opts.NestedStacks.DeleteNested(ctx, r.Name)
}

// nestedOutputsOf reads the current Outputs of every nested stack a stack recorded, by logical id — what an
// update's resources read through Fn::GetAtt <Stack>.Outputs.<Key>, and its Ref.
func nestedOutputsOf(ctx context.Context, opts DeployOptions, rs []StackResource) (map[string]map[string]any, error) {
	out := map[string]map[string]any{}
	for _, r := range rs {
		if !IsNestedStack(r) {
			continue
		}
		if opts.NestedStacks == nil {
			return nil, fmt.Errorf("the stack has nested stacks, which this path cannot read")
		}
		res, found, err := opts.NestedStacks.NestedOutputs(ctx, r.Name)
		if err != nil {
			return nil, fmt.Errorf("reading nested stack %s: %w", r.LogicalID, err)
		}
		if !found {
			return nil, fmt.Errorf("nested stack %s (%s) no longer exists", r.LogicalID, r.Name)
		}
		out[r.LogicalID] = nestedOutputsData(res)
	}
	return out, nil
}

// nestedUpdateRefusal is why an update may not run for its nested stacks ("" = it may): it adds, removes or
// changes one. desired are the update's built resources; current is the stack's record.
func nestedUpdateRefusal(ctx context.Context, opts DeployOptions, desired []builtResource, current *StackRecord) string {
	cur := map[string]StackResource{}
	for _, r := range current.Resources {
		if IsNestedStack(r) {
			cur[r.LogicalID] = r
		}
	}
	var changed []string
	seen := map[string]bool{}
	for _, b := range desired {
		if !IsNestedStack(b.res) {
			continue
		}
		seen[b.res.LogicalID] = true
		prior, ok := cur[b.res.LogicalID]
		if !ok {
			changed = append(changed, b.res.LogicalID+" (added)")
			continue
		}
		req, err := nestedRequest(opts, b.res.LogicalID, prior.Name, b.res.Spec)
		if err != nil {
			changed = append(changed, b.res.LogicalID+" ("+err.Error()+")")
			continue
		}
		if opts.NestedStacks == nil {
			changed = append(changed, b.res.LogicalID+" (cannot be compared on this path)")
			continue
		}
		same, why, err := opts.NestedStacks.NestedUnchanged(ctx, req)
		switch {
		case err != nil:
			changed = append(changed, b.res.LogicalID+" (could not be compared: "+err.Error()+")")
		case !same:
			changed = append(changed, b.res.LogicalID+" ("+why+")")
		}
	}
	for id := range cur {
		if !seen[id] {
			changed = append(changed, id+" (removed)")
		}
	}
	if len(changed) == 0 {
		return ""
	}
	sort.Strings(changed)
	return "updating a stack's nested stacks is not supported yet: this update would change " + strings.Join(changed, ", ") +
		" — nothing was changed. Update the nested stack itself (UpdateStack on it), or delete and re-create the parent stack"
}
