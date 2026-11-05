package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A stack operation provisions as the caller (impersonation), but some of its steps act with the shim's
// own authority because they are not Kubernetes objects: a custom resource's Function is invoked by the
// shim, and a REST v1 API is created and torn down in the shim's API Gateway store. Those steps run only
// for a caller that may do them itself — checked exactly as the front door that serves that step checks
// it (the Lambda Invoke, and the API Gateway CreateRestApi/PutIntegration/DeleteRestApi front doors):
// the coarse RBAC check for the caller's identity and the data-plane policy check (kind: Policy
// dataPlane; for an assumed role, its whole authority, default-deny — and unlike those front doors, an
// assumed role also needs the RBAC check here, since the shim acts for it):
//   - DeleteStack checks, before anything is touched, that the caller may delete every resource the
//     teardown would remove (authorizeTeardown) — so a caller without that authority changes nothing,
//     not even the stack's record;
//   - every shim-authority hook is wrapped with the same check as the caller (asCaller), on every path
//     (create, update, change-set execution, delete, recovery). A refusal is a cfn.UnauthorizedError, so a
//     teardown stops at it (DELETE_FAILED) instead of skipping it.

// callerClaims is the identity the data-plane checks run for: the claims the front door authenticated,
// or — an applier rebuilt from a stack record's recorded caller (recovery) — the claims of that caller.
func (ap *impersonatingApplier) callerClaims() iam.Claims {
	if ap.claims != nil {
		return *ap.claims
	}
	return iam.Claims{Sub: strings.TrimPrefix(ap.user, "openinfra:"), Groups: ap.groups, AssumedRole: ap.assumedRole}
}

// callerCan asks whether the applier's identity — the one the stack's own Kubernetes operations
// impersonate — may do verb on group/resource in namespace (fail closed). It is asked for an assumed role
// too: such a step needs both this and the role's data-plane grant.
func (h *cfnDoorway) callerCan(ctx context.Context, ap *impersonatingApplier, verb, group, resource, ns, name string) (bool, string) {
	if h.cs == nil {
		return false, "CloudFormation authorization is not configured on this shim"
	}
	if ap.user == "" {
		return false, "no caller identity"
	}
	out, err := h.cs.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{User: ap.user, Groups: ap.groups,
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: verb, Group: group, Resource: resource, Namespace: ns, Name: name}},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, "authorization check failed"
	}
	if !out.Status.Allowed || out.Status.Denied {
		return false, fmt.Sprintf("%s may not %s %s %q", ap.user, verb, resource, name)
	}
	return true, ""
}

// callerPolicyAllows is the data-plane check for the caller: action on resType::resID.
func (h *cfnDoorway) callerPolicyAllows(ctx context.Context, ap *impersonatingApplier, action, resType, resID string) (bool, string) {
	caller := ap.callerClaims()
	if ok, reason := decide(ctx, nil, h.authz, caller, action, resType, resID,
		scopedDataPlaneOnly(ctx, nil, h.authz, caller, action, resType, resID)); !ok {
		return false, fmt.Sprintf("%s may not %s on %s::%s: %s", ap.user, action, resType, resID, reason)
	}
	return true, ""
}

// canInvokeFunction is the custom-resource check: the one a Lambda Invoke of that Function makes.
func (h *cfnDoorway) canInvokeFunction(ctx context.Context, ap *impersonatingApplier, ns, fn string) (bool, string) {
	if ok, reason := h.callerCan(ctx, ap, "create", "openinfra.dev", "functions", ns, fn); !ok {
		return false, reason
	}
	return h.callerPolicyAllows(ctx, ap, "lambda:InvokeFunction", "Function", fn)
}

// canDeleteRestAPI is the REST v1 check: the one the API Gateway front door makes for a delete.
func (h *cfnDoorway) canDeleteRestAPI(ctx context.Context, ap *impersonatingApplier, apiID string) (bool, string) {
	if ok, reason := h.callerCan(ctx, ap, "delete", "openinfra.dev", "applications", h.authzNS, apiID); !ok {
		return false, reason
	}
	return h.callerPolicyAllows(ctx, ap, "apigateway:DeleteRestApi", "Api", apiID)
}

// canProvisionRestAPI is the REST v1 create check: what the API Gateway front door checks for each call
// that building the plan would make — CreateRestApi on the API's name, then each later call (PutMethod,
// PutIntegration, ...) on Api::* (the API has no id yet, so only a grant on any API covers it, as on AWS
// for a resource still to be created) — and, for every integration that invokes a Lambda, the
// PutIntegration fence: the caller may itself invoke that Function, since the API's invoke path is
// unsigned and runs it with no further check.
func (h *cfnDoorway) canProvisionRestAPI(ctx context.Context, ap *impersonatingApplier, plan cfn.RestAPIPlan) (bool, string) {
	name := plan.Name
	if name == "" {
		name = plan.LogicalID
	}
	if ok, reason := h.callerCan(ctx, ap, "create", "openinfra.dev", "applications", h.authzNS, name); !ok {
		return false, reason
	}
	if ok, reason := h.callerPolicyAllows(ctx, ap, "apigateway:CreateRestApi", "Api", name); !ok {
		return false, reason
	}
	for _, op := range restAPIPlanOps(plan) {
		if ok, reason := h.callerPolicyAllows(ctx, ap, "apigateway:"+op, "Api", anyResource); !ok {
			return false, reason
		}
	}
	for _, m := range plan.Methods {
		ig := m.Integration
		if ig == nil || (ig.Type != "AWS" && ig.Type != "AWS_PROXY") {
			continue
		}
		fn := functionFromURI(ig.URI)
		fnNS := h.ns // where the REST v1 invoke path will run the integration's Function
		if h.restV1 != nil && h.restV1.fnNS != "" {
			fnNS = h.restV1.fnNamespace(ctx, fn)
		}
		if ok, reason := h.callerCan(ctx, ap, "create", "openinfra.dev", "functions", fnNS, fn); !ok {
			return false, "not authorized to integrate function " + fn + ": " + reason
		}
		if ok, reason := h.callerPolicyAllows(ctx, ap, "lambda:InvokeFunction", "Function", fn); !ok {
			return false, "not authorized to integrate function " + fn + ": " + reason
		}
	}
	return true, ""
}

// restAPIPlanOps names the API Gateway calls (after CreateRestApi) that provisioning plan makes.
func restAPIPlanOps(plan cfn.RestAPIPlan) []string {
	var ops []string
	add := func(cond bool, op string) {
		if cond {
			ops = append(ops, op)
		}
	}
	integrations, integrationResponses, methodResponses := false, false, false
	for _, m := range plan.Methods {
		if m.Integration != nil {
			integrations = true
			integrationResponses = integrationResponses || len(m.Integration.IntegrationResponses) > 0
		}
		methodResponses = methodResponses || len(m.MethodResponses) > 0
	}
	add(true, "CreateResource") // the root resource, always
	add(len(plan.Models) > 0, "CreateModel")
	add(len(plan.Validators) > 0, "CreateRequestValidator")
	add(len(plan.Authorizers) > 0, "CreateAuthorizer")
	add(len(plan.Methods) > 0, "PutMethod")
	add(integrations, "PutIntegration")
	add(integrationResponses, "PutIntegrationResponse")
	add(methodResponses, "PutMethodResponse")
	add(true, "CreateDeployment")
	add(len(plan.Stages) > 0, "CreateStage")
	add(len(plan.APIKeys) > 0, "CreateApiKey")
	add(len(plan.UsagePlans) > 0, "CreateUsagePlan")
	usagePlanKeys := false
	for _, p := range plan.UsagePlans {
		usagePlanKeys = usagePlanKeys || len(p.Keys) > 0
	}
	add(usagePlanKeys, "CreateUsagePlanKey")
	return ops
}

// asCaller binds deploy options to one caller: a create records it as the owner, and every
// shim-authority hook first checks the caller may do that step itself.
func (h *cfnDoorway) asCaller(o cfn.DeployOptions, ap *impersonatingApplier) cfn.DeployOptions {
	o.Owner = ap.user
	// Nested stacks are created, read and deleted as the caller (cfn_nested.go). Creating one reads its
	// child template as the caller, so an operation that may create one names its request (withRequest).
	o.NestedStacks = &nestedDriver{h: h, ap: ap}
	if inv := o.Invoke; inv != nil {
		o.Invoke = func(ctx context.Context, ns, fn string, event []byte) (map[string]any, error) {
			if ok, reason := h.canInvokeFunction(ctx, ap, ns, fn); !ok {
				return nil, cfn.Unauthorized(fmt.Sprintf("custom-resource Function %s not invoked: %s", fn, reason))
			}
			return inv(ctx, ns, fn, event)
		}
	}
	if prov := o.ProvisionRestAPI; prov != nil {
		o.ProvisionRestAPI = func(ctx context.Context, planSpec map[string]any) (string, error) {
			plan, err := cfn.ParseRestAPIPlan(planSpec)
			if err != nil {
				return "", err
			}
			if ok, reason := h.canProvisionRestAPI(ctx, ap, plan); !ok {
				return "", cfn.Unauthorized(fmt.Sprintf("REST API %s not created: %s", plan.LogicalID, reason))
			}
			return prov(ctx, planSpec)
		}
	}
	if dep := o.DeprovisionRestAPI; dep != nil {
		o.DeprovisionRestAPI = func(ctx context.Context, apiID string) error {
			if ok, reason := h.canDeleteRestAPI(ctx, ap, apiID); !ok {
				return cfn.Unauthorized(fmt.Sprintf("REST API %s not deleted: %s", apiID, reason))
			}
			return dep(ctx, apiID)
		}
	}
	return o
}

// authorizeTeardown reports whether the caller may delete everything a DeleteStack of rec would remove:
// each Kubernetes object (as the caller's own delete would be checked), each custom resource's Function
// (its Delete event), each REST v1 API. Retained resources are left alone, so they need nothing.
func (h *cfnDoorway) authorizeTeardown(ctx context.Context, ap *impersonatingApplier, rec *cfn.StackRecord) (bool, string) {
	return h.authorizeTeardownDepth(ctx, ap, rec, 0)
}

// maxNestedDepth bounds how deep nested stacks are followed (AWS allows nesting several levels deep).
const maxNestedDepth = 8

func (h *cfnDoorway) authorizeTeardownDepth(ctx context.Context, ap *impersonatingApplier, rec *cfn.StackRecord, depth int) (bool, string) {
	for _, r := range append(append([]cfn.StackResource{}, rec.Resources...), rec.Pending...) {
		if cfn.IsRetained(r) || cfn.IsSignalWait(r) { // a wait condition deletes nothing
			continue
		}
		var ok bool
		var reason string
		switch {
		case cfn.IsNestedStack(r):
			// A nested stack is deleted as a stack: the caller may delete it, and everything in it.
			ok, reason = true, ""
			if depth >= maxNestedDepth {
				ok, reason = false, "nested stacks are nested too deeply"
				break
			}
			caller, name := ap.callerClaims(), r.Name
			if okDel, why := decide(ctx, nil, h.authz, caller, "cloudformation:DeleteStack", "Stack", name,
				func() (bool, string) { return h.canDo(ctx, caller, "delete", name) }); !okDel {
				ok, reason = false, why
				break
			}
			if child, found, err := h.getRecord(ctx, r.Name); err != nil {
				ok, reason = false, err.Error()
			} else if found {
				ok, reason = h.authorizeTeardownDepth(ctx, ap, child, depth+1)
			}
		case cfn.IsCustomResource(r):
			fn, _ := r.Spec["function"].(string)
			ok, reason = h.canInvokeFunction(ctx, ap, h.ns, fn)
		case cfn.IsRestV1API(r):
			ok, reason = h.canDeleteRestAPI(ctx, ap, r.ProvisionedID)
		case cfn.IsServiceResource(r): // a stack's service resource: its front door's delete checks
			ok = true
			if ap.svc != nil && ap.door != nil {
				if err := ap.svcAuthorize(ctx, r.Kind, "delete", r.Name, r.Spec); err != nil {
					ok, reason = false, err.Error()
				}
			}
		default:
			gvr, err := ap.gvrFor(r.APIVersion, r.Kind)
			if err != nil {
				return false, fmt.Sprintf("cannot check %s/%s: %v", r.Kind, r.Name, err)
			}
			ok, reason = h.callerCan(ctx, ap, "delete", gvr.Group, gvr.Resource, h.ns, r.Name)
		}
		if !ok {
			return false, "not authorized to delete stack resource " + r.LogicalID + ": " + reason
		}
	}
	return true, ""
}

// auditNonOwner logs a destructive operation by someone other than the stack's recorded owner. The owner
// is an audit fact only, never an authorization: as on AWS, who may change a stack is decided by the
// caller's own permissions (RBAC and kind: Policy, per stack), not by who created it.
func (h *cfnDoorway) auditNonOwner(action string, rec *cfn.StackRecord, ap *impersonatingApplier) {
	if rec == nil || rec.Owner == "" || rec.Owner == ap.user || h.logger == nil {
		return
	}
	h.logger.Warn("cfn: stack changed by a caller other than its owner",
		"action", action, "stack", rec.Name, "owner", rec.Owner, "caller", ap.user)
}
