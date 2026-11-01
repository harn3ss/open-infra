package main

import (
	"context"
	"fmt"

	"github.com/harn3ss/open-infra/cfn"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A stack operation provisions as the caller (impersonation), but two of its steps act with the shim's
// own authority because they are not Kubernetes objects: a custom resource's Function is invoked by the
// shim, and a REST v1 API is created and torn down in the shim's API Gateway store. Those steps run only
// for a caller that may do them itself:
//   - DeleteStack checks, before anything is touched, that the caller may delete every resource the
//     teardown would remove (authorizeTeardown) — so a caller without that authority changes nothing,
//     not even the stack's record;
//   - every shim-authority hook is wrapped with the same check as the caller (asCaller), on every path
//     (create, update, change-set execution, delete, recovery).
// The check is a SubjectAccessReview for the exact identity the caller's Kubernetes operations run as.

// callerCan asks whether the applier's identity may do verb on group/resource in namespace (fail closed).
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

// canInvokeFunction is the custom-resource check: the same one a Lambda Invoke of that Function makes.
func (h *cfnDoorway) canInvokeFunction(ctx context.Context, ap *impersonatingApplier, ns, fn string) (bool, string) {
	return h.callerCan(ctx, ap, "create", "openinfra.dev", "functions", ns, fn)
}

// canDeleteRestAPI is the REST v1 check: the one the API Gateway front door makes for a delete.
func (h *cfnDoorway) canDeleteRestAPI(ctx context.Context, ap *impersonatingApplier, apiID string) (bool, string) {
	return h.callerCan(ctx, ap, "delete", "openinfra.dev", "applications", h.authzNS, apiID)
}

// asCaller binds deploy options to one caller: a create records it as the owner, and every
// shim-authority hook first checks the caller may do that step itself.
func (h *cfnDoorway) asCaller(o cfn.DeployOptions, ap *impersonatingApplier) cfn.DeployOptions {
	o.Owner = ap.user
	if inv := o.Invoke; inv != nil {
		o.Invoke = func(ctx context.Context, ns, fn string, event []byte) (map[string]any, error) {
			if ok, reason := h.canInvokeFunction(ctx, ap, ns, fn); !ok {
				return nil, fmt.Errorf("custom-resource Function %s not invoked: %s", fn, reason)
			}
			return inv(ctx, ns, fn, event)
		}
	}
	if dep := o.DeprovisionRestAPI; dep != nil {
		o.DeprovisionRestAPI = func(ctx context.Context, apiID string) error {
			if ok, reason := h.canDeleteRestAPI(ctx, ap, apiID); !ok {
				return fmt.Errorf("REST API %s not deleted: %s", apiID, reason)
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
	for _, r := range append(append([]cfn.StackResource{}, rec.Resources...), rec.Pending...) {
		if cfn.IsRetained(r) {
			continue
		}
		var ok bool
		var reason string
		switch {
		case cfn.IsCustomResource(r):
			fn, _ := r.Spec["function"].(string)
			ok, reason = h.canInvokeFunction(ctx, ap, h.ns, fn)
		case cfn.IsRestV1API(r):
			ok, reason = h.canDeleteRestAPI(ctx, ap, r.ProvisionedID)
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

// auditNonOwner logs a destructive operation by someone other than the stack's recorded owner.
func (h *cfnDoorway) auditNonOwner(action string, rec *cfn.StackRecord, ap *impersonatingApplier) {
	if rec == nil || rec.Owner == "" || rec.Owner == ap.user || h.logger == nil {
		return
	}
	h.logger.Warn("cfn: stack changed by a caller other than its owner",
		"action", action, "stack", rec.Name, "owner", rec.Owner, "caller", ap.user)
}
