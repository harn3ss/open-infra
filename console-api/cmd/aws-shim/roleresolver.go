package main

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// dynRoleResolver reads a kind: Role's trust policy (spec.trust — who may assume it) from the
// cluster to authorize an sts:AssumeRole. A role with no trust entries cannot be assumed by anyone
// (fail closed): a trust policy is required, exactly as an AWS role needs one.
type dynRoleResolver struct {
	dyn dynamic.Interface
	ns  string
}

var roleGVR = schema.GroupVersionResource{Group: "iam.openinfra.dev", Version: "v1", Resource: "roles"}

func (r *dynRoleResolver) Resolve(ctx context.Context, roleName string) (trust []string, groups []string, ok bool) {
	u, err := r.dyn.Resource(roleGVR).Namespace(r.ns).Get(ctx, roleName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, false
	}
	trust, _, _ = unstructured.NestedStringSlice(u.Object, "spec", "trust")
	// The session acts as openinfra:users at the control plane (least privilege); the role's real
	// authority is its attached data-plane policies, evaluated with principal type "Role" (the
	// assumed-role principal). Broader control-plane authority for assumed roles lands with the
	// control-plane authorization work (#109 Phase 2).
	return trust, []string{"openinfra:users"}, true
}
