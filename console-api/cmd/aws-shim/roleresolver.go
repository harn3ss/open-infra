package main

import (
	"context"
	"strings"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
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

// k8sTokenReviewer verifies a workload's projected ServiceAccount token via a Kubernetes
// TokenReview, returning the SA username ("system:serviceaccount:<ns>:<sa>"). The token must be
// authenticated AND carry the expected audience (the shim's), so a token minted for another
// audience can't be replayed here. Fails closed on any error.
type k8sTokenReviewer struct {
	cs       kubernetes.Interface
	audience string
}

func (t *k8sTokenReviewer) Review(ctx context.Context, token string) (string, bool) {
	tr := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token, Audiences: []string{t.audience}}}
	out, err := t.cs.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil || !out.Status.Authenticated {
		return "", false
	}
	u := out.Status.User.Username
	if !strings.HasPrefix(u, "system:serviceaccount:") {
		return "", false // only ServiceAccount identities are workload principals
	}
	return u, true
}
