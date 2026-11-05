package main

import (
	"context"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
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

func (r *dynRoleResolver) Resolve(ctx context.Context, roleName string) (resolvedRole, bool) {
	return r.ResolveIn(ctx, r.ns, roleName)
}

// awsNameAnnotation carries a kind: Role's AWS name where it is not a valid Kubernetes object name (AWS
// role names are mixed case: OrganizationAccountAccessRole is the object organizationaccountaccessrole).
const awsNameAnnotation = "openinfra.dev/aws-name"

// ResolveIn is Resolve for a Role in namespace ns (another account's home, for a cross-account
// AssumeRole). A role named in AWS's mixed case resolves to the object of its lower-cased name that
// carries that name in openinfra.dev/aws-name.
func (r *dynRoleResolver) ResolveIn(ctx context.Context, ns, roleName string) (resolvedRole, bool) {
	u, err := r.dyn.Resource(roleGVR).Namespace(ns).Get(ctx, roleName, metav1.GetOptions{})
	if err != nil {
		lower := strings.ToLower(roleName)
		if lower == roleName {
			return resolvedRole{}, false
		}
		u, err = r.dyn.Resource(roleGVR).Namespace(ns).Get(ctx, lower, metav1.GetOptions{})
		if err != nil || u.GetAnnotations()[awsNameAnnotation] != roleName {
			return resolvedRole{}, false
		}
	}
	trust, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "trust")
	// The session acts as openinfra:users at the control plane (least privilege); the role's real
	// authority is its attached data-plane policies, evaluated with principal type "Role" (the
	// assumed-role principal). Broader control-plane authority for assumed roles lands with the
	// control-plane authorization work (#109 Phase 2).
	return resolvedRole{trust: trust, groups: []string{"openinfra:users"}, maxSession: roleMaxSession(u.Object)}, true
}

// roleMaxSession is a role's spec.maxSessionDuration (seconds), within AWS's 1h..12h; the default, 1h,
// when it is unset or out of range (admission refuses an out-of-range value).
func roleMaxSession(obj map[string]any) time.Duration {
	secs, found, err := unstructured.NestedInt64(obj, "spec", "maxSessionDuration")
	if err != nil || !found {
		if f, ok, _ := unstructured.NestedFloat64(obj, "spec", "maxSessionDuration"); ok {
			secs, found = int64(f), true
		}
	}
	d := time.Duration(secs) * time.Second
	if !found || d < defaultMaxSession || d > awssts.MaxDuration {
		return defaultMaxSession
	}
	return d
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
