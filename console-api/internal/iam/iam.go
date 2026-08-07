// Package iam is the platform's single authorization core: the one definition of "who is this
// principal, to the Kubernetes API server" and "may this principal do X". It is deliberately
// shared by every front door onto open-infra — the console BFF and the AWS-shim — so all of them
// resolve identity and enforce permissions through the SAME impersonated SubjectAccessReview,
// never a weaker parallel path.
//
// This is the code embodiment of the design's "one policy world, three front doors": the shim
// does not get its own notion of who-you-are-and-what-you-can-do. Whatever front door a request
// arrives through, once it has been reduced to Claims it flows through Identity and CanDo
// here, and the actual decision is made by the API server's RBAC against the impersonated
// openinfra:<user>/openinfra:<group> identity — the very same ClusterRoles compiled from
// kind: Policy/Role/Group, bounded by the permission boundary.
package iam

import (
	"context"
	"strings"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Claims is the minimal identity a front door reduces a request to before authorization: the
// subject, an optional role (for Secret-backed accounts), and explicit groups (for kind: User
// identities, whose spec.groups are authoritative). Front-door-specific material (session
// expiry, SigV4 access-key IDs, …) lives in the caller, not here.
type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	// Groups is set for identities that come from a kind: User, whose spec.groups are
	// authoritative. Empty for Secret-backed accounts, where the role name maps to a fixed
	// group set via RoleGroups.
	Groups []string `json:"groups,omitempty"`
}

// GroupsFromSpec turns a kind: User's spec.groups into the impersonation groups the principal
// acts as: each non-empty entry prefixed with "openinfra:", plus the universal "openinfra:users".
// Empty spec.groups means "authenticated but authorized for nothing" — deliberately NOT a fallback
// to a default role, so a User created without groups fails CLOSED. This is the single source of
// truth for that mapping, shared by the console (kind: User sign-in) and the shim (resolving an
// access key's owning User) so the two can never derive a principal's groups differently.
func GroupsFromSpec(specGroups []string) []string {
	out := make([]string, 0, len(specGroups)+1)
	for _, g := range specGroups {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, "openinfra:"+g)
		}
	}
	return append(out, "openinfra:users")
}

// RoleGroups maps a console role to the Kubernetes groups it acts as. Console principals are
// impersonated as `openinfra:<user>` (namespaced so they can never collide with a real cluster
// user) and carry group memberships that RBAC binds permissions to.
//
//	root / admin -> openinfra:admins (full access)
//	poweruser -> openinfra:powerusers (manage resources, not secrets/RBAC)
//	readonly -> openinfra:readers (get/list/watch only)
//
// Every principal also gets openinfra:users, for rules that apply to everyone.
func RoleGroups(role string) []string {
	switch strings.ToLower(role) {
	case "root", "admin":
		return []string{"openinfra:admins", "openinfra:users"}
	case "poweruser":
		return []string{"openinfra:powerusers", "openinfra:users"}
	default: // readonly and anything unrecognised — least privilege
		return []string{"openinfra:readers", "openinfra:users"}
	}
}

// Identity maps Claims to the Kubernetes identity they act as. This is the SINGLE definition of
// "who is this, to the API server": both the impersonating proxy and the SubjectAccessReview
// checks in CanDo must agree, or a request would be authorized under one identity and then
// performed as another.
//
// Explicit claim groups (from a kind: User) win. Secret-backed accounts carry none, so their
// role maps to a fixed group set. A principal with a subject but no resolvable groups can
// authenticate yet is authorized for nothing — least privilege, fail closed.
func Identity(c Claims) (user string, groups []string, ok bool) {
	if c.Sub == "" {
		return "", nil, false
	}
	if len(c.Groups) > 0 {
		return "openinfra:" + c.Sub, c.Groups, true
	}
	return "openinfra:" + c.Sub, RoleGroups(c.Role), true
}

// CanDo asks the API server whether the principal may perform verb on group/resource in
// namespace (optionally a named object), via a SubjectAccessReview run AS the impersonated
// identity. It fails CLOSED: any error, or the absence of a resolvable identity, means "no".
//
// Using the impersonated identity is the whole point — the check is evaluated against the exact
// same subject the request will ultimately act as, so the authorization decision and the access
// can never diverge, and the decision lands in the audit log against a person/principal rather
// than an invisible `if` in Go.
func CanDo(ctx context.Context, cs kubernetes.Interface, c Claims,
	verb, group, resource, namespace, name string) (allowed bool, reason string) {
	user, groups, ok := Identity(c)
	if !ok {
		return false, "no identity"
	}
	sar := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   user,
			Groups: groups,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:      verb,
				Group:     group,
				Resource:  resource,
				Namespace: namespace,
				Name:      name,
			},
		},
	}
	out, err := cs.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, "authorization check failed"
	}
	if !out.Status.Allowed || out.Status.Denied {
		r := out.Status.Reason
		if r == "" {
			r = "your role does not allow " + verb + " on " + resource
		}
		return false, r
	}
	return true, ""
}
