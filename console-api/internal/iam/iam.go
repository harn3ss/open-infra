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
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Claims is the minimal identity a front door reduces a request to before authorization: the
// subject, an optional role (for Secret-backed accounts), and explicit groups (for kind: User
// identities, whose spec.groups are authoritative). Front-door-specific material (SigV4 access-key
// IDs, …) lives in the caller, not here; a session's expiry is carried only so that credentials
// derived from the session never outlive it.
type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	// Groups is set for identities that come from a kind: User, whose spec.groups are
	// authoritative. Empty for Secret-backed accounts, where the role name maps to a fixed
	// group set via RoleGroups.
	Groups []string `json:"groups,omitempty"`
	// AssumedRole, when non-empty, marks this as an sts:AssumeRole session acting AS a kind: Role
	// (not a User): its value is the assumed role's name — the data-plane principal id. Sub still
	// carries the full assumed-role session identifier (role/session) for audit + GetCallerIdentity.
	AssumedRole string `json:"assumedRole,omitempty"`
	// SessionExpiry is when an assumed-role session's credentials expire; zero for long-term keys. A
	// credential minted from the session (an ECR authorization token) expires no later.
	SessionExpiry time.Time `json:"-"`
	// Account is the 12-digit account the principal belongs to; empty is the install's management
	// account. It qualifies the principal's identity (AccountIdentity) and its ARNs.
	Account string `json:"account,omitempty"`
}

// UsersGroup is the implicit group every principal carried before IAM policy became the one
// authorization plane. Membership in it confers nothing in enforce mode (MemberGroups, RoleMemberGroups,
// AccountIdentity never add it); GroupsFromSpec and RoleGroups still append it for the legacy mode.
const UsersGroup = "users"

// PrincipalType is the data-plane principal type the policy engine evaluates: "Role" for an
// assumed-role session (so the role's kind: Policy dataPlane governs it), else "User".
func (c Claims) PrincipalType() string {
	if c.AssumedRole != "" {
		return "Role"
	}
	return "User"
}

// PrincipalID is the data-plane principal id: the assumed role's name, else the user Sub.
func (c Claims) PrincipalID() string {
	if c.AssumedRole != "" {
		return c.AssumedRole
	}
	return c.Sub
}

// GroupsFromSpec turns a kind: User's spec.groups into the impersonation groups the principal
// acts as: each non-empty entry prefixed with "openinfra:", plus the universal "openinfra:users".
// Empty spec.groups means "authenticated but authorized for nothing" — deliberately NOT a fallback
// to a default role, so a User created without groups fails CLOSED. This is the single source of
// truth for that mapping, shared by the console (kind: User sign-in) and the shim (resolving an
// access key's owning User) so the two can never derive a principal's groups differently.
func GroupsFromSpec(specGroups []string) []string {
	return append(MemberGroups(specGroups), "openinfra:"+UsersGroup)
}

// MemberGroups is GroupsFromSpec without the implicit users group: a principal's groups are exactly the
// ones it is a member of, so a principal with none is in none (enforce mode; IAM policy is the authority).
func MemberGroups(specGroups []string) []string {
	out := make([]string, 0, len(specGroups))
	for _, g := range specGroups {
		g = strings.TrimSpace(g)
		// Drop any entry containing a comma. Group values are carried to the engine in a comma-joined
		// header that the engine re-splits, so a comma inside one value would smuggle a SECOND group
		// across the hop (e.g. "x,system:masters" → an un-namespaced system:masters, cluster-admin).
		// No real k8s group name contains a comma, and this is the single choke point every front door
		// (SigV4 owner, OIDC/Cognito token, @aws_lambda authorizer) funnels through — so rejecting it
		// here fails the injected entry closed everywhere at once.
		if g != "" && !strings.Contains(g, ",") {
			out = append(out, "openinfra:"+g)
		}
	}
	return out
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
	return append(RoleMemberGroups(role), "openinfra:"+UsersGroup)
}

// RoleMemberGroups is RoleGroups without the implicit users group (enforce mode).
func RoleMemberGroups(role string) []string {
	switch strings.ToLower(role) {
	case "root", "admin":
		return []string{"openinfra:admins"}
	case "poweruser":
		return []string{"openinfra:powerusers"}
	default: // readonly and anything unrecognised — least privilege
		return []string{"openinfra:readers"}
	}
}

// ManagementAccount is the install's management account id: the account of every principal whose
// Claims carry none.
const ManagementAccount = "000000000000"

// AccountIdentity is the Kubernetes identity a principal acts as once IAM policy is the authority:
// "openinfra:<account>:<user>" (an assumed role: "openinfra:<account>:role/<role>"), with NO group
// impersonation — the RBAC that still enforces underneath is generated per principal from its IAM
// policies and binds this user subject directly. The account defaults to the management account.
func AccountIdentity(c Claims) (user string, ok bool) {
	if c.Sub == "" {
		return "", false
	}
	acct := c.Account
	if acct == "" {
		acct = ManagementAccount
	}
	if c.AssumedRole != "" {
		return "openinfra:" + acct + ":role/" + c.AssumedRole, true
	}
	return "openinfra:" + acct + ":" + c.Sub, true
}

// IdentityFor is the identity a request acts as in a given mode: Identity (user + groups, the legacy
// ClusterRole tiers) unless enforce, then AccountIdentity with no groups.
func IdentityFor(c Claims, enforce bool) (user string, groups []string, ok bool) {
	if !enforce {
		return Identity(c)
	}
	user, ok = AccountIdentity(c)
	return user, nil, ok
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
	// An assumed IAM Role is an independent principal whose authority is EXACTLY its attached policies (AWS
	// model): the coarse k8s-RBAC SubjectAccessReview is a User-identity gate, not the
	// role's authority, so it does not apply to an assumed-role session. The role's real, complete authority
	// is enforced by the data-plane policy engine in CLOSED/default-deny mode (internal/dataplaneauthz: a
	// Role principal is always governed, denied unless a policy permits). This is NOT a widening: a role
	// starts from deny-all and can only reach what its policies grant, and only shim STS sessions ever carry
	// AssumedRole (the console never sets it, so its authorization is unchanged).
	if c.AssumedRole != "" {
		return true, ""
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
