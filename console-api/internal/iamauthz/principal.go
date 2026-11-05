package iamauthz

import (
	"slices"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// IAM objects (kind: Role, User, Group, Policy) are namespaced, but principal ids and Policy names are
// plain strings. Each object gets one canonical id:
//
//   - in the IAM home namespace: its bare name;
//   - anywhere else: "<namespace>/<name>".
//
// "/" cannot occur in a Kubernetes name, so the two forms never collide, and a same-named object in
// another namespace is a different principal or Policy.

// DefaultHomeNamespace is the IAM home namespace when none is configured.
const DefaultHomeNamespace = "open-infra-console"

// QualifiedName is the canonical id of the object ns/name: the bare name in home (or when ns is empty),
// else "<ns>/<name>".
func QualifiedName(home, ns, name string) string {
	if ns == "" || ns == home {
		return name
	}
	return ns + "/" + name
}

// SplitQualified is QualifiedName's inverse: a bare id is in home.
func SplitQualified(home, id string) (ns, name string) {
	if i := strings.IndexByte(id, '/'); i > 0 {
		return id[:i], id[i+1:]
	}
	return home, id
}

// StarInNamespacePrefix is the canonical form of a "*" appliesTo entry in a Policy outside home: it
// applies to every principal of that Policy's own namespace, never to anyone else.
const StarInNamespacePrefix = "*@"

// CanonAppliesTo rewrites one Policy's appliesTo entries into canonical principal keys. A home-namespace
// Policy may name any principal; a Policy in any other namespace governs only principals of its own
// namespace ("*" there means everyone in that namespace; an entry naming another namespace or a Group is
// dropped).
func CanonAppliesTo(home, policyNS string, entries []string) []string {
	out := make([]string, 0, len(entries))
	local := policyNS == "" || policyNS == home
	for _, e := range entries {
		if e == "*" {
			if local {
				out = append(out, "*")
			} else {
				out = append(out, StarInNamespacePrefix+policyNS)
			}
			continue
		}
		typ, name, ok := strings.Cut(e, "::")
		if !ok || name == "" {
			if local {
				out = append(out, e)
			}
			continue
		}
		if typ == "Group" {
			if local {
				out = append(out, e)
			}
			continue
		}
		ns, bare := policyNS, name
		if i := strings.IndexByte(name, '/'); i > 0 {
			ns, bare = name[:i], name[i+1:]
			if !local && ns != policyNS {
				continue // a namespaced Policy cannot reach into another namespace
			}
		}
		out = append(out, typ+"::"+QualifiedName(home, ns, bare))
	}
	return out
}

// ResolvePolicyRef resolves a Policy reference on a principal (spec.policies or
// spec.permissionBoundary) to a canonical Policy name. A bare reference means the principal's own
// namespace's Policy if there is one, else the home namespace's (the managed library); "<ns>/<name>"
// names one explicitly, which only a home principal may do for a namespace other than its own and home.
// "" means the reference is not allowed.
func ResolvePolicyRef(home, principalNS, ref string, exists func(string) bool) string {
	if i := strings.IndexByte(ref, '/'); i > 0 {
		ns, name := ref[:i], ref[i+1:]
		if principalNS != home && ns != principalNS && ns != home {
			return ""
		}
		return QualifiedName(home, ns, name)
	}
	if principalNS != home {
		if own := QualifiedName(home, principalNS, ref); exists(own) {
			return own
		}
	}
	return ref
}

// PrincipalType is the kind of principal a request is evaluated as.
type PrincipalType string

const (
	// User is an IAM user (kind: User, or a Secret-backed console account other than root).
	User PrincipalType = "User"
	// Role is an assumed-role session (kind: Role).
	Role PrincipalType = "Role"
	// Root is an account's root user: every action in its own account is allowed.
	Root PrincipalType = "Root"
	// Service is an AWS service principal (sns.amazonaws.com …): only resource policies grant it.
	Service PrincipalType = "Service"
)

// ManagementAccount is the account id of the install's management account: every principal and
// resource with no account of its own belongs to it, so today's ARNs stay valid.
const ManagementAccount = "000000000000"

// Principal is the subject of an authorization question.
type Principal struct {
	// Account is the 12-digit account the principal belongs to; "" is the management account.
	Account string
	Type    PrincipalType
	// ID is the canonical id: a User's or Role's canonical name (bare in the IAM home namespace,
	// "<ns>/<name>" elsewhere), a service's name for Service ("sns.amazonaws.com"); unused for Root.
	ID string
	// Groups are the user's group names (no "openinfra:" prefix). Ignored for roles, root and services.
	Groups []string
	// Session is the assumed-role session's own policy (AWS session policy), if any.
	Session *Session
}

// Session is what an assumed-role session adds to its role's authority.
type Session struct {
	// Name is the session name (assumed-role/<role>/<name>).
	Name string
	// Policies are the session policy's statements: they intersect the role's permissions (they can
	// only narrow). Empty means no session policy.
	Policies []policyengine.Statement
}

// AccountID is the principal's account, the management account when unset.
func (p Principal) AccountID() string {
	if p.Account == "" {
		return ManagementAccount
	}
	return p.Account
}

// Key is the principal's World key ("User::<id>", "Role::<id>").
func (p Principal) Key() string { return PolicyKey(string(p.Type), p.ID) }

// ARN is the principal's AWS ARN: arn:aws:iam::<acct>:user/<name>, …:role/<name>, …:root, or the
// assumed-role session arn:aws:sts::<acct>:assumed-role/<role>/<session>.
func (p Principal) ARN() string {
	acct := p.AccountID()
	name := p.ID
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	switch p.Type {
	case Root:
		return "arn:aws:iam::" + acct + ":root"
	case Role:
		if p.Session != nil && p.Session.Name != "" {
			return "arn:aws:sts::" + acct + ":assumed-role/" + name + "/" + p.Session.Name
		}
		return "arn:aws:iam::" + acct + ":role/" + name
	case Service:
		return p.ID
	default:
		return "arn:aws:iam::" + acct + ":user/" + name
	}
}

// adminGroup is the platform administrators' group (a Secret-backed admin account, a kind: User with
// spec.groups [admins]).
const adminGroup = "admins"

// IsAdminGroupMember reports whether the principal is root or in the administrators' group.
func (p Principal) IsAdminGroupMember() bool {
	return p.Type == Root || (p.Type == User && slices.Contains(p.Groups, adminGroup))
}

// PrincipalFromClaims maps a front door's Claims to the principal they are evaluated as, in account
// (""= the claims' own account, else the management account):
//   - an assumed-role session is a Role (its role name);
//   - the Secret-backed root account (role "root", no groups) is the account's Root;
//   - everyone else is a User, with its groups (the "openinfra:" prefix and the implicit users group
//     dropped: membership in "users" confers nothing).
func PrincipalFromClaims(c iam.Claims, account string) Principal {
	if account == "" {
		account = c.Account
	}
	if c.AssumedRole != "" {
		return Principal{Account: account, Type: Role, ID: c.AssumedRole, Session: sessionOf(c)}
	}
	if strings.EqualFold(c.Role, "root") && len(c.Groups) == 0 {
		return Principal{Account: account, Type: Root, ID: c.Sub}
	}
	groups := c.Groups
	if len(groups) == 0 {
		groups = iam.RoleMemberGroups(c.Role)
	}
	return Principal{Account: account, Type: User, ID: c.Sub, Groups: plainGroups(groups)}
}

func sessionOf(c iam.Claims) *Session {
	name := c.Sub
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if name == "" || name == c.AssumedRole {
		return nil
	}
	return &Session{Name: name}
}

// plainGroups strips the impersonation prefix and drops the implicit users group.
func plainGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimPrefix(g, "openinfra:")
		if g == "" || g == iam.UsersGroup || slices.Contains(out, g) {
			continue
		}
		out = append(out, g)
	}
	return out
}
