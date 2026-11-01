package dataplaneauthz

import "strings"

// IAM objects (kind: Role, User, Group, Policy) are namespaced, but the data-plane principal ids and
// Policy names are plain strings. Each object gets one canonical id:
//
//   - in the IAM home namespace (where Users, Groups, the managed Policy library and the Roles STS can
//     assume live): its bare name, exactly as before;
//   - anywhere else (a VM instance role in its VM's namespace, a stack's Role in the CloudFormation
//     namespace, a mirrored estate): "<namespace>/<name>".
//
// "/" cannot occur in a Kubernetes name, so the two forms never collide, and a same-named object in
// another namespace is a different principal or Policy: it neither inherits nor contributes the home
// object's policies.

// DefaultHomeNamespace is the IAM home namespace when none is configured (the shim's USERS_NAMESPACE /
// ROLES_NAMESPACE default).
const DefaultHomeNamespace = "open-infra-console"

// QualifiedName is the canonical id of the object ns/name: the bare name in home (or when ns is empty,
// for callers that carry no namespace), else "<ns>/<name>".
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

// starInNamespace is the canonical form of a "*" appliesTo entry in a Policy outside home: it applies
// to every principal of that Policy's own namespace, never to anyone else.
const starInNamespacePrefix = "*@"

// canonAppliesTo rewrites one Policy's appliesTo entries into canonical principal keys.
//
// A home-namespace Policy is the admins' central control: "Type::<name>" means the home principal,
// "Type::<ns>/<name>" names one in another namespace, "*" and "Group::<g>" keep their global meaning.
//
// A Policy in any other namespace governs only principals of its own namespace: "Type::<name>" and
// "Type::<its ns>/<name>" mean that namespace's principal, "*" means everyone in that namespace, and an
// entry naming another namespace or a Group (groups are home identities) is dropped.
func canonAppliesTo(home, policyNS string, entries []string) []string {
	out := make([]string, 0, len(entries))
	local := policyNS == "" || policyNS == home
	for _, e := range entries {
		if e == "*" {
			if local {
				out = append(out, "*")
			} else {
				out = append(out, starInNamespacePrefix+policyNS)
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

// resolvePolicyRef resolves a Policy reference on a principal (spec.policies or
// spec.permissionBoundary) to a canonical Policy name. A bare reference means the principal's own
// namespace's Policy if there is one, else the home namespace's (the managed library); "<ns>/<name>"
// names one explicitly, which only a home principal may do for a namespace other than its own and
// home. exists reports whether a canonical Policy name is defined. "" means the reference is not
// allowed (it then resolves to nothing).
func resolvePolicyRef(home, principalNS, ref string, exists func(string) bool) string {
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
