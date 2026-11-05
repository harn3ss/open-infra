package main

import (
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/proxy"
	"sigs.k8s.io/yaml"
)

// rootUserName is the account's root user: the break-glass account in the console-auth Secret.
//
// The name is reserved. A session's subject becomes its Kubernetes identity (openinfra:<sub>, and
// openinfra:<account>:<sub> in enforce), so anything else that signed in as "root" (a kind: User of
// that name, or a directory account) would act as the same identity root does. Only the
// Secret-backed root is root: a User named root cannot be created, and a sign-in other than the
// Secret's root never yields a session named root.
const rootUserName = "root"

// reservedRootName reports whether name is the reserved root name. Case and surrounding space are
// ignored, as a directory compares names (AD finds sAMAccountName "root" for "ROOT").
func reservedRootName(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), rootUserName)
}

// rootSessionValid reports whether claims may name the root user or carry its role: a session named
// root must be the Secret-backed root (role root, no groups, the exact name), and only that session
// carries role root. A role session root switched into keeps root's claims beside the role, as any
// switched session keeps its caller's.
func rootSessionValid(c iam.Claims) bool {
	isRootRole := strings.EqualFold(c.Role, "root")
	if reservedRootName(c.Sub) {
		return c.Sub == rootUserName && isRootRole && len(c.Groups) == 0
	}
	return !isRootRole
}

// writeReservedRoot refuses to create or change a User named root, in AWS's shape.
func writeReservedRoot(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error":     "The user name root is reserved for the account's root user, which signs in only from the console's break-glass account.",
		"errorCode": "InvalidInput",
	})
}

// proxiedRootUser reports whether a proxied Kubernetes request would create or change a kind: User
// named root, in any namespace. Reads and deletes pass, so a stray one can still be found and removed.
// A create whose name cannot be read is refused rather than let through unread.
func proxiedRootUser(r *http.Request, k proxy.Request) bool {
	if k.Group != "iam.openinfra.dev" || k.Resource != "users" || k.Subresource != "" {
		return false
	}
	switch k.Verb {
	case "update", "patch":
		return reservedRootName(k.Name)
	case "create":
		name, ok := peekObjectName(r)
		return !ok || reservedRootName(name)
	}
	return false
}

// peekObjectName reads metadata.name from a create's body (JSON or YAML), restoring the body.
func peekObjectName(r *http.Request) (string, bool) {
	b, ok := peekRaw(r)
	if !ok {
		return "", false
	}
	var obj struct {
		Metadata struct {
			Name         string `json:"name"`
			GenerateName string `json:"generateName"`
		} `json:"metadata"`
	}
	if yaml.Unmarshal(b, &obj) != nil {
		return "", false
	}
	if obj.Metadata.Name == "" {
		// generateName always adds a suffix, so it never yields exactly root.
		return obj.Metadata.GenerateName + "-", obj.Metadata.GenerateName != ""
	}
	return obj.Metadata.Name, true
}
