package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// Reading identities from `kind: User` (iam.openinfra.dev).
//
// Accounts used to live only as a JSON blob in the console-auth Secret, which meant adding a
// user or changing a role was a kubectl edit of base64. A User CR is the GitOps-managed form.
//
// Precedence is deliberate: the Secret is consulted FIRST. That keeps the bootstrap `root`
// account working as break-glass even if the CRDs are missing, a Composition is broken, or
// someone deletes their own User — the same reason AWS keeps the root user outside IAM.
//
// A User grants nothing by itself. Its spec.groups become Impersonate-Group values, and the
// ClusterRoleBindings that kind: Group creates are what actually confer permission.

type crdUserSpec struct {
	DisplayName       string   `json:"displayName"`
	Groups            []string `json:"groups"`
	Source            string   `json:"source"`
	Disabled          bool     `json:"disabled"`
	PasswordSecretRef struct {
		Name string `json:"name"`
		Key  string `json:"key"`
	} `json:"passwordSecretRef"`
}

type crdUser struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec crdUserSpec `json:"spec"`
}

// rawREST returns the REST client used for the AbsPath calls below, or nil if there
// isn't a usable one. A clientset can hand back a TYPED nil *rest.RESTClient (the fake
// clientset always does), which is non-nil as an interface and panics on first use — so
// an ordinary `!= nil` check is not enough. Sign-in must degrade to "no CR users", never
// crash the login handler.
func (a *authStore) rawREST() rest.Interface {
	rc := a.cs.CoreV1().RESTClient()
	if rc == nil {
		return nil
	}
	if v := reflect.ValueOf(rc); v.Kind() == reflect.Ptr && v.IsNil() {
		return nil
	}
	return rc
}

func usersAbsPath(ns string) string {
	return "/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/users"
}

// crdUserByName fetches one User. Returns ok=false when the CRD isn't installed, the user
// doesn't exist, or the account is disabled — all of which must fall through to "no such
// user" rather than erroring the sign-in.
func (a *authStore) crdUserByName(ctx context.Context, name string) (crdUser, bool) {
	var u crdUser
	rc := a.rawREST()
	if rc == nil {
		return u, false
	}
	raw, err := rc.Get().AbsPath(usersAbsPath(a.ns) + "/" + name).DoRaw(ctx)
	if err != nil {
		return u, false
	}
	if err := json.Unmarshal(raw, &u); err != nil {
		return u, false
	}
	if u.Spec.Disabled {
		return u, false
	}
	return u, true
}

// crdPasswordHash reads the bcrypt hash a local User points at. The hash lives in a Secret,
// never in the CR, so User objects stay safe to read, review in git and render in the UI.
func (a *authStore) crdPasswordHash(ctx context.Context, u crdUser) (string, bool) {
	ref := u.Spec.PasswordSecretRef
	if ref.Name == "" {
		return "", false
	}
	key := ref.Key
	if key == "" {
		key = "hash"
	}
	sec, err := a.cs.CoreV1().Secrets(a.ns).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", false
	}
	h := strings.TrimSpace(string(sec.Data[key]))
	if h == "" {
		return "", false
	}
	return h, true
}

// crdGroups returns the Kubernetes groups a CR user should be impersonated with.
// Empty spec.groups means "signed in but authorized for nothing" — deliberately NOT a
// fallback to a default role, so forgetting to set groups fails closed.
func crdGroups(u crdUser) []string {
	out := make([]string, 0, len(u.Spec.Groups)+1)
	for _, g := range u.Spec.Groups {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, "openinfra:"+g)
		}
	}
	return append(out, "openinfra:users")
}

// listCRDUsers returns every User, for the console's user list. Best-effort: an
// uninstalled CRD yields an empty list rather than an error.
func (a *authStore) listCRDUsers(ctx context.Context) []crdUser {
	rc := a.rawREST()
	if rc == nil {
		return nil
	}
	raw, err := rc.Get().AbsPath(usersAbsPath(a.ns)).DoRaw(ctx)
	if err != nil {
		return nil
	}
	var list struct {
		Items []crdUser `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil
	}
	return list.Items
}
