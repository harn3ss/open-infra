package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Managing IAM identities (kind: User / kind: Group) from the console.
//
// Until now the only way to add a person or change their access was `kubectl apply` of a User
// plus a hand-made bcrypt-hash Secret. These endpoints put that behind the console — but they
// are NOT a privilege back door. Every one authorizes the SIGNED-IN user with a
// SubjectAccessReview against iam.openinfra.dev (see authorize()), so it is exactly as
// restricted as `kubectl` would be: only members of a group bound to a ClusterRole that grants
// users/groups (i.e. admins) get through. The console's ServiceAccount does the work, but the
// human's own RBAC decides whether it happens.
//
// A User never carries its password. spec.passwordSecretRef points at a Secret holding a
// bcrypt HASH, created and updated here; the plaintext exists only for the moment it takes to
// hash it. Deleting a User deletes that Secret too.

const (
	// iamNS is where console identities and their password Secrets live — the console's
	// own namespace, the same one newAuthStore() and auth_crd.go read from.
	iamPasswordKey = "hash"
)

// builtinGroups are the group names that actually take effect out of the box, because
// openinfra:<name> is in the impersonator ClusterRole's resourceNames (see
// platform/console/manifests/rbac-roles.yaml). A Group with any other name is created fine
// but has no effect until an operator widens that ceiling — the UI warns using this list.
// "users" is every signed-in identity automatically and is not separately selectable.
var builtinGroups = []string{"admins", "powerusers", "readers"}

// dns1123 validates a Kubernetes object name (used for User and Group names, and derived
// Secret names). Rejecting bad input here gives a clean 400 instead of an opaque
// apiserver error deep in a REST call.
var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func validName(s string) bool { return len(s) > 0 && len(s) <= 63 && dns1123.MatchString(s) }

func iamPasswordSecretName(user string) string { return "iam-pw-" + user }

// ── Group CR (read side mirrors auth_crd.go's user helpers) ──────────────────────

type crdGroupSpec struct {
	Description string `json:"description"`
	ClusterRole string `json:"clusterRole"`
}

type crdGroup struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec   crdGroupSpec `json:"spec"`
	Status struct {
		Ready   bool   `json:"ready"`
		BoundTo string `json:"boundTo"`
	} `json:"status"`
}

func groupsAbsPath(ns string) string {
	return "/apis/iam.openinfra.dev/v1/namespaces/" + ns + "/groups"
}

func (a *authStore) listCRDGroups(ctx context.Context) []crdGroup {
	rc := a.rawREST()
	if rc == nil {
		return nil
	}
	raw, err := rc.Get().AbsPath(groupsAbsPath(a.ns)).DoRaw(ctx)
	if err != nil {
		return nil
	}
	var list struct {
		Items []crdGroup `json:"items"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil
	}
	return list.Items
}

func (a *authStore) crdGroupByName(ctx context.Context, name string) (crdGroup, bool) {
	var g crdGroup
	rc := a.rawREST()
	if rc == nil {
		return g, false
	}
	raw, err := rc.Get().AbsPath(groupsAbsPath(a.ns) + "/" + name).DoRaw(ctx)
	if err != nil {
		return g, false
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		return g, false
	}
	return g, true
}

// ── Views returned to the SPA ────────────────────────────────────────────────────

type iamUserView struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Source      string   `json:"source"`
	Disabled    bool     `json:"disabled"`
	Groups      []string `json:"groups"`
	// HasPassword is false for a User whose passwordSecretRef points nowhere usable —
	// a directory user, or one created before its Secret existed. The UI shows it so an
	// admin isn't surprised that someone can't sign in.
	HasPassword bool `json:"hasPassword"`
	// UnboundGroups lists this user's groups that will NOT take effect because they are
	// outside the impersonation ceiling. Surfaced so the UI can flag a silent no-op.
	UnboundGroups []string `json:"unboundGroups"`
}

type iamGroupView struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ClusterRole string `json:"clusterRole"`
	BoundTo     string `json:"boundTo"`
	Ready       bool   `json:"ready"`
	// Impersonable is false when openinfra:<name> is outside the impersonator ceiling, so
	// the group is inert until an operator widens it. The UI warns on these.
	Impersonable bool `json:"impersonable"`
}

func isBuiltinGroup(name string) bool {
	for _, b := range builtinGroups {
		if b == name {
			return true
		}
	}
	return name == "users"
}

func unboundGroups(groups []string) []string {
	var out []string
	for _, g := range groups {
		if g = strings.TrimSpace(g); g != "" && !isBuiltinGroup(g) {
			out = append(out, g)
		}
	}
	return out
}

// ── Config: what the UI needs to render sensibly ─────────────────────────────────

// handleIAMConfig tells the SPA which namespace identities live in and which group names
// are guaranteed to take effect, so it can offer them as first-class choices and warn on
// anything else. No authorization: it is static, non-sensitive metadata.
func handleIAMConfig(auth *authStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"namespace":     auth.ns,
			"builtinGroups": builtinGroups,
		})
	}
}

// ── Users ────────────────────────────────────────────────────────────────────────

func handleIAMUsersList(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "users", auth.ns, "") {
			return
		}
		users := auth.listCRDUsers(r.Context())
		out := make([]iamUserView, 0, len(users))
		for _, u := range users {
			_, hasPw := auth.crdPasswordHash(r.Context(), u)
			out = append(out, iamUserView{
				Name:          u.Metadata.Name,
				DisplayName:   u.Spec.DisplayName,
				Source:        u.Spec.Source,
				Disabled:      u.Spec.Disabled,
				Groups:        u.Spec.Groups,
				HasPassword:   hasPw,
				UnboundGroups: unboundGroups(u.Spec.Groups),
			})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func handleIAMUserGet(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if !authorize(w, r, cs, auth, logger, "get", "iam.openinfra.dev", "users", auth.ns, name) {
			return
		}
		// crdUserByName hides disabled users (it's the sign-in path); read raw here so the
		// management UI can see and re-enable them.
		u, ok := auth.rawUser(r.Context(), name)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
			return
		}
		_, hasPw := auth.crdPasswordHash(r.Context(), u)
		writeJSON(w, http.StatusOK, iamUserView{
			Name:          u.Metadata.Name,
			DisplayName:   u.Spec.DisplayName,
			Source:        u.Spec.Source,
			Disabled:      u.Spec.Disabled,
			Groups:        u.Spec.Groups,
			HasPassword:   hasPw,
			UnboundGroups: unboundGroups(u.Spec.Groups),
		})
	}
}

type createUserReq struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Groups      []string `json:"groups"`
	Password    string   `json:"password"`
}

func handleIAMUserCreate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in createUserReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		if !validName(in.Name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be a lowercase DNS label (a-z, 0-9, -)"})
			return
		}
		if len(in.Password) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
			return
		}
		// Creating a User needs create on users AND on secrets (the hash lives in one).
		// Check both, so a caller who could make the User but not its Secret is refused up
		// front rather than leaving a passwordless User behind.
		if !authorize(w, r, cs, auth, logger, "create", "iam.openinfra.dev", "users", auth.ns, in.Name) {
			return
		}
		if !authorize(w, r, cs, auth, logger, "create", "", "secrets", auth.ns, "") {
			return
		}

		secretName := iamPasswordSecretName(in.Name)
		if err := auth.writePasswordSecret(r.Context(), secretName, in.Name, in.Password); err != nil {
			logger.Error("iam: create password secret", "user", in.Name, "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store password"})
			return
		}

		body := map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "User",
			"metadata":   map[string]any{"name": in.Name, "namespace": auth.ns},
			"spec": map[string]any{
				"displayName":       in.DisplayName,
				"source":            "local",
				"groups":            cleanGroups(in.Groups),
				"passwordSecretRef": map[string]any{"name": secretName, "key": iamPasswordKey},
			},
		}
		if err := auth.postCR(r.Context(), usersAbsPath(auth.ns), body); err != nil {
			// Roll back the orphaned Secret so a retry with the same name isn't blocked.
			_ = cs.CoreV1().Secrets(auth.ns).Delete(r.Context(), secretName, metav1.DeleteOptions{})
			logger.Error("iam: create user", "user", in.Name, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": iamErr(err)})
			return
		}
		logger.Info("iam: user created", "user", in.Name, "by", subjectOf(r))
		writeJSON(w, http.StatusCreated, map[string]string{"name": in.Name})
	}
}

type updateUserReq struct {
	DisplayName *string   `json:"displayName"`
	Groups      *[]string `json:"groups"`
	Disabled    *bool     `json:"disabled"`
}

func handleIAMUserUpdate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var in updateUserReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if !authorize(w, r, cs, auth, logger, "update", "iam.openinfra.dev", "users", auth.ns, name) {
			return
		}
		spec := map[string]any{}
		if in.DisplayName != nil {
			spec["displayName"] = *in.DisplayName
		}
		if in.Groups != nil {
			spec["groups"] = cleanGroups(*in.Groups)
		}
		if in.Disabled != nil {
			spec["disabled"] = *in.Disabled
		}
		if len(spec) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing to update"})
			return
		}
		patch := map[string]any{"spec": spec}
		if err := auth.patchCR(r.Context(), usersAbsPath(auth.ns)+"/"+name, patch); err != nil {
			logger.Error("iam: update user", "user", name, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": iamErr(err)})
			return
		}
		logger.Info("iam: user updated", "user", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

type passwordReq struct {
	Password string `json:"password"`
}

func handleIAMUserPassword(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var in passwordReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if len(in.Password) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
			return
		}
		// A password reset mutates the user and writes a Secret — gate on both.
		if !authorize(w, r, cs, auth, logger, "update", "iam.openinfra.dev", "users", auth.ns, name) {
			return
		}
		if !authorize(w, r, cs, auth, logger, "update", "", "secrets", auth.ns, iamPasswordSecretName(name)) {
			return
		}
		u, ok := auth.rawUser(r.Context(), name)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
			return
		}
		// Write to the Secret the User already references; only fall back to the derived
		// name when it points nowhere, and repoint the User at it.
		secretName := u.Spec.PasswordSecretRef.Name
		repoint := false
		if secretName == "" {
			secretName = iamPasswordSecretName(name)
			repoint = true
		}
		if err := auth.writePasswordSecret(r.Context(), secretName, name, in.Password); err != nil {
			logger.Error("iam: reset password", "user", name, "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store password"})
			return
		}
		if repoint {
			patch := map[string]any{"spec": map[string]any{
				"passwordSecretRef": map[string]any{"name": secretName, "key": iamPasswordKey},
			}}
			if err := auth.patchCR(r.Context(), usersAbsPath(auth.ns)+"/"+name, patch); err != nil {
				logger.Error("iam: repoint passwordSecretRef", "user", name, "error", err.Error())
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": iamErr(err)})
				return
			}
		}
		logger.Info("iam: password reset", "user", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

func handleIAMUserDelete(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "root" {
			// root is the break-glass account in the console-auth Secret, not a User; there
			// is nothing to delete here and the name is reserved. Refuse, so nobody thinks
			// they've removed it.
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "root is the break-glass account and is not managed here"})
			return
		}
		if !authorize(w, r, cs, auth, logger, "delete", "iam.openinfra.dev", "users", auth.ns, name) {
			return
		}
		u, ok := auth.rawUser(r.Context(), name)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such user"})
			return
		}
		if err := auth.deleteCR(r.Context(), usersAbsPath(auth.ns)+"/"+name); err != nil {
			logger.Error("iam: delete user", "user", name, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": iamErr(err)})
			return
		}
		// Best-effort Secret cleanup — deleting the User already removed the account, so a
		// left-behind Secret is untidy, not dangerous.
		if ref := u.Spec.PasswordSecretRef.Name; ref != "" {
			_ = cs.CoreV1().Secrets(auth.ns).Delete(r.Context(), ref, metav1.DeleteOptions{})
		}
		logger.Info("iam: user deleted", "user", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

// ── Groups ───────────────────────────────────────────────────────────────────────

func handleIAMGroupsList(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, cs, auth, logger, "list", "iam.openinfra.dev", "groups", auth.ns, "") {
			return
		}
		groups := auth.listCRDGroups(r.Context())
		out := make([]iamGroupView, 0, len(groups))
		for _, g := range groups {
			out = append(out, iamGroupView{
				Name:         g.Metadata.Name,
				Description:  g.Spec.Description,
				ClusterRole:  g.Spec.ClusterRole,
				BoundTo:      g.Status.BoundTo,
				Ready:        g.Status.Ready,
				Impersonable: isBuiltinGroup(g.Metadata.Name),
			})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

type groupReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ClusterRole string `json:"clusterRole"`
}

func handleIAMGroupCreate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in groupReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		if !validName(in.Name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name must be a lowercase DNS label (a-z, 0-9, -)"})
			return
		}
		if strings.TrimSpace(in.ClusterRole) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "clusterRole is required — it is the only field that grants anything"})
			return
		}
		if !authorize(w, r, cs, auth, logger, "create", "iam.openinfra.dev", "groups", auth.ns, in.Name) {
			return
		}
		body := map[string]any{
			"apiVersion": "iam.openinfra.dev/v1",
			"kind":       "Group",
			"metadata":   map[string]any{"name": in.Name, "namespace": auth.ns},
			"spec":       map[string]any{"description": in.Description, "clusterRole": in.ClusterRole},
		}
		if err := auth.postCR(r.Context(), groupsAbsPath(auth.ns), body); err != nil {
			logger.Error("iam: create group", "group", in.Name, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": iamErr(err)})
			return
		}
		logger.Info("iam: group created", "group", in.Name, "by", subjectOf(r))
		writeJSON(w, http.StatusCreated, map[string]string{"name": in.Name})
	}
}

func handleIAMGroupUpdate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var in groupReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		if !authorize(w, r, cs, auth, logger, "update", "iam.openinfra.dev", "groups", auth.ns, name) {
			return
		}
		spec := map[string]any{"description": in.Description}
		if cr := strings.TrimSpace(in.ClusterRole); cr != "" {
			spec["clusterRole"] = cr
		}
		if err := auth.patchCR(r.Context(), groupsAbsPath(auth.ns)+"/"+name, map[string]any{"spec": spec}); err != nil {
			logger.Error("iam: update group", "group", name, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": iamErr(err)})
			return
		}
		logger.Info("iam: group updated", "group", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

func handleIAMGroupDelete(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if !authorize(w, r, cs, auth, logger, "delete", "iam.openinfra.dev", "groups", auth.ns, name) {
			return
		}
		// A group with members still attached would leave those users pointing at a group
		// that grants nothing. Warn rather than silently orphan them.
		if in := usersInGroup(auth.listCRDUsers(r.Context()), name); len(in) > 0 && r.URL.Query().Get("force") != "true" {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   fmt.Sprintf("%d user(s) are still in this group", len(in)),
				"members": in,
			})
			return
		}
		if err := auth.deleteCR(r.Context(), groupsAbsPath(auth.ns)+"/"+name); err != nil {
			logger.Error("iam: delete group", "group", name, "error", err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": iamErr(err)})
			return
		}
		logger.Info("iam: group deleted", "group", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

// ── Shared helpers ────────────────────────────────────────────────────────────────

// rawUser reads a User INCLUDING disabled ones — the opposite of crdUserByName, which hides
// them because it serves the sign-in path.
func (a *authStore) rawUser(ctx context.Context, name string) (crdUser, bool) {
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
	return u, u.Metadata.Name != ""
}

// writePasswordSecret creates or updates the bcrypt-hash Secret a local User points at.
func (a *authStore) writePasswordSecret(ctx context.Context, secretName, user, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: a.ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "open-infra-console",
				"openinfra.dev/iam-user":       user,
			},
		},
		Data: map[string][]byte{iamPasswordKey: hash},
	}
	_, err = a.cs.CoreV1().Secrets(a.ns).Create(ctx, sec, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "already exists") {
		return err
	}
	// Update the hash in place, preserving everything else on the Secret. Get+Update
	// rather than a hand-built patch, so the base64 encoding of the []byte value is the
	// client's problem, not ours.
	cur, err := a.cs.CoreV1().Secrets(a.ns).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if cur.Data == nil {
		cur.Data = map[string][]byte{}
	}
	cur.Data[iamPasswordKey] = hash
	_, err = a.cs.CoreV1().Secrets(a.ns).Update(ctx, cur, metav1.UpdateOptions{})
	return err
}

func (a *authStore) postCR(ctx context.Context, path string, body map[string]any) error {
	rc := a.rawREST()
	if rc == nil {
		return fmt.Errorf("no REST client")
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	_, err = rc.Post().AbsPath(path).Body(b).DoRaw(ctx)
	return err
}

func (a *authStore) patchCR(ctx context.Context, path string, patch map[string]any) error {
	rc := a.rawREST()
	if rc == nil {
		return fmt.Errorf("no REST client")
	}
	b, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = rc.Patch(types.MergePatchType).AbsPath(path).Body(b).DoRaw(ctx)
	return err
}

func (a *authStore) deleteCR(ctx context.Context, path string) error {
	rc := a.rawREST()
	if rc == nil {
		return fmt.Errorf("no REST client")
	}
	_, err := rc.Delete().AbsPath(path).DoRaw(ctx)
	return err
}

// cleanGroups trims blanks and dedupes, so a User's spec.groups is tidy regardless of what
// the form submitted.
func cleanGroups(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	return out
}

func usersInGroup(users []crdUser, group string) []string {
	var out []string
	for _, u := range users {
		for _, g := range u.Spec.Groups {
			if strings.TrimSpace(g) == group {
				out = append(out, u.Metadata.Name)
				break
			}
		}
	}
	return out
}

// subjectOf names the caller for the audit line, falling back to empty when auth is off.
func subjectOf(r *http.Request) string {
	if c, ok := claimsFrom(r); ok {
		return c.Sub
	}
	return ""
}

// iamErr turns an apiserver REST error into something a user can act on, without leaking the
// full status object.
func iamErr(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "already exists"):
		return "a resource with that name already exists"
	case strings.Contains(msg, "not found"):
		return "not found"
	case strings.Contains(msg, "forbidden"):
		return "the console is not permitted to do that"
	default:
		return "the API server rejected the request"
	}
}
