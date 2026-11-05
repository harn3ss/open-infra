// IAM login profiles and the account password policy through the IAM front door: CreateLoginProfile,
// GetLoginProfile, UpdateLoginProfile, DeleteLoginProfile, ChangePassword, and Get/Update/
// DeleteAccountPasswordPolicy — a local User's console password, managed as AWS manages it.
//
// Where the password lives (internal/loginprofile): a bcrypt hash in the credential store namespace (the
// keys namespace, beside the access keys), never in the console namespace — that is where root's
// console-auth Secret is, and the shim has no Secret access there at all. The User's passwordSecretRef
// names the store Secret (with its namespace); the console signs a user in from it. The shim writes a hash
// and never reads one back, except to check ChangePassword's old password, for that call only. Admission
// (platform/aws-shim/login-profile-guard.yaml) holds the store Secrets' name prefix and label together and
// keeps the shim out of the console namespace's Secrets.
//
// When a profile was created, when its password last changed and whether the user must change it at the
// next sign-in are annotations on the User (loginprofile.Ann*), read without touching a Secret.
//
// A profile the console set before the store existed (a Secret in the console namespace) is a profile like
// any other for Get, Update and Delete: Update moves it to the store; Delete unsets it (the shim cannot
// delete the console's Secret — the console removes it with the User). ChangePassword cannot check its old
// password (the shim cannot read it), so it answers EntityTemporarilyUnmodifiable until the password is
// next set — by the console, or UpdateLoginProfile.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/loginprofile"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// loginBcryptCost is the bcrypt cost the store hashes at (0 = bcrypt's default); tests lower it.
var loginBcryptCost = 0

// isLoginProfileOp reports the operations this file serves.
func isLoginProfileOp(op string) bool {
	switch op {
	case "CreateLoginProfile", "GetLoginProfile", "UpdateLoginProfile", "DeleteLoginProfile", "ChangePassword",
		"GetAccountPasswordPolicy", "UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy":
		return true
	}
	return false
}

func (h *iamHandler) loginStore() loginprofile.Store {
	ns := ""
	if h.keys != nil {
		ns = h.keys.Namespace()
	}
	return loginprofile.Store{CS: h.cs, NS: ns, Cost: loginBcryptCost}
}

// serveLoginProfile serves an authorized login-profile or password-policy operation.
func (h *iamHandler) serveLoginProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, op, requestID string, claims iam.Claims) {
	switch op {
	case "CreateLoginProfile":
		h.createLoginProfile(ctx, w, r, requestID, claims)
	case "GetLoginProfile":
		h.getLoginProfile(ctx, w, r, requestID, claims)
	case "UpdateLoginProfile":
		h.updateLoginProfile(ctx, w, r, requestID, claims)
	case "DeleteLoginProfile":
		h.deleteLoginProfile(ctx, w, r, requestID, claims)
	case "GetAccountPasswordPolicy":
		h.getAccountPasswordPolicy(ctx, w, requestID, claims)
	case "UpdateAccountPasswordPolicy":
		h.updateAccountPasswordPolicy(ctx, w, r, requestID, claims)
	case "DeleteAccountPasswordPolicy":
		h.deleteAccountPasswordPolicy(ctx, w, requestID, claims)
	}
}

// loginTarget is the user a login-profile operation names: UserName, or the calling user when it is
// omitted (as AWS defaults it).
func loginTarget(r *http.Request, claims iam.Claims) string {
	if n := r.PostFormValue("UserName"); n != "" {
		return n
	}
	if claims.AssumedRole == "" {
		return claims.PrincipalID()
	}
	return ""
}

func (h *iamHandler) accountOf(claims iam.Claims) string {
	if claims.Account != "" {
		return claims.Account
	}
	return h.account
}

// profile is what a User's login profile looks like from the User alone.
type profile struct {
	exists  bool
	legacy  bool // a Secret in the console namespace (set by the console before the store)
	created time.Time
	reset   bool
}

func (h *iamHandler) profileOf(ctx context.Context, u *unstructured.Unstructured) (profile, error) {
	ref, _, _ := unstructured.NestedMap(u.Object, "spec", "passwordSecretRef")
	name, _ := ref["name"].(string)
	if name == "" {
		return profile{}, nil
	}
	ann := u.GetAnnotations()
	p := profile{exists: true, reset: ann[loginprofile.AnnResetRequired] == "true", created: u.GetCreationTimestamp().UTC()}
	if t, err := time.Parse(time.RFC3339, ann[loginprofile.AnnCreated]); err == nil {
		p.created = t
	}
	if ns, _ := ref["namespace"].(string); ns != "" && ns == h.loginStore().NS {
		ok, err := h.loginStore().Exists(ctx, u.GetNamespace(), u.GetName())
		if err != nil {
			return profile{}, err
		}
		p.exists = ok
		return p, nil
	}
	p.legacy = true
	return p, nil
}

// userFor reads the User a login-profile operation acts on, answering NoSuchEntity when there is none.
func (h *iamHandler) userFor(ctx context.Context, w http.ResponseWriter, requestID, name string) (*unstructured.Unstructured, bool) {
	if name == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "UserName is required.", iamXMLNamespace)
		return nil, false
	}
	if strings.EqualFold(name, "root") {
		// The root user is not an IAM user, and the name is reserved for it.
		h.noSuchEntity(w, requestID, "The user with name "+name+" cannot be found.")
		return nil, false
	}
	u, err := h.dyn.Resource(gvrUsers).Namespace(h.usersNS).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		h.noSuchEntity(w, requestID, "The user with name "+name+" cannot be found.")
		return nil, false
	}
	if src, _, _ := unstructured.NestedString(u.Object, "spec", "source"); src != "" && src != "local" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"User "+name+" signs in through its directory ("+src+"); its password is managed there.", iamXMLNamespace)
		return nil, false
	}
	return u, true
}

// checkPassword applies the account's password policy (its custom one, else AWS's default), answering
// PasswordPolicyViolation; it returns the policy for the caller's other checks.
func (h *iamHandler) checkPassword(ctx context.Context, w http.ResponseWriter, requestID, account, password string) (loginprofile.Policy, bool) {
	p, _, err := h.loginStore().CheckFor(ctx, account, password)
	var v *loginprofile.ViolationError
	switch {
	case errors.As(err, &v):
		writeQueryError(w, http.StatusBadRequest, "PasswordPolicyViolation", requestID, v.Msg, iamXMLNamespace)
		return p, false
	case err != nil:
		h.internal(w, requestID, err)
		return p, false
	}
	return p, true
}

// setPassword writes user's hash to the store and points the User at it, recording the change.
func (h *iamHandler) setPassword(ctx context.Context, u *unstructured.Unstructured, password string, keep int, created bool, reset *bool) error {
	store := h.loginStore()
	name, err := store.Write(ctx, u.GetNamespace(), u.GetName(), password, keep)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	ann := map[string]any{loginprofile.AnnPasswordLastChanged: now}
	if created {
		ann[loginprofile.AnnCreated] = now
	}
	if reset != nil {
		if *reset {
			ann[loginprofile.AnnResetRequired] = "true"
		} else {
			ann[loginprofile.AnnResetRequired] = nil
		}
	}
	return h.patchUser(ctx, u.GetName(), map[string]any{
		"metadata": map[string]any{"annotations": ann},
		"spec":     map[string]any{"passwordSecretRef": map[string]any{"name": name, "key": loginprofile.HashKey, "namespace": store.NS}},
	})
}

func (h *iamHandler) patchUser(ctx context.Context, name string, patch map[string]any) error {
	b, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, err = h.dyn.Resource(gvrUsers).Namespace(h.usersNS).Patch(ctx, name, types.MergePatchType, b, metav1.PatchOptions{})
	return err
}

func loginBoolForm(r *http.Request, key string) (*bool, bool) {
	v := r.PostFormValue(key)
	if v == "" {
		return nil, true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return nil, false
	}
	return &b, true
}

func (h *iamHandler) loginProfileXML(user string, p profile) string {
	return "<LoginProfile><UserName>" + xmlEscape(user) + "</UserName><CreateDate>" + p.created.UTC().Format(time.RFC3339) +
		"</CreateDate><PasswordResetRequired>" + strconv.FormatBool(p.reset) + "</PasswordResetRequired></LoginProfile>"
}

func (h *iamHandler) createLoginProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	name := loginTarget(r, claims)
	u, ok := h.userFor(ctx, w, requestID, name)
	if !ok {
		return
	}
	password := r.PostFormValue("Password")
	if password == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "Password is required.", iamXMLNamespace)
		return
	}
	reset, valid := loginBoolForm(r, "PasswordResetRequired")
	if !valid {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "PasswordResetRequired must be true or false.", iamXMLNamespace)
		return
	}
	cur, err := h.profileOf(ctx, u)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if cur.exists {
		h.conflict(w, requestID, "EntityAlreadyExists", "Login Profile for user "+name+" already exists.")
		return
	}
	pol, ok := h.checkPassword(ctx, w, requestID, h.accountOf(claims), password)
	if !ok {
		return
	}
	if reset == nil {
		reset = new(bool)
	}
	if err := h.setPassword(ctx, u, password, pol.PasswordReusePrevention, true, reset); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateLoginProfile", name, "allow", "")
	h.writeResult(w, requestID, "CreateLoginProfile", h.loginProfileXML(name, profile{exists: true, created: time.Now().UTC(), reset: *reset}))
}

func (h *iamHandler) getLoginProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	name := loginTarget(r, claims)
	u, ok := h.userFor(ctx, w, requestID, name)
	if !ok {
		return
	}
	p, err := h.profileOf(ctx, u)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !p.exists {
		h.noSuchEntity(w, requestID, "Login Profile for User "+name+" cannot be found.")
		return
	}
	h.writeResult(w, requestID, "GetLoginProfile", h.loginProfileXML(name, p))
}

func (h *iamHandler) updateLoginProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	name := loginTarget(r, claims)
	u, ok := h.userFor(ctx, w, requestID, name)
	if !ok {
		return
	}
	reset, valid := loginBoolForm(r, "PasswordResetRequired")
	if !valid {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "PasswordResetRequired must be true or false.", iamXMLNamespace)
		return
	}
	p, err := h.profileOf(ctx, u)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !p.exists {
		h.noSuchEntity(w, requestID, "Login Profile for User "+name+" cannot be found.")
		return
	}
	if password := r.PostFormValue("Password"); password != "" {
		pol, ok := h.checkPassword(ctx, w, requestID, h.accountOf(claims), password)
		if !ok {
			return
		}
		if err := h.setPassword(ctx, u, password, pol.PasswordReusePrevention, p.legacy, reset); err != nil {
			h.internal(w, requestID, err)
			return
		}
	} else if reset != nil {
		ann := map[string]any{loginprofile.AnnResetRequired: nil}
		if *reset {
			ann[loginprofile.AnnResetRequired] = "true"
		}
		if err := h.patchUser(ctx, name, map[string]any{"metadata": map[string]any{"annotations": ann}}); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	h.audit(ctx, "UpdateLoginProfile", name, "allow", "")
	h.writeResult(w, requestID, "UpdateLoginProfile", "")
}

func (h *iamHandler) deleteLoginProfile(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	name := loginTarget(r, claims)
	u, ok := h.userFor(ctx, w, requestID, name)
	if !ok {
		return
	}
	p, err := h.profileOf(ctx, u)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !p.exists {
		h.noSuchEntity(w, requestID, "Login Profile for User "+name+" cannot be found.")
		return
	}
	// The User first (it no longer signs in), then its hash.
	if err := h.patchUser(ctx, name, map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			loginprofile.AnnCreated: nil, loginprofile.AnnPasswordLastChanged: nil, loginprofile.AnnResetRequired: nil}},
		"spec": map[string]any{"passwordSecretRef": nil},
	}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !p.legacy {
		if err := h.loginStore().Delete(ctx, u.GetNamespace(), name); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	h.audit(ctx, "DeleteLoginProfile", name, "allow", "")
	h.writeResult(w, requestID, "DeleteLoginProfile", "")
}

// changePassword serves ChangePassword: the calling IAM user changes its own password, proving the old one.
// It is authorized here, not by the coarse RBAC gate: AWS lets a user change its own password when the
// account's password policy allows users to (AllowUsersToChangePassword), or when a policy allows it
// iam:ChangePassword on itself (AWS's IAMUserChangePassword); an explicit Deny always wins.
func (h *iamHandler) changePassword(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if claims.AssumedRole != "" || claims.Role == "root" || claims.PrincipalType() != "User" {
		writeQueryError(w, http.StatusBadRequest, "InvalidUserType", requestID,
			"ChangePassword can be called only by an IAM user, to change its own password.", iamXMLNamespace)
		return
	}
	name := claims.PrincipalID()
	account := h.accountOf(claims)
	pol, custom, err := h.loginStore().GetPolicy(ctx, account)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	// The grant: IAM policy allowing iam:ChangePassword on the user itself, through the one evaluator in its
	// mode (legacy: a user who may update its own User). An explicit Deny refuses even when the account
	// password policy lets every user change their own password; without one, that policy is a grant.
	explicitLegacy := false
	d := decision(ctx, r, h.authz, claims, "iam:ChangePassword", "User", name, func() (bool, string) {
		if denied, explicit, reason := dataPlaneVerdict(ctx, h.authz, claims, "iam:ChangePassword", "User", name, r); denied && explicit {
			explicitLegacy = true
			return false, reason
		}
		return iam.CanDo(ctx, h.cs, claims, "update", "iam.openinfra.dev", "users", h.usersNS, name)
	})
	if d.ExplicitDeny || explicitLegacy || (!d.Allowed && !(custom && pol.AllowUsersToChangePassword)) {
		h.audit(ctx, "ChangePassword", name, "deny", d.Reason)
		msg := d.Reason
		if !d.ExplicitDeny && !explicitLegacy {
			msg = "User: " + h.scope(ctx).arn("user/"+name) + " is not authorized to perform: iam:ChangePassword on resource: user " + name
		}
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, msg, iamXMLNamespace)
		return
	}
	oldPW, newPW := r.PostFormValue("OldPassword"), r.PostFormValue("NewPassword")
	if oldPW == "" || newPW == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, "OldPassword and NewPassword are required.", iamXMLNamespace)
		return
	}
	u, err := h.dyn.Resource(gvrUsers).Namespace(h.usersNS).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		h.noSuchEntity(w, requestID, "The user with name "+name+" cannot be found.")
		return
	}
	p, err := h.profileOf(ctx, u)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !p.exists {
		h.noSuchEntity(w, requestID, "Login Profile for User "+name+" cannot be found.")
		return
	}
	if p.legacy {
		h.conflict(w, requestID, "EntityTemporarilyUnmodifiable",
			"User "+name+"'s password was set in the console before the IAM credential store: change it once in the console, or have an administrator set it with UpdateLoginProfile.")
		return
	}
	store := h.loginStore()
	if ok, err := store.Verify(ctx, u.GetNamespace(), name, oldPW); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		h.audit(ctx, "ChangePassword", name, "deny", "wrong old password")
		writeQueryError(w, http.StatusBadRequest, "InvalidUserType", requestID, "The specified value for oldPassword is invalid.", iamXMLNamespace)
		return
	}
	if _, ok := h.checkPassword(ctx, w, requestID, account, newPW); !ok {
		return
	}
	if reused, err := store.Reused(ctx, u.GetNamespace(), name, newPW, pol.PasswordReusePrevention); err != nil {
		h.internal(w, requestID, err)
		return
	} else if reused {
		writeQueryError(w, http.StatusBadRequest, "PasswordPolicyViolation", requestID,
			"Password cannot be one of your last "+strconv.Itoa(pol.PasswordReusePrevention)+" passwords.", iamXMLNamespace)
		return
	}
	clear := false
	if err := h.setPassword(ctx, u, newPW, pol.PasswordReusePrevention, false, &clear); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "ChangePassword", name, "allow", "")
	h.writeResult(w, requestID, "ChangePassword", "")
}

// --- the account password policy ---

func (h *iamHandler) getAccountPasswordPolicy(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims) {
	account := h.accountOf(claims)
	p, found, err := h.loginStore().GetPolicy(ctx, account)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !found {
		h.noSuchEntity(w, requestID, "The Password Policy with domain name "+account+" cannot be found.")
		return
	}
	var b strings.Builder
	b.WriteString("<PasswordPolicy>")
	b.WriteString("<MinimumPasswordLength>" + strconv.Itoa(p.MinimumPasswordLength) + "</MinimumPasswordLength>")
	b.WriteString("<RequireSymbols>" + strconv.FormatBool(p.RequireSymbols) + "</RequireSymbols>")
	b.WriteString("<RequireNumbers>" + strconv.FormatBool(p.RequireNumbers) + "</RequireNumbers>")
	b.WriteString("<RequireUppercaseCharacters>" + strconv.FormatBool(p.RequireUppercaseCharacters) + "</RequireUppercaseCharacters>")
	b.WriteString("<RequireLowercaseCharacters>" + strconv.FormatBool(p.RequireLowercaseCharacters) + "</RequireLowercaseCharacters>")
	b.WriteString("<AllowUsersToChangePassword>" + strconv.FormatBool(p.AllowUsersToChangePassword) + "</AllowUsersToChangePassword>")
	b.WriteString("<ExpirePasswords>" + strconv.FormatBool(p.ExpirePasswords()) + "</ExpirePasswords>")
	if p.MaxPasswordAge > 0 {
		b.WriteString("<MaxPasswordAge>" + strconv.Itoa(p.MaxPasswordAge) + "</MaxPasswordAge>")
	}
	if p.PasswordReusePrevention > 0 {
		b.WriteString("<PasswordReusePrevention>" + strconv.Itoa(p.PasswordReusePrevention) + "</PasswordReusePrevention>")
	}
	if p.HardExpiry {
		b.WriteString("<HardExpiry>true</HardExpiry>")
	}
	b.WriteString("</PasswordPolicy>")
	h.writeResult(w, requestID, "GetAccountPasswordPolicy", b.String())
}

func (h *iamHandler) updateAccountPasswordPolicy(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims) {
	var p loginprofile.Policy
	bad := func(field string) {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, field+" is not valid.", iamXMLNamespace)
	}
	ints := map[string]*int{"MinimumPasswordLength": &p.MinimumPasswordLength, "MaxPasswordAge": &p.MaxPasswordAge,
		"PasswordReusePrevention": &p.PasswordReusePrevention}
	for k, dst := range ints {
		if v := r.PostFormValue(k); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				bad(k)
				return
			}
			*dst = n
		}
	}
	bools := map[string]*bool{"RequireSymbols": &p.RequireSymbols, "RequireNumbers": &p.RequireNumbers,
		"RequireUppercaseCharacters": &p.RequireUppercaseCharacters, "RequireLowercaseCharacters": &p.RequireLowercaseCharacters,
		"AllowUsersToChangePassword": &p.AllowUsersToChangePassword, "HardExpiry": &p.HardExpiry}
	for k, dst := range bools {
		v, ok := loginBoolForm(r, k)
		if !ok {
			bad(k)
			return
		}
		if v != nil {
			*dst = *v
		}
	}
	if err := p.Validate(); err != nil {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, err.Error(), iamXMLNamespace)
		return
	}
	if err := h.loginStore().PutPolicy(ctx, h.accountOf(claims), p); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "UpdateAccountPasswordPolicy", h.accountOf(claims), "allow", "")
	h.writeResult(w, requestID, "UpdateAccountPasswordPolicy", "")
}

func (h *iamHandler) deleteAccountPasswordPolicy(ctx context.Context, w http.ResponseWriter, requestID string, claims iam.Claims) {
	account := h.accountOf(claims)
	removed, err := h.loginStore().DeletePolicy(ctx, account)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !removed {
		h.noSuchEntity(w, requestID, "The account policy with name PasswordPolicy cannot be found.")
		return
	}
	h.audit(ctx, "DeleteAccountPasswordPolicy", account, "allow", "")
	h.writeResult(w, requestID, "DeleteAccountPasswordPolicy", "")
}
