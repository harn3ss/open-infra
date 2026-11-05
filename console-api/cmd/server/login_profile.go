package main

// Console sign-in with an IAM login profile (internal/loginprofile).
//
// A local User's password hash is in one of two places: the credential store namespace (KEYS_NAMESPACE,
// beside the access keys), where the IAM API's CreateLoginProfile puts it and where the console now writes
// it too; or, for a password the console set before the store, an iam-pw-<user> Secret in the console's
// own namespace. Sign-in reads either, and a store Secret only when it is that user's own profile.
//
// The account password policy applies here as it does to the IAM API: a password the console sets must
// meet it, a password past its MaxPasswordAge must be changed at sign-in (and with HardExpiry cannot be,
// so the sign-in is refused), and a User marked PasswordResetRequired must change its password before
// anything else. Such a sign-in gets a session that can only change the password (requireAuth refuses
// everything else with PasswordResetRequired); POST /api/auth/change-password, with the old password,
// replaces the session with an ordinary one.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/loginprofile"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// loginBcryptCost is the store's bcrypt cost (0 = bcrypt's default); tests lower it.
var loginBcryptCost = 0

func (a *authStore) loginStore() loginprofile.Store {
	return loginprofile.Store{CS: a.cs, NS: getenv("KEYS_NAMESPACE", "open-infra-aws-shim"), Cost: loginBcryptCost}
}

// storePassword writes user's password and returns the passwordSecretRef that names it, and an undo that
// removes what it wrote. The credential store first; the console's own namespace when the store is not
// reachable (an install without the aws-shim's keys namespace).
func (a *authStore) storePassword(ctx context.Context, user, password string, keep int) (map[string]any, func(), error) {
	store := a.loginStore()
	if store.NS != "" && store.NS != a.ns {
		name, err := store.Write(ctx, a.ns, user, password, keep)
		if err == nil {
			return map[string]any{"name": name, "key": loginprofile.HashKey, "namespace": store.NS},
				func() { _ = store.Delete(context.Background(), a.ns, user) }, nil
		}
		a.logger.Warn("login profile: the credential store refused the password; writing it in the console namespace",
			"user", user, "store", store.NS, "error", err.Error())
	}
	name := iamPasswordSecretName(user)
	if err := a.writePasswordSecret(ctx, name, user, password); err != nil {
		return nil, nil, err
	}
	return map[string]any{"name": name, "key": iamPasswordKey},
		func() { _ = a.cs.CoreV1().Secrets(a.ns).Delete(context.Background(), name, metav1.DeleteOptions{}) }, nil
}

// checkConsolePassword applies the account password policy to a password the console sets, returning
// the policy (for PasswordReusePrevention) or a message for the caller.
func (a *authStore) checkConsolePassword(ctx context.Context, password string) (loginprofile.Policy, string) {
	p, _, err := a.loginStore().CheckFor(ctx, iam.ManagementAccount, password)
	var v *loginprofile.ViolationError
	if errors.As(err, &v) {
		return p, v.Msg
	}
	if err != nil {
		// No policy is readable (no store): the console's own floor.
		if len(password) < 8 {
			return p, "password must be at least 8 characters"
		}
	}
	return p, ""
}

// signInGate decides a CRD user's sign-in after its password verified: refuse (HardExpiry on an expired
// password), or must change the password first (PasswordResetRequired, or an expired password).
func (a *authStore) signInGate(ctx context.Context, u crdUser) (mustChange bool, refuse string) {
	ann := u.Metadata.Annotations
	if ann[loginprofile.AnnResetRequired] == "true" {
		mustChange = true
	}
	pol, custom, err := a.loginStore().GetPolicy(ctx, iam.ManagementAccount)
	if err != nil || !custom {
		return mustChange, ""
	}
	changed, _ := time.Parse(time.RFC3339, ann[loginprofile.AnnPasswordLastChanged])
	if pol.Expired(changed, time.Now()) {
		if pol.HardExpiry {
			return false, "your password has expired; an administrator must reset it"
		}
		mustChange = true
	}
	return mustChange, ""
}

// POST /api/auth/change-password {oldPassword, newPassword} — the signed-in local user changes its own
// password (the forced change after PasswordResetRequired, or any time), proving the old one.
func handleChangeOwnPassword(a *authStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		claims, ok := a.parse(c.Value)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}
		if r.Header.Get(csrfHeader) == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing " + csrfHeader})
			return
		}
		var in struct {
			OldPassword string `json:"oldPassword"`
			NewPassword string `json:"newPassword"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.OldPassword == "" || in.NewPassword == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "oldPassword and newPassword are required"})
			return
		}
		user := claims.Sub
		if _, secretAccount := a.users(r.Context())[user]; secretAccount || claims.AssumedRole != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "InvalidUserType",
				"error": "only an IAM user changes its password here; root's password is set by the operator"})
			return
		}
		u, ok := a.crdUserByName(r.Context(), user)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"code": "NoSuchEntity", "error": "no such user"})
			return
		}
		if _, _, ok := a.verifyCRDUser(r.Context(), user, in.OldPassword); !ok {
			a.logger.Warn("console: wrong old password", "user", user)
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "InvalidUserType", "error": "The specified value for oldPassword is invalid."})
			return
		}
		pol, why := a.checkConsolePassword(r.Context(), in.NewPassword)
		if why != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "PasswordPolicyViolation", "error": why})
			return
		}
		if reused, _ := a.loginStore().Reused(r.Context(), a.ns, user, in.NewPassword, pol.PasswordReusePrevention); reused {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "PasswordPolicyViolation",
				"error": "Password cannot be one of your last " + strconv.Itoa(pol.PasswordReusePrevention) + " passwords."})
			return
		}
		ref, _, err := a.storePassword(r.Context(), user, in.NewPassword, pol.PasswordReusePrevention)
		if err != nil {
			a.logger.Error("console: change password", "user", user, "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store password"})
			return
		}
		patch := map[string]any{
			"metadata": map[string]any{"annotations": map[string]any{
				loginprofile.AnnPasswordLastChanged: time.Now().UTC().Format(time.RFC3339), loginprofile.AnnResetRequired: nil}},
			"spec": map[string]any{"passwordSecretRef": ref},
		}
		if err := a.patchCR(r.Context(), usersAbsPath(a.ns)+"/"+user, patch); err != nil {
			a.logger.Error("console: change password", "user", user, "error", err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not record the password"})
			return
		}
		// An old Secret in the console namespace is replaced by the store's; remove it.
		if old := u.Spec.PasswordSecretRef; old.Name != "" && old.Namespace == "" && ref["namespace"] != nil {
			_ = a.cs.CoreV1().Secrets(a.ns).Delete(r.Context(), old.Name, metav1.DeleteOptions{})
		}
		claims.PwReset = false
		tok, err := a.issueSession(claims.Claims, false)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not start session"})
			return
		}
		a.setCookie(w, r, tok, sessionTTL)
		a.logger.Info("console: password changed", "user", user)
		writeJSON(w, http.StatusOK, map[string]string{"user": user})
	}
}
