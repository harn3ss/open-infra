package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Switch role, as the AWS console has it: the signed-in user assumes a role (typically another
// account's OrganizationAccountAccessRole) and the console session becomes that role's session in that
// account — every page then acts as the role, through the same evaluator. "Switch back" returns to the
// user. It is sts:AssumeRole on the role, and the role's trust must name the caller (the user, or its
// account), as on AWS.
//
// A role session is only possible where IAM policy decides it (the role is in enforce): the legacy
// checks treat an assumed-role session as the role's own policies' business (iam.CanDo), so a role
// session outside enforce would pass them. For the same reason the gate refuses any request from a role
// session that is no longer in enforce (a rollback to legacy ends role sessions; the user switches back).

// assumeRolePolicyAnnotation is the trust policy a role was created with through the IAM API, as written.
const assumeRolePolicyAnnotation = "openinfra.dev/assume-role-policy"

type switchRoleReq struct {
	Account string `json:"account"`
	Role    string `json:"roleName"`
}

// roleSessionOutsideEnforce reports whether a request carries an assumed-role console session that IAM
// policy no longer decides (the guard against a rollback turning role sessions into legacy passes).
func (z *consoleAuthz) roleSessionOutsideEnforce(r *http.Request, c sessionClaims) bool {
	if c.AssumedRole == "" {
		return false
	}
	if z == nil || z.eval == nil {
		return true
	}
	return z.eval.ModeFor(r.Context(), z.principal(c)) != iamauthz.ModeEnforce
}

// switchRoleQuestion is the gate's question: sts:AssumeRole on the role's ARN in its account.
func switchRoleQuestion(r *http.Request) (string, string) {
	acct := strings.TrimSpace(peekBody(r, "account"))
	role := strings.TrimSpace(peekBody(r, "roleName"))
	if acct == "" {
		acct = callerAccount(r)
	}
	return "sts:AssumeRole", iamEntityARN("role", acct, role)
}

// accountHome is the namespace that is an account's IAM home: the console's own for the management
// account, else the namespace labelled as that account's home.
func accountHome(ctx context.Context, cs kubernetes.Interface, auth *authStore, account string) (string, bool) {
	if account == iam.ManagementAccount {
		return auth.ns, true
	}
	list, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: accounts.LabelAccountID + "=" + account + "," + accounts.LabelAccountHome + "=true",
	})
	if err != nil || len(list.Items) != 1 {
		return "", false
	}
	home := list.Items[0]
	// A suspended account's roles cannot be assumed (as on AWS), and a platform namespace is no account.
	if home.Labels[accounts.LabelAccountStatus] == accounts.StatusSuspended || accounts.IsPlatformNamespace(home.Name) {
		return "", false
	}
	return home.Name, true
}

// trusts reports whether a role's trust entries admit the caller: anyone ("*"), the caller by name or
// ARN (or typed User::<name>), or the caller's account (its root ARN or bare id), as an AWS trust policy
// naming a principal or an account does.
func trusts(trust []string, caller iamauthz.Principal, callerName string) bool {
	acct := caller.AccountID()
	admit := []string{"*", "arn:aws:iam::" + acct + ":root", acct}
	if caller.Type == iamauthz.User {
		admit = append(admit, callerName, "User::"+callerName, caller.ARN())
	}
	for _, t := range trust {
		if slices.Contains(admit, strings.TrimSpace(t)) {
			return true
		}
	}
	return false
}

// handleSwitchRole assumes a role for the console session (POST /api/sts/switch-role).
func handleSwitchRole(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := claimsFrom(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		var in switchRoleReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		in.Account, in.Role = strings.TrimSpace(in.Account), strings.TrimSpace(in.Role)
		if in.Account == "" {
			in.Account = callerAccount(r)
		}
		if !accounts.ValidAccountID(in.Account) || !validName(in.Role) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "an account is a 12-digit id and a role a lowercase name", "errorCode": "ValidationError"})
			return
		}
		// The caller as itself (switching from a role session switches from the user).
		base := c
		base.AssumedRole, base.Account = "", ""
		caller := iamauthz.PrincipalFromClaims(base.Claims, "")
		roleARN := iamEntityARN("role", in.Account, in.Role)
		denied := func() {
			writeAccessDenied(w, "sts:AssumeRole", roleARN, "the role does not exist or its trust policy does not name you")
		}
		home, ok := accountHome(r.Context(), cs, auth, in.Account)
		if !ok {
			denied()
			return
		}
		role, ok := roleIn(r.Context(), auth, home, in.Role)
		if !ok || !trusts(role.Spec.Trust, caller, base.Sub) {
			denied()
			return
		}
		// The trust policy as written (CreateRole's document): its conditions — aws:MultiFactorAuthPresent
		// above all — hold for this console session too. The role session keeps the session's MFA.
		if doc := role.Metadata.Annotations[assumeRolePolicyAnnotation]; doc != "" {
			if ok, why := iamauthz.AuthorizeTrust(doc, caller, "sts:AssumeRole", roleARN, s3authz.RequestContext(base.Claims, r)); !ok {
				writeAccessDenied(w, "sts:AssumeRole", roleARN, why)
				return
			}
		}
		next := base
		next.Account = in.Account
		next.AssumedRole = iamauthz.QualifiedName(auth.ns, home, in.Role)
		target := iamauthz.PrincipalFromClaims(next.Claims, in.Account)
		if consoleIAM == nil || consoleIAM.eval == nil || consoleIAM.eval.ModeFor(r.Context(), target) != iamauthz.ModeEnforce {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error":     "switching role needs IAM policy to decide this role's access (IAM_AUTHZ=enforce, or the role labelled for the canary)",
				"errorCode": "InvalidState",
			})
			return
		}
		tok, err := auth.issueClaims(next.Claims)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not start the role session"})
			return
		}
		auth.setCookie(w, r, tok, sessionTTL)
		logger.Info("console switch role", "user", base.Sub, "account", in.Account, "role", in.Role)
		writeJSON(w, http.StatusOK, map[string]string{"account": in.Account, "role": in.Role, "arn": target.ARN()})
	}
}

// handleSwitchBack returns the console session to the signed-in user (POST /api/sts/switch-back).
func handleSwitchBack(auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := claimsFrom(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		c.AssumedRole, c.Account = "", ""
		tok, err := auth.issueClaims(c.Claims)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not restore the session"})
			return
		}
		auth.setCookie(w, r, tok, sessionTTL)
		logger.Info("console switch back", "user", c.Sub)
		writeJSON(w, http.StatusOK, map[string]string{"user": c.Sub})
	}
}

// roleIn reads a Role from an account's IAM home namespace.
func roleIn(ctx context.Context, auth *authStore, ns, name string) (crdRole, bool) {
	var role crdRole
	rc := auth.rawREST()
	if rc == nil {
		return role, false
	}
	raw, err := rc.Get().AbsPath(rolesAbsPath(ns) + "/" + name).DoRaw(ctx)
	if err != nil || json.Unmarshal(raw, &role) != nil {
		return role, false
	}
	return role, role.Metadata.Name != ""
}
