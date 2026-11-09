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

// switchRoleTarget is the account and role a Switch role request names (the session's own account when
// it names none).
func switchRoleTarget(r *http.Request) (account, role string) {
	account = strings.TrimSpace(peekBody(r, "account"))
	role = strings.TrimSpace(peekBody(r, "roleName"))
	if account == "" {
		account = callerAccount(r)
	}
	return account, role
}

// switchingUser is the session a Switch role acts for: the signed-in user itself, never a role session it
// is in (the console switches from the user).
func switchingUser(c sessionClaims) sessionClaims {
	c.AssumedRole, c.Account = "", ""
	return c
}

// roleFinder finds the role a Switch role names: its account's IAM home namespace and the role there.
type roleFinder func(ctx context.Context, account, role string) (home string, r crdRole, ok bool)

// accountRoles is the roleFinder over the cluster.
func accountRoles(cs kubernetes.Interface, auth *authStore) roleFinder {
	return func(ctx context.Context, account, name string) (string, crdRole, bool) {
		home, ok := accountHome(ctx, cs, auth, account)
		if !ok {
			return "", crdRole{}, false
		}
		role, ok := roleIn(ctx, auth, home, name)
		return home, role, ok
	}
}

// switchRoleQuestion is Switch role's gate: sts:AssumeRole on the role, decided as AWS decides an assume
// and as the aws-shim's STS does. The evaluator is asked as the signed-in user, with the role's trust as
// the role's resource policy (iamauthz.TrustStatements):
//   - another account's role needs both: the trust naming the caller or its account, and the caller's own
//     policy allowing sts:AssumeRole on the role;
//   - within one account a trust naming the caller itself is enough, and only an explicit Deny refuses it;
//     a trust naming the account needs the caller's policy too;
//   - an account's root user cannot assume a role.
//
// A role that is not there is asked with no trust at all, so its refusal is the same as for a role whose
// trust does not name the caller. The handler then checks that the trust names the caller (AWS requires
// the trust in every case) and the trust policy's written conditions.
func (z *consoleAuthz) switchRoleQuestion(find roleFinder) func(*http.Request) (string, string, func() (bool, string)) {
	return func(r *http.Request) (string, string, func() (bool, string)) {
		account, name := switchRoleTarget(r)
		action, arn := "sts:AssumeRole", iamEntityARN("role", account, name)
		return action, arn, func() (bool, string) {
			if c, ok := claimsFrom(r); ok && z.auth != nil && z.auth.mode != "none" &&
				iamauthz.PrincipalFromClaims(switchingUser(c).Claims, "").Type == iamauthz.Root {
				return false, "Roles may not be assumed by root accounts."
			}
			var trust []iamauthz.ResourceStatement
			if accounts.ValidAccountID(account) && validName(name) {
				if _, role, ok := find(r.Context(), account, name); ok {
					var err error
					if trust, err = iamauthz.TrustStatements(role.Spec.Trust, account); err != nil {
						return false, "the role's trust policy does not compile: " + err.Error()
					}
				}
			}
			return z.decideAs(r, switchingUser, action, arn, allowLegacy, iamauthz.WithResourcePolicy(trust))
		}
	}
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

// trusts reports whether the trust entries of a role in roleAccount admit the caller: anyone ("*"), the
// caller by ARN, or the caller's account (its root ARN or bare id), as an AWS trust policy naming a
// principal or an account does. A bare name (or typed User::<name>) is a user of the role's own account,
// so it admits the caller only there: another account's principal is named by its ARN.
func trusts(trust []string, caller iamauthz.Principal, callerName, roleAccount string) bool {
	acct := caller.AccountID()
	admit := []string{"*", "arn:aws:iam::" + acct + ":root", acct}
	if caller.Type == iamauthz.User {
		admit = append(admit, caller.ARN())
		if roleAccount == acct {
			admit = append(admit, callerName, "User::"+callerName)
		}
	}
	for _, t := range trust {
		if slices.Contains(admit, strings.TrimSpace(t)) {
			return true
		}
	}
	return false
}

// handleSwitchRole assumes a role for the console session (POST /api/sts/switch-role).
func handleSwitchRole(find roleFinder, auth *authStore, logger *slog.Logger) http.HandlerFunc {
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
		base := switchingUser(c)
		caller := iamauthz.PrincipalFromClaims(base.Claims, "")
		roleARN := iamEntityARN("role", in.Account, in.Role)
		home, role, ok := find(r.Context(), in.Account, in.Role)
		if !ok || !trusts(role.Spec.Trust, caller, base.Sub, in.Account) {
			writeAccessDenied(w, "sts:AssumeRole", roleARN, "the role does not exist or its trust policy does not name you")
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
