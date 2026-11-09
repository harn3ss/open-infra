package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awsaction"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Console authentication.
//
// Until now the console had NO authentication: /api/k8s/* reverse-proxies the Kubernetes API
// with the pod's ServiceAccount token, so anyone who could reach the console had effective
// admin over the platform. This gates every /api route behind a signed session cookie.
//
// The identity backend is chosen at install time via AUTH_MODE (see docs/auth.md):
//
//	local (default) — users stored in the console-auth Secret, bcrypt hashed
//	ldap / oidc — reserved; implemented in a later phase
//	none — NO authentication. Must be set explicitly; logs a loud warning.
//
// v1 is a gate: every authenticated user currently shares the console's ServiceAccount rights.
// Per-user authorization (Kubernetes impersonation + IAM-style roles) is the next phase — the
// session already carries a role so that work slots in without changing the login flow.

const (
	sessionCookie = "oi_session"
	authSecret    = "console-auth"
	sessionTTL    = 12 * time.Hour
	// Mutating requests must carry this header. Combined with SameSite=Lax it blocks
	// cross-site form posts / simple-request CSRF against the API.
	csrfHeader = "X-Openinfra-Console"
)

type userRec struct {
	Hash string `json:"hash"`
	Role string `json:"role"`
}

type authStore struct {
	cs         kubernetes.Interface
	ns         string
	mode       string
	sessionKey []byte
	ldap       ldapConfig
	logger     *slog.Logger

	// account and home are set only on a copy bound to a member account's IAM (iamAuth, iam_scope.go):
	// account is that account's id, ns its IAM home, and home the management account's IAM home (the
	// console's namespace). Both are empty on the console's own store: the management account.
	account, home string
}

func authMode() string {
	m := strings.ToLower(strings.TrimSpace(getenv("AUTH_MODE", "local")))
	if m == "" {
		return "local"
	}
	return m
}

// consoleNamespace resolves the namespace the console runs in (for its auth Secret).
func consoleNamespace() string {
	if v := getenv("CONSOLE_NAMESPACE", ""); v != "" {
		return v
	}
	if b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	return "open-infra-console"
}

// newAuthStore loads (or bootstraps) the console-auth Secret. On a fresh install it generates
// a session-signing key and a random root password, printing the password ONCE to the log —
// the same "grab your root credentials now" moment AWS gives you.
func newAuthStore(cs kubernetes.Interface, logger *slog.Logger) (*authStore, error) {
	a := &authStore{cs: cs, ns: consoleNamespace(), mode: authMode(), logger: logger}
	if a.mode == "ldap" {
		a.ldap = loadLDAPConfig()
		if a.ldap.host == "" {
			return nil, fmt.Errorf("AUTH_MODE=ldap but LDAP_HOST is not set")
		}
		logger.Info("console auth: LDAP backend", "host", a.ldap.host, "baseDN", a.ldap.userBaseDN)
	}
	if a.mode == "none" {
		logger.Warn("AUTH_MODE=none — the console API is UNAUTHENTICATED; anyone who can reach it has admin over this cluster")
		return a, nil
	}

	ctx := context.Background()
	sec, err := cs.CoreV1().Secrets(a.ns).Get(ctx, authSecret, metav1.GetOptions{})
	if err == nil && len(sec.Data["sessionKey"]) > 0 {
		a.sessionKey = sec.Data["sessionKey"]
		return a, nil
	}

	// Bootstrap: session key + root user.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	pw, err := randomPassword(20)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	users, _ := json.Marshal(map[string]userRec{"root": {Hash: string(hash), Role: "root"}})

	newSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: authSecret, Namespace: a.ns},
		Data: map[string][]byte{
			"sessionKey": key,
			"users":      users,
		},
	}
	if _, err := cs.CoreV1().Secrets(a.ns).Create(ctx, newSec, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return nil, fmt.Errorf("create %s secret: %w", authSecret, err)
		}
		// Raced with another replica — re-read.
		sec, err2 := cs.CoreV1().Secrets(a.ns).Get(ctx, authSecret, metav1.GetOptions{})
		if err2 != nil {
			return nil, err2
		}
		a.sessionKey = sec.Data["sessionKey"]
		return a, nil
	}

	a.sessionKey = key
	logger.Warn("════════ open-infra console: ROOT CREDENTIALS (shown once) ════════")
	logger.Warn("root user created", "username", "root", "password", pw)
	logger.Warn("Store this now. It is not recoverable — rotate by deleting the console-auth Secret.")
	logger.Warn("═══════════════════════════════════════════════════════════════════")
	return a, nil
}

func randomPassword(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n], nil
}

// users re-reads the user map so changes to the Secret take effect without a restart.
func (a *authStore) users(ctx context.Context) map[string]userRec {
	sec, err := a.cs.CoreV1().Secrets(a.ns).Get(ctx, authSecret, metav1.GetOptions{})
	if err != nil {
		return nil
	}
	var m map[string]userRec
	if err := json.Unmarshal(sec.Data["users"], &m); err != nil {
		return nil
	}
	return m
}

// verify authenticates a sign-in and returns the role plus the Kubernetes groups to
// impersonate with (nil = derive them from the role).
//
// Order is deliberate:
// 1. Secret-backed local accounts — ALWAYS accepted in every mode. This keeps the
// bootstrap `root` working as break-glass, so a broken CRD, a bad Composition or a
// directory outage can never lock you out of your own console.
// 2. kind: User (iam.openinfra.dev) — the GitOps-managed form, whose spec.groups are
// authoritative for authorization.
// 3. LDAP, when AUTH_MODE=ldap.
//
// The name root is reserved (rootUserName): it signs in only as the Secret-backed root, never as a
// kind: User or a directory account of that name, nor as "Root" or " root".
func (a *authStore) verify(ctx context.Context, user, pass string) (string, []string, bool) {
	if reservedRootName(user) {
		if user != rootUserName {
			return "", nil, false
		}
		role, ok := a.verifyLocal(ctx, user, pass)
		return role, nil, ok
	}
	if role, ok := a.verifyLocal(ctx, user, pass); ok {
		return role, nil, true
	}
	if role, groups, ok := a.verifyCRDUser(ctx, user, pass); ok {
		return role, groups, true
	}
	if a.mode == "ldap" {
		role, ok := verifyLDAP(a.ldap, user, pass)
		return role, nil, ok
	}
	return "", nil, false
}

// verifyCRDUser authenticates against a kind: User with source=local, using the bcrypt
// hash in the Secret its passwordSecretRef points at. Its spec.groups become the
// impersonation groups directly, so a User with no groups can sign in but do nothing —
// failing closed rather than defaulting to a role.
func (a *authStore) verifyCRDUser(ctx context.Context, user, pass string) (string, []string, bool) {
	u, ok := a.crdUserByName(ctx, user)
	if !ok {
		return "", nil, false
	}
	if src := strings.ToLower(u.Spec.Source); src != "" && src != "local" {
		return "", nil, false // ldap/oidc users authenticate via their directory
	}
	hash, ok := a.crdPasswordHash(ctx, u)
	if !ok {
		return "", nil, false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
		return "", nil, false
	}
	// `role` is retained for display and for the read-only write gate; the groups are
	// what Kubernetes actually authorizes against.
	role := "readonly"
	for _, g := range u.Spec.Groups {
		switch strings.ToLower(strings.TrimSpace(g)) {
		case "admins", "admin":
			role = "admin"
		case "powerusers", "poweruser":
			if role != "admin" {
				role = "poweruser"
			}
		}
	}
	return role, crdGroups(u), true
}

func (a *authStore) verifyLocal(ctx context.Context, user, pass string) (string, bool) {
	rec, ok := a.users(ctx)[user]
	if !ok {
		// Compare against a dummy hash so a missing user costs the same as a wrong
		// password (don't leak which usernames exist via timing).
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin"), []byte(pass))
		return "", false
	}
	if bcrypt.CompareHashAndPassword([]byte(rec.Hash), []byte(pass)) != nil {
		return "", false
	}
	role := rec.Role
	if role == "" {
		role = "user"
	}
	if strings.EqualFold(role, "root") && user != rootUserName {
		// Only root is root: another Secret account given role root is an administrator.
		role = "admin"
	}
	return role, true
}

// sessionClaims is the cookie-backed session: the shared iam.Claims (sub/role/groups) plus the
// console-session-specific expiry. iam.Claims is embedded (not a named field), so its fields are
// promoted into the session-cookie JSON exactly as before — existing cookies round-trip byte-for-
// byte — while c.Claims hands the shared authorization core (iam.Identity/iam.CanDo) the identity.
type sessionClaims struct {
	iam.Claims
	Exp int64 `json:"exp"`
	// PwReset marks a session that may only change its password (PasswordResetRequired, or an expired
	// password): requireAuth refuses everything else (login_profile.go).
	PwReset bool `json:"pwReset,omitempty"`
}

func (a *authStore) issue(user, role string, groups []string) (string, error) {
	return a.issueClaims(iam.Claims{Sub: user, Role: role, Groups: groups})
}

// issueClaims signs a session for claims (a switched role's session carries its account and role).
func (a *authStore) issueClaims(claims iam.Claims) (string, error) {
	return a.issueSession(claims, false)
}

// issueSession signs a session; pwReset makes it a change-your-password-only session.
func (a *authStore) issueSession(claims iam.Claims, pwReset bool) (string, error) {
	if !rootSessionValid(claims) {
		return "", errors.New("the name root is reserved for the account's root user")
	}
	c, err := json.Marshal(sessionClaims{Claims: claims, Exp: time.Now().Add(sessionTTL).Unix(), PwReset: pwReset})
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(c)
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (a *authStore) parse(tok string) (sessionClaims, bool) {
	var out sessionClaims
	body, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return out, false
	}
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return out, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return out, false
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, false
	}
	if time.Now().Unix() > out.Exp {
		return out, false
	}
	if !rootSessionValid(out.Claims) {
		return out, false // a session named root that is not the Secret's root (issued before the name was reserved)
	}
	if out.MFA == nil {
		// Every console session is a temporary credential: one issued before sessions carried their MFA
		// context was not authenticated with MFA.
		out.MFA = iam.NoMFA()
	}
	return out, true
}

func (a *authStore) setCookie(w http.ResponseWriter, r *http.Request, tok string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// requireAuth gates every /api route. Login/logout/me are exempt (handled inside).
func (a *authStore) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.mode == "none" {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}
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
		// Attribute this request to a person in the access log.
		noteIdentity(r, claims.Sub, claims.Role)
		if claims.PwReset {
			// A sign-in that must change its password first reaches nothing but /api/auth/*.
			writeJSON(w, http.StatusForbidden, map[string]string{"code": "PasswordResetRequired",
				"error": "you must change your password before you continue"})
			return
		}

		// CSRF: state-changing requests must carry the console's header. SameSite=Lax
		// already blocks cross-site form posts; this stops the simple-request bypass.
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if r.Header.Get(csrfHeader) == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing " + csrfHeader})
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUser{}, claims)))
	})
}

// requireSignedIn gates a route on a valid console session but WITHOUT the CSRF-header
// check that requireAuth adds on writes. It exists for the Grafana reverse proxy: those
// routes must be behind auth — otherwise anyone who can reach the console (an
// internet-exposed one especially) can read every dashboard, metric and log through
// /grafana/*, since Grafana itself runs with anonymous Viewer access. But Grafana's own
// iframe issues POST /api/ds/query for each panel WITHOUT our CSRF header, so requireAuth
// would 403 those and break live dashboards. Same-origin embedding + SameSite=Lax already
// stop cross-site use, and the proxied Grafana is read-only (Viewer), so a session check
// alone is the right gate here. When AUTH_MODE=none everything is open anyway (the SPA
// shows a standing banner), matching requireAuth.
func (a *authStore) requireSignedIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.mode == "none" {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		if _, ok := a.parse(c.Value); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

type ctxUser struct{}

// claimsFrom returns the signed-in user's session claims, if the request passed
// through requireAuth.
func claimsFrom(r *http.Request) (sessionClaims, bool) {
	c, ok := r.Context().Value(ctxUser{}).(sessionClaims)
	return c, ok
}

// identityFor resolves the impersonation identity for a proxied k8s request, via the shared
// authorization core (iam.Identity) so the console and the shim map identity identically.
func identityFor(r *http.Request) (string, []string, bool) {
	c, ok := claimsFrom(r)
	if !ok {
		return "", nil, false
	}
	return iam.Identity(c.Claims)
}

// requireWrite blocks state-changing calls to the BFF's OWN endpoints (the ones
// that act with the ServiceAccount rather than going through the impersonating
// k8s proxy) for read-only users. Kubernetes RBAC covers /api/k8s/*; this covers
// everything else.
func requireWrite(a *authStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sign-in/out must stay reachable: there is no session yet at that point.
		if a.mode == "none" || strings.HasPrefix(r.URL.Path, "/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		// With IAM policy deciding, a write is an IAM action like any other (ReadOnlyAccess simply grants
		// none); the "readonly" tier no longer exists to gate on.
		if consoleIAM.enforced(r) {
			next.ServeHTTP(w, r)
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			c, ok := claimsFrom(r)
			if !ok || strings.EqualFold(c.Role, "readonly") {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "your role does not allow changes (read-only)"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// POST /api/auth/login
func handleLogin(a *authStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Username, Password string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
			return
		}
		if a.mode == "oidc" {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "AUTH_MODE=oidc is not implemented yet"})
			return
		}
		role, groups, ok := a.verify(r.Context(), in.Username, in.Password)
		if !ok {
			a.logger.Warn("failed console login", "user", in.Username, "remote", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
			return
		}
		// An IAM user's login profile can require a new password first (PasswordResetRequired, or past the
		// account policy's MaxPasswordAge), or, with HardExpiry, refuse the expired password outright.
		mustChange := false
		if _, secretAccount := a.users(r.Context())[in.Username]; !secretAccount {
			if u, ok := a.crdUserByName(r.Context(), in.Username); ok {
				var refuse string
				mustChange, refuse = a.signInGate(r.Context(), u)
				if refuse != "" {
					a.logger.Warn("console login refused", "user", in.Username, "reason", refuse)
					writeJSON(w, http.StatusForbidden, map[string]string{"code": "PasswordExpired", "error": refuse})
					return
				}
				// A user with an MFA device signs in with its code too, as on AWS: the password step only
				// earns the MFA step (mfa.go). Its devices unreadable, it does not sign in at all.
				devices, err := a.mfaDevices(r.Context(), u)
				if err != nil {
					a.logger.Error("console login: the user's MFA devices cannot be read", "user", in.Username, "error", err.Error())
					writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "sign-in is unavailable: the MFA devices cannot be read"})
					return
				}
				if len(devices) > 0 {
					ch, err := a.signChallenge(mfaChallenge{Sub: in.Username, Role: role, Groups: groups, PwReset: mustChange,
						Exp: time.Now().Add(mfaChallengeTTL).Unix()})
					if err != nil {
						writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not start sign-in"})
						return
					}
					a.setChallengeCookie(w, r, ch, mfaChallengeTTL)
					a.logger.Info("console login: password verified, MFA code required", "user", in.Username)
					writeJSON(w, http.StatusOK, map[string]any{"user": in.Username, "mfaRequired": true})
					return
				}
			}
		}
		// A console session is a temporary credential; without the MFA step, one not authenticated with MFA.
		tok, err := a.issueSession(iam.Claims{Sub: in.Username, Role: role, Groups: groups, MFA: iam.NoMFA()}, mustChange)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not start session"})
			return
		}
		a.setCookie(w, r, tok, sessionTTL)
		a.logger.Info("console login", "user", in.Username, "role", role, "passwordResetRequired", mustChange)
		writeJSON(w, http.StatusOK, map[string]any{"user": in.Username, "role": role, "passwordResetRequired": mustChange})
	}
}

// POST /api/auth/logout
func handleLogout(a *authStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.setCookie(w, r, "", -1)
		writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
	}
}

// GET /api/auth/me — who am I (used by the UI to decide login vs app).
func handleMe(a *authStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.mode == "none" {
			body := map[string]any{"user": "anonymous", "role": "root", "authDisabled": true,
				"capabilities": map[string]bool{"operator": true}, "account": iam.ManagementAccount}
			consoleIAM.addAccountContext(r.Context(), body, iam.ManagementAccount)
			writeJSON(w, http.StatusOK, body)
			return
		}
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
		// The account header: who the principal is to IAM (its ARN), the account it signed in to, and
		// how far IAM policy decides (so the UI can say why a page is denied).
		acct := claims.Account
		if acct == "" {
			acct = iam.ManagementAccount
		}
		p := iamauthz.PrincipalFromClaims(claims.Claims, acct)
		mode := iamauthz.ModeLegacy
		if consoleIAM != nil && consoleIAM.eval != nil {
			mode = consoleIAM.eval.ModeFor(r.Context(), p)
		}
		body := map[string]any{
			"user": claims.Sub, "role": claims.Role,
			"account": acct, "accountAlias": getenv("ACCOUNT_ALIAS", ""),
			"arn": p.ARN(), "principalType": string(p.Type), "iamAuthz": string(mode),
			"passwordResetRequired": claims.PwReset,
			// Whether this session was signed in with MFA (aws:MultiFactorAuthPresent for its requests).
			"mfaAuthenticated": claims.MFAPresent(),
			"capabilities":     map[string]bool{"operator": consoleIAM.isOperator(r, claims, p, mode)},
		}
		consoleIAM.addAccountContext(r.Context(), body, acct)
		writeJSON(w, http.StatusOK, body)
	}
}

// addAccountContext adds the session's account context to /api/auth/me: its region (the platform serves
// one, awsaction.DefaultRegion), and the account's namespaces and home — where the console lists the
// account's resources and creates new ones. The namespaces are left out when they cannot be read.
func (z *consoleAuthz) addAccountContext(ctx context.Context, body map[string]any, acct string) {
	body["region"] = awsaction.DefaultRegion
	if z == nil || z.cs == nil {
		return
	}
	names, home, err := z.accountNamespaces(ctx, acct)
	if err != nil {
		z.logger.Warn("account namespaces", "account", acct, "error", err)
		return
	}
	if names == nil {
		names = []string{}
	}
	body["namespaces"], body["homeNamespace"] = names, home
}

// operatorSurface is the platform's raw-Kubernetes surface (pods, nodes, Secrets, namespaces …) as one
// question. Only an Allow that names all of it grants it — "*", as AdministratorAccess, or
// "openinfra-operator:*" — and PowerUserAccess's NotAction reserves it (iamauthz's reserveOperator).
const operatorSurface = awsaction.OperatorPrefix + ":*"

// isOperator reports whether the principal is the platform's operator, for whom the console shows its
// cluster views (Workloads, Nodes, Network under Platform operations). In enforce it is the evaluator's
// answer to openinfra-operator:* (the question the route gate asks of those views' calls, which are still
// authorized one by one); in legacy and shadow it is the legacy administrator role, as those modes
// decide. Shadow does not log it: it chooses what the menu shows, not what a request may do. A role
// session outside enforce is no one's operator (every request it makes is refused).
func (z *consoleAuthz) isOperator(r *http.Request, c sessionClaims, p iamauthz.Principal, mode iamauthz.Mode) bool {
	if z.roleSessionOutsideEnforce(r, c) {
		return false
	}
	if z == nil || z.eval == nil || mode != iamauthz.ModeEnforce {
		return c.Role == "admin" || c.Role == "root"
	}
	reqCtx := s3authz.RequestContext(c.Claims, r)
	return z.eval.Authorize(r.Context(), p, operatorSurface, "*", reqCtx).Allowed
}
