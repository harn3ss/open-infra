package main

import (
	"context"
	"encoding/xml"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
)

// stsHandler fronts a minimal, faithful slice of AWS STS. STS is the identity service SDKs and
// tooling probe first (`aws sts get-caller-identity` is the canonical "who am I / does auth work"
// check), so fronting it makes the shim feel real to standard tooling. It is also the cleanest
// possible service: GetCallerIdentity has NO backend — it simply reflects the identity the shim
// already proved via SigV4, so there is nothing to translate and nothing to get subtly wrong.
//
// Protocol: AWS Query (form-encoded `Action=…` POST, XML response). Only GetCallerIdentity is
// implemented; every other action returns a faithful query-protocol error rather than a guess.
// roleResolver looks up a kind: Role's trust (who may assume it), the groups an assumed session acts
// as, and the longest session it may be assumed for. Backed by a dynamic k8s client in production and a
// fake in tests.
type roleResolver interface {
	Resolve(ctx context.Context, roleName string) (resolvedRole, bool)
}

// roleResolverIn resolves a role in a given namespace: another account's home, for a cross-account
// AssumeRole. A resolver without it cannot assume across accounts.
type roleResolverIn interface {
	ResolveIn(ctx context.Context, ns, roleName string) (resolvedRole, bool)
}

// accountHomes maps a member account to its home namespace (internal/accounts.Directory).
type accountHomes interface {
	HomeOf(account string) (string, bool)
	IsManagement(account string) bool
	Suspended(account string) bool
}

// resolvedRole is what assuming a role needs to know about it.
type resolvedRole struct {
	trust  []string
	groups []string
	// maxSession is the role's spec.maxSessionDuration (AWS's MaxSessionDuration: 1h by default, at most
	// 12h); zero means the default.
	maxSession time.Duration
	// trustDoc is the trust policy the role was created with, as written (CreateRole's
	// AssumeRolePolicyDocument); "" when it has none. Its conditions — aws:MultiFactorAuthPresent above
	// all — gate AssumeRole on top of spec.trust's principals.
	trustDoc string
}

// defaultMaxSession is AWS's MaxSessionDuration default; chainedMaxSession caps a session assumed by
// another role's session (role chaining), whatever the role's own maximum, as on AWS.
const (
	defaultMaxSession = time.Hour
	chainedMaxSession = time.Hour
)

// sessionDuration is the session length an assume asks for (DurationSeconds; 1h when absent), refused —
// as AWS refuses it — when it is not a number, is under 15 minutes, or exceeds the role's maximum.
func sessionDuration(r *http.Request, role resolvedRole, chained bool) (time.Duration, string) {
	max := role.maxSession
	if max <= 0 {
		max = defaultMaxSession
	}
	if max > awssts.MaxDuration {
		max = awssts.MaxDuration
	}
	if chained && max > chainedMaxSession {
		max = chainedMaxSession
	}
	d := r.PostFormValue("DurationSeconds")
	if d == "" {
		return min(awssts.DefaultDuration, max), ""
	}
	secs, err := strconv.Atoi(d)
	if err != nil || time.Duration(secs)*time.Second < awssts.MinDuration {
		return 0, "DurationSeconds must be a number of seconds, at least 900."
	}
	ttl := time.Duration(secs) * time.Second
	if ttl > max {
		if chained {
			return 0, "The requested DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining."
		}
		return 0, "The requested DurationSeconds exceeds the MaxSessionDuration set for this role."
	}
	return ttl, ""
}

// tokenReviewer verifies a projected ServiceAccount token (the web-identity token) and returns the
// SA username ("system:serviceaccount:<ns>:<sa>"). Backed by a k8s TokenReview in production. nil
// disables AssumeRoleWithWebIdentity (workload identity).
type tokenReviewer interface {
	Review(ctx context.Context, token string) (username string, ok bool)
}

type stsHandler struct {
	account   string         // the install's 12-digit account id (awsidentity), surfaced in the ARN/Account fields
	minter    *awssts.Minter // mints sts:AssumeRole session tokens; nil disables AssumeRole
	roles     roleResolver   // resolves a role's trust policy + session groups; nil disables AssumeRole
	webID     tokenReviewer  // verifies workload SA tokens (IRSA path); nil disables that path
	oidcWebID oidcVerifier   // verifies EXTERNAL OIDC tokens vs registered kind: IdentityProvider; nil disables
	// functions recognizes a Lambda function's own identity token, which assumes the function's execution
	// role (lambda_role.go); nil disables execution roles.
	functions functionIdentities
	// applications recognizes an Application's own identity token, which assumes the app's task role
	// (app_role.go); nil disables task roles (an app's token is then decided by the role's trust alone).
	applications applicationIdentities
	// accounts maps member accounts to their home namespaces; nil means every role is the management
	// account's (a RoleArn naming another account is AccessDenied).
	accounts accountHomes
	// mfa verifies an IAM user's MFA code (GetSessionToken's and AssumeRole's SerialNumber + TokenCode);
	// nil refuses every code.
	mfa mfaChecker
	// authz decides the caller's own IAM policy for sts:AssumeRole, which AWS requires whenever the role's
	// trust delegates to the caller's account (its root) or the role is another account's. A nil checker
	// has no IAM policy world: the management account's callers are decided by the trust alone, as before
	// IAM policy, and a member account's caller is refused wherever its own policy must allow.
	authz  *dataplaneauthz.Checker
	logger *slog.Logger
}

// callerAccount is the 12-digit account a caller acts in.
func (h *stsHandler) callerAccount(c iam.Claims) string {
	if c.Account != "" {
		return c.Account
	}
	return h.account
}

// identIn is the identity ARNs are built in for account acct.
func (h *stsHandler) identIn(acct string) awsidentity.Identity {
	id := h.ident()
	if acct != "" {
		id.AccountID = acct
	}
	return id
}

// ident is the identity the handler's ARNs are built in: its account, the install's region.
func (h *stsHandler) ident() awsidentity.Identity {
	id := awsidentity.Current()
	id.AccountID = h.account
	return id
}

func (h *stsHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	action := stsAction(r)
	// An IAM user's own session (GetSessionToken) calls no STS operation but AssumeRole and
	// GetCallerIdentity, as on AWS.
	if claims.UserSession && action != "AssumeRole" && action != "GetCallerIdentity" {
		msg := "Credentials from GetSessionToken can call only AssumeRole and GetCallerIdentity in STS"
		if action == "GetSessionToken" {
			msg = "Cannot call GetSessionToken with session credentials"
		}
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, msg, stsXMLNamespace)
		return
	}
	switch action {
	case "GetSessionToken":
		h.getSessionToken(w, r, claims, requestID)
	case "GetCallerIdentity":
		// AWS allows GetCallerIdentity for ANY authenticated principal (no extra authorization) —
		// it only reports who you are. We mirror that: the request is already authenticated.
		h.writeCallerIdentity(w, claims, requestID)
	case "AssumeRole":
		h.assumeRole(w, r, claims, requestID)
	case "AssumeRoleWithWebIdentity":
		// Reachable pre-auth via the router (the web-identity token IS the credential); if it
		// arrives here it was SigV4-authenticated, which is fine too — the token still governs.
		h.assumeRoleWithWebIdentity(w, r, requestID)
	default:
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"The STS action '"+action+"' is not implemented by this open-infra shim", stsXMLNamespace)
	}
}

// assumeRole implements a faithful sts:AssumeRole. It authorizes the caller against the target
// role's trust policy (who may assume), then mints a temporary credential (AccessKeyId +
// SecretAccessKey + SessionToken) that acts AS the role. Fails closed: assume disabled, an unknown
// role, or a caller not named by the trust policy all deny.
func (h *stsHandler) assumeRole(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if h.minter == nil || h.roles == nil {
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"sts:AssumeRole is not enabled on this shim (no signing key configured)", stsXMLNamespace)
		return
	}
	_ = r.ParseForm()
	roleName := roleNameFromArn(r.PostFormValue("RoleArn"))
	sessionName := r.PostFormValue("RoleSessionName")
	if roleName == "" || sessionName == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"AssumeRole requires RoleArn and RoleSessionName", stsXMLNamespace)
		return
	}
	// The role's account: the one its ARN names (a bare name, or an ARN with no account, is the management
	// account's role). Another account's role lives in that account's home namespace.
	roleAcct := awsidentity.AccountOfARN(r.PostFormValue("RoleArn"))
	if roleAcct == "" {
		roleAcct = h.account
	}
	var role resolvedRole
	var ok bool
	roleNS := "" // the IAM home namespace
	if roleAcct == h.account || (h.accounts != nil && h.accounts.IsManagement(roleAcct)) {
		roleAcct = h.account
		role, ok = h.roles.Resolve(r.Context(), roleName)
	} else if in, can := h.roles.(roleResolverIn); can && h.accounts != nil && !h.accounts.Suspended(roleAcct) {
		if home, known := h.accounts.HomeOf(roleAcct); known {
			roleNS = home
			role, ok = in.ResolveIn(r.Context(), home, roleName)
		}
	}
	if !ok {
		// AWS returns AccessDenied (not "not found") so a caller can't probe which roles exist.
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			"not authorized to perform sts:AssumeRole on role "+roleName, stsXMLNamespace)
		return
	}
	// MFA: the caller's SerialNumber + TokenCode, verified against its own device, authenticate this
	// session with MFA; without them it carries the calling session's MFA context (a GetSessionToken
	// session obtained with MFA, or a role session that was), as AWS does.
	serial, code, ok := mfaParams(w, r, requestID)
	if !ok {
		return
	}
	mfaCtx := claims.MFA
	if serial != "" {
		if claims.AssumedRole != "" || h.mfa == nil {
			// A role session has no MFA device of its own.
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, mfaUnknownDevice, stsXMLNamespace)
			return
		}
		at, why := h.mfa.verify(r.Context(), h.memberAcct(claims), claims.Sub, serial, code)
		if why != "" {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, why, stsXMLNamespace)
			return
		}
		mfaCtx = iam.WithMFA(at)
	}
	who := callerTrust(claims)
	who.account = h.callerAccount(claims)
	if !trustedFrom(who, role.trust, roleAcct) {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			who.String()+" is not authorized to assume role "+roleName+" (not named by its trust policy)", stsXMLNamespace)
		return
	}
	// The trust policy as written: its conditions (aws:MultiFactorAuthPresent, aws:MultiFactorAuthAge)
	// must hold for this caller too. An unparseable or unevaluable condition never widens the trust.
	if role.trustDoc != "" {
		c := claims
		c.MFA = mfaCtx
		p := iamauthz.PrincipalFromClaims(c, h.callerAccount(claims))
		if ok, why := iamauthz.AuthorizeTrust(role.trustDoc, p, "sts:AssumeRole",
			h.identIn(roleAcct).IAMARN("role/"+roleName), requestContext(c, r)); !ok {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
				who.String()+" is not authorized to perform: sts:AssumeRole on resource: "+h.identIn(roleAcct).IAMARN("role/"+roleName)+" ("+why+")", stsXMLNamespace)
			return
		}
	}
	if ok, why := h.identityAllows(r, claims, mfaCtx, who, role.trust, roleAcct, roleName); !ok {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, why, stsXMLNamespace)
		return
	}
	ttl, bad := sessionDuration(r, role, claims.AssumedRole != "")
	if bad != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, bad, stsXMLNamespace)
		return
	}
	sess := awssts.Session{RoleName: roleName, Groups: role.groups, SessionName: sessionName, Caller: callerName(claims)}
	if roleAcct != h.account {
		// A session of another account's role acts in that account (its token records it).
		sess.Account, sess.Namespace = roleAcct, roleNS
	}
	if mfaCtx != nil && mfaCtx.Present {
		sess.MFA, sess.MFAAuthTime = true, mfaCtx.AuthTime
	}
	akid, sk, token, exp, err := h.minter.MintSession(sess, ttl, awssts.MaxDuration)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not mint credentials", stsXMLNamespace)
		return
	}
	h.writeAssumeRoleIn(w, roleAcct, roleName, sessionName, akid, sk, token, exp, requestID)
}

// assumeRoleWithWebIdentity implements a faithful sts:AssumeRoleWithWebIdentity — the workload
// identity (IRSA) path. A pod presents its projected ServiceAccount token; the shim verifies it via
// a k8s TokenReview, then authorizes the SA against the role's trust policy and mints session
// credentials for the role. No static keys, no SigV4 on this call: the SA token IS the credential.
func (h *stsHandler) assumeRoleWithWebIdentity(w http.ResponseWriter, r *http.Request, requestID string) {
	if h.minter == nil || h.roles == nil || (h.webID == nil && h.oidcWebID == nil) {
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"sts:AssumeRoleWithWebIdentity is not enabled on this shim", stsXMLNamespace)
		return
	}
	_ = r.ParseForm()
	roleName := roleNameFromArn(r.PostFormValue("RoleArn"))
	token := r.PostFormValue("WebIdentityToken")
	sessionName := r.PostFormValue("RoleSessionName")
	if roleName == "" || token == "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"AssumeRoleWithWebIdentity requires RoleArn and WebIdentityToken", stsXMLNamespace)
		return
	}
	// Two web-identity paths. First the k8s workload-identity (IRSA) path: a projected SA token verified
	// by a TokenReview, whose principal is the SA username. If that does not match, the external-OIDC
	// path: a token from a registered kind: IdentityProvider, verified via go-oidc; its trust principal
	// is the provider ("OIDC::<name>", or "OIDC::<name>:<subject>" for one subject of it). `username` is
	// the assumed subject; `who` is what the role's trust policy is matched against.
	var username string
	var who trustCaller
	if h.webID != nil {
		if u, ok := h.webID.Review(r.Context(), token); ok {
			username, who = u, trustCaller{kind: "ServiceAccount", name: u}
		}
	}
	if username == "" && h.oidcWebID != nil {
		if name, sub, ok := h.oidcWebID.verify(r.Context(), token); ok {
			username, who = sub, trustCaller{kind: "OIDC", name: name, subject: sub}
		}
	}
	if username == "" {
		// STS's dialect for a bad web-identity token.
		writeQueryError(w, http.StatusBadRequest, "InvalidIdentityToken", requestID,
			"the web identity token could not be validated", stsXMLNamespace)
		return
	}
	// A Lambda function's own identity assumes its execution role in its account, as Lambda assumes a role
	// trusting lambda.amazonaws.com (lambda_role.go); an Application's own identity its task role, as ECS
	// assumes a role trusting ecs-tasks.amazonaws.com (app_role.go). Any other token is decided below, as
	// before.
	if who.kind == "ServiceAccount" && h.functions != nil && isFunctionIdentity(username) {
		if fn, ok := h.functions.functionOf(r.Context(), token); ok {
			h.assumeFunctionRole(w, r, fn, sessionName, requestID)
			return
		}
	}
	if who.kind == "ServiceAccount" && h.applications != nil {
		if app, ok := h.applications.applicationOf(r.Context(), token); ok {
			h.assumeApplicationRole(w, r, app, sessionName, requestID)
			return
		}
	}
	role, ok := h.roles.Resolve(r.Context(), roleName)
	if !ok || !trusted(who, role.trust) {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID,
			who.String()+" is not authorized to assume role "+roleName+" (not named by its trust policy)", stsXMLNamespace)
		return
	}
	if sessionName == "" {
		sessionName = saShortName(username)
	}
	ttl, bad := sessionDuration(r, role, false)
	if bad != "" {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID, bad, stsXMLNamespace)
		return
	}
	// A web-identity session carries no MFA context: AWS cannot know whether the provider used MFA.
	akid, sk, tok, exp, err := h.minter.MintSession(awssts.Session{RoleName: roleName, Groups: role.groups,
		SessionName: sessionName, Caller: username, Federated: true}, ttl, awssts.MaxDuration)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not mint credentials", stsXMLNamespace)
		return
	}
	h.writeWebIdentity(w, roleName, sessionName, username, akid, sk, tok, exp, requestID)
}

// saShortName turns "system:serviceaccount:ns:sa" into "sa" for a default session name.
func saShortName(username string) string {
	parts := strings.Split(username, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return username
}

// roleNameFromArn accepts a role ARN (arn:aws:iam::<acct>:role/<name>, or the legacy
// arn:openinfra:iam::open-infra:role/<name>) or a bare role name.
func roleNameFromArn(arn string) string {
	arn = strings.TrimSpace(arn)
	if i := strings.Index(arn, ":role/"); i >= 0 {
		return arn[i+len(":role/"):]
	}
	return arn
}

// callerName is the principal the trust policy is evaluated against: the User's name, or (for a
// chained assume) the already-assumed role's name.
func callerName(c iam.Claims) string {
	if c.AssumedRole != "" {
		return c.AssumedRole
	}
	return c.Sub
}

// trustCaller is the principal asking to assume a role, typed the way a trust entry names it.
type trustCaller struct {
	kind    string // "User", "Role" (a session of that role: role chaining), "ServiceAccount" or "OIDC"
	name    string // the User's name, the Role's name, the ServiceAccount username, or the IdentityProvider's name
	subject string // OIDC: the token's subject
	// account is the caller's 12-digit account, matched by an ARN trust entry; "" matches none.
	account string
}

// callerTrust is a SigV4 caller as a trust policy names it: a User, or an assumed role's session.
func callerTrust(c iam.Claims) trustCaller {
	if c.AssumedRole != "" {
		return trustCaller{kind: "Role", name: c.AssumedRole}
	}
	return trustCaller{kind: "User", name: c.Sub}
}

func (c trustCaller) String() string {
	switch c.kind {
	case "ServiceAccount":
		return c.name
	case "OIDC":
		return "OIDC::" + c.name + ":" + c.subject
	}
	return c.kind + "::" + c.name
}

// trusted reports whether a role's trust policy names the caller. Entries are typed, so a principal of
// one kind never stands in for another of the same name — as an AWS trust policy names a user's ARN, a
// role's, or a federated provider:
//
//	"*"                                any authenticated principal (AWS's Principal "*")
//	"<name>" or "User::<name>"         that kind: User (a bare name is a User, as spec.trust documents)
//	"Role::<name>", "<namespace>/<name>"  a session of that role (role chaining)
//	"system:serviceaccount:<ns>:<sa>"  that workload's projected ServiceAccount token
//	"OIDC::<provider>"                 any token that kind: IdentityProvider issued
//	"OIDC::<provider>:<subject>"       that provider's token for that one subject
//	"arn:aws:iam::<acct>:root"         any principal of that account (AWS delegates to the account: its
//	                                   own policies must still allow sts:AssumeRole on the role)
//	"arn:aws:iam::<acct>:user/<name>"  that user of that account
//	"arn:aws:iam::<acct>:role/<name>"  a session of that role of that account (role chaining)
//
// "vm" is the VM instance principal: only the instance-credentials path matches it (vmcreds.go).
func trusted(c trustCaller, trust []string) bool {
	for _, t := range trust {
		if t == "*" {
			return true
		}
		if strings.HasPrefix(t, "arn:") {
			if trustedARN(c, t) {
				return true
			}
			continue
		}
		switch {
		case strings.HasPrefix(t, "User::"):
			if c.kind == "User" && t[len("User::"):] == c.name {
				return true
			}
		case strings.HasPrefix(t, "Role::"):
			if c.kind == "Role" && t[len("Role::"):] == c.name {
				return true
			}
		case strings.HasPrefix(t, "OIDC::"):
			provider, subject, pinned := strings.Cut(t[len("OIDC::"):], ":")
			if c.kind == "OIDC" && provider == c.name && (!pinned || subject == c.subject) {
				return true
			}
		case strings.HasPrefix(t, "system:serviceaccount:"):
			if c.kind == "ServiceAccount" && t == c.name {
				return true
			}
		case t == "vm" || strings.Contains(t, "::"):
			// the instance principal, or a principal type no assume path presents
		default:
			// A bare name is a User; one with a "/" — <namespace>/<name>, which no User name can be — is a
			// Role outside the IAM home namespace, as docs/iam.md has a trust policy name one.
			kind := "User"
			if strings.Contains(t, "/") {
				kind = "Role"
			}
			if c.kind == kind && t == c.name {
				return true
			}
		}
	}
	return false
}

// trustedFrom is trusted for a role of roleAccount: a caller of another account is named only by "*" or
// by an ARN (its account's root, or itself) — a bare name in a trust policy is always a principal of the
// role's own account, as on AWS, where another account's principal is named by its ARN.
func trustedFrom(c trustCaller, trust []string, roleAccount string) bool {
	if c.account == "" || roleAccount == "" || c.account == roleAccount {
		return trusted(c, trust)
	}
	var cross []string
	for _, t := range trust {
		if t == "*" || strings.HasPrefix(t, "arn:") {
			cross = append(cross, t)
		}
	}
	return trusted(c, cross)
}

// trustNamesCaller reports whether a role's trust names the caller itself — its user, its role, or "*" —
// rather than only its account's root, which delegates the decision to the account's own policies.
func trustNamesCaller(c trustCaller, trust []string) bool {
	var named []string
	for _, t := range trust {
		if strings.HasPrefix(t, "arn:") && strings.HasSuffix(t, ":root") {
			continue
		}
		named = append(named, t)
	}
	return trusted(c, named)
}

// identityAllows is the caller's own side of sts:AssumeRole, as AWS evaluates it; the role's trust, its
// resource policy, was decided before. Within one account, a trust naming the caller itself grants the
// assume on its own, and only an explicit Deny in the caller's policies refuses it. A trust naming the
// caller's account (arn:aws:iam::<account>:root) delegates to that account: its policies must allow
// sts:AssumeRole on the role. Another account's role always needs both the trust and the caller's policy.
func (h *stsHandler) identityAllows(r *http.Request, claims iam.Claims, mfaCtx *iam.MFAContext, who trustCaller,
	trust []string, roleAcct, roleName string) (bool, string) {
	c := claims
	c.MFA = mfaCtx
	callerAcct := h.callerAccount(claims)
	// The caller's policies alone, in its own account: the resource's side is the trust, already decided.
	// Before IAM policy decides (legacy, shadow) the trust alone decided, so legacy's answer is an allow.
	d := decision(r.Context(), r, h.authz, c, "sts:AssumeRole", arnType, h.identIn(roleAcct).IAMARN("role/"+roleName),
		func() (bool, string) { return true, "" }, iamauthz.WithResourceAccount(callerAcct))
	if callerAcct == roleAcct && trustNamesCaller(who, trust) {
		if d.ExplicitDeny {
			return false, d.Reason
		}
		return true, ""
	}
	return d.Allowed, d.Reason
}

// trustedARN reports whether an ARN trust entry names the caller: its account's root (every principal of
// that account), or the user or role of that account. A caller with no account matches none.
func trustedARN(c trustCaller, arn string) bool {
	if c.account == "" || (c.kind != "User" && c.kind != "Role") {
		return false
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[2] != "iam" || parts[4] != c.account {
		return false
	}
	res := parts[5]
	if res == "root" {
		return true
	}
	name := c.name
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:] // a role outside the IAM home is "<namespace>/<name>": its ARN names the role alone
	}
	switch {
	case c.kind == "User" && strings.HasPrefix(res, "user/"):
		return lastSegment(res) == name
	case c.kind == "Role" && strings.HasPrefix(res, "role/"):
		return lastSegment(res) == name
	}
	return false
}

// lastSegment is the name at the end of an IAM resource path (user/path/name -> name).
func lastSegment(res string) string {
	if i := strings.LastIndexByte(res, '/'); i >= 0 {
		return res[i+1:]
	}
	return res
}

func (h *stsHandler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	// STS's dialect: a query-protocol <ErrorResponse> with the SignatureDoesNotMatch code.
	writeQueryError(w, http.StatusForbidden, authCode(r, "SignatureDoesNotMatch"), requestID,
		authMessage(r, "The request signature we calculated does not match the signature you provided."), stsXMLNamespace)
}

const stsXMLNamespace = "https://sts.amazonaws.com/doc/2011-06-15/"

// stsAction extracts the query-protocol Action. It is in the form body (POST) or the query string.
func stsAction(r *http.Request) string {
	if err := r.ParseForm(); err == nil {
		if a := r.PostFormValue("Action"); a != "" {
			return a
		}
	}
	return r.URL.Query().Get("Action")
}

// getCallerIdentityResponse is the STS GetCallerIdentity XML body. SDKs read Arn/UserId/Account.
type getCallerIdentityResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetCallerIdentityResponse"`
	Result  struct {
		Arn     string `xml:"Arn"`
		UserId  string `xml:"UserId"`
		Account string `xml:"Account"`
	} `xml:"GetCallerIdentityResult"`
	ResponseMetadata struct {
		RequestId string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

// assumeRoleResponse is the STS AssumeRole XML body — SDKs read Credentials + AssumedRoleUser.
type assumeRoleResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyId     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
		AssumedRoleUser struct {
			Arn           string `xml:"Arn"`
			AssumedRoleId string `xml:"AssumedRoleId"`
		} `xml:"AssumedRoleUser"`
	} `xml:"AssumeRoleResult"`
	ResponseMetadata struct {
		RequestId string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

func (h *stsHandler) writeAssumeRole(w http.ResponseWriter, role, session, akid, sk, token string, exp time.Time, requestID string) {
	h.writeAssumeRoleIn(w, h.account, role, session, akid, sk, token, exp, requestID)
}

// writeAssumeRoleIn is writeAssumeRole for a role of account acct: the session's ARN is that account's.
func (h *stsHandler) writeAssumeRoleIn(w http.ResponseWriter, acct, role, session, akid, sk, token string, exp time.Time, requestID string) {
	var resp assumeRoleResponse
	resp.Result.Credentials.AccessKeyId = akid
	resp.Result.Credentials.SecretAccessKey = sk
	resp.Result.Credentials.SessionToken = token
	resp.Result.Credentials.Expiration = exp.UTC().Format(time.RFC3339)
	resp.Result.AssumedRoleUser.Arn = h.identIn(acct).STSARN("assumed-role/" + role + "/" + session)
	resp.Result.AssumedRoleUser.AssumedRoleId = role + ":" + session
	resp.ResponseMetadata.RequestId = requestID
	out, err := xml.Marshal(resp)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "internal error", stsXMLNamespace)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}

// assumeRoleWithWebIdentityResponse is the STS AssumeRoleWithWebIdentity XML body.
type assumeRoleWithWebIdentityResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleWithWebIdentityResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyId     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
		AssumedRoleUser struct {
			Arn           string `xml:"Arn"`
			AssumedRoleId string `xml:"AssumedRoleId"`
		} `xml:"AssumedRoleUser"`
		SubjectFromWebIdentityToken string `xml:"SubjectFromWebIdentityToken"`
		Provider                    string `xml:"Provider"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
	ResponseMetadata struct {
		RequestId string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

func (h *stsHandler) writeWebIdentity(w http.ResponseWriter, role, session, subject, akid, sk, token string, exp time.Time, requestID string) {
	var resp assumeRoleWithWebIdentityResponse
	resp.Result.Credentials.AccessKeyId = akid
	resp.Result.Credentials.SecretAccessKey = sk
	resp.Result.Credentials.SessionToken = token
	resp.Result.Credentials.Expiration = exp.UTC().Format(time.RFC3339)
	resp.Result.AssumedRoleUser.Arn = h.ident().STSARN("assumed-role/" + role + "/" + session)
	resp.Result.AssumedRoleUser.AssumedRoleId = role + ":" + session
	resp.Result.SubjectFromWebIdentityToken = subject
	resp.Result.Provider = "openinfra:serviceaccount"
	resp.ResponseMetadata.RequestId = requestID
	out, err := xml.Marshal(resp)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "internal error", stsXMLNamespace)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}

func (h *stsHandler) writeCallerIdentity(w http.ResponseWriter, claims iam.Claims, requestID string) {
	var resp getCallerIdentityResponse
	// AWS's ARN forms, in the install's account: an assumed-role session is arn:aws:sts::<acct>:
	// assumed-role/<role>/<session> (claims.Sub is "assumed-role/<role>/<sess>"), a user is
	// arn:aws:iam::<acct>:user/<name>.
	acct := h.callerAccount(claims)
	if claims.AssumedRole != "" {
		resp.Result.Arn = h.identIn(acct).STSARN(claims.Sub)
	} else {
		resp.Result.Arn = h.identIn(acct).IAMARN("user/" + claims.Sub)
	}
	resp.Result.UserId = claims.Sub
	resp.Result.Account = acct
	resp.ResponseMetadata.RequestId = requestID

	out, err := xml.Marshal(resp)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "internal error", stsXMLNamespace)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}

// errorResponse is the AWS Query-protocol error envelope (STS, IAM, EC2, …).
type errorResponse struct {
	XMLName   xml.Name `xml:"ErrorResponse"`
	Xmlns     string   `xml:"xmlns,attr"`
	Error     queryError
	RequestId string `xml:"RequestId"`
}

type queryError struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// writeQueryError writes an AWS Query-protocol <ErrorResponse> with the given code/status.
func writeQueryError(w http.ResponseWriter, status int, code, requestID, message, xmlns string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
	body := errorResponse{Xmlns: xmlns, RequestId: requestID}
	body.Error = queryError{Type: "Sender", Code: code, Message: message}
	out, err := xml.Marshal(body)
	if err != nil {
		http.Error(w, "InternalFailure", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}
