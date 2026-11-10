package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/awssig"
	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// errAuth is the single failure the authenticator surfaces. Every distinct reason a request can
// fail authentication — no Authorization header, an unknown access key, a bad signature, a
// vanished/disabled owner — collapses to this one error, which the handler maps to S3's
// SignatureDoesNotMatch. Nothing an attacker observes distinguishes "that key does not exist"
// from "your signature was wrong", so valid key IDs can't be enumerated by probing.
var errAuth = errors.New("aws-shim: authentication failed")

// errExpiredToken is the one failure answered apart: a request signed with an authentic session's own
// secret whose session has expired. AWS answers it ExpiredToken (ExpiredTokenException in the JSON
// protocols), which tells an SDK to renew its credentials; revealing it tells the caller nothing it did
// not already hold (the session's secret). Each service writes it in its dialect (authCode, authMessage).
var errExpiredToken = errors.New("aws-shim: the security token included in the request is expired")

type expiredTokenKey struct{}

// withExpiredToken marks r as refused for an expired session token, for its service's authFailure.
func withExpiredToken(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), expiredTokenKey{}, true))
}

func expiredToken(r *http.Request) bool {
	if r == nil {
		return false
	}
	v, _ := r.Context().Value(expiredTokenKey{}).(bool)
	return v
}

// authCode is a service's authentication-failure code for r: AWS's expired-token code when r's session
// token had expired (ExpiredTokenException where the service's code is an ...Exception, else
// ExpiredToken), the service's own code otherwise.
func authCode(r *http.Request, code string) string {
	if !expiredToken(r) {
		return code
	}
	if strings.HasSuffix(code, "Exception") {
		return "ExpiredTokenException"
	}
	return "ExpiredToken"
}

// authMessage is the failure's message: AWS's for an expired session token, the service's own otherwise.
func authMessage(r *http.Request, msg string) string {
	if expiredToken(r) {
		return "The security token included in the request is expired"
	}
	return msg
}

// keyLookuper resolves an access key ID to its secret + owner (satisfied by *awskeys.Store).
type keyLookuper interface {
	Lookup(ctx context.Context, accessKeyID string) (awskeys.Key, bool)
}

// ownerResolver returns the CURRENT impersonation groups for a principal (a kind: User name), or
// ok=false if that user no longer exists or is disabled. Resolving fresh on every request is
// deliberate: revoking a group (or the whole user) takes effect immediately, without having to
// touch or re-mint the access key.
type ownerResolver func(ctx context.Context, owner string) (groups []string, ok bool)

type authenticator struct {
	keys    keyLookuper
	resolve ownerResolver
	sts     *awssts.Minter // verifies sts:AssumeRole session tokens; nil disables assumed-role auth
	revoke  sessionRevoker // per-role revokeSessionsBefore cutoff; nil disables it
	// home is the IAM home namespace (ROLES_NAMESPACE): a session for a Role there acts as the bare
	// role name; one for a Role elsewhere as "<namespace>/<name>". "" means the default home.
	home string
	// dir maps namespaces to accounts (internal/accounts); nil puts every principal in the management
	// account, as before accounts existed.
	dir *accounts.Directory
	// resolveIn resolves a key's owner that lives in a member account's home namespace (ns). nil: a key
	// recording a member account does not authenticate.
	resolveIn func(ctx context.Context, ns, owner string) (groups []string, ok bool)
}

// accountOfNamespace is the account namespace ns belongs to, "" for the management account (and for an
// authenticator with no directory).
func (a *authenticator) accountOfNamespace(ns string) string {
	if a.dir == nil {
		return ""
	}
	if acct := a.dir.AccountOf(ns); acct != "" && !a.dir.IsManagement(acct) {
		return acct
	}
	return ""
}

// memberAccount reports whether acct names a member account ("" and the management account do not).
func (a *authenticator) memberAccount(acct string) bool {
	return acct != "" && a.dir != nil && !a.dir.IsManagement(acct)
}

// keyClaims is the identity an access key acts as: its owner, in the account the key records (a key
// minted before accounts: the account of the namespace its owner lives in, the IAM home's). A principal
// of a suspended account, or of an account the directory does not know, does not authenticate.
func (a *authenticator) keyClaims(ctx context.Context, key awskeys.Key) (iam.Claims, bool) {
	acct := key.Account
	var groups []string
	var ok bool
	if a.memberAccount(acct) {
		home, known := a.dir.HomeOf(acct)
		if !known || a.resolveIn == nil {
			return iam.Claims{}, false
		}
		groups, ok = a.resolveIn(ctx, home, key.Owner)
	} else {
		groups, ok = a.resolve(ctx, key.Owner)
		acct = a.accountOfNamespace(a.ownerNamespace())
	}
	if !ok || (a.dir != nil && acct != "" && a.dir.Suspended(acct)) {
		return iam.Claims{}, false
	}
	return iam.Claims{Sub: key.Owner, Groups: groups, Account: acct}, true
}

// ownerNamespace is where a management-account key's owner (a kind: User) lives: the IAM home.
func (a *authenticator) ownerNamespace() string {
	if a.home == "" {
		return dataplaneauthz.DefaultHomeNamespace
	}
	return a.home
}

// sessionClaims is the identity a verified assumed-role session acts as. Its data-plane principal is
// the role's canonical id (dataplaneauthz.QualifiedName), so a Role in another namespace never acts
// with — or is revoked by — a same-named home Role. ok=false when the role's "Revoke sessions" cutoff
// (spec.revokeSessionsBefore, the AWSRevokeOlderSessions analog) postdates the session: it is denied
// even though its token is valid and unexpired. A nil revoker skips that check (crypto + expiry still
// gate the request; see roleCutoffCache's failure posture).
func (a *authenticator) sessionClaims(ctx context.Context, sess awssts.Session) (iam.Claims, bool) {
	if sess.User != "" {
		return a.userSessionClaims(ctx, sess)
	}
	home := a.home
	if home == "" {
		home = dataplaneauthz.DefaultHomeNamespace
	}
	// The role's principal is its object (the IAM policy world keys a role by its object name), which is
	// its AWS name lower-cased — OrganizationAccountAccessRole is the object organizationaccountaccessrole
	// (dynRoleResolver.ResolveIn) — while the session's ARN keeps the AWS name, as AWS shows it.
	principal := dataplaneauthz.QualifiedName(home, sess.Namespace, strings.ToLower(sess.RoleName))
	if a.revoke != nil {
		if cutoff, on := a.revoke.RevokedBefore(ctx, principal); on && sess.IssuedAt.Before(cutoff) {
			return iam.Claims{}, false
		}
	}
	// The session acts in the account of the role it assumed: the one its token records, else (a token
	// minted before accounts) the account of the namespace the role lives in.
	acct := sess.Account
	if !a.memberAccount(acct) {
		roleNS := sess.Namespace
		if roleNS == "" {
			roleNS = home
		}
		acct = a.accountOfNamespace(roleNS)
	}
	if a.dir != nil && acct != "" && a.dir.Suspended(acct) {
		return iam.Claims{}, false
	}
	return iam.Claims{
		Sub:           "assumed-role/" + sess.RoleName + "/" + sess.SessionName,
		Groups:        sess.Groups,
		AssumedRole:   principal,
		SessionExpiry: sess.Expiry,
		Account:       acct,
		MFA:           sessionMFA(sess),
	}, true
}

// userSessionClaims is the identity an IAM user's own session (sts:GetSessionToken) acts as: the user, as
// its access key would (its groups resolved fresh, so a user deleted or disabled since is no one), with
// the session's MFA context. AWS restricts what such a session may call (Claims.UserSession).
func (a *authenticator) userSessionClaims(ctx context.Context, sess awssts.Session) (iam.Claims, bool) {
	c, ok := a.keyClaims(ctx, awskeys.Key{Owner: sess.User, Account: sess.Account})
	if !ok {
		return iam.Claims{}, false
	}
	c.SessionExpiry = sess.Expiry
	c.MFA = sessionMFA(sess)
	c.UserSession = true
	return c, true
}

// sessionMFA is a session's MFA context, as AWS carries it on a temporary credential: authenticated with
// MFA (and when), or not; none at all for a web-identity session, for which AWS cannot know.
func sessionMFA(sess awssts.Session) *iam.MFAContext {
	switch {
	case sess.Federated:
		return nil
	case sess.MFA:
		return &iam.MFAContext{Present: true, AuthTime: sess.MFAAuthTime}
	}
	return iam.NoMFA()
}

// authenticate proves the caller holds a valid open-infra access key and returns the iam.Claims
// the request will act as. It performs NO authorization — that is iam.CanDo's job, run afterward
// by the handler against the specific action — keeping "who you are" strictly separate from "what
// you may do", and ensuring the authorization check runs against the very identity that was proven.
func (a *authenticator) authenticate(ctx context.Context, r *http.Request) (iam.Claims, error) {
	// Presigned URL (query-string SigV4): no Authorization header — the credential and signature
	// ride in the query (X-Amz-Algorithm=AWS4-HMAC-SHA256). A browser fetching a presigned GET/PUT
	// has no AWS headers to header-sign, so this is the only path by which those requests can
	// authenticate. It is verified exactly like a header-signed request (recompute from the key's
	// secret) and returns the same Claims, so the handler's RBAC/Cedar authorization is unchanged.
	if r.Header.Get("Authorization") == "" && r.URL.Query().Get("X-Amz-Algorithm") != "" {
		return a.authenticatePresigned(ctx, r)
	}
	cred, err := awssig.ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return iam.Claims{}, errAuth
	}
	// Assumed-role path: a request carrying a session token (X-Amz-Security-Token) is an
	// sts:AssumeRole credential. Verify the sealed token, then verify the SigV4 signature against the
	// temp secret the token carries, and act AS the role. Falls closed on any failure.
	if tok := r.Header.Get("X-Amz-Security-Token"); tok != "" {
		if a.sts == nil {
			return iam.Claims{}, errAuth
		}
		sess, ok := a.sts.Verify(cred.AccessKeyID, tok)
		if !ok {
			if exp, isExp := a.sts.VerifyExpired(cred.AccessKeyID, tok); isExp && awssig.Verify(r, cred, exp.SecretKey) == nil {
				return iam.Claims{}, errExpiredToken
			}
			return iam.Claims{}, errAuth
		}
		if err := awssig.Verify(r, cred, sess.SecretKey); err != nil {
			return iam.Claims{}, errAuth
		}
		// Per-role "Revoke sessions" is checked AFTER the SigV4 verify so a forged-signature request
		// never triggers the k8s cutoff read (sessionClaims).
		claims, ok := a.sessionClaims(ctx, sess)
		if !ok {
			return iam.Claims{}, errAuth
		}
		return claims, nil
	}
	key, ok := a.keys.Lookup(ctx, cred.AccessKeyID)
	if !ok {
		return iam.Claims{}, errAuth
	}
	// The heart of it: recompute the signature from the stored secret and constant-time compare.
	// A caller who merely NAMES a valid key but cannot reproduce its signature is rejected here.
	if err := awssig.Verify(r, cred, key.SecretKey); err != nil {
		return iam.Claims{}, errAuth
	}
	claims, ok := a.keyClaims(ctx, key)
	if !ok {
		return iam.Claims{}, errAuth
	}
	return claims, nil
}

// authenticatePresigned is the query-string (presigned URL) analog of authenticate: same identity
// resolution and the same fail-closed, single-errAuth posture, but the SigV4 material comes from the
// query and expiry (X-Amz-Expires) is enforced. It supports the assumed-role case too, where the
// session token rides in the (signed) X-Amz-Security-Token query parameter.
func (a *authenticator) authenticatePresigned(ctx context.Context, r *http.Request) (iam.Claims, error) {
	p, err := awssig.ParsePresigned(r)
	if err != nil {
		return iam.Claims{}, errAuth
	}
	now := time.Now()
	if tok := r.URL.Query().Get("X-Amz-Security-Token"); tok != "" {
		if a.sts == nil {
			return iam.Claims{}, errAuth
		}
		sess, ok := a.sts.Verify(p.AccessKeyID, tok)
		if !ok {
			if exp, isExp := a.sts.VerifyExpired(p.AccessKeyID, tok); isExp && awssig.VerifyPresigned(r, p, exp.SecretKey, now) == nil {
				return iam.Claims{}, errExpiredToken
			}
			return iam.Claims{}, errAuth
		}
		if err := awssig.VerifyPresigned(r, p, sess.SecretKey, now); err != nil {
			return iam.Claims{}, errAuth
		}
		claims, ok := a.sessionClaims(ctx, sess)
		if !ok {
			return iam.Claims{}, errAuth
		}
		return claims, nil
	}
	key, ok := a.keys.Lookup(ctx, p.AccessKeyID)
	if !ok {
		return iam.Claims{}, errAuth
	}
	if err := awssig.VerifyPresigned(r, p, key.SecretKey, now); err != nil {
		return iam.Claims{}, errAuth
	}
	claims, ok := a.keyClaims(ctx, key)
	if !ok {
		return iam.Claims{}, errAuth
	}
	return claims, nil
}
