package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/awssig"
	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// errAuth is the single failure the authenticator surfaces. Every distinct reason a request can
// fail authentication — no Authorization header, an unknown access key, a bad signature, a
// vanished/disabled owner — collapses to this one error, which the handler maps to S3's
// SignatureDoesNotMatch. Nothing an attacker observes distinguishes "that key does not exist"
// from "your signature was wrong", so valid key IDs can't be enumerated by probing.
var errAuth = errors.New("aws-shim: authentication failed")

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
			return iam.Claims{}, errAuth
		}
		if err := awssig.Verify(r, cred, sess.SecretKey); err != nil {
			return iam.Claims{}, errAuth
		}
		// Per-role "Revoke sessions": a session minted before the role's
		// revokeSessionsBefore cutoff is revoked — denied here even though its token is valid and
		// unexpired, the AWS AWSRevokeOlderSessions analog. Checked AFTER the SigV4 verify so a
		// forged-signature request never triggers the k8s cutoff read. New assumes (issued at/after
		// the cutoff) survive; nil revoker leaves behaviour unchanged (fail-open only for that check,
		// crypto + expiry still enforced — see roleCutoffCache's failure posture).
		if a.revoke != nil {
			if cutoff, on := a.revoke.RevokedBefore(ctx, sess.RoleName); on && sess.IssuedAt.Before(cutoff) {
				return iam.Claims{}, errAuth
			}
		}
		return iam.Claims{
			Sub:         "assumed-role/" + sess.RoleName + "/" + sess.SessionName,
			Groups:      sess.Groups,
			AssumedRole: sess.RoleName,
		}, nil
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
	groups, ok := a.resolve(ctx, key.Owner)
	if !ok {
		return iam.Claims{}, errAuth
	}
	return iam.Claims{Sub: key.Owner, Groups: groups}, nil
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
			return iam.Claims{}, errAuth
		}
		if err := awssig.VerifyPresigned(r, p, sess.SecretKey, now); err != nil {
			return iam.Claims{}, errAuth
		}
		if a.revoke != nil {
			if cutoff, on := a.revoke.RevokedBefore(ctx, sess.RoleName); on && sess.IssuedAt.Before(cutoff) {
				return iam.Claims{}, errAuth
			}
		}
		return iam.Claims{
			Sub:         "assumed-role/" + sess.RoleName + "/" + sess.SessionName,
			Groups:      sess.Groups,
			AssumedRole: sess.RoleName,
		}, nil
	}
	key, ok := a.keys.Lookup(ctx, p.AccessKeyID)
	if !ok {
		return iam.Claims{}, errAuth
	}
	if err := awssig.VerifyPresigned(r, p, key.SecretKey, now); err != nil {
		return iam.Claims{}, errAuth
	}
	groups, ok := a.resolve(ctx, key.Owner)
	if !ok {
		return iam.Claims{}, errAuth
	}
	return iam.Claims{Sub: key.Owner, Groups: groups}, nil
}
