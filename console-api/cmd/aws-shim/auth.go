package main

import (
	"context"
	"errors"
	"net/http"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/awssig"
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
}

// authenticate proves the caller holds a valid open-infra access key and returns the iam.Claims
// the request will act as. It performs NO authorization — that is iam.CanDo's job, run afterward
// by the handler against the specific action — keeping "who you are" strictly separate from "what
// you may do", and ensuring the authorization check runs against the very identity that was proven.
func (a *authenticator) authenticate(ctx context.Context, r *http.Request) (iam.Claims, error) {
	cred, err := awssig.ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return iam.Claims{}, errAuth
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
