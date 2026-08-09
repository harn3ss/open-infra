package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// jwtAuthenticator verifies OIDC / Cognito User Pools JWTs for the AppSync data plane — the ONE
// non-SigV4 authentication path, scoped structurally to the appsync service (no other service accepts
// it). It reuses coreos/go-oidc: JWKS discovery + signature / issuer / audience / expiry verification,
// which rejects alg:none and unknown keys for us (hand-rolled JWT is how bypasses happen). Config is
// shim-global — one issuer/audience/mode — matching the shim's single GRAPHQL_ENDPOINT shape.
//
// On success it produces the SAME principal contract as the SigV4 path (iam.Claims{Sub, Groups}) plus
// the auth mode to forward, so the engine gates @aws_oidc / @aws_cognito_user_pools fields and runs the
// field's SAR against the token subject — one policy world.
type jwtAuthenticator struct {
	verifier    *oidc.IDTokenVerifier
	groupsClaim string
	mode        string // forwarded auth mode: aws_oidc | aws_cognito_user_pools
}

// newJWTAuthenticator builds the verifier from the OIDC issuer (discovery → JWKS). audience is REQUIRED
// (empty is refused by the caller) so a token minted for another audience is rejected. mode is the
// explicit auth mode this issuer represents (never inferred — see resolveGroupsClaim for the one thing
// that IS inferred). groupsClaim is the token claim carrying the caller's groups.
func newJWTAuthenticator(ctx context.Context, issuer, audience, groupsClaim, mode string) (*jwtAuthenticator, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover issuer %q: %w", issuer, err)
	}
	// ClientID set ⇒ go-oidc enforces the audience. We require audience upstream, so it is always on.
	verifier := provider.Verifier(&oidc.Config{ClientID: audience})
	return &jwtAuthenticator{verifier: verifier, groupsClaim: groupsClaim, mode: mode}, nil
}

// verify checks the token (signature via JWKS, issuer, audience, expiry; alg:none and unknown keys are
// rejected by go-oidc) and returns the principal + the mode to forward. Any failure is an error — the
// caller rejects it exactly as hard as a bad SigV4 signature.
func (j *jwtAuthenticator) verify(ctx context.Context, rawToken string) (iam.Claims, string, error) {
	idToken, err := j.verifier.Verify(ctx, rawToken)
	if err != nil {
		return iam.Claims{}, "", err
	}
	if idToken.Subject == "" {
		return iam.Claims{}, "", fmt.Errorf("oidc: token has no subject")
	}
	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return iam.Claims{}, "", fmt.Errorf("oidc: parse claims: %w", err)
	}
	// CRITICAL: run the token's groups through the SAME single-source-of-truth transform every other
	// front door uses (iam.GroupsFromSpec) BEFORE they become k8s impersonation groups. This namespaces
	// each to "openinfra:<group>" so an untrusted token claim can never collide with a real cluster group
	// (e.g. system:masters) and impersonate cluster-admin, and appends "openinfra:users" so an empty
	// groups claim resolves to the authenticated-but-unprivileged set (fail-closed at RBAC), never a
	// default role. Field cognito_groups requirements are matched in this same namespaced vocabulary.
	groups := iam.GroupsFromSpec(extractGroups(raw[j.groupsClaim]))
	return iam.Claims{Sub: idToken.Subject, Groups: groups}, j.mode, nil
}

// extractGroups reads a groups claim that may be a string array, a []string, or a single string.
func extractGroups(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}

// resolveGroupsClaim returns the groups-claim name: an explicit override ALWAYS wins; otherwise the
// issuer picks the DEFAULT claim name (Cognito uses cognito:groups, generic OIDC uses groups). This
// issuer inference decides ONLY the default claim name — nothing security-relevant (mode + audience are
// explicit config).
func resolveGroupsClaim(override, issuer string) string {
	if override != "" {
		return override
	}
	if strings.Contains(issuer, "cognito-idp.") {
		return "cognito:groups"
	}
	return "groups"
}

// bearerToken extracts a JWT from an Authorization header for the appsync JWT path. Clients send
// "Authorization: Bearer <jwt>" or the raw token; either way it must look like a JWT (header.payload.sig
// — the signature segment may be empty, e.g. an alg:none forgery, which we deliberately still route so
// the verifier rejects it). A SigV4 Authorization ("AWS4-HMAC-SHA256 …") is not a bearer token.
func bearerToken(authHeader string) (string, bool) {
	h := strings.TrimSpace(authHeader)
	if h == "" || strings.HasPrefix(h, "AWS4-HMAC-SHA256") {
		return "", false
	}
	if len(h) >= 7 && strings.EqualFold(h[:7], "bearer ") {
		h = strings.TrimSpace(h[7:])
	}
	if parts := strings.Split(h, "."); len(parts) == 3 && parts[0] != "" && parts[1] != "" {
		return h, true
	}
	return "", false
}
