package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// lambdaAuthorizer validates the AppSync @aws_lambda auth mode — the fifth and last AWS auth mode — by
// invoking a tenant's authorizer Function (kind: Function) and mapping its verdict into the shim's
// principal contract. Like the OIDC path it produces iam.Claims{Sub, Groups} plus the forwarded mode
// (aws_lambda), so the engine gates @aws_lambda fields and runs the field's SAR against the authorizer's
// returned subject — one policy world. Config is shim-global (one authorizer Function), matching the
// shim's single GRAPHQL_ENDPOINT / one-issuer shape.
//
// AUTHORITY-RELOCATION COST (stated plainly, per the auth-directive decision): AWS's Lambda authorizer
// can also return deniedFields (per-field denial) and ttlOverride (auth-result caching). open-appsync
// does NOT honor either. Honoring deniedFields would make the tenant's Lambda a PARALLEL field-authorization
// layer living outside the one policy world — exactly the arrangement the decision rules out. Field-level
// control stays with the resolver's SAR auth (the field `auth` block); ttlOverride is moot with no auth
// cache. A migrator relying on deniedFields must move that logic into the resolver's SAR requirements.
type lambdaAuthorizer struct {
	client      *http.Client
	fnURL       string // resolved kind: Function URL: http://<name>.<ns>.<suffix>/
	fnName      string
	userClaim   string // resolverContext key carrying the subject (default "sub")
	groupsClaim string // resolverContext key carrying the caller's groups (default "groups")
}

func newLambdaAuthorizer(fnName, fnNS, svcSuffix, userClaim, groupsClaim string) *lambdaAuthorizer {
	return &lambdaAuthorizer{
		client:      &http.Client{Timeout: 10 * time.Second},
		fnURL:       "http://" + fnName + "." + fnNS + "." + svcSuffix + "/",
		fnName:      fnName,
		userClaim:   userClaim,
		groupsClaim: groupsClaim,
	}
}

// authorizerEvent is the payload POSTed to the authorizer Function. It mirrors AppSync's Lambda-authorizer
// event (authorizationToken + requestContext), so an unmodified AppSync authorizer runs here.
type authorizerEvent struct {
	AuthorizationToken string         `json:"authorizationToken"`
	RequestContext     map[string]any `json:"requestContext,omitempty"`
}

// authorizerResponse is the authorizer's verdict (AppSync's shape). Only isAuthorized and resolverContext
// are consulted; deniedFields/ttlOverride are decoded but deliberately ignored (see the type doc).
type authorizerResponse struct {
	IsAuthorized    bool           `json:"isAuthorized"`
	ResolverContext map[string]any `json:"resolverContext"`
	DeniedFields    []string       `json:"deniedFields"`
	TTLOverride     *int           `json:"ttlOverride"`
}

// verify invokes the authorizer with the caller's token and returns the principal on isAuthorized:true.
// EVERY failure mode — unreachable, non-2xx, unparseable, or isAuthorized:false — is an error, so the
// caller rejects it exactly as hard as a bad SigV4 signature (fail closed).
func (l *lambdaAuthorizer) verify(ctx context.Context, token string) (iam.Claims, error) {
	body, err := json.Marshal(authorizerEvent{
		AuthorizationToken: token,
		RequestContext:     map[string]any{"apiId": "open-appsync"},
	})
	if err != nil {
		return iam.Claims{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.fnURL, bytes.NewReader(body))
	if err != nil {
		return iam.Claims{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(req)
	if err != nil {
		return iam.Claims{}, fmt.Errorf("lambda authorizer %q unreachable: %w", l.fnName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return iam.Claims{}, fmt.Errorf("lambda authorizer %q returned status %d", l.fnName, resp.StatusCode)
	}
	var out authorizerResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return iam.Claims{}, fmt.Errorf("lambda authorizer %q: parse response: %w", l.fnName, err)
	}
	if !out.IsAuthorized {
		return iam.Claims{}, fmt.Errorf("lambda authorizer %q denied the request", l.fnName)
	}
	// Map the authorizer's returned identity into the one policy world. Groups run through the SAME
	// single-source-of-truth transform every other front door uses (iam.GroupsFromSpec): each is
	// namespaced to "openinfra:<group>" so an authorizer-returned group can never collide with a real
	// cluster group (e.g. system:masters), and an empty set resolves to the authenticated-but-unprivileged
	// floor ("openinfra:users"), never a default role — fail-closed at RBAC.
	sub := stringClaim(out.ResolverContext, l.userClaim)
	groups := iam.GroupsFromSpec(extractGroups(out.ResolverContext[l.groupsClaim]))
	return iam.Claims{Sub: sub, Groups: groups}, nil
}

// stringClaim reads a string value from the resolver context, tolerating absence / wrong type.
func stringClaim(ctx map[string]any, key string) string {
	if ctx == nil {
		return ""
	}
	if s, ok := ctx[key].(string); ok {
		return s
	}
	return ""
}
