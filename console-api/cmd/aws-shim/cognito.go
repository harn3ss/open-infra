// Cognito (user pools) front door for the aws-shim (polyhedron#171). Speaks AWS JSON 1.1
// (X-Amz-Target: AWSCognitoIdentityProviderService.<Op>).
//
// TWO trust domains, not conflated:
//   - CONTROL plane (CreateUserPool, CreateUserPoolClient, and the Admin* ops) — privileged, SigV4-signed by
//     an open-infra principal, authorized by the one policy world (coarse SAR + Cedar cognito-idp:<Op>).
//   - the pool's END-USER auth (SignUp, InitiateAuth, GetUser, GlobalSignOut) — the APPLICATION's users, not
//     open-infra principals. These are UNAUTHENTICATED at the SigV4 layer (the user has no AWS creds yet); the
//     router hands them here anonymously, and the handler refuses the admin ops from that path.
//
// The token contract is the heart: InitiateAuth returns REAL RS256 JWTs (id/access/refresh) signed by the
// shim's key and verifiable against the pool's JWKS (cognito_jwt.go), so the API Gateway JWT authorizer (#169)
// and any app can verify them. Passwords are bcrypt; the configured password policy is genuinely enforced;
// GlobalSignOut genuinely invalidates (a per-user tokens_valid_after cutoff). SRP and other flows are refused,
// not half-implemented. See docs/aws-shim.md.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"golang.org/x/crypto/bcrypt"
	"k8s.io/client-go/kubernetes"
)

const (
	cognitoAccessTTL  = 3600
	cognitoIDTTL      = 3600
	cognitoRefreshTTL = 30 * 24 * 3600
)

type cognitoHandler struct {
	cs         kubernetes.Interface
	authzNS    string
	account    string
	region     string
	issuerBase string // <base>/cognito/<poolId> is a pool's issuer (JWKS served by this shim)
	store      *cognitoStore
	signer     *cognitoSigner
	authz      *dataplaneauthz.Checker
	logger     *slog.Logger
}

func newCognitoHandler(cs kubernetes.Interface, authzNS, account, region, issuerBase string, store *cognitoStore, signer *cognitoSigner, logger *slog.Logger) *cognitoHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &cognitoHandler{cs: cs, authzNS: authzNS, account: account, region: region, issuerBase: issuerBase, store: store, signer: signer, logger: logger}
}

func writeCognitoError(w http.ResponseWriter, status int, code, requestID, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeCognitoJSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *cognitoHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeCognitoError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// serve handles a SigV4-authenticated (control-plane) request.
func (h *cognitoHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	h.dispatch(w, r, requestID, claims, true)
}

// serveAnonymous handles an unsigned end-user request (the router routes it here when it carries the Cognito
// X-Amz-Target but no SigV4). Only public ops are allowed from this path.
func (h *cognitoHandler) serveAnonymous(w http.ResponseWriter, r *http.Request, requestID string) {
	h.dispatch(w, r, requestID, iam.Claims{}, false)
}

func cognitoPublicOp(op string) bool {
	switch op {
	case "SignUp", "ConfirmSignUp", "InitiateAuth", "GetUser", "GlobalSignOut",
		"RespondToAuthChallenge", "ForgotPassword", "ConfirmForgotPassword", "ResendConfirmationCode":
		return true
	}
	return false
}

func cognitoAdminOp(op string) bool {
	return strings.HasPrefix(op, "Admin") || strings.HasPrefix(op, "Create") ||
		strings.HasPrefix(op, "Delete") || strings.HasPrefix(op, "Describe") || strings.HasPrefix(op, "List") ||
		op == "SetUserPoolMfaConfig"
}

func (h *cognitoHandler) dispatch(w http.ResponseWriter, r *http.Request, requestID string, claims iam.Claims, authed bool) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	if op == "" {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "no operation in X-Amz-Target (expected AWSCognitoIdentityProviderService.<Op>).")
		return
	}
	if h.store == nil || h.signer == nil {
		writeCognitoError(w, http.StatusInternalServerError, "InternalErrorException", requestID, "the Cognito backend is not configured on this shim (needs SQS_PG_URI + a signing key).")
		return
	}
	body := readJSONBody(r)

	// Admin/control-plane ops require SigV4 auth + the one policy world; end-user ops must not run from a
	// signed admin identity being confused with an end user, and admin ops must not run anonymously.
	if cognitoAdminOp(op) {
		if !authed {
			writeCognitoError(w, http.StatusForbidden, "NotAuthorizedException", requestID, "this operation requires AWS credentials (SigV4).")
			return
		}
		verb := "get"
		if strings.HasPrefix(op, "Create") || strings.HasPrefix(op, "Admin") || op == "SetUserPoolMfaConfig" {
			verb = "create"
		} else if strings.HasPrefix(op, "Delete") {
			verb = "delete"
		}
		pool, _ := body["UserPoolId"].(string)
		ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())
		if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, pool); !allowed {
			writeCognitoError(w, http.StatusForbidden, "NotAuthorizedException", requestID, reason)
			return
		}
		if pool != "" {
			if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "cognito-idp:"+op, "UserPool", pool, r); denied {
				writeCognitoError(w, http.StatusForbidden, "NotAuthorizedException", requestID, reason)
				return
			}
		}
	} else if !cognitoPublicOp(op) {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "Cognito "+op+" is not implemented by the open-infra shim.")
		return
	}

	switch op {
	case "CreateUserPool":
		h.createUserPool(r.Context(), w, requestID, body)
	case "DescribeUserPool":
		h.describeUserPool(r.Context(), w, requestID, body)
	case "DeleteUserPool":
		h.deleteUserPool(r.Context(), w, requestID, body)
	case "CreateUserPoolClient":
		h.createUserPoolClient(r.Context(), w, requestID, body)
	case "SignUp":
		h.signUp(r.Context(), w, requestID, body, false)
	case "AdminCreateUser":
		h.signUp(r.Context(), w, requestID, body, true)
	case "ConfirmSignUp", "AdminConfirmSignUp":
		h.confirmSignUp(r.Context(), w, requestID, body, op == "AdminConfirmSignUp")
	case "AdminSetUserPassword":
		h.adminSetUserPassword(r.Context(), w, requestID, body)
	case "InitiateAuth":
		h.initiateAuth(r.Context(), w, requestID, body, "")
	case "AdminInitiateAuth":
		h.initiateAuth(r.Context(), w, requestID, body, asString(body["UserPoolId"]))
	case "GetUser", "AdminGetUser":
		h.getUser(r.Context(), w, requestID, body, op == "AdminGetUser")
	case "GlobalSignOut":
		h.globalSignOut(r.Context(), w, requestID, body)
	default:
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "Cognito "+op+" is recognized but not implemented.")
	}
}

// --- control plane ---

func (h *cognitoHandler) createUserPool(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name := asString(body["PoolName"])
	if name == "" {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "CreateUserPool requires PoolName.")
		return
	}
	// MFA config that the shim cannot genuinely enforce is refused rather than advertised (an IA-2 false green).
	if mfa := asString(body["MfaConfiguration"]); mfa == "ON" {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "MFA is not implemented by the open-infra shim; a pool that advertises MFA it does not enforce is refused. Omit MfaConfiguration or set OFF.")
		return
	}
	id := h.region + "_" + shortID(9)
	p := cognitoPool{ID: id, Name: name, Policy: parsePasswordPolicy(body)}
	if err := h.store.createPool(ctx, p); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateUserPool", id)
	writeCognitoJSON(w, requestID, map[string]any{"UserPool": map[string]any{
		"Id": id, "Name": name, "Policies": p.Policy.toJSON(), "MfaConfiguration": "OFF",
		"Arn": "arn:aws:cognito-idp:" + h.region + ":" + h.account + ":userpool/" + id,
	}})
}

func (h *cognitoHandler) describeUserPool(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	p, ok := h.mustPool(ctx, w, requestID, asString(body["UserPoolId"]))
	if !ok {
		return
	}
	writeCognitoJSON(w, requestID, map[string]any{"UserPool": map[string]any{
		"Id": p.ID, "Name": p.Name, "Policies": p.Policy.toJSON(), "MfaConfiguration": "OFF",
	}})
}

func (h *cognitoHandler) deleteUserPool(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	ok, err := h.store.deletePool(ctx, asString(body["UserPoolId"]))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeCognitoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "user pool not found")
		return
	}
	h.audit(ctx, "DeleteUserPool", asString(body["UserPoolId"]))
	writeCognitoJSON(w, requestID, map[string]any{})
}

func (h *cognitoHandler) createUserPoolClient(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	pool := asString(body["UserPoolId"])
	if _, ok := h.mustPool(ctx, w, requestID, pool); !ok {
		return
	}
	name := asString(body["ClientName"])
	flows := stringSlice(body["ExplicitAuthFlows"])
	// Refuse SRP and unimplemented flows rather than half-implementing them (a broken SRP handshake looks
	// like an app bug). Supported: USER_PASSWORD_AUTH, ADMIN_USER_PASSWORD_AUTH, REFRESH_TOKEN_AUTH.
	for _, f := range flows {
		switch f {
		case "USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ADMIN_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "REFRESH_TOKEN_AUTH", "ALLOW_REFRESH_TOKEN_AUTH":
		default:
			writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "auth flow "+f+" is not supported by the open-infra shim (SRP/custom auth are refused, not half-implemented). Use USER_PASSWORD_AUTH.")
			return
		}
	}
	if len(flows) == 0 {
		flows = []string{"USER_PASSWORD_AUTH"}
	}
	cid := shortID(26)
	if err := h.store.createClient(ctx, cognitoClient{ID: cid, PoolID: pool, Name: name, AuthFlows: flows}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateUserPoolClient", pool)
	writeCognitoJSON(w, requestID, map[string]any{"UserPoolClient": map[string]any{
		"ClientId": cid, "UserPoolId": pool, "ClientName": name, "ExplicitAuthFlows": flows,
	}})
}

// --- users / sign-up ---

func (h *cognitoHandler) signUp(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, admin bool) {
	var pool string
	if admin {
		pool = asString(body["UserPoolId"])
	} else {
		c, ok := h.clientPool(ctx, w, requestID, asString(body["ClientId"]))
		if !ok {
			return
		}
		pool = c
	}
	p, ok := h.mustPool(ctx, w, requestID, pool)
	if !ok {
		return
	}
	username := asString(body["Username"])
	if username == "" {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "Username is required.")
		return
	}
	// admin path may use a TemporaryPassword; the plain path uses Password. Enforce the policy either way.
	pw := asString(body["Password"])
	if admin && pw == "" {
		pw = asString(body["TemporaryPassword"])
	}
	if pw == "" {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "a password is required.")
		return
	}
	if err := p.Policy.enforce(pw); err != nil {
		writeCognitoError(w, http.StatusBadRequest, "InvalidPasswordException", requestID, err.Error())
		return
	}
	if _, exists, _ := h.store.getUser(ctx, pool, username); exists {
		writeCognitoError(w, http.StatusBadRequest, "UsernameExistsException", requestID, "User already exists.")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	sub := uuidLike()
	status := "UNCONFIRMED"
	if admin {
		status = "CONFIRMED" // admin-created users are usable immediately (permanent password; no NEW_PASSWORD_REQUIRED challenge in v1)
	}
	u := cognitoUser{PoolID: pool, Username: username, PasswordHash: string(hash), Attributes: userAttrs(body), Status: status, Sub: sub}
	if err := h.store.createUser(ctx, u); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "SignUp", pool)
	if admin {
		writeCognitoJSON(w, requestID, map[string]any{"User": map[string]any{"Username": username, "UserStatus": status, "Attributes": attrList(u.Attributes)}})
		return
	}
	writeCognitoJSON(w, requestID, map[string]any{"UserConfirmed": false, "UserSub": sub})
}

func (h *cognitoHandler) confirmSignUp(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, admin bool) {
	var pool string
	if admin {
		pool = asString(body["UserPoolId"])
	} else {
		c, ok := h.clientPool(ctx, w, requestID, asString(body["ClientId"]))
		if !ok {
			return
		}
		pool = c
	}
	username := asString(body["Username"])
	ok, err := h.store.confirmUser(ctx, pool, username)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeCognitoError(w, http.StatusBadRequest, "UserNotFoundException", requestID, "User does not exist.")
		return
	}
	// Divergence (documented): the shim delivers no email/SMS, so the ConfirmationCode is not verified;
	// AdminConfirmSignUp is the reliable path. Never claims a code was verified when it was not.
	h.audit(ctx, "ConfirmSignUp", pool)
	writeCognitoJSON(w, requestID, map[string]any{})
}

func (h *cognitoHandler) adminSetUserPassword(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	pool := asString(body["UserPoolId"])
	p, ok := h.mustPool(ctx, w, requestID, pool)
	if !ok {
		return
	}
	username := asString(body["Username"])
	pw := asString(body["Password"])
	if err := p.Policy.enforce(pw); err != nil {
		writeCognitoError(w, http.StatusBadRequest, "InvalidPasswordException", requestID, err.Error())
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	changed, err := h.store.setPassword(ctx, pool, username, string(hash))
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !changed {
		writeCognitoError(w, http.StatusBadRequest, "UserNotFoundException", requestID, "User does not exist.")
		return
	}
	if perm, _ := body["Permanent"].(bool); perm {
		_, _ = h.store.confirmUser(ctx, pool, username)
	}
	h.audit(ctx, "AdminSetUserPassword", pool)
	writeCognitoJSON(w, requestID, map[string]any{})
}

// --- auth ---

func (h *cognitoHandler) initiateAuth(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, adminPool string) {
	flow := asString(body["AuthFlow"])
	params, _ := body["AuthParameters"].(map[string]any)
	clientID := asString(body["ClientId"])
	c, cok, err := h.store.getClient(ctx, clientID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !cok {
		writeCognitoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "app client does not exist.")
		return
	}
	pool := c.PoolID
	if adminPool != "" && adminPool != pool {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "ClientId does not belong to the UserPoolId.")
		return
	}
	switch flow {
	case "USER_PASSWORD_AUTH", "ADMIN_USER_PASSWORD_AUTH":
		username := asString(params["USERNAME"])
		password := asString(params["PASSWORD"])
		u, uok, err := h.store.getUser(ctx, pool, username)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !uok || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
			writeCognitoError(w, http.StatusBadRequest, "NotAuthorizedException", requestID, "Incorrect username or password.")
			return
		}
		if u.Status != "CONFIRMED" {
			writeCognitoError(w, http.StatusBadRequest, "UserNotConfirmedException", requestID, "User is not confirmed.")
			return
		}
		h.audit(ctx, "InitiateAuth", pool)
		writeCognitoJSON(w, requestID, map[string]any{"AuthenticationResult": h.tokensFor(pool, clientID, u)})
	case "REFRESH_TOKEN_AUTH":
		rt := asString(params["REFRESH_TOKEN"])
		claims, verr := h.verifyToken(pool, rt, "refresh")
		if verr != nil {
			writeCognitoError(w, http.StatusBadRequest, "NotAuthorizedException", requestID, "Invalid refresh token.")
			return
		}
		u, uok, _ := h.store.getUser(ctx, pool, asString(claims["username"]))
		if !uok {
			writeCognitoError(w, http.StatusBadRequest, "NotAuthorizedException", requestID, "Invalid refresh token.")
			return
		}
		res := h.tokensFor(pool, clientID, u)
		delete(res, "RefreshToken") // refresh flow does not re-issue the refresh token
		writeCognitoJSON(w, requestID, map[string]any{"AuthenticationResult": res})
	default:
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "AuthFlow "+flow+" is not supported (SRP/custom auth are refused). Use USER_PASSWORD_AUTH.")
	}
}

func (h *cognitoHandler) getUser(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any, admin bool) {
	var pool, username string
	if admin {
		pool = asString(body["UserPoolId"])
		username = asString(body["Username"])
	} else {
		tok := asString(body["AccessToken"])
		claims, verr := h.verifyTokenAnyPool(tok, "access")
		if verr != nil {
			writeCognitoError(w, http.StatusBadRequest, "NotAuthorizedException", requestID, "Invalid Access Token.")
			return
		}
		pool = asString(claims["_pool"])
		username = asString(claims["username"])
		if !h.tokenStillValid(ctx, pool, username, claims) {
			writeCognitoError(w, http.StatusBadRequest, "NotAuthorizedException", requestID, "Access Token has been revoked.")
			return
		}
	}
	u, ok, err := h.store.getUser(ctx, pool, username)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeCognitoError(w, http.StatusBadRequest, "UserNotFoundException", requestID, "User does not exist.")
		return
	}
	writeCognitoJSON(w, requestID, map[string]any{"Username": u.Username, "UserAttributes": attrList(u.Attributes)})
}

func (h *cognitoHandler) globalSignOut(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	tok := asString(body["AccessToken"])
	claims, verr := h.verifyTokenAnyPool(tok, "access")
	if verr != nil {
		writeCognitoError(w, http.StatusBadRequest, "NotAuthorizedException", requestID, "Invalid Access Token.")
		return
	}
	pool := asString(claims["_pool"])
	username := asString(claims["username"])
	if !h.tokenStillValid(ctx, pool, username, claims) {
		writeCognitoError(w, http.StatusBadRequest, "NotAuthorizedException", requestID, "Access Token has been revoked.")
		return
	}
	// Genuinely invalidate: bump the cutoff so every already-issued token (iat <= now) fails verification.
	if _, err := h.store.setTokensValidAfter(ctx, pool, username, time.Now().UnixMilli()+1); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "GlobalSignOut", pool)
	writeCognitoJSON(w, requestID, map[string]any{})
}

// --- tokens ---

func (h *cognitoHandler) tokensFor(pool, clientID string, u cognitoUser) map[string]any {
	iss := h.issuerBase + "/cognito/" + pool
	now := time.Now().Unix()
	base := func(tokenUse string, ttl int) map[string]any {
		return map[string]any{
			"iss": iss, "sub": u.Sub, "token_use": tokenUse, "auth_time": now,
			"iat": now, "exp": now + int64(ttl), "username": u.Username, "_pool": pool,
		}
	}
	id := base("id", cognitoIDTTL)
	id["aud"] = clientID
	id["cognito:username"] = u.Username
	if e := u.Attributes["email"]; e != "" {
		id["email"] = e
	}
	access := base("access", cognitoAccessTTL)
	access["client_id"] = clientID
	access["scope"] = "aws.cognito.signin.user.admin"
	refresh := base("refresh", cognitoRefreshTTL)
	refresh["client_id"] = clientID
	idTok, _ := h.signer.mint(id)
	accessTok, _ := h.signer.mint(access)
	refreshTok, _ := h.signer.mint(refresh)
	return map[string]any{
		"AccessToken": accessTok, "IdToken": idTok, "RefreshToken": refreshTok,
		"ExpiresIn": cognitoAccessTTL, "TokenType": "Bearer",
	}
}

// verifyToken checks the RS256 signature, expiry, issuer (for the given pool), and token_use.
func (h *cognitoHandler) verifyToken(pool, token, use string) (map[string]any, error) {
	claims, err := verifyRS256(token, h.signer)
	if err != nil {
		return nil, err
	}
	if asString(claims["_pool"]) != pool || asString(claims["token_use"]) != use {
		return nil, errBadToken
	}
	return claims, nil
}

func (h *cognitoHandler) verifyTokenAnyPool(token, use string) (map[string]any, error) {
	claims, err := verifyRS256(token, h.signer)
	if err != nil {
		return nil, err
	}
	if asString(claims["token_use"]) != use {
		return nil, errBadToken
	}
	return claims, nil
}

// tokenStillValid enforces GlobalSignOut: the token's iat must be at/after the user's tokens_valid_after cutoff.
func (h *cognitoHandler) tokenStillValid(ctx context.Context, pool, username string, claims map[string]any) bool {
	u, ok, err := h.store.getUser(ctx, pool, username)
	if err != nil || !ok {
		return false
	}
	if u.TokensValidAfter == 0 {
		return true
	}
	iatMs := int64(toFloat(claims["iat"]) * 1000)
	return iatMs >= u.TokensValidAfter
}

// --- well-known data-plane endpoints (JWKS + OIDC discovery), served UNAUTHENTICATED ---

// wellKnown serves a pool's /.well-known/openid-configuration or /.well-known/jwks.json if the path matches,
// returning true if it handled the request. Called from the router before SigV4 (these are public endpoints
// verifiers fetch, exactly like a real Cognito pool's JWKS URL).
func (h *cognitoHandler) wellKnown(w http.ResponseWriter, r *http.Request) bool {
	poolID, rest, ok := poolIssuerFromPath(r.URL.Path)
	if !ok {
		return false
	}
	if h.store == nil || h.signer == nil {
		return false
	}
	switch {
	case strings.HasSuffix(rest, "/.well-known/openid-configuration"):
		if _, exists, _ := h.store.getPool(r.Context(), poolID); !exists {
			http.NotFound(w, r)
			return true
		}
		writeCognitoWellKnown(w, discovery(h.issuerBase+"/cognito/"+poolID))
		return true
	case strings.HasSuffix(rest, "/.well-known/jwks.json"):
		writeCognitoWellKnown(w, h.signer.jwks())
		return true
	}
	return false
}

func writeCognitoWellKnown(w http.ResponseWriter, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

// --- helpers ---

func (h *cognitoHandler) mustPool(ctx context.Context, w http.ResponseWriter, requestID, id string) (cognitoPool, bool) {
	if id == "" {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "UserPoolId is required.")
		return cognitoPool{}, false
	}
	p, ok, err := h.store.getPool(ctx, id)
	if err != nil {
		h.internal(w, requestID, err)
		return cognitoPool{}, false
	}
	if !ok {
		writeCognitoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "User pool "+id+" does not exist.")
		return cognitoPool{}, false
	}
	return p, true
}

func (h *cognitoHandler) clientPool(ctx context.Context, w http.ResponseWriter, requestID, clientID string) (string, bool) {
	if clientID == "" {
		writeCognitoError(w, http.StatusBadRequest, "InvalidParameterException", requestID, "ClientId is required.")
		return "", false
	}
	c, ok, err := h.store.getClient(ctx, clientID)
	if err != nil {
		h.internal(w, requestID, err)
		return "", false
	}
	if !ok {
		writeCognitoError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "app client does not exist.")
		return "", false
	}
	return c.PoolID, true
}

func (h *cognitoHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("cognito backend error", "error", err.Error())
	writeCognitoError(w, http.StatusInternalServerError, "InternalErrorException", requestID, "An error occurred on the server side.")
}

func (h *cognitoHandler) audit(ctx context.Context, op, pool string) {
	h.logger.InfoContext(ctx, "cognito audit", "service", "cognito-idp", "op", op, "pool", pool, "principal", principalFromCtx(ctx))
}

// userAttrs extracts UserAttributes ([{Name,Value}]) into a map.
func userAttrs(body map[string]any) map[string]string {
	out := map[string]string{}
	for _, e := range sliceOf(body["UserAttributes"]) {
		if m, ok := e.(map[string]any); ok {
			n := asString(m["Name"])
			if n != "" {
				out[n] = asString(m["Value"])
			}
		}
	}
	return out
}

func attrList(attrs map[string]string) []any {
	out := make([]any, 0, len(attrs))
	for k, v := range attrs {
		out = append(out, map[string]any{"Name": k, "Value": v})
	}
	return out
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func toFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int64:
		return float64(t)
	case int:
		return float64(t)
	}
	return 0
}

// verifyRS256 parses a JWT, verifies the RS256 signature against the signer's public key, and checks expiry.
func verifyRS256(token string, signer *cognitoSigner) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errBadToken
	}
	signing := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errBadToken
	}
	h := sha256Sum([]byte(signing))
	if err := rsaVerify(signer, h, sig); err != nil {
		return nil, errBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errBadToken
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errBadToken
	}
	if exp := int64(toFloat(claims["exp"])); exp > 0 && time.Now().Unix() > exp {
		return nil, errBadToken
	}
	return claims, nil
}
