// API Gateway (HTTP API v2) front door for the aws-shim (polyhedron#169) — the REST/HTTP complement to
// AppSync, completing the API Gateway → Lambda → DynamoDB serverless triad.
//
// TWO planes, like RDS (polyhedron#162):
//   - Control plane: the apigatewayv2 management API — restJson1 over REST PATHS (POST /v2/apis, …), NOT
//     X-Amz-Target dispatch. Authenticated by the shared SigV4 path; authorized by the one policy world
//     (coarse impersonated SubjectAccessReview + Cedar dataPlane `apigateway:<Op>`). This is PLATFORM-admin
//     authorization — who may create APIs/routes/integrations.
//   - Data plane: the actual runtime HTTP requests to the deployed API's invoke URL, translated into the
//     API Gateway v2 proxy event and proxied to a Lambda (Knative Function), whose returned
//     {statusCode,headers,body} becomes the real HTTP response. The proxy IS the product — getting the
//     management shapes right while the event/response contract is wrong is a false green.
//     The API's OWN request auth (JWT authorizers) is the APPLICATION's auth for its END USERS — a
//     different trust domain from the platform principals, and never conflated with the control-plane check.
//
// Scoped to HTTP API (v2). REST API (v1) and non-Lambda integrations are refused, not faked. See
// docs/aws-shim.md.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

// apigwInvokePrefix is the shim-local, in-cluster-routable base path for the data plane (the documented
// divergence from AWS's per-API execute-api hostname, which would need wildcard DNS + TLS). The shim also
// accepts the AWS-shaped `<api-id>.execute-api.<region>.amazonaws.com` Host, for a client that overrides
// endpoint resolution.
const apigwInvokePrefix = "/_apigw/"

type apigwHandler struct {
	cs         kubernetes.Interface
	authzNS    string
	account    string
	region     string
	fnNS       string // namespace kind: Function / Knative Services live in
	svcSuffix  string // cluster DNS suffix; a function is http://<name>.<fnNS>.<svcSuffix>/
	invokeBase string // public base for the invoke URL returned as apiEndpoint
	store      *apigwStore
	authz      *dataplaneauthz.Checker
	logger     *slog.Logger
	client     *http.Client

	oidcMu    sync.Mutex
	providers map[string]*oidc.Provider // issuer -> provider (JWKS discovery is network; cache)
}

func newAPIGWHandler(cs kubernetes.Interface, authzNS, account, region, fnNS, svcSuffix, invokeBase string, store *apigwStore, logger *slog.Logger) *apigwHandler {
	if region == "" {
		region = "us-east-1"
	}
	return &apigwHandler{
		cs: cs, authzNS: authzNS, account: account, region: region, fnNS: fnNS, svcSuffix: svcSuffix,
		invokeBase: invokeBase, store: store, logger: logger,
		client:    &http.Client{Timeout: 30 * time.Second},
		providers: map[string]*oidc.Provider{},
	}
}

// --- error dialect (apigatewayv2 restJson1: {"message": "..."} + x-amzn-errortype) ---

func writeAGWError(w http.ResponseWriter, status int, errType, requestID, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	if errType != "" {
		w.Header().Set("x-amzn-errortype", errType)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}

func writeAGWJSON(w http.ResponseWriter, status int, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(obj)
}

func (h *apigwHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeAGWError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

// --- control plane ---

func (h *apigwHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if h.store == nil {
		writeAGWError(w, http.StatusNotImplemented, "InternalServerException", requestID,
			"the API Gateway data layer is not configured on this shim (set SQS_PG_URI)")
		return
	}
	op, apiID, ok := agwOpFromRequest(r)
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID,
			"unrecognized API Gateway v2 management path: "+r.Method+" "+r.URL.Path)
		return
	}
	verb := agwVerb(op)
	body := readJSONBody(r)

	// authz resource: the api id, or (for CreateApi) the requested name.
	resID := apiID
	if op == "CreateApi" {
		resID, _ = body["name"].(string)
	}
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	if allowed, reason := iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, resID); !allowed {
		h.auditDeny(ctx, op, resID, reason)
		writeAGWError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "apigateway:"+op, "Api", resID, r); denied {
		h.auditDeny(ctx, op, resID, reason)
		writeAGWError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}

	switch op {
	case "CreateApi":
		h.createApi(ctx, w, requestID, body)
	case "GetApis":
		h.getApis(ctx, w, requestID)
	case "GetApi":
		h.getApi(ctx, w, requestID, apiID)
	case "DeleteApi":
		h.deleteApi(ctx, w, requestID, apiID)
	case "CreateRoute":
		h.createRoute(ctx, w, requestID, apiID, body)
	case "GetRoutes":
		h.getRoutes(ctx, w, requestID, apiID)
	case "CreateIntegration":
		h.createIntegration(ctx, w, requestID, apiID, body)
	case "CreateStage":
		h.createStage(ctx, w, requestID, apiID, body)
	case "GetStages":
		h.getStages(ctx, w, requestID, apiID)
	case "CreateDeployment":
		h.createDeployment(ctx, w, requestID, apiID)
	case "CreateAuthorizer":
		h.createAuthorizer(ctx, w, requestID, apiID, body)
	default:
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "unimplemented op: "+op)
	}
}

func (h *apigwHandler) createApi(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["name"].(string)
	proto, _ := body["protocolType"].(string)
	if name == "" || proto == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "CreateApi requires name and protocolType.")
		return
	}
	if proto != "HTTP" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID,
			"the open-infra shim supports protocolType HTTP (API Gateway v2 / HTTP API) only; WEBSOCKET and REST API (v1) are not fronted.")
		return
	}
	api := agwAPI{ID: shortID(10), Name: name, ProtocolType: proto}
	if c, ok := body["corsConfiguration"].(map[string]any); ok {
		api.CORS = c
	}
	if err := h.store.createAPI(ctx, api); err != nil {
		h.internal(w, requestID, err)
		return
	}
	// Quick-create: a Target (a Lambda) with an optional RouteKey wires a default integration + route +
	// $default stage in one call, exactly as AWS does.
	if target, _ := body["target"].(string); target != "" {
		routeKey, _ := body["routeKey"].(string)
		if routeKey == "" {
			routeKey = "$default"
		}
		intID := shortID(10)
		_ = h.store.createIntegration(ctx, api.ID, agwIntegration{ID: intID, IntegrationType: "AWS_PROXY", IntegrationURI: functionFromURI(target), PayloadFormatVersion: "2.0"})
		_ = h.store.createRoute(ctx, api.ID, agwRoute{ID: shortID(10), RouteKey: routeKey, Target: "integrations/" + intID, AuthorizationType: "NONE"})
		_ = h.store.createStage(ctx, api.ID, agwStage{Name: "$default", AutoDeploy: true})
	}
	h.audit(ctx, "CreateApi", api.ID, "name", name)
	writeAGWJSON(w, http.StatusCreated, requestID, h.apiJSON(api))
}

func (h *apigwHandler) getApis(ctx context.Context, w http.ResponseWriter, requestID string) {
	apis, err := h.store.listAPIs(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]any, 0, len(apis))
	for _, a := range apis {
		items = append(items, h.apiJSON(a))
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"items": items})
}

func (h *apigwHandler) getApi(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	a, ok, err := h.store.getAPI(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "api "+apiID+" not found")
		return
	}
	writeAGWJSON(w, http.StatusOK, requestID, h.apiJSON(a))
}

func (h *apigwHandler) deleteApi(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	ok, err := h.store.deleteAPI(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "api "+apiID+" not found")
		return
	}
	h.audit(ctx, "DeleteApi", apiID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *apigwHandler) createRoute(ctx context.Context, w http.ResponseWriter, requestID, apiID string, body map[string]any) {
	if _, ok := h.mustAPI(ctx, w, requestID, apiID); !ok {
		return
	}
	routeKey, _ := body["routeKey"].(string)
	if routeKey == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "CreateRoute requires routeKey.")
		return
	}
	if routeKey != "$default" && !validRouteKey(routeKey) {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID,
			"routeKey must be '$default' or '<METHOD> /<path>' (e.g. 'POST /items/{id}').")
		return
	}
	rt := agwRoute{ID: shortID(10), RouteKey: routeKey, AuthorizationType: "NONE"}
	if t, _ := body["target"].(string); t != "" {
		rt.Target = t
	}
	if at, _ := body["authorizationType"].(string); at != "" {
		rt.AuthorizationType = at
	}
	if aid, _ := body["authorizerId"].(string); aid != "" {
		rt.AuthorizerID = aid
	}
	if err := h.store.createRoute(ctx, apiID, rt); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateRoute", apiID, "routeKey", routeKey)
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{
		"routeId": rt.ID, "routeKey": rt.RouteKey, "target": rt.Target,
		"authorizationType": rt.AuthorizationType, "authorizerId": rt.AuthorizerID,
	})
}

func (h *apigwHandler) getRoutes(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	routes, err := h.store.listRoutes(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]any, 0, len(routes))
	for _, rt := range routes {
		items = append(items, map[string]any{
			"routeId": rt.ID, "routeKey": rt.RouteKey, "target": rt.Target,
			"authorizationType": rt.AuthorizationType, "authorizerId": rt.AuthorizerID,
		})
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"items": items})
}

func (h *apigwHandler) createIntegration(ctx context.Context, w http.ResponseWriter, requestID, apiID string, body map[string]any) {
	if _, ok := h.mustAPI(ctx, w, requestID, apiID); !ok {
		return
	}
	itype, _ := body["integrationType"].(string)
	if itype != "AWS_PROXY" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID,
			"the open-infra shim supports integrationType AWS_PROXY (Lambda proxy) only; HTTP_PROXY and other types are not fronted (refused rather than accepted into a route that then 502s).")
		return
	}
	uri, _ := body["integrationUri"].(string)
	if uri == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "CreateIntegration (AWS_PROXY) requires integrationUri (a Lambda function ARN or name).")
		return
	}
	pfv, _ := body["payloadFormatVersion"].(string)
	if pfv == "" {
		pfv = "2.0"
	}
	if pfv != "2.0" && pfv != "1.0" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "payloadFormatVersion must be '2.0' or '1.0'.")
		return
	}
	integ := agwIntegration{ID: shortID(10), IntegrationType: itype, IntegrationURI: functionFromURI(uri), PayloadFormatVersion: pfv}
	if err := h.store.createIntegration(ctx, apiID, integ); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateIntegration", apiID, "function", integ.IntegrationURI, "pfv", pfv)
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{
		"integrationId": integ.ID, "integrationType": integ.IntegrationType,
		"integrationUri": integ.IntegrationURI, "payloadFormatVersion": integ.PayloadFormatVersion,
		"integrationMethod": "POST",
	})
}

func (h *apigwHandler) createStage(ctx context.Context, w http.ResponseWriter, requestID, apiID string, body map[string]any) {
	if _, ok := h.mustAPI(ctx, w, requestID, apiID); !ok {
		return
	}
	name, _ := body["stageName"].(string)
	if name == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "CreateStage requires stageName.")
		return
	}
	auto := true
	if v, ok := body["autoDeploy"].(bool); ok {
		auto = v
	}
	if err := h.store.createStage(ctx, apiID, agwStage{Name: name, AutoDeploy: auto}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateStage", apiID, "stage", name)
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"stageName": name, "autoDeploy": auto})
}

func (h *apigwHandler) getStages(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	stages, err := h.store.listStages(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]any, 0, len(stages))
	for _, st := range stages {
		items = append(items, map[string]any{"stageName": st.Name, "autoDeploy": st.AutoDeploy})
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"items": items})
}

func (h *apigwHandler) createDeployment(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	if _, ok := h.mustAPI(ctx, w, requestID, apiID); !ok {
		return
	}
	depID := shortID(10)
	if err := h.store.createDeployment(ctx, apiID, depID); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateDeployment", apiID)
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"deploymentId": depID, "deploymentStatus": "DEPLOYED"})
}

func (h *apigwHandler) createAuthorizer(ctx context.Context, w http.ResponseWriter, requestID, apiID string, body map[string]any) {
	if _, ok := h.mustAPI(ctx, w, requestID, apiID); !ok {
		return
	}
	name, _ := body["name"].(string)
	atype, _ := body["authorizerType"].(string)
	if atype != "JWT" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID,
			"the open-infra shim supports authorizerType JWT only (validated against the OIDC IdP registry); REQUEST/Lambda authorizers are not fronted. An authorizer that admits everything is an authentication false green — refused rather than faked.")
		return
	}
	jc, _ := body["jwtConfiguration"].(map[string]any)
	issuer, _ := jc["issuer"].(string)
	if issuer == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "a JWT authorizer requires jwtConfiguration.issuer.")
		return
	}
	var auds []string
	for _, a := range sliceOf(jc["audience"]) {
		if s, ok := a.(string); ok && s != "" {
			auds = append(auds, s)
		}
	}
	ids := stringSlice(body["identitySource"])
	identitySource := "$request.header.Authorization"
	if len(ids) > 0 {
		identitySource = ids[0]
	}
	a := agwAuthorizer{ID: shortID(10), Name: name, Type: atype, Issuer: issuer, Audiences: auds, IdentitySource: identitySource}
	if err := h.store.createAuthorizer(ctx, apiID, a); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.audit(ctx, "CreateAuthorizer", apiID, "issuer", issuer)
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{
		"authorizerId": a.ID, "name": a.Name, "authorizerType": a.Type,
		"identitySource":   []string{identitySource},
		"jwtConfiguration": map[string]any{"issuer": issuer, "audience": auds},
	})
}

// --- data plane (the runtime HTTP -> Lambda proxy) ---

// invokeTarget reports whether this request is a runtime invoke (not a control-plane management call) and,
// if so, the api id and the path within the API. Two forms: the shim-local /_apigw/<apiId>/… prefix, and
// the AWS-shaped <apiId>.execute-api.<region>.amazonaws.com Host.
func (h *apigwHandler) invokeTarget(r *http.Request) (apiID, path string, ok bool) {
	if strings.HasPrefix(r.URL.Path, apigwInvokePrefix) {
		rest := strings.TrimPrefix(r.URL.Path, apigwInvokePrefix)
		i := strings.IndexByte(rest, '/')
		if i < 0 {
			return rest, "/", rest != ""
		}
		return rest[:i], rest[i:], rest[:i] != ""
	}
	host := r.Host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if j := strings.Index(host, ".execute-api."); j > 0 {
		p := r.URL.Path
		if p == "" {
			p = "/"
		}
		return host[:j], p, true
	}
	return "", "", false
}

// serveInvoke handles a runtime request: resolve stage + route, run the route's JWT authorizer (the
// application's own end-user auth), build the proxy event, invoke the Lambda, translate the response.
func (h *apigwHandler) serveInvoke(w http.ResponseWriter, r *http.Request, apiID, path, requestID string) {
	if h.store == nil {
		writeAGWError(w, http.StatusNotImplemented, "InternalServerException", requestID, "data layer not configured")
		return
	}
	api, ok, err := h.store.getAPI(r.Context(), apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Not Found")
		return
	}
	// Resolve the stage: $default serves at the root; a named stage is the leading path segment.
	stage := "$default"
	routePath := path
	if seg, rest := firstSeg(path); seg != "" {
		if exists, _ := h.store.stageExists(r.Context(), apiID, seg); exists {
			stage = seg
			routePath = rest
		}
	}
	if routePath == "" {
		routePath = "/"
	}

	// CORS preflight: answered by the gateway itself (no Lambda), when CORS is configured.
	if r.Method == http.MethodOptions && api.CORS != nil && r.Header.Get("Access-Control-Request-Method") != "" {
		h.writeCORSPreflight(w, api.CORS, r)
		return
	}

	routes, err := h.store.listRoutes(r.Context(), apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	match, pathParams, matched := matchRoute(routes, r.Method, routePath)
	if !matched {
		h.applyCORSActual(w, api.CORS, r)
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Not Found")
		return
	}

	// The API's OWN request auth: a JWT authorizer gates end-user requests. This is the application's
	// auth for its users, a different trust domain from the platform principals — never the control check.
	if match.AuthorizationType == "JWT" && match.AuthorizerID != "" {
		if !h.runJWTAuthorizer(w, r, apiID, match.AuthorizerID, requestID, api.CORS) {
			return
		}
	}

	// Resolve the integration (AWS_PROXY -> a Lambda function).
	intID := strings.TrimPrefix(match.Target, "integrations/")
	integ, iok, err := h.store.getIntegration(r.Context(), apiID, intID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !iok || integ.IntegrationType != "AWS_PROXY" {
		h.applyCORSActual(w, api.CORS, r)
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}

	reqBody, _ := io.ReadAll(io.LimitReader(r.Body, 6<<20))
	event := buildProxyEvent(integ.PayloadFormatVersion, r, apiID, stage, match.RouteKey, routePath, pathParams, reqBody, requestID)
	evJSON, _ := json.Marshal(event)

	target := "http://" + integ.IntegrationURI + "." + h.fnNS + "." + h.svcSuffix + "/"
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(evJSON))
	if err != nil {
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(upReq)
	if err != nil {
		h.logger.Warn("apigw upstream unreachable", "function", integ.IntegrationURI, "target", target, "error", err.Error())
		h.applyCORSActual(w, api.CORS, r)
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	defer resp.Body.Close()
	fnOut, _ := io.ReadAll(io.LimitReader(resp.Body, 6<<20))

	h.audit(r.Context(), "Invoke", apiID, "route", match.RouteKey, "function", integ.IntegrationURI, "stage", stage)
	h.applyCORSActual(w, api.CORS, r)
	writeProxyResponse(w, integ.PayloadFormatVersion, resp.StatusCode, fnOut, requestID)
}

// runJWTAuthorizer validates the bearer token per the route's JWT authorizer, using the SAME coreos/go-oidc
// JWKS-discovery + signature/issuer/audience/expiry verification the STS web-identity path uses. Fails
// CLOSED: a missing/expired/unsigned/wrong-audience token is 401. Returns true only if admitted.
func (h *apigwHandler) runJWTAuthorizer(w http.ResponseWriter, r *http.Request, apiID, authzID, requestID string, cors map[string]any) bool {
	a, ok, err := h.store.getAuthorizer(r.Context(), apiID, authzID)
	if err != nil || !ok {
		h.applyCORSActual(w, cors, r)
		writeAGWError(w, http.StatusUnauthorized, "UnauthorizedException", requestID, "Unauthorized")
		return false
	}
	tok, hasTok := bearerToken(r.Header.Get("Authorization"))
	if !hasTok {
		h.applyCORSActual(w, cors, r)
		writeAGWError(w, http.StatusUnauthorized, "UnauthorizedException", requestID, "Unauthorized")
		return false
	}
	provider, perr := h.oidcProvider(r.Context(), a.Issuer)
	if perr != nil {
		h.logger.Warn("apigw jwt authorizer: issuer discovery failed", "issuer", a.Issuer, "error", perr.Error())
		h.applyCORSActual(w, cors, r)
		writeAGWError(w, http.StatusUnauthorized, "UnauthorizedException", requestID, "Unauthorized")
		return false
	}
	auds := a.Audiences
	if len(auds) == 0 {
		auds = []string{""} // no audience configured -> a verifier that skips the aud check
	}
	for _, aud := range auds {
		cfg := &oidc.Config{ClientID: aud}
		if aud == "" {
			cfg = &oidc.Config{SkipClientIDCheck: true}
		}
		if _, verr := provider.Verifier(cfg).Verify(r.Context(), tok); verr == nil {
			return true
		}
	}
	h.applyCORSActual(w, cors, r)
	writeAGWError(w, http.StatusUnauthorized, "UnauthorizedException", requestID, "Unauthorized")
	return false
}

func (h *apigwHandler) oidcProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	h.oidcMu.Lock()
	defer h.oidcMu.Unlock()
	if p, ok := h.providers[issuer]; ok {
		return p, nil
	}
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	h.providers[issuer] = p
	return p, nil
}

// --- CORS ---

func (h *apigwHandler) writeCORSPreflight(w http.ResponseWriter, cors map[string]any, r *http.Request) {
	h.setCORSHeaders(w, cors, r)
	w.WriteHeader(http.StatusNoContent)
}

func (h *apigwHandler) applyCORSActual(w http.ResponseWriter, cors map[string]any, r *http.Request) {
	if cors == nil {
		return
	}
	h.setCORSHeaders(w, cors, r)
}

func (h *apigwHandler) setCORSHeaders(w http.ResponseWriter, cors map[string]any, r *http.Request) {
	origin := r.Header.Get("Origin")
	allowOrigins := corsList(cors["allowOrigins"])
	allowed := ""
	for _, o := range allowOrigins {
		if o == "*" || strings.EqualFold(o, origin) {
			allowed = o
			break
		}
	}
	if allowed != "" {
		w.Header().Set("Access-Control-Allow-Origin", allowed)
	}
	if m := corsList(cors["allowMethods"]); len(m) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(m, ","))
	}
	if hh := corsList(cors["allowHeaders"]); len(hh) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(hh, ","))
	}
	if eh := corsList(cors["exposeHeaders"]); len(eh) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(eh, ","))
	}
	if ac, ok := cors["allowCredentials"].(bool); ok && ac {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	if ma, ok := cors["maxAge"]; ok {
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(toInt(ma)))
	}
}

// --- helpers ---

func (h *apigwHandler) mustAPI(ctx context.Context, w http.ResponseWriter, requestID, apiID string) (agwAPI, bool) {
	a, ok, err := h.store.getAPI(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return agwAPI{}, false
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "api "+apiID+" not found")
		return agwAPI{}, false
	}
	return a, true
}

func (h *apigwHandler) apiJSON(a agwAPI) map[string]any {
	out := map[string]any{
		"apiId": a.ID, "name": a.Name, "protocolType": a.ProtocolType,
		"apiEndpoint":              h.invokeBase + apigwInvokePrefix + a.ID,
		"routeSelectionExpression": "$request.method $request.path",
	}
	if a.CORS != nil {
		out["corsConfiguration"] = a.CORS
	}
	return out
}

func (h *apigwHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("apigateway backend error", "error", err.Error())
	writeAGWError(w, http.StatusInternalServerError, "InternalServerException", requestID, "An error occurred on the server side.")
}

func (h *apigwHandler) audit(ctx context.Context, op, apiID string, kv ...any) {
	args := []any{"service", "apigateway", "op", op, "decision", "allow", "principal", principalFromCtx(ctx)}
	if apiID != "" {
		args = append(args, "api", apiID)
	}
	args = append(args, kv...)
	h.logger.InfoContext(ctx, "apigateway audit", args...)
}

func (h *apigwHandler) auditDeny(ctx context.Context, op, apiID, reason string) {
	args := []any{"service", "apigateway", "op", op, "decision", "deny", "principal", principalFromCtx(ctx), "reason", reason}
	if apiID != "" {
		args = append(args, "api", apiID)
	}
	h.logger.InfoContext(ctx, "apigateway audit", args...)
}

func agwVerb(op string) string {
	switch {
	case strings.HasPrefix(op, "Create"):
		return "create"
	case strings.HasPrefix(op, "Delete"):
		return "delete"
	default:
		return "get"
	}
}

func corsList(v any) []string {
	var out []string
	for _, e := range sliceOf(v) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
