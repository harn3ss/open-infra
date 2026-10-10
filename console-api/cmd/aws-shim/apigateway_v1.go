// API Gateway REST API (v1) front door for the aws-shim. The REST-v1 complement to
// the HTTP-API (v2) handler in apigateway.go: a resource TREE + methods + integrations, an immutable
// deployment SNAPSHOT, and stages that point at a deployment. Same two trust planes as v2 — a
// SigV4-signed, policy-authorized control plane, and an unsigned data plane that proxies the deployed
// API to a Lambda (AWS_PROXY, payload-format 1.0) or an HTTP origin (HTTP/HTTP_PROXY).
//
// REST v1 and HTTP v2 BOTH sign as "apigateway", so one apigwMux is registered under that key and
// path-muxes: /restapis/... -> this handler, /v2/apis/... -> the v2 handler. VTL request/response
// mapping templates and non-NONE method authorizers are tracked follow-ons (see docs/aws-shim.md).
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

type apigwV1Handler struct {
	cs                kubernetes.Interface
	authzNS           string
	fnNS              string
	svcSuffix         string
	cognitoIssuerBase string // issuer prefix a Cognito pool ARN resolves to (<base>/<poolId>)
	store             *apigwV1Store
	authz             *dataplaneauthz.Checker
	logger            *slog.Logger
	client            *http.Client

	oidcMu    sync.Mutex
	providers map[string]*oidc.Provider // issuer -> provider (JWKS discovery is network; cache). Reused by the COGNITO_USER_POOLS authorizer, the SAME coreos/go-oidc path the v2 handler uses.
}

func newAPIGWV1Handler(cs kubernetes.Interface, authzNS, fnNS, svcSuffix, cognitoIssuerBase string, store *apigwV1Store, authz *dataplaneauthz.Checker, logger *slog.Logger) *apigwV1Handler {
	return &apigwV1Handler{
		cs: cs, authzNS: authzNS, fnNS: fnNS, svcSuffix: svcSuffix, cognitoIssuerBase: cognitoIssuerBase,
		store: store, authz: authz, logger: logger,
		client:    &http.Client{Timeout: 30 * time.Second},
		providers: map[string]*oidc.Provider{},
	}
}

func restVerb(op string) string {
	switch {
	case strings.HasPrefix(op, "Delete"):
		return "delete"
	case strings.HasPrefix(op, "Get"):
		return "get"
	default: // Create*, Put*
		return "create"
	}
}

func (h *apigwV1Handler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("apigw v1 internal", "error", err.Error())
	writeAGWError(w, http.StatusInternalServerError, "InternalServerException", requestID, "Internal Server Error")
}

func (h *apigwV1Handler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if h.store == nil {
		writeAGWError(w, http.StatusNotImplemented, "InternalServerException", requestID,
			"the API Gateway data layer is not configured on this shim (set SQS_PG_URI)")
		return
	}
	v, ok := restV1OpFromRequest(r)
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID,
			"unrecognized API Gateway REST (v1) path: "+r.Method+" "+r.URL.Path)
		return
	}
	body := readJSONBody(r)
	resID := v.APIID
	if v.Op == "CreateRestApi" {
		resID, _ = body["name"].(string)
	}
	ctx := withPrincipal(r.Context(), claims.PrincipalType()+"::"+claims.PrincipalID())

	// One policy world: coarse impersonated SubjectAccessReview + Cedar data-plane (apigateway:<Op>).
	if allowed, reason := iam.CanDo(ctx, h.cs, claims, restVerb(v.Op), "openinfra.dev", "applications", h.authzNS, resID); !allowed {
		writeAGWError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "apigateway:"+v.Op, "Api", resID, r); denied {
		writeAGWError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}

	switch v.Op {
	case "CreateRestApi":
		h.createRestApi(ctx, w, requestID, body)
	case "GetRestApis":
		h.getRestApis(ctx, w, requestID)
	case "GetRestApi":
		h.getRestApi(ctx, w, requestID, v.APIID)
	case "DeleteRestApi":
		h.deleteRestApi(ctx, w, requestID, v.APIID)
	case "GetResources":
		h.getResources(ctx, w, requestID, v.APIID)
	case "CreateResource":
		h.createResource(ctx, w, requestID, v.APIID, v.ResourceID, body)
	case "PutMethod":
		h.putMethod(ctx, w, requestID, v.APIID, v.ResourceID, v.HTTPMethod, body)
	case "PutIntegration":
		h.putIntegration(ctx, w, r, claims, requestID, v.APIID, v.ResourceID, v.HTTPMethod, body)
	case "PutIntegrationResponse":
		h.putIntegrationResponse(ctx, w, requestID, v.APIID, v.ResourceID, v.HTTPMethod, v.StatusCode, body)
	case "CreateDeployment":
		h.createDeployment(ctx, w, requestID, v.APIID, body)
	case "CreateStage":
		h.createStage(ctx, w, requestID, v.APIID, body)
	case "GetStages":
		h.getStages(ctx, w, requestID, v.APIID)
	case "CreateAuthorizer":
		h.createAuthorizer(ctx, w, requestID, v.APIID, body)
	default:
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "unimplemented op: "+v.Op)
	}
}

func (h *apigwV1Handler) mustAPI(ctx context.Context, w http.ResponseWriter, requestID, apiID string) bool {
	_, ok, err := h.store.getAPI(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return false
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid API identifier specified: "+apiID)
		return false
	}
	return true
}

func (h *apigwV1Handler) createRestApi(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["name"].(string)
	if name == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "CreateRestApi requires a name.")
		return
	}
	id := shortID(10)
	if err := h.store.createAPI(ctx, restAPI{ID: id, Name: name}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	// Seed the root resource "/" (AWS returns its id as rootResourceId).
	rootID := shortID(10)
	if err := h.store.createResource(ctx, id, restResource{ID: rootID, ParentID: "", PathPart: "", FullPath: "/"}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{
		"id": id, "name": name, "rootResourceId": rootID, "createdDate": time.Now().UTC().Unix(),
	})
}

func (h *apigwV1Handler) getRestApis(ctx context.Context, w http.ResponseWriter, requestID string) {
	apis, err := h.store.listAPIs(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(apis))
	for _, a := range apis {
		items = append(items, map[string]any{"id": a.ID, "name": a.Name, "createdDate": a.Created.Unix()})
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

func (h *apigwV1Handler) getRestApi(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	a, ok, err := h.store.getAPI(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid API identifier specified: "+apiID)
		return
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"id": a.ID, "name": a.Name, "createdDate": a.Created.Unix()})
}

func (h *apigwV1Handler) deleteRestApi(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	ok, err := h.store.deleteAPI(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid API identifier specified: "+apiID)
		return
	}
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusAccepted)
}

func (h *apigwV1Handler) getResources(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	res, err := h.store.listResources(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(res))
	for _, r := range res {
		m := map[string]any{"id": r.ID, "path": r.FullPath}
		if r.ParentID != "" {
			m["parentId"] = r.ParentID
		}
		if r.PathPart != "" {
			m["pathPart"] = r.PathPart
		}
		items = append(items, m)
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

func (h *apigwV1Handler) createResource(ctx context.Context, w http.ResponseWriter, requestID, apiID, parentID string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	pathPart, _ := body["pathPart"].(string)
	if pathPart == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "CreateResource requires pathPart.")
		return
	}
	parent, ok, err := h.store.getResource(ctx, apiID, parentID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid parent resource identifier: "+parentID)
		return
	}
	id := shortID(10)
	full := childFullPath(parent.FullPath, pathPart)
	if err := h.store.createResource(ctx, apiID, restResource{ID: id, ParentID: parentID, PathPart: pathPart, FullPath: full}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"id": id, "parentId": parentID, "pathPart": pathPart, "path": full})
}

func (h *apigwV1Handler) putMethod(ctx context.Context, w http.ResponseWriter, requestID, apiID, resID, httpMethod string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	if _, ok, _ := h.store.getResource(ctx, apiID, resID); !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid resource identifier: "+resID)
		return
	}
	authType, _ := body["authorizationType"].(string)
	if authType == "" {
		authType = "NONE"
	}
	authID, _ := body["authorizerId"].(string)
	if err := h.store.putMethod(ctx, apiID, restMethod{ResourceID: resID, HTTPMethod: httpMethod, AuthorizationType: authType, AuthorizerID: authID}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"httpMethod": httpMethod, "authorizationType": authType})
}

func (h *apigwV1Handler) putIntegration(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID, apiID, resID, httpMethod string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	itype, _ := body["type"].(string)
	uri, _ := body["uri"].(string)
	switch itype {
	case "AWS_PROXY", "AWS":
		// AWS_PROXY proxies the raw proxy event; AWS (non-proxy, increment 2) transforms the body
		// through VTL request/response templates. Both invoke a Lambda, so both take the same
		// wiring-time escalation fence: a caller may only integrate a Lambda it is
		// authorized to invoke, since the data-plane invoke path is unsigned by design.
		if uri == "" {
			writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, itype+" integration requires uri (a Lambda ARN or name).")
			return
		}
		fn := functionFromURI(uri)
		if denied, reason := deniedByDataPlane(ctx, h.authz, claims, "lambda:InvokeFunction", "Function", fn, r); denied {
			writeAGWError(w, http.StatusForbidden, "AccessDeniedException", requestID, "not authorized to integrate function "+fn+": "+reason)
			return
		}
		if allowed, reason := iam.CanDo(ctx, h.cs, claims, "create", "openinfra.dev", "functions", h.fnNS, fn); !allowed {
			writeAGWError(w, http.StatusForbidden, "AccessDeniedException", requestID, "not authorized to integrate function "+fn+": "+reason)
			return
		}
	case "HTTP", "HTTP_PROXY":
		if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
			writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, itype+" integration requires an http(s) uri.")
			return
		}
	case "MOCK":
		// no uri
	default:
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID,
			"integration type must be AWS, AWS_PROXY, HTTP, HTTP_PROXY, or MOCK.")
		return
	}
	pfv, _ := body["payloadFormatVersion"].(string)
	if pfv == "" {
		pfv = "1.0" // REST v1 Lambda proxy events are format 1.0
	}
	ihm, _ := body["integrationHttpMethod"].(string)
	// requestTemplates (contentType → VTL) drive non-proxy AWS/HTTP REQUEST body mapping. The RESPONSE
	// side is set separately by PutIntegrationResponse, exactly as AWS models it.
	reqTmpls := stringMap(body["requestTemplates"])
	if err := h.store.putIntegration(ctx, apiID, restIntegration{
		ResourceID: resID, HTTPMethod: httpMethod, Type: itype, URI: uri, IntegrationHTTPMethod: ihm, PayloadFormatVersion: pfv,
		RequestTemplates: reqTmpls,
	}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"type": itype, "uri": uri})
}

// putIntegrationResponse records an IntegrationResponse (PutIntegrationResponse): the responseTemplates
// (contentType → VTL) for one statusCode that map the backend response body. The integration must
// already exist (AWS semantics); a missing one is a NotFoundException.
func (h *apigwV1Handler) putIntegrationResponse(ctx context.Context, w http.ResponseWriter, requestID, apiID, resID, httpMethod, statusCode string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	if statusCode == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "PutIntegrationResponse requires a statusCode.")
		return
	}
	respTmpls := stringMap(body["responseTemplates"])
	if err := h.store.putIntegrationResponse(ctx, apiID, resID, httpMethod, statusCode, respTmpls); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "no integration on "+httpMethod+" "+resID+" to attach a response to (call PutIntegration first).")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"statusCode": statusCode})
}

// createAuthorizer registers a method authorizer. The shim enforces COGNITO_USER_POOLS (validate the
// caller's JWT against the pool's issuer/JWKS). TOKEN/REQUEST (Lambda) authorizers are refused
// fail-closed — an authorizer the shim cannot vet must never silently admit a request (the same
// "authentication false green" stance the v2 HTTP-API path takes). providerARNs accepts a Cognito user
// pool ARN (resolved to <COGNITO_ISSUER_BASE>/<poolId>) or a bare OIDC issuer URL.
func (h *apigwV1Handler) createAuthorizer(ctx context.Context, w http.ResponseWriter, requestID, apiID string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	name, _ := body["name"].(string)
	atype, _ := body["type"].(string)
	switch atype {
	case "COGNITO_USER_POOLS":
		// enforced below
	case "TOKEN", "REQUEST":
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID,
			"the shim supports authorizer type COGNITO_USER_POOLS only (the caller's JWT is validated against the pool's issuer/JWKS). TOKEN/REQUEST (Lambda) authorizers are not fronted — an authorizer the shim cannot vet is an authentication false green, refused rather than faked.")
		return
	default:
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID,
			"authorizer type must be COGNITO_USER_POOLS.")
		return
	}
	var issuer string
	for _, arn := range stringSlice(body["providerARNs"]) {
		if iss := h.resolveCognitoIssuer(arn); iss != "" {
			issuer = iss
			break
		}
	}
	if issuer == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID,
			"a COGNITO_USER_POOLS authorizer requires providerARNs — a Cognito user pool ARN (arn:aws:cognito-idp:…:userpool/<poolId>) or an OIDC issuer URL.")
		return
	}
	var auds []string
	for _, a := range sliceOf(body["audience"]) {
		if s, ok := a.(string); ok && s != "" {
			auds = append(auds, s)
		}
	}
	a := restAuthorizer{
		ID: shortID(10), Name: name, Type: "COGNITO_USER_POOLS", Issuer: issuer, Audiences: auds,
		IdentitySource: headerFromIdentitySource(firstStr(stringSlice(body["identitySource"]))),
	}
	if err := h.store.createAuthorizer(ctx, apiID, a); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{
		"id": a.ID, "name": a.Name, "type": a.Type, "providerARNs": stringSlice(body["providerARNs"]),
		"identitySource": a.IdentitySource,
	})
}

// resolveCognitoIssuer maps a providerARN to an OIDC issuer: a bare http(s) URL is the issuer as-is; a
// Cognito user pool ARN (…:userpool/<poolId>) resolves to <COGNITO_ISSUER_BASE>/<poolId> (the shim's own
// Cognito serves that issuer's discovery + JWKS). Anything else is unresolvable ("").
func (h *apigwV1Handler) resolveCognitoIssuer(arn string) string {
	if strings.HasPrefix(arn, "https://") || strings.HasPrefix(arn, "http://") {
		return strings.TrimRight(arn, "/")
	}
	if i := strings.Index(arn, "userpool/"); i >= 0 {
		poolID := arn[i+len("userpool/"):]
		if poolID != "" {
			return strings.TrimRight(h.cognitoIssuerBase, "/") + "/" + poolID
		}
	}
	return ""
}

// headerFromIdentitySource extracts the header name from a REST identity-source expression
// ("method.request.header.Authorization" -> "Authorization"); default Authorization.
func headerFromIdentitySource(src string) string {
	const pfx = "method.request.header."
	if strings.HasPrefix(src, pfx) {
		if h := strings.TrimPrefix(src, pfx); h != "" {
			return h
		}
	}
	return "Authorization"
}

func firstStr(ss []string) string {
	if len(ss) > 0 {
		return ss[0]
	}
	return ""
}

func (h *apigwV1Handler) createDeployment(ctx context.Context, w http.ResponseWriter, requestID, apiID string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	snap, err := h.store.snapshot(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	depID := shortID(10)
	if err := h.store.createDeployment(ctx, apiID, depID, snap); err != nil {
		h.internal(w, requestID, err)
		return
	}
	// AWS: a deployment may also create/point a stage in the same call.
	if stageName, _ := body["stageName"].(string); stageName != "" {
		if err := h.store.putStage(ctx, apiID, stageName, depID, stringMap(body["variables"])); err != nil {
			h.internal(w, requestID, err)
			return
		}
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"id": depID, "createdDate": time.Now().UTC().Unix()})
}

func (h *apigwV1Handler) createStage(ctx context.Context, w http.ResponseWriter, requestID, apiID string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	stageName, _ := body["stageName"].(string)
	depID, _ := body["deploymentId"].(string)
	if stageName == "" || depID == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "CreateStage requires stageName and deploymentId.")
		return
	}
	if _, ok, _ := h.store.getDeploymentSnapshot(ctx, apiID, depID); !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid deployment identifier specified: "+depID)
		return
	}
	if err := h.store.putStage(ctx, apiID, stageName, depID, stringMap(body["variables"])); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"stageName": stageName, "deploymentId": depID})
}

func (h *apigwV1Handler) getStages(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	names, err := h.store.listStages(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(names))
	for _, n := range names {
		depID, _, _, _ := h.store.getStage(ctx, apiID, n)
		items = append(items, map[string]any{"stageName": n, "deploymentId": depID})
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

// --- data plane ---

func (h *apigwV1Handler) serveInvoke(w http.ResponseWriter, r *http.Request, apiID, path, requestID string) {
	if h.store == nil {
		writeAGWError(w, http.StatusNotImplemented, "InternalServerException", requestID, "data layer not configured")
		return
	}
	if _, ok, err := h.store.getAPI(r.Context(), apiID); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Not Found")
		return
	}
	// REST v1 always serves under a stage: the leading path segment is the stage name.
	stage, routePath := firstSeg(path)
	if stage == "" {
		writeAGWError(w, http.StatusForbidden, "MissingAuthenticationTokenException", requestID, "Missing Authentication Token")
		return
	}
	depID, stageVars, sok, err := h.store.getStage(r.Context(), apiID, stage)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !sok || depID == "" {
		writeAGWError(w, http.StatusForbidden, "MissingAuthenticationTokenException", requestID, "Missing Authentication Token")
		return
	}
	snap, ok, err := h.store.getDeploymentSnapshot(r.Context(), apiID, depID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Not Found")
		return
	}
	if routePath == "" {
		routePath = "/"
	}
	integ, pathParams, authType, authorizerID, matched := matchRestRoute(snap, r.Method, routePath)
	if !matched {
		writeAGWError(w, http.StatusForbidden, "MissingAuthenticationTokenException", requestID, "Missing Authentication Token")
		return
	}
	// Method authorizer. NONE serves open; COGNITO_USER_POOLS validates the caller's JWT (fail-closed);
	// AWS_IAM and any unsupported type are refused (never silently bypassed).
	if authType != "" && authType != "NONE" {
		if !h.enforceMethodAuthorizer(w, r, snap, authType, authorizerID, requestID) {
			return
		}
	}

	reqBody, _ := io.ReadAll(io.LimitReader(r.Body, 6<<20))

	switch integ.Type {
	case "AWS_PROXY":
		pfv := integ.PayloadFormatVersion
		if pfv == "" {
			pfv = "1.0"
		}
		event := buildProxyEvent(pfv, r, apiID, stage, r.Method+" "+routePath, routePath, pathParams, reqBody, requestID)
		evJSON, _ := json.Marshal(event)
		target := "http://" + functionFromURI(integ.URI) + "." + h.fnNS + "." + h.svcSuffix + "/"
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(evJSON))
		if err != nil {
			writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
			return
		}
		upReq.Header.Set("Content-Type", "application/json")
		resp, err := h.client.Do(upReq)
		if err != nil {
			h.logger.Warn("apigw v1 upstream unreachable", "function", integ.URI, "error", err.Error())
			writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
			return
		}
		defer resp.Body.Close()
		h.logger.Info("apigw v1 invoke", "api", apiID, "stage", stage, "method", r.Method, "path", routePath, "integration", "AWS_PROXY", "function", integ.URI, "pfv", pfv)
		// open-infra's Lambda runtime ALREADY translates a handler's {statusCode,headers,body} proxy
		// response into the HTTP response at the Function URL (see lambda-runtime/*/bootstrap), exactly
		// as the Lambda doorway returns it verbatim — so the Function URL hands back the already-unwrapped
		// HTTP response. Pass it through rather than re-applying the AWS proxy-response translation (which
		// would see no {statusCode} wrapper and 502 under the 1.0 rule). The handler still receives the
		// faithful proxy event we built above.
		h.copyResponse(w, resp, requestID)
	case "AWS":
		// Non-proxy Lambda (increment 2): VTL request template → event body, VTL response template →
		// HTTP response body.
		h.invokeAWSIntegration(w, r, integ, apiID, stage, routePath, requestID, pathParams, stageVars, reqBody)
	case "HTTP":
		// Non-proxy HTTP: VTL request/response body mapping around an http(s) origin.
		h.invokeHTTPIntegration(w, r, integ, apiID, stage, routePath, requestID, pathParams, stageVars, reqBody)
	case "HTTP_PROXY":
		h.proxyHTTP(w, r, integ, routePath, reqBody, requestID)
	case "MOCK":
		w.Header().Set("x-amzn-RequestId", requestID)
		w.WriteHeader(http.StatusOK)
	default:
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
	}
}

// --- non-proxy VTL body mapping (increment 2) ---

// invokeAWSIntegration serves a non-proxy "AWS" (Lambda) integration: it maps the request body with the
// matching requestTemplates VTL template (pass-through if none), POSTs the result to the Function's URL,
// then maps the response body with the matching responseTemplates template (pass-through if none).
func (h *apigwV1Handler) invokeAWSIntegration(w http.ResponseWriter, r *http.Request, integ restIntegration, apiID, stage, routePath, requestID string, pathParams, stageVars map[string]string, reqBody []byte) {
	eventBody, ok := h.mapRequestBody(w, r, integ, apiID, stage, routePath, requestID, pathParams, stageVars, reqBody)
	if !ok {
		return
	}
	target := "http://" + functionFromURI(integ.URI) + "." + h.fnNS + "." + h.svcSuffix + "/"
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(eventBody))
	if err != nil {
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(upReq)
	if err != nil {
		h.logger.Warn("apigw v1 upstream unreachable", "function", integ.URI, "error", err.Error())
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	defer resp.Body.Close()
	h.logger.Info("apigw v1 invoke", "api", apiID, "stage", stage, "method", r.Method, "path", routePath, "integration", "AWS", "function", integ.URI)
	h.writeMappedResponse(w, r, integ, resp, apiID, stage, routePath, requestID, pathParams, stageVars)
}

// invokeHTTPIntegration serves a non-proxy "HTTP" integration: same request/response VTL mapping as AWS,
// around an http(s) origin instead of a Lambda.
func (h *apigwV1Handler) invokeHTTPIntegration(w http.ResponseWriter, r *http.Request, integ restIntegration, apiID, stage, routePath, requestID string, pathParams, stageVars map[string]string, reqBody []byte) {
	fwdBody, ok := h.mapRequestBody(w, r, integ, apiID, stage, routePath, requestID, pathParams, stageVars, reqBody)
	if !ok {
		return
	}
	method := integ.IntegrationHTTPMethod
	if method == "" {
		method = r.Method
	}
	target := strings.TrimRight(integ.URI, "/")
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	upReq, err := http.NewRequestWithContext(r.Context(), method, target, bytes.NewReader(fwdBody))
	if err != nil {
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	for k, vs := range r.Header {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Content-Type") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			upReq.Header.Add(k, v)
		}
	}
	resp, err := h.client.Do(upReq)
	if err != nil {
		h.logger.Warn("apigw v1 http upstream unreachable", "uri", integ.URI, "error", err.Error())
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	defer resp.Body.Close()
	h.writeMappedResponse(w, r, integ, resp, apiID, stage, routePath, requestID, pathParams, stageVars)
}

// mapRequestBody applies the matching requestTemplates template to the request body (pass-through if
// none matches); on a template render error it writes a 500 and returns ok=false.
func (h *apigwV1Handler) mapRequestBody(w http.ResponseWriter, r *http.Request, integ restIntegration, apiID, stage, routePath, requestID string, pathParams, stageVars map[string]string, reqBody []byte) ([]byte, bool) {
	tmpl, matched := pickMappingTemplate(integ.RequestTemplates, r.Header.Get("Content-Type"))
	if !matched {
		return reqBody, true // pass-through
	}
	out, err := renderMappingTemplate(tmpl, reqBody, mergeInputParams(r, pathParams), stageVars, h.vtlContext(r, apiID, stage, routePath, requestID))
	if err != nil {
		h.logger.Warn("apigw v1 request template error", "api", apiID, "path", routePath, "error", err.Error())
		writeAGWError(w, http.StatusInternalServerError, "InternalServerException", requestID, "request mapping template error")
		return nil, false
	}
	return []byte(out), true
}

// writeMappedResponse reads the upstream response body and applies the IntegrationResponse that matches
// the backend status (exact statusCode → "200"/default → any). The matched response's statusCode
// becomes the method response status and its responseTemplates (keyed by content-type) map the body.
// With no IntegrationResponse configured at all it is pass-through, copying the upstream status +
// headers + body (so an AWS/HTTP integration with no response mapping still works).
func (h *apigwV1Handler) writeMappedResponse(w http.ResponseWriter, r *http.Request, integ restIntegration, resp *http.Response, apiID, stage, routePath, requestID string, pathParams, stageVars map[string]string) {
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	mappedStatus, tmpls, ok := pickIntegrationResponse(integ.IntegrationResponses, resp.StatusCode)
	if !ok {
		// pass-through: copy the upstream status + headers + (already-read) body.
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("x-amzn-RequestId", requestID)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
		return
	}
	out := string(respBody)
	if tmpl, matched := pickMappingTemplate(tmpls, resp.Header.Get("Content-Type")); matched {
		rendered, err := renderMappingTemplate(tmpl, respBody, mergeInputParams(r, pathParams), stageVars, h.vtlContext(r, apiID, stage, routePath, requestID))
		if err != nil {
			h.logger.Warn("apigw v1 response template error", "api", apiID, "path", routePath, "error", err.Error())
			writeAGWError(w, http.StatusInternalServerError, "InternalServerException", requestID, "response mapping template error")
			return
		}
		out = rendered
	}
	status := mappedStatus
	if status == 0 {
		status = resp.StatusCode
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(out))
}

// --- method authorizers (increment 3) ---

// enforceMethodAuthorizer gates a non-NONE method. COGNITO_USER_POOLS → validate the caller's JWT.
// AWS_IAM is refused (the REST v1 invoke path is unsigned by design — honest, not a silent bypass). A
// method that references a missing/unknown authorizer fails closed (401). Returns true only when the
// request is authorized to proceed.
func (h *apigwV1Handler) enforceMethodAuthorizer(w http.ResponseWriter, r *http.Request, snap restSnapshot, authType, authorizerID, requestID string) bool {
	if authType == "AWS_IAM" {
		writeAGWError(w, http.StatusForbidden, "AccessDeniedException", requestID,
			"method authorizationType AWS_IAM is not enforced on the REST v1 invoke path (unsigned by design); use a COGNITO_USER_POOLS authorizer.")
		return false
	}
	var authz *restAuthorizer
	for i := range snap.Authorizers {
		if snap.Authorizers[i].ID == authorizerID {
			authz = &snap.Authorizers[i]
			break
		}
	}
	if authz == nil || authz.Type != "COGNITO_USER_POOLS" {
		// method asks for an authorizer the deployment doesn't carry / the shim doesn't enforce — fail closed.
		writeAGWError(w, http.StatusUnauthorized, "UnauthorizedException", requestID, "Unauthorized")
		return false
	}
	return h.runCognitoAuthorizer(w, r, authz, requestID)
}

// runCognitoAuthorizer validates the caller's JWT against the authorizer's issuer (JWKS discovery via
// coreos/go-oidc — the SAME path the v2 handler uses). Missing token, issuer-discovery failure,
// bad/expired signature, or an audience mismatch all 401 (fail closed).
func (h *apigwV1Handler) runCognitoAuthorizer(w http.ResponseWriter, r *http.Request, a *restAuthorizer, requestID string) bool {
	hdr := a.IdentitySource
	if hdr == "" {
		hdr = "Authorization"
	}
	raw := r.Header.Get(hdr)
	if tok, ok := bearerToken(raw); ok {
		raw = tok // strip a "Bearer " prefix when present (Authorization header); a custom header carries the raw token
	}
	if raw == "" {
		writeAGWError(w, http.StatusUnauthorized, "UnauthorizedException", requestID, "Unauthorized")
		return false
	}
	provider, perr := h.oidcProvider(r.Context(), a.Issuer)
	if perr != nil {
		h.logger.Warn("apigw v1 cognito authorizer: issuer discovery failed", "issuer", a.Issuer, "error", perr.Error())
		writeAGWError(w, http.StatusUnauthorized, "UnauthorizedException", requestID, "Unauthorized")
		return false
	}
	auds := a.Audiences
	if len(auds) == 0 {
		auds = []string{""} // no audience configured -> skip the aud check
	}
	for _, aud := range auds {
		cfg := &oidc.Config{ClientID: aud}
		if aud == "" {
			cfg = &oidc.Config{SkipClientIDCheck: true}
		}
		if _, verr := provider.Verifier(cfg).Verify(r.Context(), raw); verr == nil {
			return true
		}
	}
	writeAGWError(w, http.StatusUnauthorized, "UnauthorizedException", requestID, "Unauthorized")
	return false
}

func (h *apigwV1Handler) oidcProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
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

// vtlContext builds the minimal $context map a mapping template can read (honest subset).
func (h *apigwV1Handler) vtlContext(r *http.Request, apiID, stage, routePath, requestID string) map[string]any {
	return map[string]any{
		"apiId":        apiID,
		"stage":        stage,
		"httpMethod":   r.Method,
		"path":         r.URL.Path,
		"resourcePath": routePath,
		"requestId":    requestID,
		"identity":     map[string]any{"sourceIp": clientIP(r), "userAgent": r.UserAgent()},
	}
}

// mergeInputParams flattens path, query, and header parameters into the single name→value map that
// $input.params(name) resolves against, with AWS's precedence (path > query > header).
func mergeInputParams(r *http.Request, pathParams map[string]string) map[string]string {
	out := map[string]string{}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	for k, v := range pathParams {
		out[k] = v
	}
	return out
}

// proxyHTTP forwards the request to an HTTP(S) origin (the HTTP / HTTP_PROXY integration). For a
// greedy {proxy+} match the captured remainder is appended to the origin path.
func (h *apigwV1Handler) proxyHTTP(w http.ResponseWriter, r *http.Request, integ restIntegration, routePath string, body []byte, requestID string) {
	method := integ.IntegrationHTTPMethod
	if method == "" {
		method = r.Method
	}
	target := strings.TrimRight(integ.URI, "/")
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	upReq, err := http.NewRequestWithContext(r.Context(), method, target, bytes.NewReader(body))
	if err != nil {
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	for k, vs := range r.Header {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Authorization") {
			continue
		}
		for _, v := range vs {
			upReq.Header.Add(k, v)
		}
	}
	resp, err := h.client.Do(upReq)
	if err != nil {
		h.logger.Warn("apigw v1 http upstream unreachable", "uri", integ.URI, "error", err.Error())
		writeAGWError(w, http.StatusBadGateway, "InternalServerException", requestID, "Internal Server Error")
		return
	}
	defer resp.Body.Close()
	h.copyResponse(w, resp, requestID)
}

// copyResponse streams an upstream HTTP response (status + headers + body) through to the client. Used
// for both HTTP(S) origins and open-infra Lambda Functions, whose runtime already produced the HTTP
// response from the handler's proxy return.
func (h *apigwV1Handler) copyResponse(w http.ResponseWriter, resp *http.Response, requestID string) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 10<<20))
}

// apigwInvoker is the data-plane invoke surface the router recognizes before SigV4 parsing. Both the
// v2 handler (when registered alone) and the apigwMux satisfy it.
type apigwInvoker interface {
	invokeTarget(*http.Request) (apiID, path string, ok bool)
	serveInvoke(w http.ResponseWriter, r *http.Request, apiID, path, requestID string)
}

// --- the shared "apigateway" mux (REST v1 and HTTP v2 share the SigV4 signing name) ---

type apigwMux struct {
	v1 *apigwV1Handler
	v2 *apigwHandler
}

func (m *apigwMux) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	m.v2.authFailure(w, r, requestID)
}

func (m *apigwMux) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if segs := splitPath(r.URL.Path); len(segs) > 0 && segs[0] == "restapis" {
		m.v1.serve(w, r, claims, requestID)
		return
	}
	m.v2.serve(w, r, claims, requestID)
}

// invokeTarget parses the data-plane invoke shape (shared by v1 and v2 — /_apigw/<id>/… or the
// execute-api Host); the real plane is chosen in serveInvoke by which store owns the api id.
func (m *apigwMux) invokeTarget(r *http.Request) (apiID, path string, ok bool) {
	return m.v2.invokeTarget(r)
}

func (m *apigwMux) serveInvoke(w http.ResponseWriter, r *http.Request, apiID, path, requestID string) {
	if _, ok, _ := m.v1.store.getAPI(r.Context(), apiID); ok {
		m.v1.serveInvoke(w, r, apiID, path, requestID)
		return
	}
	m.v2.serveInvoke(w, r, apiID, path, requestID)
}
