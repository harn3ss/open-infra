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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes"
)

type apigwV1Handler struct {
	cs        kubernetes.Interface
	authzNS   string
	fnNS      string
	svcSuffix string
	store     *apigwV1Store
	authz     *dataplaneauthz.Checker
	logger    *slog.Logger
	client    *http.Client
}

func newAPIGWV1Handler(cs kubernetes.Interface, authzNS, fnNS, svcSuffix string, store *apigwV1Store, authz *dataplaneauthz.Checker, logger *slog.Logger) *apigwV1Handler {
	return &apigwV1Handler{
		cs: cs, authzNS: authzNS, fnNS: fnNS, svcSuffix: svcSuffix, store: store, authz: authz, logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
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
	case "CreateDeployment":
		h.createDeployment(ctx, w, requestID, v.APIID, body)
	case "CreateStage":
		h.createStage(ctx, w, requestID, v.APIID, body)
	case "GetStages":
		h.getStages(ctx, w, requestID, v.APIID)
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
	// requestTemplates/responseTemplates (contentType → VTL) drive non-proxy AWS/HTTP body mapping.
	reqTmpls := stringMap(body["requestTemplates"])
	respTmpls := stringMap(body["responseTemplates"])
	if err := h.store.putIntegration(ctx, apiID, restIntegration{
		ResourceID: resID, HTTPMethod: httpMethod, Type: itype, URI: uri, IntegrationHTTPMethod: ihm, PayloadFormatVersion: pfv,
		RequestTemplates: reqTmpls, ResponseTemplates: respTmpls,
	}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"type": itype, "uri": uri})
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
	integ, pathParams, authType, _, matched := matchRestRoute(snap, r.Method, routePath)
	if !matched {
		writeAGWError(w, http.StatusForbidden, "MissingAuthenticationTokenException", requestID, "Missing Authentication Token")
		return
	}
	// v1 increment 1 serves NONE-auth methods; enforcing IAM/Cognito/JWT method authorizers is a
	// tracked follow-on — refuse (don't silently bypass) a method that asks for more.
	if authType != "" && authType != "NONE" {
		writeAGWError(w, http.StatusForbidden, "AccessDeniedException", requestID,
			"method authorizationType "+authType+" is not yet enforced by the shim's REST v1 data plane")
		return
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

// writeMappedResponse reads the upstream response body and applies the matching responseTemplates
// template (pass-through, copying status+headers, if none matches). A mapped response is written as
// application/json with the upstream status.
func (h *apigwV1Handler) writeMappedResponse(w http.ResponseWriter, r *http.Request, integ restIntegration, resp *http.Response, apiID, stage, routePath, requestID string, pathParams, stageVars map[string]string) {
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	tmpl, matched := pickMappingTemplate(integ.ResponseTemplates, resp.Header.Get("Content-Type"))
	if !matched {
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
	out, err := renderMappingTemplate(tmpl, respBody, mergeInputParams(r, pathParams), stageVars, h.vtlContext(r, apiID, stage, routePath, requestID))
	if err != nil {
		h.logger.Warn("apigw v1 response template error", "api", apiID, "path", routePath, "error", err.Error())
		writeAGWError(w, http.StatusInternalServerError, "InternalServerException", requestID, "response mapping template error")
		return
	}
	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(out))
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
