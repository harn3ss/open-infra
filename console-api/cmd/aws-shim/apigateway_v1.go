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
	case "PutMethodResponse":
		h.putMethodResponse(ctx, w, requestID, v.APIID, v.ResourceID, v.HTTPMethod, v.StatusCode, body)
	case "CreateModel":
		h.createModel(ctx, w, requestID, v.APIID, body)
	case "GetModels":
		h.getModels(ctx, w, requestID, v.APIID)
	case "GetModel":
		h.getModel(ctx, w, requestID, v.APIID, v.Name)
	case "CreateRequestValidator":
		h.createRequestValidator(ctx, w, requestID, v.APIID, body)
	case "GetRequestValidators":
		h.getRequestValidators(ctx, w, requestID, v.APIID)
	case "GetRequestValidator":
		h.getRequestValidator(ctx, w, requestID, v.APIID, v.Name)
	case "CreateApiKey":
		h.createAPIKey(ctx, w, requestID, body)
	case "GetApiKeys":
		h.getAPIKeys(ctx, w, requestID, r)
	case "GetApiKey":
		h.getAPIKey(ctx, w, requestID, v.KeyID, r)
	case "CreateUsagePlan":
		h.createUsagePlan(ctx, w, requestID, body)
	case "GetUsagePlans":
		h.getUsagePlans(ctx, w, requestID)
	case "GetUsagePlan":
		h.getUsagePlan(ctx, w, requestID, v.PlanID)
	case "CreateUsagePlanKey":
		h.createUsagePlanKey(ctx, w, requestID, v.PlanID, body)
	case "GetUsagePlanKeys":
		h.getUsagePlanKeys(ctx, w, requestID, v.PlanID)
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
	validatorID, _ := body["requestValidatorId"].(string)
	// Request-validation config (AWS PutMethod): a validator id + the request models (contentType →
	// model name) + required request parameters. Enforced at invoke against the deployed snapshot.
	apiKeyRequired, _ := body["apiKeyRequired"].(bool)
	m := restMethod{
		ResourceID: resID, HTTPMethod: httpMethod, AuthorizationType: authType, AuthorizerID: authID,
		RequestValidatorID: validatorID,
		RequestModels:      stringMap(body["requestModels"]),
		RequestParameters:  boolMap(body["requestParameters"]),
		APIKeyRequired:     apiKeyRequired,
	}
	if err := h.store.putMethod(ctx, apiID, m); err != nil {
		h.internal(w, requestID, err)
		return
	}
	resp := map[string]any{"httpMethod": httpMethod, "authorizationType": authType}
	if m.APIKeyRequired {
		resp["apiKeyRequired"] = true
	}
	if m.RequestValidatorID != "" {
		resp["requestValidatorId"] = m.RequestValidatorID
	}
	if len(m.RequestModels) > 0 {
		resp["requestModels"] = m.RequestModels
	}
	if len(m.RequestParameters) > 0 {
		resp["requestParameters"] = m.RequestParameters
	}
	writeAGWJSON(w, http.StatusCreated, requestID, resp)
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

// putMethodResponse records a method response (PutMethodResponse): the response models +
// response-parameter declarations for one statusCode. The method must already exist (AWS semantics); a
// missing one is a NotFoundException. This is the method-response side of the model — a control-plane
// contract tools define; the invoke path maps responses via IntegrationResponse, so it is not enforced
// at runtime (matching AWS, which does not validate responses against method-response models).
func (h *apigwV1Handler) putMethodResponse(ctx context.Context, w http.ResponseWriter, requestID, apiID, resID, httpMethod, statusCode string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	if statusCode == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "PutMethodResponse requires a statusCode.")
		return
	}
	mr := restMethodResponse{
		ResourceID: resID, HTTPMethod: httpMethod, StatusCode: statusCode,
		ResponseModels:     stringMap(body["responseModels"]),
		ResponseParameters: boolMap(body["responseParameters"]),
	}
	if err := h.store.putMethodResponse(ctx, apiID, mr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "no method "+httpMethod+" on resource "+resID+" to attach a response to (call PutMethod first).")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	resp := map[string]any{"statusCode": statusCode}
	if len(mr.ResponseModels) > 0 {
		resp["responseModels"] = mr.ResponseModels
	}
	if len(mr.ResponseParameters) > 0 {
		resp["responseParameters"] = mr.ResponseParameters
	}
	writeAGWJSON(w, http.StatusCreated, requestID, resp)
}

// createModel registers a reusable payload schema (CreateModel). The schema is JSON Schema; the shared
// internal/apigwschema validator (the v2 apigw-validator tier) checks request bodies against it.
func (h *apigwV1Handler) createModel(ctx context.Context, w http.ResponseWriter, requestID, apiID string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	name, _ := body["name"].(string)
	if name == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "CreateModel requires a name.")
		return
	}
	ct, _ := body["contentType"].(string)
	if ct == "" {
		ct = "application/json"
	}
	desc, _ := body["description"].(string)
	// AWS accepts the schema as a JSON string; accept either a string or an inline object.
	schema := schemaFromBody(body["schema"])
	if err := h.store.createModel(ctx, apiID, restModel{Name: name, ContentType: ct, Schema: schema, Description: desc}); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, modelJSON(restModel{Name: name, ContentType: ct, Schema: schema, Description: desc}))
}

func (h *apigwV1Handler) getModels(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	models, err := h.store.listModels(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(models))
	for _, m := range models {
		items = append(items, modelJSON(m))
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

func (h *apigwV1Handler) getModel(ctx context.Context, w http.ResponseWriter, requestID, apiID, name string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	m, ok, err := h.store.getModel(ctx, apiID, name)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid model name specified: "+name)
		return
	}
	writeAGWJSON(w, http.StatusOK, requestID, modelJSON(m))
}

// createRequestValidator registers a named (validateRequestBody, validateRequestParameters) pair.
func (h *apigwV1Handler) createRequestValidator(ctx context.Context, w http.ResponseWriter, requestID, apiID string, body map[string]any) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	name, _ := body["name"].(string)
	vBody, _ := body["validateRequestBody"].(bool)
	vParams, _ := body["validateRequestParameters"].(bool)
	v := restRequestValidator{ID: shortID(10), Name: name, ValidateRequestBody: vBody, ValidateRequestParameters: vParams}
	if err := h.store.createRequestValidator(ctx, apiID, v); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, validatorJSON(v))
}

func (h *apigwV1Handler) getRequestValidators(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	vs, err := h.store.listRequestValidators(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		items = append(items, validatorJSON(v))
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

func (h *apigwV1Handler) getRequestValidator(ctx context.Context, w http.ResponseWriter, requestID, apiID, id string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	v, ok, err := h.store.getRequestValidator(ctx, apiID, id)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid request validator identifier specified: "+id)
		return
	}
	writeAGWJSON(w, http.StatusOK, requestID, validatorJSON(v))
}

// schemaFromBody accepts an AWS model schema as either a JSON string (how the SDK sends it) or an inline
// JSON object, returning the decoded schema map (nil when absent/unparseable).
func schemaFromBody(v any) map[string]any {
	switch s := v.(type) {
	case string:
		if s == "" {
			return nil
		}
		var m map[string]any
		if json.Unmarshal([]byte(s), &m) == nil {
			return m
		}
	case map[string]any:
		return s
	}
	return nil
}

// modelJSON renders a model in AWS's GetModel shape (schema serialized back to a JSON string).
func modelJSON(m restModel) map[string]any {
	out := map[string]any{"name": m.Name, "contentType": m.ContentType}
	if m.Description != "" {
		out["description"] = m.Description
	}
	if len(m.Schema) > 0 {
		if b, err := json.Marshal(m.Schema); err == nil {
			out["schema"] = string(b)
		}
	}
	return out
}

func validatorJSON(v restRequestValidator) map[string]any {
	return map[string]any{
		"id": v.ID, "name": v.Name,
		"validateRequestBody":       v.ValidateRequestBody,
		"validateRequestParameters": v.ValidateRequestParameters,
	}
}

// --- API keys + usage plans (account-level; the data-plane gate for apiKeyRequired methods) ---

// createAPIKey mints an API key (CreateApiKey). AWS returns the key VALUE on create (the only time it
// is shown by default); the caller may also supply a value. A key grants nothing until it is associated
// with a usage plan that targets an api+stage (CreateUsagePlanKey).
func (h *apigwV1Handler) createAPIKey(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["name"].(string)
	enabled := true
	if v, ok := body["enabled"].(bool); ok {
		enabled = v
	}
	value, _ := body["value"].(string)
	if value == "" {
		value = shortID(40)
	}
	k := restAPIKey{ID: shortID(10), Name: name, Value: value, Enabled: enabled}
	if err := h.store.createAPIKey(ctx, k); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, apiKeyJSON(k, true)) // create echoes the value, as AWS does
}

func (h *apigwV1Handler) getAPIKeys(ctx context.Context, w http.ResponseWriter, requestID string, r *http.Request) {
	keys, err := h.store.listAPIKeys(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	incl := r.URL.Query().Get("includeValues") == "true"
	items := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		items = append(items, apiKeyJSON(k, incl))
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

func (h *apigwV1Handler) getAPIKey(ctx context.Context, w http.ResponseWriter, requestID, id string, r *http.Request) {
	k, ok, err := h.store.getAPIKey(ctx, id)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid API Key identifier specified: "+id)
		return
	}
	writeAGWJSON(w, http.StatusOK, requestID, apiKeyJSON(k, r.URL.Query().Get("includeValue") == "true"))
}

// createUsagePlan registers a usage plan + its apiStages (which api+stage the plan's keys unlock).
// throttle/quota fields are accepted but NOT enforced (the shim does not rate-limit — documented).
func (h *apigwV1Handler) createUsagePlan(ctx context.Context, w http.ResponseWriter, requestID string, body map[string]any) {
	name, _ := body["name"].(string)
	p := restUsagePlan{ID: shortID(10), Name: name, APIStages: parseAPIStages(body["apiStages"])}
	if err := h.store.createUsagePlan(ctx, p); err != nil {
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, usagePlanJSON(p))
}

func (h *apigwV1Handler) getUsagePlans(ctx context.Context, w http.ResponseWriter, requestID string) {
	plans, err := h.store.listUsagePlans(ctx)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(plans))
	for _, p := range plans {
		items = append(items, usagePlanJSON(p))
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

func (h *apigwV1Handler) getUsagePlan(ctx context.Context, w http.ResponseWriter, requestID, id string) {
	p, ok, err := h.store.getUsagePlan(ctx, id)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid Usage Plan ID specified: "+id)
		return
	}
	writeAGWJSON(w, http.StatusOK, requestID, usagePlanJSON(p))
}

// createUsagePlanKey associates an existing API key with a usage plan (CreateUsagePlanKey). keyType
// must be API_KEY; both the plan and the key must exist (NotFound otherwise).
func (h *apigwV1Handler) createUsagePlanKey(ctx context.Context, w http.ResponseWriter, requestID, planID string, body map[string]any) {
	keyID, _ := body["keyId"].(string)
	keyType, _ := body["keyType"].(string)
	if keyID == "" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "CreateUsagePlanKey requires keyId.")
		return
	}
	if keyType != "" && keyType != "API_KEY" {
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, "keyType must be API_KEY.")
		return
	}
	if err := h.store.createUsagePlanKey(ctx, planID, keyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid Usage Plan ID or API Key identifier specified.")
			return
		}
		h.internal(w, requestID, err)
		return
	}
	writeAGWJSON(w, http.StatusCreated, requestID, map[string]any{"id": keyID, "type": "API_KEY"})
}

func (h *apigwV1Handler) getUsagePlanKeys(ctx context.Context, w http.ResponseWriter, requestID, planID string) {
	ids, err := h.store.listUsagePlanKeys(ctx, planID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		items = append(items, map[string]any{"id": id, "type": "API_KEY"})
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

// parseAPIStages decodes a usage plan's apiStages ([{apiId, stage}]).
func parseAPIStages(v any) []restUsagePlanAPI {
	var out []restUsagePlanAPI
	for _, e := range sliceOf(v) {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		api, _ := m["apiId"].(string)
		stage, _ := m["stage"].(string)
		if api != "" && stage != "" {
			out = append(out, restUsagePlanAPI{APIID: api, Stage: stage})
		}
	}
	return out
}

func apiKeyJSON(k restAPIKey, includeValue bool) map[string]any {
	out := map[string]any{"id": k.ID, "name": k.Name, "enabled": k.Enabled}
	if includeValue {
		out["value"] = k.Value
	}
	return out
}

func usagePlanJSON(p restUsagePlan) map[string]any {
	stages := make([]map[string]any, 0, len(p.APIStages))
	for _, s := range p.APIStages {
		stages = append(stages, map[string]any{"apiId": s.APIID, "stage": s.Stage})
	}
	return map[string]any{"id": p.ID, "name": p.Name, "apiStages": stages}
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
	integ, meth, pathParams, matched := matchRestRoute(snap, r.Method, routePath)
	if !matched {
		writeAGWError(w, http.StatusForbidden, "MissingAuthenticationTokenException", requestID, "Missing Authentication Token")
		return
	}
	// Method authorizer. NONE serves open; COGNITO_USER_POOLS validates the caller's JWT (fail-closed);
	// AWS_IAM and any unsupported type are refused (never silently bypassed).
	if meth.AuthorizationType != "" && meth.AuthorizationType != "NONE" {
		if !h.enforceMethodAuthorizer(w, r, snap, meth.AuthorizationType, meth.AuthorizerID, requestID) {
			return
		}
	}
	// API key gate (AWS apiKeyRequired, apiKeySource HEADER): the x-api-key must be an ENABLED key
	// associated via a usage plan with this api+stage. Checked LIVE (not the snapshot), so a key can be
	// enabled/disabled or (dis)associated without a redeploy. Missing/invalid → 403 Forbidden, exactly
	// as AWS, BEFORE the body is read or the integration runs — never a silent admit of a keyless call.
	if meth.APIKeyRequired {
		authorized, err := h.store.apiKeyAuthorized(r.Context(), r.Header.Get("x-api-key"), apiID, stage)
		if err != nil {
			h.internal(w, requestID, err)
			return
		}
		if !authorized {
			writeAGWError(w, http.StatusForbidden, "ForbiddenException", requestID, "Forbidden")
			return
		}
	}

	reqBody, _ := io.ReadAll(io.LimitReader(r.Body, 6<<20))

	// Request validation (AWS "request validation"): runs AFTER the authorizer, BEFORE the integration,
	// against the deployed snapshot's validator + models. An AWS-faithful 400 ({"message": "..."}) on
	// failure; a no-op when the method has no validator attached.
	if reason, valid := validateRestRequest(snap, meth, r.Header.Get("Content-Type"), r.URL.Query(), r.Header, pathParams, reqBody); !valid {
		h.logger.Info("apigw v1 request validation rejected", "api", apiID, "stage", stage, "method", r.Method, "path", routePath, "reason", reason)
		writeAGWError(w, http.StatusBadRequest, "BadRequestException", requestID, reason)
		return
	}

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
