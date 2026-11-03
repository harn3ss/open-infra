// API Gateway REST (v1) reads of what PutMethod, CreateDeployment and CreateAuthorizer write: GetMethod
// (the method with its integration and method responses), GetDeployments/GetDeployment and
// GetAuthorizers/GetAuthorizer, in the restJson1 shapes the AWS CLI and SDKs parse. Authorized like every
// other REST v1 operation in serve (get on the coarse gate, apigateway:<Op> on Api::<restApiId>).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

func (h *apigwV1Handler) getMethod(ctx context.Context, w http.ResponseWriter, requestID, apiID, resID, httpMethod string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	if _, ok, err := h.store.getResource(ctx, apiID, resID); err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid Resource identifier specified")
		return
	}
	m, ok, err := h.store.getMethod(ctx, apiID, resID, httpMethod)
	if err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid Method identifier specified")
		return
	}
	out := map[string]any{"httpMethod": m.HTTPMethod, "authorizationType": m.AuthorizationType, "apiKeyRequired": m.APIKeyRequired}
	if m.AuthorizerID != "" {
		out["authorizerId"] = m.AuthorizerID
	}
	if m.RequestValidatorID != "" {
		out["requestValidatorId"] = m.RequestValidatorID
	}
	if len(m.RequestModels) > 0 {
		out["requestModels"] = m.RequestModels
	}
	if len(m.RequestParameters) > 0 {
		out["requestParameters"] = m.RequestParameters
	}
	responses, err := h.store.listMethodResponses(ctx, apiID, resID, httpMethod)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if len(responses) > 0 {
		mr := map[string]any{}
		for _, r := range responses {
			e := map[string]any{"statusCode": r.StatusCode}
			if len(r.ResponseModels) > 0 {
				e["responseModels"] = r.ResponseModels
			}
			if len(r.ResponseParameters) > 0 {
				e["responseParameters"] = r.ResponseParameters
			}
			mr[r.StatusCode] = e
		}
		out["methodResponses"] = mr
	}
	integ, ok, err := h.store.getIntegration(ctx, apiID, resID, httpMethod)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	if ok {
		out["methodIntegration"] = integrationJSON(integ)
	}
	writeAGWJSON(w, http.StatusOK, requestID, out)
}

// integrationJSON is a stored integration in the Integration shape (GetMethod's methodIntegration).
func integrationJSON(i restIntegration) map[string]any {
	out := map[string]any{"type": i.Type}
	if i.URI != "" {
		out["uri"] = i.URI
	}
	if i.IntegrationHTTPMethod != "" {
		out["httpMethod"] = i.IntegrationHTTPMethod
	}
	if len(i.RequestTemplates) > 0 {
		out["requestTemplates"] = i.RequestTemplates
	}
	if len(i.IntegrationResponses) > 0 {
		ir := map[string]any{}
		for code, tmpl := range i.IntegrationResponses {
			e := map[string]any{"statusCode": code}
			if len(tmpl) > 0 {
				e["responseTemplates"] = tmpl
			}
			ir[code] = e
		}
		out["integrationResponses"] = ir
	}
	return out
}

func (h *apigwV1Handler) getDeployments(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	deps, err := h.store.listDeployments(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(deps))
	for _, d := range deps {
		items = append(items, map[string]any{"id": d.ID, "createdDate": d.Created.Unix()})
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

func (h *apigwV1Handler) getDeployment(ctx context.Context, w http.ResponseWriter, requestID, apiID, depID string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	d, ok, err := h.store.getDeployment(ctx, apiID, depID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	} else if !ok {
		writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid Deployment identifier specified")
		return
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"id": d.ID, "createdDate": d.Created.Unix()})
}

func (h *apigwV1Handler) getAuthorizers(ctx context.Context, w http.ResponseWriter, requestID, apiID string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	as, err := h.store.listAuthorizers(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	items := make([]map[string]any, 0, len(as))
	for _, a := range as {
		items = append(items, authorizerJSON(a))
	}
	writeAGWJSON(w, http.StatusOK, requestID, map[string]any{"item": items})
}

func (h *apigwV1Handler) getAuthorizer(ctx context.Context, w http.ResponseWriter, requestID, apiID, id string) {
	if !h.mustAPI(ctx, w, requestID, apiID) {
		return
	}
	as, err := h.store.listAuthorizers(ctx, apiID)
	if err != nil {
		h.internal(w, requestID, err)
		return
	}
	for _, a := range as {
		if a.ID == id {
			writeAGWJSON(w, http.StatusOK, requestID, authorizerJSON(a))
			return
		}
	}
	writeAGWError(w, http.StatusNotFound, "NotFoundException", requestID, "Invalid Authorizer identifier specified")
}

// authorizerJSON is a stored authorizer in the Authorizer shape. Its providerARNs are the ones it was
// created with; one created before they were kept answers the issuer they resolved to (an issuer URL is
// itself a providerARNs value CreateAuthorizer accepts).
func authorizerJSON(a restAuthorizer) map[string]any {
	arns := a.ProviderARNs
	if len(arns) == 0 && a.Issuer != "" {
		arns = []string{a.Issuer}
	}
	header := a.IdentitySource // stored as the header name
	if header == "" {
		header = "Authorization"
	}
	out := map[string]any{"id": a.ID, "name": a.Name, "type": a.Type, "identitySource": "method.request.header." + header}
	if len(arns) > 0 {
		out["providerARNs"] = arns
	}
	return out
}

// --- store reads ---

type restDeployment struct {
	ID      string
	Created time.Time
}

func (s *apigwV1Store) getMethod(ctx context.Context, apiID, resID, httpMethod string) (restMethod, bool, error) {
	m := restMethod{ResourceID: resID, HTTPMethod: httpMethod}
	var reqModels, reqParams []byte
	err := s.db.QueryRowContext(ctx, `SELECT authorization_type, authorizer_id, request_validator_id, request_models, request_parameters, api_key_required
		FROM rest_methods WHERE api_id=$1 AND resource_id=$2 AND http_method=$3`, apiID, resID, httpMethod).
		Scan(&m.AuthorizationType, &m.AuthorizerID, &m.RequestValidatorID, &reqModels, &reqParams, &m.APIKeyRequired)
	if err == sql.ErrNoRows {
		return restMethod{}, false, nil
	} else if err != nil {
		return restMethod{}, false, err
	}
	if len(reqModels) > 0 {
		_ = json.Unmarshal(reqModels, &m.RequestModels)
	}
	if len(reqParams) > 0 {
		_ = json.Unmarshal(reqParams, &m.RequestParameters)
	}
	return m, true, nil
}

func (s *apigwV1Store) getIntegration(ctx context.Context, apiID, resID, httpMethod string) (restIntegration, bool, error) {
	i := restIntegration{ResourceID: resID, HTTPMethod: httpMethod}
	var reqT, intResp []byte
	err := s.db.QueryRowContext(ctx, `SELECT type, uri, integration_http_method, payload_format_version, request_templates, integration_responses
		FROM rest_integrations WHERE api_id=$1 AND resource_id=$2 AND http_method=$3`, apiID, resID, httpMethod).
		Scan(&i.Type, &i.URI, &i.IntegrationHTTPMethod, &i.PayloadFormatVersion, &reqT, &intResp)
	if err == sql.ErrNoRows {
		return restIntegration{}, false, nil
	} else if err != nil {
		return restIntegration{}, false, err
	}
	if len(reqT) > 0 {
		_ = json.Unmarshal(reqT, &i.RequestTemplates)
	}
	if len(intResp) > 0 {
		_ = json.Unmarshal(intResp, &i.IntegrationResponses)
	}
	return i, true, nil
}

func (s *apigwV1Store) listMethodResponses(ctx context.Context, apiID, resID, httpMethod string) ([]restMethodResponse, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status_code, response_models, response_parameters FROM rest_method_responses
		WHERE api_id=$1 AND resource_id=$2 AND http_method=$3 ORDER BY status_code`, apiID, resID, httpMethod)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restMethodResponse
	for rows.Next() {
		mr := restMethodResponse{ResourceID: resID, HTTPMethod: httpMethod}
		var models, params []byte
		if err := rows.Scan(&mr.StatusCode, &models, &params); err != nil {
			return nil, err
		}
		if len(models) > 0 {
			_ = json.Unmarshal(models, &mr.ResponseModels)
		}
		if len(params) > 0 {
			_ = json.Unmarshal(params, &mr.ResponseParameters)
		}
		out = append(out, mr)
	}
	return out, rows.Err()
}

// listDeployments is an API's deployments, oldest first — ids and times only (not their snapshots).
func (s *apigwV1Store) listDeployments(ctx context.Context, apiID string) ([]restDeployment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT deployment_id, created FROM rest_deployments WHERE api_id=$1 ORDER BY created, deployment_id`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restDeployment
	for rows.Next() {
		var d restDeployment
		if err := rows.Scan(&d.ID, &d.Created); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *apigwV1Store) getDeployment(ctx context.Context, apiID, depID string) (restDeployment, bool, error) {
	d := restDeployment{ID: depID}
	err := s.db.QueryRowContext(ctx, `SELECT created FROM rest_deployments WHERE api_id=$1 AND deployment_id=$2`, apiID, depID).Scan(&d.Created)
	if err == sql.ErrNoRows {
		return restDeployment{}, false, nil
	} else if err != nil {
		return restDeployment{}, false, err
	}
	return d, true, nil
}
