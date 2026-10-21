// API Gateway REST API (v1) control-plane state for the aws-shim. REST v1 differs
// structurally from the HTTP-API (v2) model in apigateway_store.go: a resource TREE + per-resource
// methods + integrations, an immutable DEPLOYMENT snapshot of that tree, and a STAGE that points at a
// deployment (+ stage variables). Invoke resolves stage -> deployment snapshot -> resource -> method
// -> integration. Shares the same Postgres as the v2 store; own tables (rest_*), never overloads agw_*.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type apigwV1Store struct{ db *sql.DB }

type restAPI struct {
	ID      string
	Name    string
	Created time.Time
}

type restResource struct {
	ID       string `json:"id"`
	ParentID string `json:"parentId"`
	PathPart string `json:"pathPart"` // "" for the root; a literal or "{var}" / "{proxy+}" segment
	FullPath string `json:"path"`     // e.g. "/" or "/items/{id}"
}

type restMethod struct {
	ResourceID        string `json:"resourceId"`
	HTTPMethod        string `json:"httpMethod"` // GET, POST, …, ANY
	AuthorizationType string `json:"authorizationType"`
	AuthorizerID      string `json:"authorizerId"`
	// Request validation (PutMethod) — the AWS "method request" validation contract, enforced at the
	// data plane against the deployed snapshot (see validateRestRequest). RequestValidatorID names the
	// restRequestValidator that decides WHAT is validated; RequestModels maps a content-type to a model
	// name whose JSON Schema the body must satisfy; RequestParameters maps a method.request.* parameter
	// to whether it is required.
	RequestValidatorID string            `json:"requestValidatorId,omitempty"`
	RequestModels      map[string]string `json:"requestModels,omitempty"`     // contentType → model name
	RequestParameters  map[string]bool   `json:"requestParameters,omitempty"` // method.request.(querystring|header|path).<name> → required
	// APIKeyRequired gates the method on a valid x-api-key at invoke (AWS apiKeyRequired). It is a
	// method property frozen into the deployment snapshot; the KEY and its usage-plan association are
	// LIVE account/plan state checked at invoke (not snapshotted), so a key can be enabled/disabled or
	// (dis)associated without a redeploy — matching AWS.
	APIKeyRequired bool `json:"apiKeyRequired,omitempty"`
}

// restAPIKey is an API key (CreateApiKey): a secret VALUE a caller presents as x-api-key, plus an
// enabled flag. A key grants access to a method only when (a) enabled and (b) associated — via a usage
// plan — with the invoked api+stage; the key value itself carries no scope. Account-level, not per-API.
type restAPIKey struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Enabled bool   `json:"enabled"`
}

// restUsagePlan ties a set of api+stage targets (apiStages) to the keys associated with the plan
// (CreateUsagePlan + CreateUsagePlanKey). Throttle/quota (rate/burst/quota) are ACCEPTED but NOT
// enforced — the shim does not rate-limit; documented non-goal, never faked as if limits applied.
type restUsagePlan struct {
	ID        string             `json:"id"`
	Name      string             `json:"name"`
	APIStages []restUsagePlanAPI `json:"apiStages,omitempty"`
}

type restUsagePlanAPI struct {
	APIID string `json:"apiId"`
	Stage string `json:"stage"`
}

// restModel is a reusable request/response payload schema (CreateModel). Its Schema is the JSON Schema
// a method's RequestModels points at; the shared internal/apigwschema validator (the same tier the v2
// apigw-validator runs) checks a request body against it. Identified by name within an API (AWS keys
// models by name, not an id).
type restModel struct {
	Name        string         `json:"name"`
	ContentType string         `json:"contentType"`
	Schema      map[string]any `json:"schema"`
	Description string         `json:"description,omitempty"`
}

// restRequestValidator is a named (validateRequestBody, validateRequestParameters) pair
// (CreateRequestValidator). A method references one by id; the two booleans decide whether the body
// (against the method's RequestModels) and/or the required RequestParameters are checked at invoke.
type restRequestValidator struct {
	ID                        string `json:"id"`
	Name                      string `json:"name"`
	ValidateRequestBody       bool   `json:"validateRequestBody"`
	ValidateRequestParameters bool   `json:"validateRequestParameters"`
}

// restMethodResponse is a method's declared response contract for one statusCode (PutMethodResponse):
// the response models + which response headers the method may return. It is the AWS "method response"
// side of the model and is stored for control-plane fidelity (tools that define an API call
// PutMethodResponse); the invoke path maps responses via IntegrationResponse, so this is not enforced
// at runtime — matching AWS, which does not validate responses against method-response models.
type restMethodResponse struct {
	ResourceID         string            `json:"resourceId"`
	HTTPMethod         string            `json:"httpMethod"`
	StatusCode         string            `json:"statusCode"`
	ResponseModels     map[string]string `json:"responseModels,omitempty"`
	ResponseParameters map[string]bool   `json:"responseParameters,omitempty"`
}

type restIntegration struct {
	ResourceID            string            `json:"resourceId"`
	HTTPMethod            string            `json:"httpMethod"`
	Type                  string            `json:"type"`                       // AWS | AWS_PROXY | HTTP | HTTP_PROXY | MOCK
	URI                   string            `json:"uri"`                        // Lambda ARN/name, or an http(s) origin
	IntegrationHTTPMethod string            `json:"integrationHttpMethod"`      // for HTTP/HTTP_PROXY
	PayloadFormatVersion  string            `json:"payloadFormatVersion"`       // Lambda proxy event format (default 1.0 for REST)
	RequestTemplates      map[string]string `json:"requestTemplates,omitempty"` // contentType → VTL (non-proxy AWS/HTTP)
	// IntegrationResponses holds the per-status response mapping (PutIntegrationResponse), as AWS models
	// it: statusCode → (contentType → VTL responseTemplate). The matched response's statusCode becomes
	// the method response status; its templates map the backend body. selectionPattern is not modelled
	// (the default/200 entry catches every backend response — documented honest subset).
	IntegrationResponses map[string]map[string]string `json:"integrationResponses,omitempty"`
}

// restAuthorizer is a method authorizer (CreateAuthorizer). The shim enforces COGNITO_USER_POOLS by
// validating the caller's JWT against the pool's issuer/JWKS (the shim's own Cognito serves these, and
// any OIDC issuer works). TOKEN/REQUEST (Lambda) and the method-level AWS_IAM authType are refused
// fail-closed at the control plane (see the handler) — an authorizer the shim cannot vet must never
// silently admit a request.
type restAuthorizer struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`           // COGNITO_USER_POOLS (TOKEN/REQUEST refused at CreateAuthorizer)
	Issuer         string   `json:"issuer"`         // resolved OIDC issuer (from a Cognito pool ARN or a bare issuer URL)
	Audiences      []string `json:"audiences"`      // allowed token audiences (empty = skip aud check)
	IdentitySource string   `json:"identitySource"` // header the token is read from (default Authorization)
}

// restSnapshot is the immutable picture a deployment freezes and a stage serves. Models + Validators
// are frozen in too, so request validation at the data plane reflects the DEPLOYED config (a model or
// validator change only takes effect on redeploy — exactly AWS's deployment semantics).
type restSnapshot struct {
	Resources    []restResource         `json:"resources"`
	Methods      []restMethod           `json:"methods"`
	Integrations []restIntegration      `json:"integrations"`
	Authorizers  []restAuthorizer       `json:"authorizers,omitempty"`
	Models       []restModel            `json:"models,omitempty"`
	Validators   []restRequestValidator `json:"validators,omitempty"`
}

func (s *apigwV1Store) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS rest_apis (
    api_id  text PRIMARY KEY,
    name    text NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS rest_resources (
    api_id      text NOT NULL,
    resource_id text NOT NULL,
    parent_id   text NOT NULL DEFAULT '',
    path_part   text NOT NULL DEFAULT '',
    full_path   text NOT NULL,
    PRIMARY KEY (api_id, resource_id)
);
CREATE TABLE IF NOT EXISTS rest_methods (
    api_id             text NOT NULL,
    resource_id        text NOT NULL,
    http_method        text NOT NULL,
    authorization_type text NOT NULL DEFAULT 'NONE',
    authorizer_id      text NOT NULL DEFAULT '',
    request_validator_id text NOT NULL DEFAULT '',
    request_models       jsonb,
    request_parameters   jsonb,
    api_key_required     boolean NOT NULL DEFAULT false,
    PRIMARY KEY (api_id, resource_id, http_method)
);
-- API keys + usage plans are ACCOUNT-level (not per-API, not snapshotted): a key's enabled state and
-- its usage-plan↔api+stage association are read LIVE at invoke, so enabling/disabling or (dis)associating
-- a key takes effect without a redeploy (matching AWS).
CREATE TABLE IF NOT EXISTS rest_api_keys (
    key_id  text PRIMARY KEY,
    name    text NOT NULL DEFAULT '',
    value   text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS rest_api_keys_value ON rest_api_keys (value);
CREATE TABLE IF NOT EXISTS rest_usage_plans (
    plan_id text PRIMARY KEY,
    name    text NOT NULL DEFAULT '',
    created timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS rest_usage_plan_stages (
    plan_id    text NOT NULL,
    api_id     text NOT NULL,
    stage_name text NOT NULL,
    PRIMARY KEY (plan_id, api_id, stage_name)
);
CREATE TABLE IF NOT EXISTS rest_usage_plan_keys (
    plan_id text NOT NULL,
    key_id  text NOT NULL,
    PRIMARY KEY (plan_id, key_id)
);
CREATE TABLE IF NOT EXISTS rest_models (
    api_id       text NOT NULL,
    name         text NOT NULL,
    content_type text NOT NULL DEFAULT 'application/json',
    schema       jsonb,
    description  text NOT NULL DEFAULT '',
    PRIMARY KEY (api_id, name)
);
CREATE TABLE IF NOT EXISTS rest_request_validators (
    api_id        text NOT NULL,
    validator_id  text NOT NULL,
    name          text NOT NULL DEFAULT '',
    validate_body   boolean NOT NULL DEFAULT false,
    validate_params boolean NOT NULL DEFAULT false,
    PRIMARY KEY (api_id, validator_id)
);
CREATE TABLE IF NOT EXISTS rest_method_responses (
    api_id              text NOT NULL,
    resource_id         text NOT NULL,
    http_method         text NOT NULL,
    status_code         text NOT NULL,
    response_models     jsonb,
    response_parameters jsonb,
    PRIMARY KEY (api_id, resource_id, http_method, status_code)
);
CREATE TABLE IF NOT EXISTS rest_integrations (
    api_id         text NOT NULL,
    resource_id    text NOT NULL,
    http_method    text NOT NULL,
    type           text NOT NULL,
    uri            text NOT NULL DEFAULT '',
    integration_http_method text NOT NULL DEFAULT '',
    payload_format_version  text NOT NULL DEFAULT '1.0',
    request_templates     jsonb,
    integration_responses jsonb,
    PRIMARY KEY (api_id, resource_id, http_method)
);
CREATE TABLE IF NOT EXISTS rest_authorizers (
    api_id          text NOT NULL,
    authorizer_id   text NOT NULL,
    name            text NOT NULL DEFAULT '',
    type            text NOT NULL,
    issuer          text NOT NULL DEFAULT '',
    audiences       jsonb,
    identity_source text NOT NULL DEFAULT '',
    PRIMARY KEY (api_id, authorizer_id)
);
CREATE TABLE IF NOT EXISTS rest_deployments (
    api_id        text NOT NULL,
    deployment_id text NOT NULL,
    snapshot      jsonb NOT NULL,
    created       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (api_id, deployment_id)
);
CREATE TABLE IF NOT EXISTS rest_stages (
    api_id        text NOT NULL,
    stage_name    text NOT NULL,
    deployment_id text NOT NULL DEFAULT '',
    variables     jsonb,
    created       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (api_id, stage_name)
);
-- increment 2 (non-proxy VTL mapping): add the mapping columns in place so an already-live
-- rest_integrations table (increment 1) gains them. CREATE TABLE IF NOT EXISTS above is a no-op on an
-- existing table, so the ALTERs are what migrate it; both are no-ops on a freshly created table.
ALTER TABLE rest_integrations ADD COLUMN IF NOT EXISTS request_templates     jsonb;
ALTER TABLE rest_integrations ADD COLUMN IF NOT EXISTS integration_responses jsonb;
-- increment 3 (request validation): add the method-request validation columns in place so an
-- already-live rest_methods table (increment 1) gains them. No-ops on a freshly created table.
ALTER TABLE rest_methods ADD COLUMN IF NOT EXISTS request_validator_id text NOT NULL DEFAULT '';
ALTER TABLE rest_methods ADD COLUMN IF NOT EXISTS request_models       jsonb;
ALTER TABLE rest_methods ADD COLUMN IF NOT EXISTS request_parameters   jsonb;
-- increment 4 (API keys): add the method gate column in place for an already-live rest_methods table.
ALTER TABLE rest_methods ADD COLUMN IF NOT EXISTS api_key_required boolean NOT NULL DEFAULT false;`)
	return err
}

// --- APIs ---

func (s *apigwV1Store) createAPI(ctx context.Context, a restAPI) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO rest_apis (api_id, name) VALUES ($1,$2)`, a.ID, a.Name)
	return err
}

func (s *apigwV1Store) getAPI(ctx context.Context, id string) (restAPI, bool, error) {
	var a restAPI
	err := s.db.QueryRowContext(ctx, `SELECT api_id, name, created FROM rest_apis WHERE api_id=$1`, id).
		Scan(&a.ID, &a.Name, &a.Created)
	if err == sql.ErrNoRows {
		return restAPI{}, false, nil
	}
	return a, err == nil, err
}

func (s *apigwV1Store) listAPIs(ctx context.Context) ([]restAPI, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT api_id, name, created FROM rest_apis ORDER BY created`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restAPI
	for rows.Next() {
		var a restAPI
		if err := rows.Scan(&a.ID, &a.Name, &a.Created); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *apigwV1Store) deleteAPI(ctx context.Context, id string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`DELETE FROM rest_resources WHERE api_id=$1`,
		`DELETE FROM rest_methods WHERE api_id=$1`,
		`DELETE FROM rest_integrations WHERE api_id=$1`,
		`DELETE FROM rest_deployments WHERE api_id=$1`,
		`DELETE FROM rest_stages WHERE api_id=$1`,
		`DELETE FROM rest_models WHERE api_id=$1`,
		`DELETE FROM rest_request_validators WHERE api_id=$1`,
		`DELETE FROM rest_method_responses WHERE api_id=$1`,
		`DELETE FROM rest_authorizers WHERE api_id=$1`,
		// account-level API keys + usage plans survive an API delete; only this API's stage associations go.
		`DELETE FROM rest_usage_plan_stages WHERE api_id=$1`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return false, err
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM rest_apis WHERE api_id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

// --- resources ---

func (s *apigwV1Store) createResource(ctx context.Context, apiID string, r restResource) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_resources (api_id, resource_id, parent_id, path_part, full_path) VALUES ($1,$2,$3,$4,$5)`,
		apiID, r.ID, r.ParentID, r.PathPart, r.FullPath)
	return err
}

func (s *apigwV1Store) getResource(ctx context.Context, apiID, resID string) (restResource, bool, error) {
	var r restResource
	err := s.db.QueryRowContext(ctx,
		`SELECT resource_id, parent_id, path_part, full_path FROM rest_resources WHERE api_id=$1 AND resource_id=$2`, apiID, resID).
		Scan(&r.ID, &r.ParentID, &r.PathPart, &r.FullPath)
	if err == sql.ErrNoRows {
		return restResource{}, false, nil
	}
	return r, err == nil, err
}

func (s *apigwV1Store) listResources(ctx context.Context, apiID string) ([]restResource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT resource_id, parent_id, path_part, full_path FROM rest_resources WHERE api_id=$1 ORDER BY full_path`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restResource
	for rows.Next() {
		var r restResource
		if err := rows.Scan(&r.ID, &r.ParentID, &r.PathPart, &r.FullPath); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- methods + integrations ---

func (s *apigwV1Store) putMethod(ctx context.Context, apiID string, m restMethod) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_methods (api_id, resource_id, http_method, authorization_type, authorizer_id, request_validator_id, request_models, request_parameters, api_key_required)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (api_id, resource_id, http_method)
		 DO UPDATE SET authorization_type=EXCLUDED.authorization_type, authorizer_id=EXCLUDED.authorizer_id,
		   request_validator_id=EXCLUDED.request_validator_id, request_models=EXCLUDED.request_models,
		   request_parameters=EXCLUDED.request_parameters, api_key_required=EXCLUDED.api_key_required`,
		apiID, m.ResourceID, m.HTTPMethod, m.AuthorizationType, m.AuthorizerID,
		m.RequestValidatorID, marshalJSONB(m.RequestModels), marshalJSONB(m.RequestParameters), m.APIKeyRequired)
	return err
}

func (s *apigwV1Store) putIntegration(ctx context.Context, apiID string, i restIntegration) error {
	reqT := marshalJSONB(i.RequestTemplates)
	// PutIntegration carries the request side; the response side (integration_responses) is written by
	// PutIntegrationResponse, so DO NOT clobber it here — COALESCE keeps any responses already set.
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_integrations (api_id, resource_id, http_method, type, uri, integration_http_method, payload_format_version, request_templates)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (api_id, resource_id, http_method)
		 DO UPDATE SET type=EXCLUDED.type, uri=EXCLUDED.uri,
		   integration_http_method=EXCLUDED.integration_http_method, payload_format_version=EXCLUDED.payload_format_version,
		   request_templates=EXCLUDED.request_templates`,
		apiID, i.ResourceID, i.HTTPMethod, i.Type, i.URI, i.IntegrationHTTPMethod, i.PayloadFormatVersion, reqT)
	return err
}

// putIntegrationResponse records a single IntegrationResponse (PutIntegrationResponse): it merges the
// {contentType → VTL} templates for one statusCode into the integration's integration_responses map.
// AWS requires the integration to exist first; a missing one returns sql.ErrNoRows so the handler can
// map it to NotFoundException.
func (s *apigwV1Store) putIntegrationResponse(ctx context.Context, apiID, resID, method, statusCode string, templates map[string]string) error {
	tj, err := json.Marshal(templates)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE rest_integrations
		   SET integration_responses = jsonb_set(COALESCE(integration_responses, '{}'::jsonb), ARRAY[$4], $5::jsonb, true)
		 WHERE api_id=$1 AND resource_id=$2 AND http_method=$3`,
		apiID, resID, method, statusCode, string(tj))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// marshalJSONB encodes a value for a jsonb column (nil when empty, so the column stays NULL rather
// than "{}"/"null").
func marshalJSONB[T any](m map[string]T) []byte {
	if len(m) == 0 {
		return nil
	}
	b, _ := json.Marshal(m)
	return b
}

func (s *apigwV1Store) listMethods(ctx context.Context, apiID string) ([]restMethod, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT resource_id, http_method, authorization_type, authorizer_id, request_validator_id, request_models, request_parameters, api_key_required FROM rest_methods WHERE api_id=$1`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restMethod
	for rows.Next() {
		var m restMethod
		var reqModels, reqParams []byte
		if err := rows.Scan(&m.ResourceID, &m.HTTPMethod, &m.AuthorizationType, &m.AuthorizerID, &m.RequestValidatorID, &reqModels, &reqParams, &m.APIKeyRequired); err != nil {
			return nil, err
		}
		if len(reqModels) > 0 {
			_ = json.Unmarshal(reqModels, &m.RequestModels)
		}
		if len(reqParams) > 0 {
			_ = json.Unmarshal(reqParams, &m.RequestParameters)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *apigwV1Store) listIntegrations(ctx context.Context, apiID string) ([]restIntegration, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT resource_id, http_method, type, uri, integration_http_method, payload_format_version, request_templates, integration_responses FROM rest_integrations WHERE api_id=$1`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restIntegration
	for rows.Next() {
		var i restIntegration
		var reqT, intResp []byte
		if err := rows.Scan(&i.ResourceID, &i.HTTPMethod, &i.Type, &i.URI, &i.IntegrationHTTPMethod, &i.PayloadFormatVersion, &reqT, &intResp); err != nil {
			return nil, err
		}
		if len(reqT) > 0 {
			_ = json.Unmarshal(reqT, &i.RequestTemplates)
		}
		if len(intResp) > 0 {
			_ = json.Unmarshal(intResp, &i.IntegrationResponses)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *apigwV1Store) createAuthorizer(ctx context.Context, apiID string, a restAuthorizer) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_authorizers (api_id, authorizer_id, name, type, issuer, audiences, identity_source)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (api_id, authorizer_id)
		 DO UPDATE SET name=EXCLUDED.name, type=EXCLUDED.type, issuer=EXCLUDED.issuer,
		   audiences=EXCLUDED.audiences, identity_source=EXCLUDED.identity_source`,
		apiID, a.ID, a.Name, a.Type, a.Issuer, marshalJSONBSlice(a.Audiences), a.IdentitySource)
	return err
}

func (s *apigwV1Store) listAuthorizers(ctx context.Context, apiID string) ([]restAuthorizer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT authorizer_id, name, type, issuer, audiences, identity_source FROM rest_authorizers WHERE api_id=$1`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restAuthorizer
	for rows.Next() {
		var a restAuthorizer
		var auds []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.Issuer, &auds, &a.IdentitySource); err != nil {
			return nil, err
		}
		if len(auds) > 0 {
			_ = json.Unmarshal(auds, &a.Audiences)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// marshalJSONBSlice encodes a string slice for a jsonb column (nil when empty → NULL).
func marshalJSONBSlice(v []string) []byte {
	if len(v) == 0 {
		return nil
	}
	b, _ := json.Marshal(v)
	return b
}

// --- models + request validators + method responses ---

func (s *apigwV1Store) createModel(ctx context.Context, apiID string, m restModel) error {
	var sch []byte
	if len(m.Schema) > 0 {
		sch, _ = json.Marshal(m.Schema)
	}
	ct := m.ContentType
	if ct == "" {
		ct = "application/json"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_models (api_id, name, content_type, schema, description)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (api_id, name)
		 DO UPDATE SET content_type=EXCLUDED.content_type, schema=EXCLUDED.schema, description=EXCLUDED.description`,
		apiID, m.Name, ct, sch, m.Description)
	return err
}

func (s *apigwV1Store) getModel(ctx context.Context, apiID, name string) (restModel, bool, error) {
	var m restModel
	var sch []byte
	err := s.db.QueryRowContext(ctx, `SELECT name, content_type, schema, description FROM rest_models WHERE api_id=$1 AND name=$2`, apiID, name).
		Scan(&m.Name, &m.ContentType, &sch, &m.Description)
	if err == sql.ErrNoRows {
		return restModel{}, false, nil
	}
	if err != nil {
		return restModel{}, false, err
	}
	if len(sch) > 0 {
		_ = json.Unmarshal(sch, &m.Schema)
	}
	return m, true, nil
}

func (s *apigwV1Store) listModels(ctx context.Context, apiID string) ([]restModel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, content_type, schema, description FROM rest_models WHERE api_id=$1 ORDER BY name`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restModel
	for rows.Next() {
		var m restModel
		var sch []byte
		if err := rows.Scan(&m.Name, &m.ContentType, &sch, &m.Description); err != nil {
			return nil, err
		}
		if len(sch) > 0 {
			_ = json.Unmarshal(sch, &m.Schema)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *apigwV1Store) createRequestValidator(ctx context.Context, apiID string, v restRequestValidator) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_request_validators (api_id, validator_id, name, validate_body, validate_params)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (api_id, validator_id)
		 DO UPDATE SET name=EXCLUDED.name, validate_body=EXCLUDED.validate_body, validate_params=EXCLUDED.validate_params`,
		apiID, v.ID, v.Name, v.ValidateRequestBody, v.ValidateRequestParameters)
	return err
}

func (s *apigwV1Store) getRequestValidator(ctx context.Context, apiID, id string) (restRequestValidator, bool, error) {
	var v restRequestValidator
	err := s.db.QueryRowContext(ctx, `SELECT validator_id, name, validate_body, validate_params FROM rest_request_validators WHERE api_id=$1 AND validator_id=$2`, apiID, id).
		Scan(&v.ID, &v.Name, &v.ValidateRequestBody, &v.ValidateRequestParameters)
	if err == sql.ErrNoRows {
		return restRequestValidator{}, false, nil
	}
	return v, err == nil, err
}

func (s *apigwV1Store) listRequestValidators(ctx context.Context, apiID string) ([]restRequestValidator, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT validator_id, name, validate_body, validate_params FROM rest_request_validators WHERE api_id=$1 ORDER BY validator_id`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restRequestValidator
	for rows.Next() {
		var v restRequestValidator
		if err := rows.Scan(&v.ID, &v.Name, &v.ValidateRequestBody, &v.ValidateRequestParameters); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// putMethodResponse records a method response (PutMethodResponse). The method must exist first (AWS
// semantics); a missing one returns sql.ErrNoRows so the handler maps it to NotFoundException.
func (s *apigwV1Store) putMethodResponse(ctx context.Context, apiID string, mr restMethodResponse) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM rest_methods WHERE api_id=$1 AND resource_id=$2 AND http_method=$3)`,
		apiID, mr.ResourceID, mr.HTTPMethod).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return sql.ErrNoRows
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_method_responses (api_id, resource_id, http_method, status_code, response_models, response_parameters)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (api_id, resource_id, http_method, status_code)
		 DO UPDATE SET response_models=EXCLUDED.response_models, response_parameters=EXCLUDED.response_parameters`,
		apiID, mr.ResourceID, mr.HTTPMethod, mr.StatusCode, marshalJSONB(mr.ResponseModels), marshalJSONB(mr.ResponseParameters))
	return err
}

// --- API keys + usage plans (account-level; read LIVE at invoke, never snapshotted) ---

func (s *apigwV1Store) createAPIKey(ctx context.Context, k restAPIKey) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_api_keys (key_id, name, value, enabled) VALUES ($1,$2,$3,$4)`,
		k.ID, k.Name, k.Value, k.Enabled)
	return err
}

func (s *apigwV1Store) getAPIKey(ctx context.Context, id string) (restAPIKey, bool, error) {
	var k restAPIKey
	err := s.db.QueryRowContext(ctx, `SELECT key_id, name, value, enabled FROM rest_api_keys WHERE key_id=$1`, id).
		Scan(&k.ID, &k.Name, &k.Value, &k.Enabled)
	if err == sql.ErrNoRows {
		return restAPIKey{}, false, nil
	}
	return k, err == nil, err
}

func (s *apigwV1Store) listAPIKeys(ctx context.Context) ([]restAPIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key_id, name, value, enabled FROM rest_api_keys ORDER BY created`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restAPIKey
	for rows.Next() {
		var k restAPIKey
		if err := rows.Scan(&k.ID, &k.Name, &k.Value, &k.Enabled); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *apigwV1Store) createUsagePlan(ctx context.Context, p restUsagePlan) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO rest_usage_plans (plan_id, name) VALUES ($1,$2)`, p.ID, p.Name); err != nil {
		return err
	}
	for _, st := range p.APIStages {
		if st.APIID == "" || st.Stage == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO rest_usage_plan_stages (plan_id, api_id, stage_name) VALUES ($1,$2,$3)
			 ON CONFLICT (plan_id, api_id, stage_name) DO NOTHING`, p.ID, st.APIID, st.Stage); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *apigwV1Store) getUsagePlan(ctx context.Context, id string) (restUsagePlan, bool, error) {
	var p restUsagePlan
	err := s.db.QueryRowContext(ctx, `SELECT plan_id, name FROM rest_usage_plans WHERE plan_id=$1`, id).Scan(&p.ID, &p.Name)
	if err == sql.ErrNoRows {
		return restUsagePlan{}, false, nil
	}
	if err != nil {
		return restUsagePlan{}, false, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT api_id, stage_name FROM rest_usage_plan_stages WHERE plan_id=$1 ORDER BY api_id, stage_name`, id)
	if err != nil {
		return restUsagePlan{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var a restUsagePlanAPI
		if err := rows.Scan(&a.APIID, &a.Stage); err != nil {
			return restUsagePlan{}, false, err
		}
		p.APIStages = append(p.APIStages, a)
	}
	return p, true, rows.Err()
}

func (s *apigwV1Store) listUsagePlans(ctx context.Context) ([]restUsagePlan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT plan_id, name FROM rest_usage_plans ORDER BY created`)
	if err != nil {
		return nil, err
	}
	var ids []restUsagePlan
	for rows.Next() {
		var p restUsagePlan
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range ids { // fill apiStages per plan
		full, _, err := s.getUsagePlan(ctx, ids[i].ID)
		if err != nil {
			return nil, err
		}
		ids[i] = full
	}
	return ids, nil
}

// createUsagePlanKey associates an existing key with a usage plan. Both must exist (AWS NotFound
// otherwise); a missing one returns sql.ErrNoRows.
func (s *apigwV1Store) createUsagePlanKey(ctx context.Context, planID, keyID string) error {
	var ok bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM rest_usage_plans WHERE plan_id=$1) AND EXISTS(SELECT 1 FROM rest_api_keys WHERE key_id=$2)`,
		planID, keyID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return sql.ErrNoRows
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_usage_plan_keys (plan_id, key_id) VALUES ($1,$2) ON CONFLICT (plan_id, key_id) DO NOTHING`,
		planID, keyID)
	return err
}

func (s *apigwV1Store) listUsagePlanKeys(ctx context.Context, planID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key_id FROM rest_usage_plan_keys WHERE plan_id=$1 ORDER BY key_id`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// apiKeyAuthorized is the data-plane gate for a method with apiKeyRequired: the presented x-api-key
// VALUE must match an ENABLED key that is associated (via a usage plan) with the invoked api+stage.
// This is checked LIVE (not from the deployment snapshot), so enabling/disabling or (dis)associating a
// key takes effect without a redeploy — AWS semantics. A blank value is never authorized.
func (s *apigwV1Store) apiKeyAuthorized(ctx context.Context, value, apiID, stage string) (bool, error) {
	if value == "" {
		return false, nil
	}
	var ok bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM rest_api_keys k
		   JOIN rest_usage_plan_keys pk ON pk.key_id = k.key_id
		   JOIN rest_usage_plan_stages ps ON ps.plan_id = pk.plan_id
		   WHERE k.value = $1 AND k.enabled = true AND ps.api_id = $2 AND ps.stage_name = $3
		 )`, value, apiID, stage).Scan(&ok)
	return ok, err
}

// snapshot captures the current resource/method/integration/authorizer tree + models + validators for
// a deployment. Models + validators are frozen so data-plane request validation reflects the deployed
// config (not later edits).
func (s *apigwV1Store) snapshot(ctx context.Context, apiID string) (restSnapshot, error) {
	var snap restSnapshot
	var err error
	if snap.Resources, err = s.listResources(ctx, apiID); err != nil {
		return snap, err
	}
	if snap.Methods, err = s.listMethods(ctx, apiID); err != nil {
		return snap, err
	}
	if snap.Integrations, err = s.listIntegrations(ctx, apiID); err != nil {
		return snap, err
	}
	if snap.Authorizers, err = s.listAuthorizers(ctx, apiID); err != nil {
		return snap, err
	}
	if snap.Models, err = s.listModels(ctx, apiID); err != nil {
		return snap, err
	}
	if snap.Validators, err = s.listRequestValidators(ctx, apiID); err != nil {
		return snap, err
	}
	return snap, nil
}

// --- deployments + stages ---

func (s *apigwV1Store) createDeployment(ctx context.Context, apiID, depID string, snap restSnapshot) error {
	b, _ := json.Marshal(snap)
	_, err := s.db.ExecContext(ctx, `INSERT INTO rest_deployments (api_id, deployment_id, snapshot) VALUES ($1,$2,$3)`, apiID, depID, b)
	return err
}

func (s *apigwV1Store) getDeploymentSnapshot(ctx context.Context, apiID, depID string) (restSnapshot, bool, error) {
	var b []byte
	err := s.db.QueryRowContext(ctx, `SELECT snapshot FROM rest_deployments WHERE api_id=$1 AND deployment_id=$2`, apiID, depID).Scan(&b)
	if err == sql.ErrNoRows {
		return restSnapshot{}, false, nil
	}
	if err != nil {
		return restSnapshot{}, false, err
	}
	var snap restSnapshot
	_ = json.Unmarshal(b, &snap)
	return snap, true, nil
}

func (s *apigwV1Store) putStage(ctx context.Context, apiID, name, depID string, vars map[string]string) error {
	var vb []byte
	if len(vars) > 0 {
		vb, _ = json.Marshal(vars)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO rest_stages (api_id, stage_name, deployment_id, variables) VALUES ($1,$2,$3,$4)
		 ON CONFLICT (api_id, stage_name) DO UPDATE SET deployment_id=EXCLUDED.deployment_id, variables=EXCLUDED.variables`,
		apiID, name, depID, vb)
	return err
}

func (s *apigwV1Store) getStage(ctx context.Context, apiID, name string) (depID string, vars map[string]string, ok bool, err error) {
	var vb []byte
	err = s.db.QueryRowContext(ctx, `SELECT deployment_id, variables FROM rest_stages WHERE api_id=$1 AND stage_name=$2`, apiID, name).Scan(&depID, &vb)
	if err == sql.ErrNoRows {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	if len(vb) > 0 {
		_ = json.Unmarshal(vb, &vars)
	}
	return depID, vars, true, nil
}

func (s *apigwV1Store) listStages(ctx context.Context, apiID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT stage_name FROM rest_stages WHERE api_id=$1 ORDER BY stage_name`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
