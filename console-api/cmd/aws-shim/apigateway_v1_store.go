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

// restSnapshot is the immutable picture a deployment freezes and a stage serves.
type restSnapshot struct {
	Resources    []restResource    `json:"resources"`
	Methods      []restMethod      `json:"methods"`
	Integrations []restIntegration `json:"integrations"`
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
    PRIMARY KEY (api_id, resource_id, http_method)
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
ALTER TABLE rest_integrations ADD COLUMN IF NOT EXISTS integration_responses jsonb;`)
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
		`INSERT INTO rest_methods (api_id, resource_id, http_method, authorization_type, authorizer_id)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (api_id, resource_id, http_method)
		 DO UPDATE SET authorization_type=EXCLUDED.authorization_type, authorizer_id=EXCLUDED.authorizer_id`,
		apiID, m.ResourceID, m.HTTPMethod, m.AuthorizationType, m.AuthorizerID)
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
	rows, err := s.db.QueryContext(ctx, `SELECT resource_id, http_method, authorization_type, authorizer_id FROM rest_methods WHERE api_id=$1`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []restMethod
	for rows.Next() {
		var m restMethod
		if err := rows.Scan(&m.ResourceID, &m.HTTPMethod, &m.AuthorizationType, &m.AuthorizerID); err != nil {
			return nil, err
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

// snapshot captures the current resource/method/integration tree for a deployment.
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
