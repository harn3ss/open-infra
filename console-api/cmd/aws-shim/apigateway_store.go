// API Gateway (HTTP API v2) control-plane state for the aws-shim (polyhedron#169): APIs, routes,
// integrations, stages, authorizers, deployments. Shares the SQS/KMS Postgres. The data plane (the
// runtime HTTP→Lambda proxy) reads this state on every invoke; nothing here holds request/response bodies.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"time"
)

type apigwStore struct{ db *sql.DB }

type agwAPI struct {
	ID           string
	Name         string
	ProtocolType string
	CORS         map[string]any // AWS Cors config, stored as-sent; nil = CORS not configured
	Created      time.Time
}

type agwRoute struct {
	ID                string
	RouteKey          string // "POST /items/{id}", "ANY /{proxy+}", "$default"
	Target            string // "integrations/<integrationId>"
	AuthorizerID      string
	AuthorizationType string // "NONE" | "JWT"
}

type agwIntegration struct {
	ID                   string
	IntegrationType      string // "AWS_PROXY" (others refused at handler)
	IntegrationURI       string // the Lambda function name (resolved from an ARN or a bare name)
	PayloadFormatVersion string // "2.0" (default) | "1.0"
}

type agwStage struct {
	Name       string
	AutoDeploy bool
	Created    time.Time
}

type agwAuthorizer struct {
	ID             string
	Name           string
	Type           string // "JWT" (REQUEST/Lambda refused at handler)
	Issuer         string
	Audiences      []string
	IdentitySource string
}

func (s *apigwStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS agw_apis (
    api_id        text PRIMARY KEY,
    name          text NOT NULL,
    protocol_type text NOT NULL DEFAULT 'HTTP',
    cors          jsonb,
    created       timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agw_routes (
    api_id             text NOT NULL,
    route_id           text NOT NULL,
    route_key          text NOT NULL,
    target             text NOT NULL DEFAULT '',
    authorizer_id      text NOT NULL DEFAULT '',
    authorization_type text NOT NULL DEFAULT 'NONE',
    PRIMARY KEY (api_id, route_id)
);
CREATE TABLE IF NOT EXISTS agw_integrations (
    api_id                 text NOT NULL,
    integration_id         text NOT NULL,
    integration_type       text NOT NULL,
    integration_uri        text NOT NULL,
    payload_format_version text NOT NULL DEFAULT '2.0',
    PRIMARY KEY (api_id, integration_id)
);
CREATE TABLE IF NOT EXISTS agw_stages (
    api_id      text NOT NULL,
    stage_name  text NOT NULL,
    auto_deploy boolean NOT NULL DEFAULT true,
    created     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (api_id, stage_name)
);
CREATE TABLE IF NOT EXISTS agw_authorizers (
    api_id          text NOT NULL,
    authorizer_id   text NOT NULL,
    name            text NOT NULL,
    authorizer_type text NOT NULL,
    issuer          text NOT NULL DEFAULT '',
    audiences       jsonb,
    identity_source text NOT NULL DEFAULT '',
    PRIMARY KEY (api_id, authorizer_id)
);
CREATE TABLE IF NOT EXISTS agw_deployments (
    api_id        text NOT NULL,
    deployment_id text NOT NULL,
    created       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (api_id, deployment_id)
);`)
	return err
}

// --- APIs ---

func (s *apigwStore) createAPI(ctx context.Context, a agwAPI) error {
	cors, _ := json.Marshal(a.CORS)
	if a.CORS == nil {
		cors = nil
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agw_apis (api_id, name, protocol_type, cors) VALUES ($1,$2,$3,$4)`,
		a.ID, a.Name, a.ProtocolType, cors)
	return err
}

func (s *apigwStore) getAPI(ctx context.Context, id string) (agwAPI, bool, error) {
	var a agwAPI
	var cors []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT api_id, name, protocol_type, cors, created FROM agw_apis WHERE api_id=$1`, id).
		Scan(&a.ID, &a.Name, &a.ProtocolType, &cors, &a.Created)
	if err == sql.ErrNoRows {
		return agwAPI{}, false, nil
	}
	if err != nil {
		return agwAPI{}, false, err
	}
	if len(cors) > 0 {
		_ = json.Unmarshal(cors, &a.CORS)
	}
	return a, true, nil
}

func (s *apigwStore) listAPIs(ctx context.Context) ([]agwAPI, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT api_id, name, protocol_type, cors, created FROM agw_apis ORDER BY created`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []agwAPI
	for rows.Next() {
		var a agwAPI
		var cors []byte
		if err := rows.Scan(&a.ID, &a.Name, &a.ProtocolType, &cors, &a.Created); err != nil {
			return nil, err
		}
		if len(cors) > 0 {
			_ = json.Unmarshal(cors, &a.CORS)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *apigwStore) deleteAPI(ctx context.Context, id string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`DELETE FROM agw_routes WHERE api_id=$1`,
		`DELETE FROM agw_integrations WHERE api_id=$1`,
		`DELETE FROM agw_stages WHERE api_id=$1`,
		`DELETE FROM agw_authorizers WHERE api_id=$1`,
		`DELETE FROM agw_deployments WHERE api_id=$1`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return false, err
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM agw_apis WHERE api_id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

// --- routes ---

func (s *apigwStore) createRoute(ctx context.Context, apiID string, r agwRoute) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agw_routes (api_id, route_id, route_key, target, authorizer_id, authorization_type)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		apiID, r.ID, r.RouteKey, r.Target, r.AuthorizerID, r.AuthorizationType)
	return err
}

func (s *apigwStore) listRoutes(ctx context.Context, apiID string) ([]agwRoute, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT route_id, route_key, target, authorizer_id, authorization_type FROM agw_routes WHERE api_id=$1`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []agwRoute
	for rows.Next() {
		var r agwRoute
		if err := rows.Scan(&r.ID, &r.RouteKey, &r.Target, &r.AuthorizerID, &r.AuthorizationType); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- integrations ---

func (s *apigwStore) createIntegration(ctx context.Context, apiID string, i agwIntegration) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agw_integrations (api_id, integration_id, integration_type, integration_uri, payload_format_version)
		 VALUES ($1,$2,$3,$4,$5)`,
		apiID, i.ID, i.IntegrationType, i.IntegrationURI, i.PayloadFormatVersion)
	return err
}

func (s *apigwStore) getIntegration(ctx context.Context, apiID, intID string) (agwIntegration, bool, error) {
	var i agwIntegration
	err := s.db.QueryRowContext(ctx,
		`SELECT integration_id, integration_type, integration_uri, payload_format_version
		   FROM agw_integrations WHERE api_id=$1 AND integration_id=$2`, apiID, intID).
		Scan(&i.ID, &i.IntegrationType, &i.IntegrationURI, &i.PayloadFormatVersion)
	if err == sql.ErrNoRows {
		return agwIntegration{}, false, nil
	}
	return i, err == nil, err
}

// --- stages ---

func (s *apigwStore) createStage(ctx context.Context, apiID string, st agwStage) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agw_stages (api_id, stage_name, auto_deploy) VALUES ($1,$2,$3)
		 ON CONFLICT (api_id, stage_name) DO UPDATE SET auto_deploy=EXCLUDED.auto_deploy`,
		apiID, st.Name, st.AutoDeploy)
	return err
}

func (s *apigwStore) listStages(ctx context.Context, apiID string) ([]agwStage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT stage_name, auto_deploy, created FROM agw_stages WHERE api_id=$1 ORDER BY stage_name`, apiID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []agwStage
	for rows.Next() {
		var st agwStage
		if err := rows.Scan(&st.Name, &st.AutoDeploy, &st.Created); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *apigwStore) stageExists(ctx context.Context, apiID, name string) (bool, error) {
	var x bool
	err := s.db.QueryRowContext(ctx, `SELECT true FROM agw_stages WHERE api_id=$1 AND stage_name=$2`, apiID, name).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// --- deployments ---

func (s *apigwStore) createDeployment(ctx context.Context, apiID, depID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO agw_deployments (api_id, deployment_id) VALUES ($1,$2)`, apiID, depID)
	return err
}

// --- authorizers ---

func (s *apigwStore) createAuthorizer(ctx context.Context, apiID string, a agwAuthorizer) error {
	auds, _ := json.Marshal(a.Audiences)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agw_authorizers (api_id, authorizer_id, name, authorizer_type, issuer, audiences, identity_source)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		apiID, a.ID, a.Name, a.Type, a.Issuer, auds, a.IdentitySource)
	return err
}

func (s *apigwStore) getAuthorizer(ctx context.Context, apiID, authzID string) (agwAuthorizer, bool, error) {
	var a agwAuthorizer
	var auds []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT authorizer_id, name, authorizer_type, issuer, audiences, identity_source
		   FROM agw_authorizers WHERE api_id=$1 AND authorizer_id=$2`, apiID, authzID).
		Scan(&a.ID, &a.Name, &a.Type, &a.Issuer, &auds, &a.IdentitySource)
	if err == sql.ErrNoRows {
		return agwAuthorizer{}, false, nil
	}
	if err != nil {
		return agwAuthorizer{}, false, err
	}
	if len(auds) > 0 {
		_ = json.Unmarshal(auds, &a.Audiences)
	}
	return a, true, nil
}

// shortID returns an AWS-style lowercase-alphanumeric id of length n (api-ids, route-ids, etc.).
func shortID(n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alpha[int(b[i])%len(alpha)]
	}
	return string(b)
}
