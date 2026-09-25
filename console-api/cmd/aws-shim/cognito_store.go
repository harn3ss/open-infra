// Cognito user-pool state for the aws-shim (polyhedron#171): pools, app clients, and users. Shares the
// SQS/KMS Postgres. Passwords are stored as bcrypt hashes (never plaintext); GlobalSignOut is enforced via a
// per-user tokens_valid_after cutoff (an access token minted before the cutoff no longer verifies).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type cognitoStore struct{ db *sql.DB }

type cognitoPool struct {
	ID      string
	Name    string
	Policy  passwordPolicy
	Created time.Time
}

type cognitoClient struct {
	ID        string
	PoolID    string
	Name      string
	AuthFlows []string
}

type cognitoUser struct {
	PoolID           string
	Username         string
	PasswordHash     string
	Attributes       map[string]string
	Status           string // UNCONFIRMED | CONFIRMED
	Sub              string
	TokensValidAfter int64 // ms epoch; access tokens iat < this are invalid (GlobalSignOut)
	Created          time.Time
}

func (s *cognitoStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS cognito_pools (
    pool_id         text PRIMARY KEY,
    name            text NOT NULL,
    password_policy jsonb NOT NULL DEFAULT '{}',
    created         timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cognito_clients (
    client_id   text PRIMARY KEY,
    pool_id     text NOT NULL,
    name        text NOT NULL,
    auth_flows  jsonb NOT NULL DEFAULT '[]',
    created     timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cognito_users (
    pool_id            text NOT NULL,
    username           text NOT NULL,
    password_hash      text NOT NULL DEFAULT '',
    attributes         jsonb NOT NULL DEFAULT '{}',
    status             text NOT NULL DEFAULT 'UNCONFIRMED',
    sub                text NOT NULL,
    tokens_valid_after bigint NOT NULL DEFAULT 0,
    created            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (pool_id, username)
);`)
	return err
}

func (s *cognitoStore) createPool(ctx context.Context, p cognitoPool) error {
	pol, _ := json.Marshal(p.Policy.toJSON())
	_, err := s.db.ExecContext(ctx, `INSERT INTO cognito_pools (pool_id, name, password_policy) VALUES ($1,$2,$3)`, p.ID, p.Name, pol)
	return err
}

func (s *cognitoStore) getPool(ctx context.Context, id string) (cognitoPool, bool, error) {
	var p cognitoPool
	var pol []byte
	err := s.db.QueryRowContext(ctx, `SELECT pool_id, name, password_policy, created FROM cognito_pools WHERE pool_id=$1`, id).
		Scan(&p.ID, &p.Name, &pol, &p.Created)
	if err == sql.ErrNoRows {
		return cognitoPool{}, false, nil
	}
	if err != nil {
		return cognitoPool{}, false, err
	}
	var m map[string]any
	_ = json.Unmarshal(pol, &m)
	p.Policy = parsePasswordPolicy(map[string]any{"Policies": m})
	return p, true, nil
}

func (s *cognitoStore) deletePool(ctx context.Context, id string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	_, _ = tx.ExecContext(ctx, `DELETE FROM cognito_users WHERE pool_id=$1`, id)
	_, _ = tx.ExecContext(ctx, `DELETE FROM cognito_clients WHERE pool_id=$1`, id)
	res, err := tx.ExecContext(ctx, `DELETE FROM cognito_pools WHERE pool_id=$1`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *cognitoStore) createClient(ctx context.Context, c cognitoClient) error {
	af, _ := json.Marshal(c.AuthFlows)
	_, err := s.db.ExecContext(ctx, `INSERT INTO cognito_clients (client_id, pool_id, name, auth_flows) VALUES ($1,$2,$3,$4)`, c.ID, c.PoolID, c.Name, af)
	return err
}

func (s *cognitoStore) getClient(ctx context.Context, id string) (cognitoClient, bool, error) {
	var c cognitoClient
	var af []byte
	err := s.db.QueryRowContext(ctx, `SELECT client_id, pool_id, name, auth_flows FROM cognito_clients WHERE client_id=$1`, id).
		Scan(&c.ID, &c.PoolID, &c.Name, &af)
	if err == sql.ErrNoRows {
		return cognitoClient{}, false, nil
	}
	if err != nil {
		return cognitoClient{}, false, err
	}
	_ = json.Unmarshal(af, &c.AuthFlows)
	return c, true, nil
}

func (s *cognitoStore) createUser(ctx context.Context, u cognitoUser) error {
	attrs, _ := json.Marshal(u.Attributes)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cognito_users (pool_id, username, password_hash, attributes, status, sub) VALUES ($1,$2,$3,$4,$5,$6)`,
		u.PoolID, u.Username, u.PasswordHash, attrs, u.Status, u.Sub)
	return err
}

func (s *cognitoStore) getUser(ctx context.Context, poolID, username string) (cognitoUser, bool, error) {
	var u cognitoUser
	var attrs []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT pool_id, username, password_hash, attributes, status, sub, tokens_valid_after, created
		   FROM cognito_users WHERE pool_id=$1 AND username=$2`, poolID, username).
		Scan(&u.PoolID, &u.Username, &u.PasswordHash, &attrs, &u.Status, &u.Sub, &u.TokensValidAfter, &u.Created)
	if err == sql.ErrNoRows {
		return cognitoUser{}, false, nil
	}
	if err != nil {
		return cognitoUser{}, false, err
	}
	_ = json.Unmarshal(attrs, &u.Attributes)
	return u, true, nil
}

func (s *cognitoStore) confirmUser(ctx context.Context, poolID, username string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE cognito_users SET status='CONFIRMED' WHERE pool_id=$1 AND username=$2`, poolID, username)
	return rowsAffected(res, err)
}

func (s *cognitoStore) setPassword(ctx context.Context, poolID, username, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE cognito_users SET password_hash=$3 WHERE pool_id=$1 AND username=$2`, poolID, username, hash)
	return rowsAffected(res, err)
}

// setTokensValidAfter records a GlobalSignOut cutoff: tokens minted at/before ms are no longer valid.
func (s *cognitoStore) setTokensValidAfter(ctx context.Context, poolID, username string, ms int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE cognito_users SET tokens_valid_after=$3 WHERE pool_id=$1 AND username=$2`, poolID, username, ms)
	return rowsAffected(res, err)
}
