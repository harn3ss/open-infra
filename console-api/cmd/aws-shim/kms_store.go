// KMS control-plane state for the aws-shim (polyhedron#160).
//
// The cryptographic material lives entirely in Vault Transit (see vault_transit.go); this store holds
// only the METADATA that makes a Transit key look like a KMS CMK: its lifecycle state, key usage/spec,
// rotation flag, description, and the alias namespace. It shares the SQS/SNS CNPG Postgres (one durable
// store for the shim's stateful front doors), in its own kms_* tables.
package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type kmsStore struct{ db *sql.DB }

// keyMeta mirrors the AWS KMS KeyMetadata fields the shim populates.
type keyMeta struct {
	KeyID        string
	Arn          string
	Description  string
	KeyUsage     string // ENCRYPT_DECRYPT (v1 only)
	KeySpec      string // SYMMETRIC_DEFAULT (v1 only)
	State        string // Enabled | Disabled | PendingDeletion
	Rotation     bool
	Created      time.Time
	DeletionDate sql.NullTime
}

var errAliasExists = errors.New("alias already exists")

func (s *kmsStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS kms_keys (
    key_id        text PRIMARY KEY,
    arn           text NOT NULL,
    description   text NOT NULL DEFAULT '',
    key_usage     text NOT NULL DEFAULT 'ENCRYPT_DECRYPT',
    key_spec      text NOT NULL DEFAULT 'SYMMETRIC_DEFAULT',
    state         text NOT NULL DEFAULT 'Enabled',
    rotation      boolean NOT NULL DEFAULT false,
    created       timestamptz NOT NULL DEFAULT now(),
    deletion_date timestamptz
);
CREATE TABLE IF NOT EXISTS kms_aliases (
    alias_name text PRIMARY KEY,
    key_id     text NOT NULL,
    created    timestamptz NOT NULL DEFAULT now(),
    updated    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kms_aliases_key_id ON kms_aliases (key_id);`)
	return err
}

func (s *kmsStore) createKey(ctx context.Context, m keyMeta) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO kms_keys (key_id, arn, description, key_usage, key_spec, state, rotation, created)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		m.KeyID, m.Arn, m.Description, m.KeyUsage, m.KeySpec, m.State, m.Rotation, m.Created)
	return err
}

func (s *kmsStore) getKey(ctx context.Context, keyID string) (keyMeta, bool, error) {
	var m keyMeta
	err := s.db.QueryRowContext(ctx,
		`SELECT key_id, arn, description, key_usage, key_spec, state, rotation, created, deletion_date
		   FROM kms_keys WHERE key_id=$1`, keyID).
		Scan(&m.KeyID, &m.Arn, &m.Description, &m.KeyUsage, &m.KeySpec, &m.State, &m.Rotation, &m.Created, &m.DeletionDate)
	if err == sql.ErrNoRows {
		return keyMeta{}, false, nil
	}
	if err != nil {
		return keyMeta{}, false, err
	}
	return m, true, nil
}

func (s *kmsStore) listKeys(ctx context.Context, limit int) ([]keyMeta, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT key_id, arn, description, key_usage, key_spec, state, rotation, created, deletion_date
		   FROM kms_keys ORDER BY created LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keyMeta
	for rows.Next() {
		var m keyMeta
		if err := rows.Scan(&m.KeyID, &m.Arn, &m.Description, &m.KeyUsage, &m.KeySpec, &m.State, &m.Rotation, &m.Created, &m.DeletionDate); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// setState transitions a key's lifecycle state; deletionDate is set only for PendingDeletion (nil otherwise).
func (s *kmsStore) setState(ctx context.Context, keyID, state string, deletionDate *time.Time) (bool, error) {
	var res sql.Result
	var err error
	if deletionDate != nil {
		res, err = s.db.ExecContext(ctx, `UPDATE kms_keys SET state=$2, deletion_date=$3 WHERE key_id=$1`, keyID, state, *deletionDate)
	} else {
		res, err = s.db.ExecContext(ctx, `UPDATE kms_keys SET state=$2, deletion_date=NULL WHERE key_id=$1`, keyID, state)
	}
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *kmsStore) setRotation(ctx context.Context, keyID string, on bool) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE kms_keys SET rotation=$2 WHERE key_id=$1`, keyID, on)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// deleteKeyRow removes a key's metadata row (called by the reaper after crypto-erase).
func (s *kmsStore) deleteKeyRow(ctx context.Context, keyID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM kms_keys WHERE key_id=$1`, keyID)
	return err
}

// dueForDeletion returns keys whose deletion window has elapsed (state PendingDeletion, deletion_date past).
func (s *kmsStore) dueForDeletion(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT key_id FROM kms_keys WHERE state='PendingDeletion' AND deletion_date IS NOT NULL AND deletion_date <= $1`, now)
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

// --- aliases ---

func (s *kmsStore) createAlias(ctx context.Context, name, keyID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO kms_aliases (alias_name, key_id) VALUES ($1,$2)`, name, keyID)
	if err != nil && strings.Contains(err.Error(), "duplicate key") {
		return errAliasExists
	}
	return err
}

func (s *kmsStore) updateAlias(ctx context.Context, name, keyID string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE kms_aliases SET key_id=$2, updated=now() WHERE alias_name=$1`, name, keyID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *kmsStore) deleteAlias(ctx context.Context, name string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM kms_aliases WHERE alias_name=$1`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *kmsStore) aliasTarget(ctx context.Context, name string) (string, bool, error) {
	var keyID string
	err := s.db.QueryRowContext(ctx, `SELECT key_id FROM kms_aliases WHERE alias_name=$1`, name).Scan(&keyID)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return keyID, true, nil
}

type aliasRow struct {
	Name    string
	KeyID   string
	Created time.Time
	Updated time.Time
}

func (s *kmsStore) listAliases(ctx context.Context, keyIDFilter string) ([]aliasRow, error) {
	var rows *sql.Rows
	var err error
	if keyIDFilter != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT alias_name, key_id, created, updated FROM kms_aliases WHERE key_id=$1 ORDER BY alias_name`, keyIDFilter)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT alias_name, key_id, created, updated FROM kms_aliases ORDER BY alias_name`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []aliasRow
	for rows.Next() {
		var a aliasRow
		if err := rows.Scan(&a.Name, &a.KeyID, &a.Created, &a.Updated); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
