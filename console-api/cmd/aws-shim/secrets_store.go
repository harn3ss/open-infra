// Secrets Manager control-plane + version state for the aws-shim (polyhedron#161).
//
// This store holds secret METADATA (description, tags, KMS key, deletion window, ARN) and the VERSION +
// STAGING-LABEL machinery that is the heart of Secrets Manager — the label→version map AWS calls
// AWSCURRENT/AWSPREVIOUS/AWSPENDING. Vault KV v2 has version numbers but no staging labels, so the
// mapping is maintained here, atomically, in Postgres (shared with SQS/SNS/KMS).
//
// It never holds secret plaintext: each version's value is stored as a KMS ciphertext blob (encrypted
// through the shim's own KMS doorway / Vault Transit, see secrets.go), so a Postgres compromise yields
// only ciphertext undecryptable without Vault.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type secretsStore struct{ db *sql.DB }

type secretMeta struct {
	Name            string
	Arn             string
	Description     string
	KmsKeyID        string // "" = the default managed key (kms-aws-secretsmanager)
	Tags            map[string]string
	RotationEnabled bool
	DeletedAt       sql.NullTime
	Created         time.Time
	LastChanged     time.Time
	LastAccessed    sql.NullTime
}

var (
	errSecretExists = errors.New("secret already exists")
)

func (s *secretsStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS sm_secrets (
    name             text PRIMARY KEY,
    arn              text NOT NULL,
    description      text NOT NULL DEFAULT '',
    kms_key_id       text NOT NULL DEFAULT '',
    tags             jsonb NOT NULL DEFAULT '{}',
    rotation_enabled boolean NOT NULL DEFAULT false,
    deleted_at       timestamptz,
    created          timestamptz NOT NULL DEFAULT now(),
    last_changed     timestamptz NOT NULL DEFAULT now(),
    last_accessed    timestamptz
);
CREATE TABLE IF NOT EXISTS sm_versions (
    secret_name text NOT NULL,
    version_id  text NOT NULL,
    value_ct    text NOT NULL,
    is_binary   boolean NOT NULL DEFAULT false,
    created     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (secret_name, version_id)
);
CREATE TABLE IF NOT EXISTS sm_stages (
    secret_name text NOT NULL,
    stage       text NOT NULL,
    version_id  text NOT NULL,
    PRIMARY KEY (secret_name, stage)
);
CREATE INDEX IF NOT EXISTS sm_versions_secret ON sm_versions (secret_name);
CREATE INDEX IF NOT EXISTS sm_stages_version ON sm_stages (secret_name, version_id);`)
	return err
}

// createSecret inserts a new secret with its first version labeled AWSCURRENT, atomically. Returns
// errSecretExists if the name is already taken (active or pending deletion).
func (s *secretsStore) createSecret(ctx context.Context, m secretMeta, versionID, valueCT string, isBinary bool) error {
	tags, _ := json.Marshal(m.Tags)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT true FROM sm_secrets WHERE name=$1`, m.Name).Scan(&exists); err == nil {
		return errSecretExists
	} else if err != sql.ErrNoRows {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sm_secrets (name, arn, description, kms_key_id, tags) VALUES ($1,$2,$3,$4,$5)`,
		m.Name, m.Arn, m.Description, m.KmsKeyID, tags); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sm_versions (secret_name, version_id, value_ct, is_binary) VALUES ($1,$2,$3,$4)`,
		m.Name, versionID, valueCT, isBinary); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sm_stages (secret_name, stage, version_id) VALUES ($1,'AWSCURRENT',$2)`,
		m.Name, versionID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *secretsStore) getSecret(ctx context.Context, name string) (secretMeta, bool, error) {
	var m secretMeta
	var tags []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT name, arn, description, kms_key_id, tags, rotation_enabled, deleted_at, created, last_changed, last_accessed
		   FROM sm_secrets WHERE name=$1`, name).
		Scan(&m.Name, &m.Arn, &m.Description, &m.KmsKeyID, &tags, &m.RotationEnabled, &m.DeletedAt, &m.Created, &m.LastChanged, &m.LastAccessed)
	if err == sql.ErrNoRows {
		return secretMeta{}, false, nil
	}
	if err != nil {
		return secretMeta{}, false, err
	}
	_ = json.Unmarshal(tags, &m.Tags)
	return m, true, nil
}

// putVersion adds a new version. When makeCurrent is true it moves the AWSCURRENT label to the new
// version and demotes the old current to AWSPREVIOUS — the rotation-safe promotion. All in one tx.
func (s *secretsStore) putVersion(ctx context.Context, name, versionID, valueCT string, isBinary bool, stages []string, makeCurrent bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO sm_versions (secret_name, version_id, value_ct, is_binary) VALUES ($1,$2,$3,$4)
		 ON CONFLICT (secret_name, version_id) DO UPDATE SET value_ct=EXCLUDED.value_ct, is_binary=EXCLUDED.is_binary`,
		name, versionID, valueCT, isBinary); err != nil {
		return err
	}
	if makeCurrent {
		// old AWSCURRENT -> AWSPREVIOUS; new version -> AWSCURRENT.
		var oldCur string
		switch err := tx.QueryRowContext(ctx, `SELECT version_id FROM sm_stages WHERE secret_name=$1 AND stage='AWSCURRENT'`, name).Scan(&oldCur); err {
		case nil:
			if oldCur != versionID {
				if err := upsertStage(ctx, tx, name, "AWSPREVIOUS", oldCur); err != nil {
					return err
				}
			}
		case sql.ErrNoRows:
			// no current yet
		default:
			return err
		}
		if err := upsertStage(ctx, tx, name, "AWSCURRENT", versionID); err != nil {
			return err
		}
	}
	for _, st := range stages {
		if st == "AWSCURRENT" {
			continue // handled above
		}
		if err := upsertStage(ctx, tx, name, st, versionID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sm_secrets SET last_changed=now() WHERE name=$1`, name); err != nil {
		return err
	}
	return tx.Commit()
}

func upsertStage(ctx context.Context, tx *sql.Tx, name, stage, versionID string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO sm_stages (secret_name, stage, version_id) VALUES ($1,$2,$3)
		 ON CONFLICT (secret_name, stage) DO UPDATE SET version_id=EXCLUDED.version_id`,
		name, stage, versionID)
	return err
}

// versionByStage returns the value ciphertext for the version currently carrying a staging label.
func (s *secretsStore) versionByStage(ctx context.Context, name, stage string) (versionID, valueCT string, isBinary, ok bool, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT v.version_id, v.value_ct, v.is_binary
		   FROM sm_stages st JOIN sm_versions v ON v.secret_name=st.secret_name AND v.version_id=st.version_id
		  WHERE st.secret_name=$1 AND st.stage=$2`, name, stage).
		Scan(&versionID, &valueCT, &isBinary)
	if err == sql.ErrNoRows {
		return "", "", false, false, nil
	}
	if err != nil {
		return "", "", false, false, err
	}
	return versionID, valueCT, isBinary, true, nil
}

// versionByID returns a specific version's value.
func (s *secretsStore) versionByID(ctx context.Context, name, versionID string) (valueCT string, isBinary, ok bool, err error) {
	err = s.db.QueryRowContext(ctx,
		`SELECT value_ct, is_binary FROM sm_versions WHERE secret_name=$1 AND version_id=$2`, name, versionID).
		Scan(&valueCT, &isBinary)
	if err == sql.ErrNoRows {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	return valueCT, isBinary, true, nil
}

// stagesByVersion returns the map of version_id -> [stages] for a secret (DescribeSecret / ListSecretVersionIds).
func (s *secretsStore) stagesByVersion(ctx context.Context, name string) (map[string][]string, []string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version_id, stage FROM sm_stages WHERE secret_name=$1`, name)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var vid, st string
		if err := rows.Scan(&vid, &st); err != nil {
			return nil, nil, err
		}
		out[vid] = append(out[vid], st)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	// also include versions that have no stage label (they still exist)
	vrows, err := s.db.QueryContext(ctx, `SELECT version_id FROM sm_versions WHERE secret_name=$1 ORDER BY created DESC`, name)
	if err != nil {
		return nil, nil, err
	}
	defer vrows.Close()
	var allVersions []string
	for vrows.Next() {
		var vid string
		if err := vrows.Scan(&vid); err != nil {
			return nil, nil, err
		}
		allVersions = append(allVersions, vid)
		if _, seen := out[vid]; !seen {
			out[vid] = nil
		}
	}
	return out, allVersions, vrows.Err()
}

// moveStage implements UpdateSecretVersionStage: attach `stage` to moveTo (if set) and/or detach it from
// removeFrom (if set). Returns false if removeFrom is given but does not currently hold the stage.
func (s *secretsStore) moveStage(ctx context.Context, name, stage, moveTo, removeFrom string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	if removeFrom != "" {
		var cur string
		switch err := tx.QueryRowContext(ctx, `SELECT version_id FROM sm_stages WHERE secret_name=$1 AND stage=$2`, name, stage).Scan(&cur); err {
		case nil:
			if cur != removeFrom {
				return false, nil
			}
		case sql.ErrNoRows:
			return false, nil
		default:
			return false, err
		}
	}
	if moveTo != "" {
		if err := upsertStage(ctx, tx, name, stage, moveTo); err != nil {
			return false, err
		}
	} else if removeFrom != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sm_stages WHERE secret_name=$1 AND stage=$2`, name, stage); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

func (s *secretsStore) scheduleDelete(ctx context.Context, name string, deletedAt time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE sm_secrets SET deleted_at=$2, last_changed=now() WHERE name=$1`, name, deletedAt)
	return rowsAffected(res, err)
}

func (s *secretsStore) restore(ctx context.Context, name string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE sm_secrets SET deleted_at=NULL, last_changed=now() WHERE name=$1`, name)
	return rowsAffected(res, err)
}

func (s *secretsStore) forceDelete(ctx context.Context, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{
		`DELETE FROM sm_stages WHERE secret_name=$1`,
		`DELETE FROM sm_versions WHERE secret_name=$1`,
		`DELETE FROM sm_secrets WHERE name=$1`,
	} {
		if _, err := tx.ExecContext(ctx, q, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *secretsStore) setDescription(ctx context.Context, name, desc string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sm_secrets SET description=$2, last_changed=now() WHERE name=$1`, name, desc)
	return err
}

func (s *secretsStore) setTags(ctx context.Context, name string, tags map[string]string) error {
	b, _ := json.Marshal(tags)
	_, err := s.db.ExecContext(ctx, `UPDATE sm_secrets SET tags=$2, last_changed=now() WHERE name=$1`, name, b)
	return err
}

func (s *secretsStore) touchAccessed(ctx context.Context, name string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE sm_secrets SET last_accessed=now() WHERE name=$1`, name)
}

func (s *secretsStore) listSecrets(ctx context.Context, limit int) ([]secretMeta, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, arn, description, kms_key_id, tags, rotation_enabled, deleted_at, created, last_changed, last_accessed
		   FROM sm_secrets ORDER BY name LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []secretMeta
	for rows.Next() {
		var m secretMeta
		var tags []byte
		if err := rows.Scan(&m.Name, &m.Arn, &m.Description, &m.KmsKeyID, &tags, &m.RotationEnabled, &m.DeletedAt, &m.Created, &m.LastChanged, &m.LastAccessed); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tags, &m.Tags)
		out = append(out, m)
	}
	return out, rows.Err()
}

func rowsAffected(res sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// arnSuffix is the six lowercase-alnum characters AWS appends to a secret ARN. Kept stable for the
// secret's life (stored in the arn) so a delete+recreate does not inherit the old grants.
func arnSuffix(b []byte) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(alpha[int(x)%len(alpha)])
	}
	return sb.String()
}
