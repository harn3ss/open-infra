// SSM Parameter Store state for the aws-shim (polyhedron#167): the parameter path tree, versions, and
// labels. Shares the SQS/SNS/KMS/SecretsManager/CloudWatchLogs Postgres. SecureString VALUES are stored as
// KMS ciphertext (never plaintext — see ssm.go); String/StringList values are stored as-is.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type ssmStore struct{ db *sql.DB }

type ssmParam struct {
	Name         string
	Type         string // String | StringList | SecureString
	CurrentVer   int64
	Tags         map[string]string
	Created      time.Time
	LastModified time.Time
}

var errParamExists = errParam("parameter already exists")

type errParam string

func (e errParam) Error() string { return string(e) }

func (s *ssmStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS ssm_params (
    name            text PRIMARY KEY,
    type            text NOT NULL,
    tags            jsonb NOT NULL DEFAULT '{}',
    current_version bigint NOT NULL DEFAULT 1,
    created         timestamptz NOT NULL DEFAULT now(),
    last_modified   timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ssm_versions (
    name    text NOT NULL,
    version bigint NOT NULL,
    value   text NOT NULL,
    created timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (name, version)
);
CREATE TABLE IF NOT EXISTS ssm_labels (
    name    text NOT NULL,
    label   text NOT NULL,
    version bigint NOT NULL,
    PRIMARY KEY (name, label)
);
CREATE INDEX IF NOT EXISTS ssm_params_name ON ssm_params (name text_pattern_ops);`)
	return err
}

func (s *ssmStore) getParam(ctx context.Context, name string) (ssmParam, bool, error) {
	var p ssmParam
	var tags []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT name, type, tags, current_version, created, last_modified FROM ssm_params WHERE name=$1`, name).
		Scan(&p.Name, &p.Type, &tags, &p.CurrentVer, &p.Created, &p.LastModified)
	if err == sql.ErrNoRows {
		return ssmParam{}, false, nil
	}
	if err != nil {
		return ssmParam{}, false, err
	}
	_ = json.Unmarshal(tags, &p.Tags)
	return p, true, nil
}

// putParam creates or (with overwrite) updates a parameter, bumping its version. Returns the new version.
// Without overwrite on an existing name it returns errParamExists.
func (s *ssmStore) putParam(ctx context.Context, name, ptype, value string, overwrite bool, tags map[string]string) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var cur int64
	var existed bool
	switch err := tx.QueryRowContext(ctx, `SELECT current_version FROM ssm_params WHERE name=$1 FOR UPDATE`, name).Scan(&cur); err {
	case nil:
		existed = true
	case sql.ErrNoRows:
		existed = false
	default:
		return 0, err
	}
	if existed && !overwrite {
		return 0, errParamExists
	}
	var newVer int64 = 1
	if existed {
		newVer = cur + 1
		tj, _ := json.Marshal(tags)
		if _, err := tx.ExecContext(ctx, `UPDATE ssm_params SET type=$2, current_version=$3, last_modified=now(), tags=CASE WHEN $4::jsonb <> '{}'::jsonb THEN $4::jsonb ELSE tags END WHERE name=$1`,
			name, ptype, newVer, string(tj)); err != nil {
			return 0, err
		}
	} else {
		tj, _ := json.Marshal(tags)
		if _, err := tx.ExecContext(ctx, `INSERT INTO ssm_params (name, type, tags, current_version) VALUES ($1,$2,$3,1)`, name, ptype, string(tj)); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ssm_versions (name, version, value) VALUES ($1,$2,$3)`, name, newVer, value); err != nil {
		return 0, err
	}
	return newVer, tx.Commit()
}

func (s *ssmStore) getVersion(ctx context.Context, name string, version int64) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM ssm_versions WHERE name=$1 AND version=$2`, name, version).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s *ssmStore) labelVersion(ctx context.Context, name, label string, version int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ssm_labels (name, label, version) VALUES ($1,$2,$3)
		 ON CONFLICT (name, label) DO UPDATE SET version=EXCLUDED.version`, name, label, version)
	return err
}

func (s *ssmStore) versionForLabel(ctx context.Context, name, label string) (int64, bool, error) {
	var v int64
	err := s.db.QueryRowContext(ctx, `SELECT version FROM ssm_labels WHERE name=$1 AND label=$2`, name, label).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return v, err == nil, err
}

func (s *ssmStore) deleteParam(ctx context.Context, name string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	_, _ = tx.ExecContext(ctx, `DELETE FROM ssm_versions WHERE name=$1`, name)
	_, _ = tx.ExecContext(ctx, `DELETE FROM ssm_labels WHERE name=$1`, name)
	res, err := tx.ExecContext(ctx, `DELETE FROM ssm_params WHERE name=$1`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

// byPath returns parameters whose name is under pathPrefix. recursive=false returns only the immediate
// level (no further '/' after the prefix).
func (s *ssmStore) byPath(ctx context.Context, pathPrefix string, recursive bool) ([]ssmParam, error) {
	// normalize: ensure the prefix ends with '/'
	pre := pathPrefix
	if pre == "" {
		pre = "/"
	}
	if pre[len(pre)-1] != '/' {
		pre += "/"
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, type, tags, current_version, created, last_modified FROM ssm_params WHERE name LIKE $1 ORDER BY name`, pre+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ssmParam
	for rows.Next() {
		var p ssmParam
		var tags []byte
		if err := rows.Scan(&p.Name, &p.Type, &tags, &p.CurrentVer, &p.Created, &p.LastModified); err != nil {
			return nil, err
		}
		if !recursive {
			// only the immediate level: the remainder after the prefix has no '/'
			rest := p.Name[len(pre):]
			if containsSlash(rest) {
				continue
			}
		}
		_ = json.Unmarshal(tags, &p.Tags)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *ssmStore) list(ctx context.Context, limit int) ([]ssmParam, error) {
	if limit <= 0 || limit > 50 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name, type, tags, current_version, created, last_modified FROM ssm_params ORDER BY name LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ssmParam
	for rows.Next() {
		var p ssmParam
		var tags []byte
		if err := rows.Scan(&p.Name, &p.Type, &tags, &p.CurrentVer, &p.Created, &p.LastModified); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tags, &p.Tags)
		out = append(out, p)
	}
	return out, rows.Err()
}

type ssmVersionRow struct {
	Version int64
	Value   string
	Created time.Time
}

func (s *ssmStore) history(ctx context.Context, name string) ([]ssmVersionRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version, value, created FROM ssm_versions WHERE name=$1 ORDER BY version`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ssmVersionRow
	for rows.Next() {
		var r ssmVersionRow
		if err := rows.Scan(&r.Version, &r.Value, &r.Created); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *ssmStore) setTags(ctx context.Context, name string, tags map[string]string) (bool, error) {
	tj, _ := json.Marshal(tags)
	res, err := s.db.ExecContext(ctx, `UPDATE ssm_params SET tags=$2 WHERE name=$1`, name, string(tj))
	return rowsAffected(res, err)
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}
