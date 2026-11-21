// The instance profiles made through the IAM API (CreateInstanceProfile, AddRoleToInstanceProfile,
// RemoveRoleFromInstanceProfile, DeleteInstanceProfile), kept in the shim's Postgres (the SQS/SSM store,
// beside the EC2 key pairs). A profile is a name, a path, tags and at most one role, as on AWS. Its role
// binds on an instance's VM (kind: VirtualMachine spec.instanceRole) when a CloudFormation stack's instance
// names the profile by its name or ARN (the CloudFormation front door reads the profiles into its deploy
// Capabilities, cfn/translate_instanceprofile.go).
//
// Accounts: a profile is its account's, and its name is unique within that account without regard to case,
// as IAM names are. Each row records its account in the account column: empty for the management account,
// the member account's id for a member's. Its id (AIPA…) is unique across accounts.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
)

type iamProfileStore struct{ db *sql.DB }

// storedInstanceProfile is a profile made through the IAM API. Role is the kind: Role object its one role
// is ("" for none).
type storedInstanceProfile struct {
	Name, Path, ID, Role string
	Tags                 map[string]string
	Created              time.Time
}

var (
	errProfileExists    = errors.New("instance profile exists")
	errNoProfile        = errors.New("no such instance profile")
	errProfileHasRole   = errors.New("instance profile has a role")
	errRoleNotInProfile = errors.New("the role is not the instance profile's")
)

func (s *iamProfileStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS iam_instance_profiles (
    account    text NOT NULL DEFAULT '',
    name_key   text NOT NULL,
    name       text NOT NULL,
    path       text NOT NULL DEFAULT '/',
    profile_id text NOT NULL UNIQUE,
    role_name  text NOT NULL DEFAULT '',
    tags       jsonb NOT NULL DEFAULT '{}',
    created    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account, name_key)
);
CREATE INDEX IF NOT EXISTS iam_instance_profiles_role ON iam_instance_profiles (account, lower(role_name)) WHERE role_name <> '';`)
	return err
}

// profileStoreAccount is the account column of the account ctx acts in: "" for the management account, the
// member account's id for a member's (as a stack's account is its request's).
func profileStoreAccount(ctx context.Context) string {
	if !isMemberRequest(ctx) {
		return ""
	}
	return callerAccount(ctx)
}

// newInstanceProfileID is a profile id in AWS's shape: AIPA and 17 upper-case letters and digits.
func newInstanceProfileID() string {
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b := make([]byte, 17)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alnum[int(b[i])%len(alnum)]
	}
	return "AIPA" + string(b)
}

// create records a profile of account; errProfileExists when the account has one of that name in any case.
func (s *iamProfileStore) create(ctx context.Context, account string, p storedInstanceProfile) (storedInstanceProfile, error) {
	tags, _ := json.Marshal(p.Tags)
	if p.Tags == nil {
		tags = []byte("{}")
	}
	err := s.db.QueryRowContext(ctx, `INSERT INTO iam_instance_profiles (account, name_key, name, path, profile_id, tags)
VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (account, name_key) DO NOTHING RETURNING created`,
		account, strings.ToLower(p.Name), p.Name, p.Path, p.ID, string(tags)).Scan(&p.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return storedInstanceProfile{}, errProfileExists
	}
	return p, err
}

const profileColumns = `name, path, profile_id, role_name, tags, created`

func scanProfile(row interface{ Scan(...any) error }) (storedInstanceProfile, error) {
	var p storedInstanceProfile
	var tags []byte
	if err := row.Scan(&p.Name, &p.Path, &p.ID, &p.Role, &tags, &p.Created); err != nil {
		return p, err
	}
	_ = json.Unmarshal(tags, &p.Tags)
	return p, nil
}

// get is account's profile named name, in any case.
func (s *iamProfileStore) get(ctx context.Context, account, name string) (storedInstanceProfile, bool, error) {
	p, err := scanProfile(s.db.QueryRowContext(ctx, `SELECT `+profileColumns+` FROM iam_instance_profiles
WHERE account=$1 AND name_key=$2`, account, strings.ToLower(name)))
	if errors.Is(err, sql.ErrNoRows) {
		return p, false, nil
	}
	return p, err == nil, err
}

// list is account's profiles, by name.
func (s *iamProfileStore) list(ctx context.Context, account string) ([]storedInstanceProfile, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+profileColumns+` FROM iam_instance_profiles WHERE account=$1 ORDER BY name`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storedInstanceProfile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// profileWriteOutcome reads a conditional write's result: changed rows, and whether the profile was there at all.
func profileWriteOutcome(row *sql.Row) (changed, existed bool, err error) {
	var c, e int
	if err := row.Scan(&c, &e); err != nil {
		return false, false, err
	}
	return c > 0, e > 0, nil
}

// delete removes account's profile named name: errNoProfile when it has none, errProfileHasRole while the
// profile still has its role (AWS's DeleteConflict).
func (s *iamProfileStore) delete(ctx context.Context, account, name string) error {
	changed, existed, err := profileWriteOutcome(s.db.QueryRowContext(ctx, `
WITH d AS (DELETE FROM iam_instance_profiles WHERE account=$1 AND name_key=$2 AND role_name='' RETURNING 1)
SELECT (SELECT count(*) FROM d), (SELECT count(*) FROM iam_instance_profiles WHERE account=$1 AND name_key=$2)`,
		account, strings.ToLower(name)))
	switch {
	case err != nil:
		return err
	case changed:
		return nil
	case existed:
		return errProfileHasRole
	}
	return errNoProfile
}

// addRole gives account's profile named name its role (a kind: Role object name): errNoProfile when it has
// no such profile, errProfileHasRole when the profile already has one (a profile holds one role, as on AWS).
func (s *iamProfileStore) addRole(ctx context.Context, account, name, role string) error {
	changed, existed, err := profileWriteOutcome(s.db.QueryRowContext(ctx, `
WITH u AS (UPDATE iam_instance_profiles SET role_name=$3 WHERE account=$1 AND name_key=$2 AND role_name='' RETURNING 1)
SELECT (SELECT count(*) FROM u), (SELECT count(*) FROM iam_instance_profiles WHERE account=$1 AND name_key=$2)`,
		account, strings.ToLower(name), role))
	switch {
	case err != nil:
		return err
	case changed:
		return nil
	case existed:
		return errProfileHasRole
	}
	return errNoProfile
}

// removeRole takes role (in any case) from account's profile named name: errNoProfile when it has no such
// profile, errRoleNotInProfile when the profile's role is not that one.
func (s *iamProfileStore) removeRole(ctx context.Context, account, name, role string) error {
	changed, existed, err := profileWriteOutcome(s.db.QueryRowContext(ctx, `
WITH u AS (UPDATE iam_instance_profiles SET role_name='' WHERE account=$1 AND name_key=$2 AND role_name <> '' AND lower(role_name)=lower($3) RETURNING 1)
SELECT (SELECT count(*) FROM u), (SELECT count(*) FROM iam_instance_profiles WHERE account=$1 AND name_key=$2)`,
		account, strings.ToLower(name), role))
	switch {
	case err != nil:
		return err
	case changed:
		return nil
	case existed:
		return errRoleNotInProfile
	}
	return errNoProfile
}

// roleInUse reports whether one of account's profiles has role (in any case): AWS refuses to delete such a
// role until it is removed from the profile.
func (s *iamProfileStore) roleInUse(ctx context.Context, account, role string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM iam_instance_profiles WHERE account=$1 AND role_name <> '' AND lower(role_name)=lower($2)`,
		account, role).Scan(&n)
	return n > 0, err
}

// forStacks is every profile of the account ctx acts in, by lower-cased name, with its path and role: the
// CloudFormation front door's Capabilities.InstanceProfiles (a stack's instance names a profile of the
// stack's own account).
func (s *iamProfileStore) forStacks(ctx context.Context) (map[string]cfn.InstanceProfile, error) {
	all, err := s.list(ctx, profileStoreAccount(ctx))
	if err != nil {
		return nil, err
	}
	out := make(map[string]cfn.InstanceProfile, len(all))
	for _, p := range all {
		out[strings.ToLower(p.Name)] = cfn.InstanceProfile{Name: p.Name, Path: p.Path, Role: p.Role}
	}
	return out, nil
}
