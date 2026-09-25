// EventBridge control-plane state for the aws-shim (polyhedron#163): event buses, rules (schedule OR
// event-pattern), and targets. Shared with the other front doors' Postgres. Rules are persisted so the
// in-process scheduler reloads them after a restart; delivery itself rides the durable JetStream/SQS
// paths (see eventbridge.go).
package main

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type ebStore struct{ db *sql.DB }

type ebRule struct {
	Bus          string
	Name         string
	Arn          string
	ScheduleExpr string // "" unless a schedule rule
	EventPattern string // "" unless a pattern rule
	State        string // ENABLED | DISABLED
	Description  string
	Creator      string // principal that created the rule (the invocation authority)
	NextFireAt   sql.NullTime
}

type ebTarget struct {
	ID    string
	Arn   string
	Type  string // lambda | sqs
	Input string // constant Input JSON ("" = pass the whole event)
}

var errBusNotEmpty = errors.New("event bus is not empty")

func (s *ebStore) ensureSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS eb_buses (
    name    text PRIMARY KEY,
    arn     text NOT NULL,
    created timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS eb_rules (
    bus           text NOT NULL,
    name          text NOT NULL,
    arn           text NOT NULL,
    schedule_expr text NOT NULL DEFAULT '',
    event_pattern text NOT NULL DEFAULT '',
    state         text NOT NULL DEFAULT 'ENABLED',
    description   text NOT NULL DEFAULT '',
    creator       text NOT NULL DEFAULT '',
    next_fire_at  timestamptz,
    created       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (bus, name)
);
CREATE TABLE IF NOT EXISTS eb_targets (
    bus       text NOT NULL,
    rule      text NOT NULL,
    target_id text NOT NULL,
    arn       text NOT NULL,
    ttype     text NOT NULL,
    input     text NOT NULL DEFAULT '',
    PRIMARY KEY (bus, rule, target_id)
);
CREATE INDEX IF NOT EXISTS eb_rules_due ON eb_rules (state, next_fire_at);`); err != nil {
		return err
	}
	// The default bus always exists.
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO eb_buses (name, arn) VALUES ('default', $1) ON CONFLICT (name) DO NOTHING`,
		"arn:aws:events:::event-bus/default")
	return err
}

// --- buses ---

func (s *ebStore) createBus(ctx context.Context, name, arn string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO eb_buses (name, arn) VALUES ($1,$2) ON CONFLICT (name) DO NOTHING`, name, arn)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *ebStore) busExists(ctx context.Context, name string) (bool, error) {
	var x bool
	err := s.db.QueryRowContext(ctx, `SELECT true FROM eb_buses WHERE name=$1`, name).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil && x, err
}

func (s *ebStore) deleteBus(ctx context.Context, name string) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM eb_rules WHERE bus=$1`, name).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, errBusNotEmpty
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM eb_buses WHERE name=$1`, name)
	return rowsAffected(res, err)
}

func (s *ebStore) listBuses(ctx context.Context) ([]struct{ Name, Arn string }, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, arn FROM eb_buses ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct{ Name, Arn string }
	for rows.Next() {
		var e struct{ Name, Arn string }
		if err := rows.Scan(&e.Name, &e.Arn); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- rules ---

func (s *ebStore) putRule(ctx context.Context, r ebRule) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO eb_rules (bus, name, arn, schedule_expr, event_pattern, state, description, creator, next_fire_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (bus, name) DO UPDATE SET
		   arn=EXCLUDED.arn, schedule_expr=EXCLUDED.schedule_expr, event_pattern=EXCLUDED.event_pattern,
		   state=EXCLUDED.state, description=EXCLUDED.description, creator=EXCLUDED.creator, next_fire_at=EXCLUDED.next_fire_at`,
		r.Bus, r.Name, r.Arn, r.ScheduleExpr, r.EventPattern, r.State, r.Description, r.Creator, r.NextFireAt)
	return err
}

func (s *ebStore) getRule(ctx context.Context, bus, name string) (ebRule, bool, error) {
	var r ebRule
	err := s.db.QueryRowContext(ctx,
		`SELECT bus, name, arn, schedule_expr, event_pattern, state, description, creator, next_fire_at
		   FROM eb_rules WHERE bus=$1 AND name=$2`, bus, name).
		Scan(&r.Bus, &r.Name, &r.Arn, &r.ScheduleExpr, &r.EventPattern, &r.State, &r.Description, &r.Creator, &r.NextFireAt)
	if err == sql.ErrNoRows {
		return ebRule{}, false, nil
	}
	if err != nil {
		return ebRule{}, false, err
	}
	return r, true, nil
}

func (s *ebStore) listRules(ctx context.Context, bus, prefix string) ([]ebRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT bus, name, arn, schedule_expr, event_pattern, state, description, creator, next_fire_at
		   FROM eb_rules WHERE bus=$1 AND name LIKE $2 ORDER BY name`, bus, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ebRule
	for rows.Next() {
		var r ebRule
		if err := rows.Scan(&r.Bus, &r.Name, &r.Arn, &r.ScheduleExpr, &r.EventPattern, &r.State, &r.Description, &r.Creator, &r.NextFireAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *ebStore) setState(ctx context.Context, bus, name, state string, nextFire sql.NullTime) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE eb_rules SET state=$3, next_fire_at=$4 WHERE bus=$1 AND name=$2`, bus, name, state, nextFire)
	return rowsAffected(res, err)
}

func (s *ebStore) setNextFire(ctx context.Context, bus, name string, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE eb_rules SET next_fire_at=$3 WHERE bus=$1 AND name=$2`, bus, name, next)
	return err
}

func (s *ebStore) deleteRule(ctx context.Context, bus, name string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM eb_targets WHERE bus=$1 AND rule=$2`, bus, name); err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM eb_rules WHERE bus=$1 AND name=$2`, bus, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

// dueScheduled returns enabled schedule rules whose next fire time has arrived.
func (s *ebStore) dueScheduled(ctx context.Context, now time.Time) ([]ebRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT bus, name, arn, schedule_expr, event_pattern, state, description, creator, next_fire_at
		   FROM eb_rules
		  WHERE state='ENABLED' AND schedule_expr<>'' AND next_fire_at IS NOT NULL AND next_fire_at<=$1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ebRule
	for rows.Next() {
		var r ebRule
		if err := rows.Scan(&r.Bus, &r.Name, &r.Arn, &r.ScheduleExpr, &r.EventPattern, &r.State, &r.Description, &r.Creator, &r.NextFireAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// enabledPatternRules returns enabled event-pattern rules on a bus (for PutEvents routing).
func (s *ebStore) enabledPatternRules(ctx context.Context, bus string) ([]ebRule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT bus, name, arn, schedule_expr, event_pattern, state, description, creator, next_fire_at
		   FROM eb_rules WHERE bus=$1 AND state='ENABLED' AND event_pattern<>''`, bus)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ebRule
	for rows.Next() {
		var r ebRule
		if err := rows.Scan(&r.Bus, &r.Name, &r.Arn, &r.ScheduleExpr, &r.EventPattern, &r.State, &r.Description, &r.Creator, &r.NextFireAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- targets ---

func (s *ebStore) putTarget(ctx context.Context, bus, rule string, t ebTarget) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO eb_targets (bus, rule, target_id, arn, ttype, input) VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (bus, rule, target_id) DO UPDATE SET arn=EXCLUDED.arn, ttype=EXCLUDED.ttype, input=EXCLUDED.input`,
		bus, rule, t.ID, t.Arn, t.Type, t.Input)
	return err
}

func (s *ebStore) removeTarget(ctx context.Context, bus, rule, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM eb_targets WHERE bus=$1 AND rule=$2 AND target_id=$3`, bus, rule, id)
	return rowsAffected(res, err)
}

func (s *ebStore) listTargets(ctx context.Context, bus, rule string) ([]ebTarget, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target_id, arn, ttype, input FROM eb_targets WHERE bus=$1 AND rule=$2 ORDER BY target_id`, bus, rule)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ebTarget
	for rows.Next() {
		var t ebTarget
		if err := rows.Scan(&t.ID, &t.Arn, &t.Type, &t.Input); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *ebStore) countTargets(ctx context.Context, bus, rule string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM eb_targets WHERE bus=$1 AND rule=$2`, bus, rule).Scan(&n)
	return n, err
}
