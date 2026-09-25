// CloudWatch Logs state for the aws-shim (polyhedron#164): log groups, streams, and events.
//
// Backed by the shared Postgres (not Loki) DELIBERATELY: the CloudWatch Logs API contract needs
// byte-identical ordered read-back with the original millisecond timestamps, TERMINATING pagination, and —
// the compliance pivot — GENUINE per-group retention at AWS's day granularity, which a reaper over SQL
// rows enforces exactly. Loki remains the cluster's own log/observability stack (pod logs, the shim's own
// audit lines); this store is the faithful AWS-API log sink for applications.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type cwlStore struct{ db *sql.DB }

type logGroup struct {
	Name          string
	Arn           string
	RetentionDays sql.NullInt64
	Tags          map[string]string
	Created       time.Time
}

type logStream struct {
	Name       string
	Created    time.Time
	FirstEvent sql.NullInt64
	LastEvent  sql.NullInt64
	LastIngest sql.NullInt64
}

type logEvent struct {
	ID       int64
	Stream   string
	TsMs     int64
	Message  string
	IngestMs int64
}

func (s *cwlStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS cwl_groups (
    name           text PRIMARY KEY,
    arn            text NOT NULL,
    retention_days int,
    tags           jsonb NOT NULL DEFAULT '{}',
    created        timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cwl_streams (
    group_name  text NOT NULL,
    stream_name text NOT NULL,
    created     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_name, stream_name)
);
CREATE TABLE IF NOT EXISTS cwl_events (
    id           bigserial PRIMARY KEY,
    group_name   text NOT NULL,
    stream_name  text NOT NULL,
    ts_ms        bigint NOT NULL,
    ingestion_ms bigint NOT NULL,
    message      text NOT NULL
);
CREATE INDEX IF NOT EXISTS cwl_events_stream ON cwl_events (group_name, stream_name, ts_ms, id);
CREATE INDEX IF NOT EXISTS cwl_events_group ON cwl_events (group_name, ts_ms, id);`)
	return err
}

// --- groups ---

func (s *cwlStore) createGroup(ctx context.Context, name, arn string, tags map[string]string) (bool, error) {
	tj, _ := json.Marshal(tags)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO cwl_groups (name, arn, tags) VALUES ($1,$2,$3) ON CONFLICT (name) DO NOTHING`, name, arn, tj)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *cwlStore) getGroup(ctx context.Context, name string) (logGroup, bool, error) {
	var g logGroup
	var tags []byte
	err := s.db.QueryRowContext(ctx, `SELECT name, arn, retention_days, tags, created FROM cwl_groups WHERE name=$1`, name).
		Scan(&g.Name, &g.Arn, &g.RetentionDays, &tags, &g.Created)
	if err == sql.ErrNoRows {
		return logGroup{}, false, nil
	}
	if err != nil {
		return logGroup{}, false, err
	}
	_ = json.Unmarshal(tags, &g.Tags)
	return g, true, nil
}

func (s *cwlStore) listGroups(ctx context.Context, prefix string) ([]logGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, arn, retention_days, tags, created FROM cwl_groups WHERE name LIKE $1 ORDER BY name`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []logGroup
	for rows.Next() {
		var g logGroup
		var tags []byte
		if err := rows.Scan(&g.Name, &g.Arn, &g.RetentionDays, &tags, &g.Created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tags, &g.Tags)
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *cwlStore) deleteGroup(ctx context.Context, name string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	_, _ = tx.ExecContext(ctx, `DELETE FROM cwl_events WHERE group_name=$1`, name)
	_, _ = tx.ExecContext(ctx, `DELETE FROM cwl_streams WHERE group_name=$1`, name)
	res, err := tx.ExecContext(ctx, `DELETE FROM cwl_groups WHERE name=$1`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *cwlStore) setRetention(ctx context.Context, name string, days int) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE cwl_groups SET retention_days=$2 WHERE name=$1`, name, days)
	return rowsAffected(res, err)
}

func (s *cwlStore) setTags(ctx context.Context, name string, tags map[string]string) error {
	tj, _ := json.Marshal(tags)
	_, err := s.db.ExecContext(ctx, `UPDATE cwl_groups SET tags=$2 WHERE name=$1`, name, tj)
	return err
}

// --- streams ---

// createStream returns (created, groupExists). created=false with groupExists=true means it already existed.
func (s *cwlStore) createStream(ctx context.Context, group, stream string) (bool, bool, error) {
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT true FROM cwl_groups WHERE name=$1`, group).Scan(&exists); err == sql.ErrNoRows {
		return false, false, nil
	} else if err != nil {
		return false, false, err
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO cwl_streams (group_name, stream_name) VALUES ($1,$2) ON CONFLICT DO NOTHING`, group, stream)
	if err != nil {
		return false, true, err
	}
	n, _ := res.RowsAffected()
	return n > 0, true, nil
}

func (s *cwlStore) streamExists(ctx context.Context, group, stream string) (bool, error) {
	var x bool
	err := s.db.QueryRowContext(ctx, `SELECT true FROM cwl_streams WHERE group_name=$1 AND stream_name=$2`, group, stream).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil && x, err
}

func (s *cwlStore) deleteStream(ctx context.Context, group, stream string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	_, _ = tx.ExecContext(ctx, `DELETE FROM cwl_events WHERE group_name=$1 AND stream_name=$2`, group, stream)
	res, err := tx.ExecContext(ctx, `DELETE FROM cwl_streams WHERE group_name=$1 AND stream_name=$2`, group, stream)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *cwlStore) listStreams(ctx context.Context, group, prefix string) ([]logStream, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT st.stream_name, st.created,
       (SELECT min(ts_ms) FROM cwl_events e WHERE e.group_name=st.group_name AND e.stream_name=st.stream_name),
       (SELECT max(ts_ms) FROM cwl_events e WHERE e.group_name=st.group_name AND e.stream_name=st.stream_name),
       (SELECT max(ingestion_ms) FROM cwl_events e WHERE e.group_name=st.group_name AND e.stream_name=st.stream_name)
  FROM cwl_streams st WHERE st.group_name=$1 AND st.stream_name LIKE $2 ORDER BY st.stream_name`, group, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []logStream
	for rows.Next() {
		var st logStream
		if err := rows.Scan(&st.Name, &st.Created, &st.FirstEvent, &st.LastEvent, &st.LastIngest); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// --- events ---

type putEvent struct {
	TsMs    int64
	Message string
}

func (s *cwlStore) putEvents(ctx context.Context, group, stream string, events []putEvent, ingestMs int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO cwl_events (group_name, stream_name, ts_ms, ingestion_ms, message) VALUES ($1,$2,$3,$4,$5)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx, group, stream, e.TsMs, ingestMs, e.Message); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// getEvents returns events for one stream ordered by (ts_ms, id). afterID/beforeID bound the page; head
// selects oldest-first. Returns the events and the min/max ids seen (for the forward/backward tokens).
func (s *cwlStore) getEvents(ctx context.Context, group, stream string, startFromHead bool, limit int, afterID int64) ([]logEvent, int64, int64, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	order := "DESC"
	if startFromHead {
		order = "ASC"
	}
	// afterID is the pagination cursor: forward from it (id > afterID) in the chosen order.
	q := `SELECT id, ts_ms, message, ingestion_ms FROM cwl_events WHERE group_name=$1 AND stream_name=$2 AND id > $3 ORDER BY ts_ms ` + order + `, id ` + order + ` LIMIT $4`
	rows, err := s.db.QueryContext(ctx, q, group, stream, afterID, limit)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	var out []logEvent
	var minID, maxID int64
	for rows.Next() {
		var e logEvent
		if err := rows.Scan(&e.ID, &e.TsMs, &e.Message, &e.IngestMs); err != nil {
			return nil, 0, 0, err
		}
		if minID == 0 || e.ID < minID {
			minID = e.ID
		}
		if e.ID > maxID {
			maxID = e.ID
		}
		out = append(out, e)
	}
	return out, minID, maxID, rows.Err()
}

// filterEvents returns events across a group (optionally a stream prefix), time-bounded, whose message
// matches ALL of terms (substring). afterID paginates. matchAll(terms) done in SQL via ILIKE-free LIKE.
func (s *cwlStore) filterEvents(ctx context.Context, group string, startMs, endMs int64, terms []string, limit int, afterID int64) ([]logEvent, int64, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	args := []any{group, afterID}
	q := `SELECT id, stream_name, ts_ms, message, ingestion_ms FROM cwl_events WHERE group_name=$1 AND id > $2`
	n := 3
	if startMs > 0 {
		q += ` AND ts_ms >= $` + itoa(n)
		args = append(args, startMs)
		n++
	}
	if endMs > 0 {
		q += ` AND ts_ms <= $` + itoa(n)
		args = append(args, endMs)
		n++
	}
	for _, t := range terms {
		q += ` AND message LIKE $` + itoa(n)
		args = append(args, "%"+likeEscape(t)+"%")
		n++
	}
	q += ` ORDER BY ts_ms ASC, id ASC LIMIT $` + itoa(n)
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []logEvent
	var maxID int64
	for rows.Next() {
		var e logEvent
		if err := rows.Scan(&e.ID, &e.Stream, &e.TsMs, &e.Message, &e.IngestMs); err != nil {
			return nil, 0, err
		}
		if e.ID > maxID {
			maxID = e.ID
		}
		out = append(out, e)
	}
	return out, maxID, rows.Err()
}

// reapExpired deletes events older than each group's retention_days — genuine per-group retention (AU-11).
func (s *cwlStore) reapExpired(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
DELETE FROM cwl_events e USING cwl_groups g
 WHERE e.group_name = g.name
   AND g.retention_days IS NOT NULL
   AND e.ts_ms < ($1 - g.retention_days::bigint * 86400000)`, now.UnixMilli())
	return err
}

// likeEscape neutralizes LIKE metacharacters in a filter term (we match it literally as a substring).
func likeEscape(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' || s[i] == '_' || s[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(out)
}
