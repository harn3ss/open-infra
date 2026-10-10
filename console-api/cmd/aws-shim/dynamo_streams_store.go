// DynamoDB Streams state for the aws-shim: per-table change-record logs with monotonic sequence
// numbers, served by the dynamodbstreams API (dynamo_streams.go).
//
// Backend decision: Postgres, the SAME faithful-over-convenient choice as the Kinesis doorway
// (kinesis_store.go). DynamoDB Streams is Kinesis-shaped — ordered records per shard, monotonic
// SequenceNumbers, shard iterators that advance, replay within a 24h retention window — which
// JetStream's per-subject ordering does not model. SQL rows keyed (stream, shard, seq) give exact
// control. A DEDICATED set of tables (not the kinesis_* ones) keeps the two doorways' streams from
// polluting each other's ListStreams. One shard per stream in v1.
package main

import (
	"context"
	"database/sql"
)

// ddbStreamShard is the single shard id every DynamoDB stream uses in v1. The DynamoDB Streams SDK
// validates ShardId at a 28-char minimum (longer than Kinesis's shardId-%012d), so this is padded
// to a valid length.
const ddbStreamShard = "shardId-00000000000000000000000001"

// ddbStreamRetentionHours is DynamoDB Streams' fixed 24h retention.
const ddbStreamRetentionHours = 24

type ddbStreamStore struct{ db *sql.DB }

// ddbStreamRecord is one change record as stored: a monotonic seq, the event kind, the DynamoDB
// stream payload (Keys / NewImage / OldImage / StreamViewType, JSON), and its arrival time.
type ddbStreamRecord struct {
	Seq       int64
	EventName string // INSERT | MODIFY | REMOVE
	Payload   string // JSON of the record's `dynamodb` block
	TsMs      int64
}

func (s *ddbStreamStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS ddbstream_streams (
    table_name text PRIMARY KEY,
    view_type  text NOT NULL,
    next_seq   bigint NOT NULL DEFAULT 0,
    created    timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ddbstream_records (
    table_name text   NOT NULL,
    seq        bigint NOT NULL,
    event_name text   NOT NULL,
    payload    text   NOT NULL,
    ts_ms      bigint NOT NULL,
    PRIMARY KEY (table_name, seq)
);
CREATE INDEX IF NOT EXISTS ddbstream_records_ts ON ddbstream_records (table_name, ts_ms);`)
	return err
}

// openStream enables (or updates the view type of) a table's stream. Idempotent: re-opening keeps
// the existing records + sequence counter, only refreshing the view type.
func (s *ddbStreamStore) openStream(ctx context.Context, table, viewType string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO ddbstream_streams (table_name, view_type) VALUES ($1,$2)
		 ON CONFLICT (table_name) DO UPDATE SET view_type = EXCLUDED.view_type`,
		table, viewType)
	return err
}

// closeStream disables a table's stream and drops its records (used when a table drops streams).
func (s *ddbStreamStore) closeStream(ctx context.Context, table string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	_, _ = tx.ExecContext(ctx, `DELETE FROM ddbstream_records WHERE table_name=$1`, table)
	_, _ = tx.ExecContext(ctx, `DELETE FROM ddbstream_streams WHERE table_name=$1`, table)
	return tx.Commit()
}

// getStream returns a table's stream view type (ok=false if streams are not enabled for it).
func (s *ddbStreamStore) getStream(ctx context.Context, table string) (viewType string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT view_type FROM ddbstream_streams WHERE table_name=$1`, table).Scan(&viewType)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return viewType, err == nil, err
}

// listStreams returns the tables that currently have a stream enabled.
func (s *ddbStreamStore) listStreams(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT table_name FROM ddbstream_streams ORDER BY table_name`)
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

// appendRecord assigns the next monotonic sequence number (atomic, persisted, under a row lock) and
// stores the change record. Returns the sequence number.
func (s *ddbStreamStore) appendRecord(ctx context.Context, table, eventName, payload string, tsMs int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var seq int64
	if err := tx.QueryRowContext(ctx,
		`UPDATE ddbstream_streams SET next_seq = next_seq + 1 WHERE table_name=$1 RETURNING next_seq`,
		table).Scan(&seq); err != nil {
		return 0, err // stream not open for this table
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO ddbstream_records (table_name, seq, event_name, payload, ts_ms) VALUES ($1,$2,$3,$4,$5)`,
		table, seq, eventName, payload, tsMs); err != nil {
		return 0, err
	}
	return seq, tx.Commit()
}

// getRecords returns up to limit records with seq >= fromSeq, in order.
func (s *ddbStreamStore) getRecords(ctx context.Context, table string, fromSeq int64, limit int) ([]ddbStreamRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, event_name, payload, ts_ms FROM ddbstream_records
		  WHERE table_name=$1 AND seq>=$2 ORDER BY seq LIMIT $3`, table, fromSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ddbStreamRecord
	for rows.Next() {
		var r ddbStreamRecord
		if err := rows.Scan(&r.Seq, &r.EventName, &r.Payload, &r.TsMs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// shardBounds returns the min (TRIM_HORIZON) and latest sequence for the stream's single shard,
// plus the latest record's timestamp. ok=false if there are no records yet.
func (s *ddbStreamStore) shardBounds(ctx context.Context, table string) (minSeq, latestSeq, latestTsMs int64, ok bool, err error) {
	var mn, mx, ts sql.NullInt64
	err = s.db.QueryRowContext(ctx,
		`SELECT MIN(seq), MAX(seq), MAX(ts_ms) FROM ddbstream_records WHERE table_name=$1`, table).
		Scan(&mn, &mx, &ts)
	if err != nil {
		return 0, 0, 0, false, err
	}
	if !mn.Valid {
		return 0, 0, 0, false, nil
	}
	return mn.Int64, mx.Int64, ts.Int64, true, nil
}

// reap deletes records older than the 24h retention window. Returns rows deleted.
func (s *ddbStreamStore) reap(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM ddbstream_records
		  WHERE ts_ms < (EXTRACT(EPOCH FROM now())*1000)::bigint - $1*3600*1000`, ddbStreamRetentionHours)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
