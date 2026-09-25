// Kinesis Data Streams state for the aws-shim (polyhedron#173): streams, shards, and the ordered record
// log. Shares the SQS/KMS Postgres.
//
// Backend decision: Postgres, not JetStream. Kinesis's contract is strict per-shard ordering with monotonic
// SequenceNumbers, replay within a retention window, and shard iterators that advance — and the issue is
// explicit that JetStream's per-subject ordering does NOT map to the shard/partition-key + explicit
// SequenceNumber contract for free. SQL rows keyed (stream, shard, seq) give EXACT control of all three:
// the SequenceNumber is a per-shard monotonic counter (atomic, persisted → stable across restarts), order
// is the seq order, and replay is a re-read from an earlier seq. Same faithful-over-convenient choice as
// the CloudWatch Logs (#164) and CloudWatch (#170) doorways.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type kinesisStore struct{ db *sql.DB }

type kinesisStream struct {
	Name       string
	ShardCount int
	Retention  int // hours
	Status     string
	Created    time.Time
}

type kinesisRecord struct {
	Seq          int64
	ShardID      string
	PartitionKey string
	Data         string // base64
	TsMs         int64
}

func (s *kinesisStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS kinesis_streams (
    name           text PRIMARY KEY,
    shard_count    int NOT NULL,
    retention_hours int NOT NULL DEFAULT 24,
    status         text NOT NULL DEFAULT 'ACTIVE',
    created        timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS kinesis_shards (
    stream   text NOT NULL,
    shard_id text NOT NULL,
    next_seq bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (stream, shard_id)
);
CREATE TABLE IF NOT EXISTS kinesis_records (
    stream        text   NOT NULL,
    shard_id      text   NOT NULL,
    seq           bigint NOT NULL,
    partition_key text   NOT NULL,
    data          text   NOT NULL,
    ts_ms         bigint NOT NULL,
    PRIMARY KEY (stream, shard_id, seq)
);
CREATE INDEX IF NOT EXISTS kinesis_records_ts ON kinesis_records (stream, shard_id, ts_ms);`)
	return err
}

// shardID renders the AWS shard id shape: shardId-000000000000.
func shardID(i int) string { return fmt.Sprintf("shardId-%012d", i) }

func (s *kinesisStore) createStream(ctx context.Context, name string, shardCount, retention int) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists bool
	switch err := tx.QueryRowContext(ctx, `SELECT true FROM kinesis_streams WHERE name=$1`, name).Scan(&exists); err {
	case nil:
		return false, nil // already exists
	case sql.ErrNoRows:
	default:
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO kinesis_streams (name, shard_count, retention_hours) VALUES ($1,$2,$3)`, name, shardCount, retention); err != nil {
		return false, err
	}
	for i := 0; i < shardCount; i++ {
		if _, err := tx.ExecContext(ctx, `INSERT INTO kinesis_shards (stream, shard_id, next_seq) VALUES ($1,$2,0)`, name, shardID(i)); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

func (s *kinesisStore) getStream(ctx context.Context, name string) (kinesisStream, bool, error) {
	var st kinesisStream
	err := s.db.QueryRowContext(ctx,
		`SELECT name, shard_count, retention_hours, status, created FROM kinesis_streams WHERE name=$1`, name).
		Scan(&st.Name, &st.ShardCount, &st.Retention, &st.Status, &st.Created)
	if err == sql.ErrNoRows {
		return kinesisStream{}, false, nil
	}
	return st, err == nil, err
}

func (s *kinesisStore) listStreams(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM kinesis_streams ORDER BY name`)
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

func (s *kinesisStore) deleteStream(ctx context.Context, name string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	_, _ = tx.ExecContext(ctx, `DELETE FROM kinesis_records WHERE stream=$1`, name)
	_, _ = tx.ExecContext(ctx, `DELETE FROM kinesis_shards WHERE stream=$1`, name)
	res, err := tx.ExecContext(ctx, `DELETE FROM kinesis_streams WHERE name=$1`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}

func (s *kinesisStore) setRetention(ctx context.Context, name string, hours int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE kinesis_streams SET retention_hours=$2 WHERE name=$1`, name, hours)
	return err
}

// appendRecord assigns the next monotonic per-shard sequence number (atomic, persisted) and stores the
// record. Concurrency-safe: the shard row's next_seq is incremented under a row lock, so two concurrent
// puts to the same shard get distinct, ordered sequence numbers.
func (s *kinesisStore) appendRecord(ctx context.Context, stream, shard, partitionKey, dataB64 string, tsMs int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var seq int64
	if err := tx.QueryRowContext(ctx,
		`UPDATE kinesis_shards SET next_seq = next_seq + 1 WHERE stream=$1 AND shard_id=$2 RETURNING next_seq`,
		stream, shard).Scan(&seq); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO kinesis_records (stream, shard_id, seq, partition_key, data, ts_ms) VALUES ($1,$2,$3,$4,$5,$6)`,
		stream, shard, seq, partitionKey, dataB64, tsMs); err != nil {
		return 0, err
	}
	return seq, tx.Commit()
}

// getRecords returns up to limit records in a shard with seq >= fromSeq, in order.
func (s *kinesisStore) getRecords(ctx context.Context, stream, shard string, fromSeq int64, limit int) ([]kinesisRecord, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, partition_key, data, ts_ms FROM kinesis_records
		  WHERE stream=$1 AND shard_id=$2 AND seq>=$3 ORDER BY seq LIMIT $4`,
		stream, shard, fromSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []kinesisRecord
	for rows.Next() {
		r := kinesisRecord{ShardID: shard}
		if err := rows.Scan(&r.Seq, &r.PartitionKey, &r.Data, &r.TsMs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// shardBounds returns the minimum (TRIM_HORIZON) and next-after-latest (LATEST) sequence numbers for a
// shard, plus the latest record's timestamp (for MillisBehindLatest). ok=false if the shard has no records.
func (s *kinesisStore) shardBounds(ctx context.Context, stream, shard string) (minSeq, latestSeq, latestTsMs int64, ok bool, err error) {
	var mn, mx, ts sql.NullInt64
	err = s.db.QueryRowContext(ctx,
		`SELECT MIN(seq), MAX(seq), MAX(ts_ms) FROM kinesis_records WHERE stream=$1 AND shard_id=$2`, stream, shard).
		Scan(&mn, &mx, &ts)
	if err != nil {
		return 0, 0, 0, false, err
	}
	if !mn.Valid {
		return 0, 0, 0, false, nil
	}
	return mn.Int64, mx.Int64, ts.Int64, true, nil
}

// seqAtOrAfterTimestamp returns the first sequence in a shard with ts_ms >= tsMs (for AT_TIMESTAMP).
func (s *kinesisStore) seqAtOrAfterTimestamp(ctx context.Context, stream, shard string, tsMs int64) (int64, error) {
	var seq sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT MIN(seq) FROM kinesis_records WHERE stream=$1 AND shard_id=$2 AND ts_ms>=$3`, stream, shard, tsMs).
		Scan(&seq)
	if err != nil {
		return 0, err
	}
	if !seq.Valid {
		return -1, nil // nothing at/after that time yet → iterator parks at LATEST
	}
	return seq.Int64, nil
}

// reap deletes records older than each stream's retention window. Returns rows deleted.
func (s *kinesisStore) reap(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
DELETE FROM kinesis_records r USING kinesis_streams s
 WHERE r.stream = s.name
   AND r.ts_ms < (EXTRACT(EPOCH FROM now())*1000)::bigint - s.retention_hours*3600*1000`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
