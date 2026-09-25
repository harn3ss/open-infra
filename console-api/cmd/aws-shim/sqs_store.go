// Postgres-backed store for the aws-shim SQS front door.
//
// SQS's hard semantics — a per-receive ReceiptHandle that a STALE handle can never use to delete a
// redelivered message, a visibility timeout, per-message ChangeMessageVisibility, an observable
// ApproximateReceiveCount, and maxReceiveCount → DLQ — are all trivially correct over a row-locked
// SQL table, which is why this front door is Postgres-backed rather than JetStream-backed (the
// receipt-handle boundary is a correctness-and-security boundary; see docs/aws-shim.md and
// polyhedron#158). The receive path is the classic `FOR UPDATE SKIP LOCKED` queue claim: it makes the
// claimed rows invisible for the visibility window, bumps the receive count, and mints a FRESH opaque
// handle per row in the same statement — so an old handle simply matches no row on delete (stale
// rejection is structural, not bolted on).
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// sqsStore is the Postgres persistence for queues and messages. A nil store means the data layer is
// unconfigured and every operation answers an honest 501 at the handler.
type sqsStore struct{ db *sql.DB }

// errQueueExistsDiff is returned by createQueue when a queue of the same name exists with DIFFERENT
// attributes — AWS's QueueNameExists, distinct from the idempotent same-attributes create.
var errQueueExistsDiff = errors.New("queue exists with different attributes")

const sqsSchema = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS sqs_queues (
  url        text PRIMARY KEY,
  name       text NOT NULL UNIQUE,
  attributes jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sqs_messages (
  id                bigserial PRIMARY KEY,
  queue_url         text NOT NULL REFERENCES sqs_queues(url) ON DELETE CASCADE,
  message_id        text NOT NULL DEFAULT gen_random_uuid()::text,
  body              text NOT NULL,
  md5_body          text NOT NULL,
  msg_attrs         jsonb NOT NULL DEFAULT '{}',
  md5_attrs         text,
  visible_after     timestamptz NOT NULL DEFAULT now(),
  receive_count     int NOT NULL DEFAULT 0,
  receipt_handle    text,
  sent_at           timestamptz NOT NULL DEFAULT now(),
  first_received_at timestamptz
);
CREATE INDEX IF NOT EXISTS sqs_messages_recv_idx ON sqs_messages(queue_url, visible_after);
CREATE INDEX IF NOT EXISTS sqs_messages_handle_idx ON sqs_messages(queue_url, receipt_handle);
`

func (s *sqsStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, sqsSchema)
	return err
}

// storedMessage is one message as the store returns it to the handler.
type storedMessage struct {
	MessageID     string
	Body          string
	MD5Body       string
	MD5Attrs      string // "" when the message carries no attributes
	Attrs         map[string]any
	ReceiptHandle string
	ReceiveCount  int
	SentAt        time.Time
	FirstReceived time.Time
}

// --- queues ---

// createQueue inserts a queue idempotently. It returns existed=true when a same-named queue is already
// present; if that existing queue's attributes DIFFER it returns errQueueExistsDiff (AWS QueueNameExists).
func (s *sqsStore) createQueue(ctx context.Context, name, url string, attrs map[string]string) (existed bool, err error) {
	aj, _ := json.Marshal(attrs)
	var existingURL string
	var existingAttrs []byte
	row := s.db.QueryRowContext(ctx, `SELECT url, attributes::text FROM sqs_queues WHERE name = $1`, name)
	switch err = row.Scan(&existingURL, &existingAttrs); {
	case err == sql.ErrNoRows:
		_, err = s.db.ExecContext(ctx, `INSERT INTO sqs_queues (url, name, attributes) VALUES ($1, $2, $3::jsonb)`, url, name, string(aj))
		return false, err
	case err != nil:
		return false, err
	}
	// Same name already exists — idempotent only if the attributes match.
	var have map[string]string
	_ = json.Unmarshal(existingAttrs, &have)
	if !sameStringMap(have, attrs) {
		return true, errQueueExistsDiff
	}
	return true, nil
}

func (s *sqsStore) queueURLByName(ctx context.Context, name string) (string, bool, error) {
	var url string
	err := s.db.QueryRowContext(ctx, `SELECT url FROM sqs_queues WHERE name = $1`, name).Scan(&url)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return url, err == nil, err
}

func (s *sqsStore) queueAttrs(ctx context.Context, url string) (map[string]string, time.Time, bool, error) {
	var aj []byte
	var created time.Time
	err := s.db.QueryRowContext(ctx, `SELECT attributes::text, created_at FROM sqs_queues WHERE url = $1`, url).Scan(&aj, &created)
	if err == sql.ErrNoRows {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, err
	}
	m := map[string]string{}
	_ = json.Unmarshal(aj, &m)
	return m, created, true, nil
}

func (s *sqsStore) setQueueAttrs(ctx context.Context, url string, attrs map[string]string) (bool, error) {
	have, _, ok, err := s.queueAttrs(ctx, url)
	if err != nil || !ok {
		return ok, err
	}
	for k, v := range attrs {
		have[k] = v
	}
	aj, _ := json.Marshal(have)
	res, err := s.db.ExecContext(ctx, `UPDATE sqs_queues SET attributes = $2::jsonb WHERE url = $1`, url, string(aj))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *sqsStore) deleteQueue(ctx context.Context, url string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sqs_queues WHERE url = $1`, url)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *sqsStore) listQueues(ctx context.Context, prefix string, limit int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT url FROM sqs_queues WHERE name LIKE $1 ORDER BY name LIMIT $2`, prefix+"%", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// counts returns (available, inFlight): messages currently visible vs currently invisible (received,
// not yet deleted, visibility not expired). These back ApproximateNumberOfMessages(NotVisible).
func (s *sqsStore) counts(ctx context.Context, url string) (available, inFlight int, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT
		  count(*) FILTER (WHERE visible_after <= now()),
		  count(*) FILTER (WHERE visible_after > now())
		FROM sqs_messages WHERE queue_url = $1`, url).Scan(&available, &inFlight)
	return
}

// --- messages ---

func (s *sqsStore) sendMessage(ctx context.Context, url, body, md5Body, md5Attrs string, attrs map[string]any, delay time.Duration) (string, error) {
	aj, _ := json.Marshal(attrs)
	var mAttrs any
	if md5Attrs != "" {
		mAttrs = md5Attrs
	}
	var messageID string
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO sqs_messages (queue_url, body, md5_body, md5_attrs, msg_attrs, visible_after)
		VALUES ($1, $2, $3, $4, $5::jsonb, now() + make_interval(secs => $6))
		RETURNING message_id`,
		url, body, md5Body, mAttrs, string(aj), delay.Seconds()).Scan(&messageID)
	return messageID, err
}

// receive claims up to max currently-visible messages atomically (FOR UPDATE SKIP LOCKED), makes them
// invisible for `visibility`, bumps receive_count, and mints a fresh opaque receipt handle per row.
// Messages whose receive_count now EXCEEDS maxReceiveCount (when a RedrivePolicy is set) are moved to
// the dead-letter queue instead of being returned — that is where dlqURL comes from (resolved by the
// caller from the RedrivePolicy). maxReceive <= 0 means no redrive.
func (s *sqsStore) receive(ctx context.Context, url string, max int, visibility time.Duration, maxReceive int, dlqURL string) ([]storedMessage, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		UPDATE sqs_messages m
		SET visible_after     = now() + make_interval(secs => $3),
		    receive_count     = m.receive_count + 1,
		    receipt_handle    = encode(gen_random_bytes(48), 'base64'),
		    first_received_at = COALESCE(m.first_received_at, now())
		WHERE m.id IN (
		  SELECT id FROM sqs_messages
		  WHERE queue_url = $1 AND visible_after <= now()
		  ORDER BY sent_at
		  LIMIT $2
		  FOR UPDATE SKIP LOCKED
		)
		RETURNING m.id, m.message_id, m.body, m.md5_body, m.md5_attrs, m.msg_attrs::text,
		          m.receipt_handle, m.receive_count, m.sent_at, m.first_received_at`,
		url, max, visibility.Seconds())
	if err != nil {
		return nil, err
	}
	type claimed struct {
		id int64
		m  storedMessage
	}
	var all []claimed
	for rows.Next() {
		var c claimed
		var md5Attrs sql.NullString
		var attrsJSON string
		if err := rows.Scan(&c.id, &c.m.MessageID, &c.m.Body, &c.m.MD5Body, &md5Attrs, &attrsJSON,
			&c.m.ReceiptHandle, &c.m.ReceiveCount, &c.m.SentAt, &c.m.FirstReceived); err != nil {
			rows.Close()
			return nil, err
		}
		c.m.MD5Attrs = md5Attrs.String
		_ = json.Unmarshal([]byte(attrsJSON), &c.m.Attrs)
		all = append(all, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]storedMessage, 0, len(all))
	var dead []int64
	for _, c := range all {
		// maxReceiveCount → DLQ: AWS moves a message after it has been received more than
		// maxReceiveCount times without a delete. receive_count was just incremented, so the check is
		// strictly-greater. Requires a resolvable DLQ; without one, fall through and deliver.
		if maxReceive > 0 && dlqURL != "" && c.m.ReceiveCount > maxReceive {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO sqs_messages (queue_url, message_id, body, md5_body, md5_attrs, msg_attrs, receive_count)
				SELECT $2, message_id, body, md5_body, md5_attrs, msg_attrs, 0 FROM sqs_messages WHERE id = $1`,
				c.id, dlqURL); err != nil {
				return nil, err
			}
			dead = append(dead, c.id)
			continue
		}
		out = append(out, c.m)
	}
	for _, id := range dead {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sqs_messages WHERE id = $1`, id); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// deleteByHandle deletes the message the handle currently names. A stale handle (the message was
// redelivered and re-minted a new handle, or was already deleted) matches no row → ok=false, which the
// handler renders as ReceiptHandleIsInvalid. The delete is scoped to the queue so a handle from one
// queue can never delete in another.
func (s *sqsStore) deleteByHandle(ctx context.Context, url, handle string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sqs_messages WHERE queue_url = $1 AND receipt_handle = $2`, url, handle)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// changeVisibility resets the visibility deadline of the in-flight message the handle names.
// visibility 0 makes it immediately redeliverable. A stale/unknown handle → ok=false (MessageNotInflight).
func (s *sqsStore) changeVisibility(ctx context.Context, url, handle string, visibility time.Duration) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sqs_messages SET visible_after = now() + make_interval(secs => $3)
		WHERE queue_url = $1 AND receipt_handle = $2`, url, handle, visibility.Seconds())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *sqsStore) purge(ctx context.Context, url string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sqs_messages WHERE queue_url = $1`, url)
	return err
}

// reapExpired deletes messages past their queue's MessageRetentionPeriod (default 4 days). Runs on a
// ticker; a no-op when the data layer is unconfigured.
func (s *sqsStore) reapExpired(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM sqs_messages m USING sqs_queues q
		WHERE m.queue_url = q.url
		  AND m.sent_at < now() - make_interval(secs =>
		        COALESCE(NULLIF(q.attributes->>'MessageRetentionPeriod','')::int, 345600))`)
	return err
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
