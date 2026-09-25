// Postgres-backed store for the aws-shim SNS front door — topics and subscriptions.
//
// SNS's one dangerous-to-get-wrong semantic is that Publish must not acknowledge until the message is
// DURABLY accepted for every current subscription (a fire-and-forget publish that returns a MessageId
// but drops the message is the exact false-green this program refuses). Topics and subscriptions live
// here; delivery for the supported protocol (sqs) is a durable INSERT into the target queue via the
// SQS store, so Publish is durable by construction (see sns.go). Shares the shim's SQS Postgres.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
)

type snsStore struct{ db *sql.DB }

const snsSchema = `
CREATE TABLE IF NOT EXISTS sns_topics (
  arn        text PRIMARY KEY,
  name       text NOT NULL UNIQUE,
  attributes jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sns_subscriptions (
  arn          text PRIMARY KEY,
  topic_arn    text NOT NULL REFERENCES sns_topics(arn) ON DELETE CASCADE,
  protocol     text NOT NULL,
  endpoint     text NOT NULL,
  raw_delivery boolean NOT NULL DEFAULT false,
  confirmed    boolean NOT NULL DEFAULT true,
  attributes   jsonb NOT NULL DEFAULT '{}',
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sns_subs_topic_idx ON sns_subscriptions(topic_arn);
`

func (s *snsStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, snsSchema)
	return err
}

type snsSubscription struct {
	Arn      string
	TopicArn string
	Protocol string
	Endpoint string
	Raw      bool
}

// createTopic is idempotent: creating a topic that already exists (by name) returns its existing ARN,
// exactly as AWS's CreateTopic does. existed reports whether it was already present.
func (s *snsStore) createTopic(ctx context.Context, arn, name string) (existed bool, err error) {
	var have string
	err = s.db.QueryRowContext(ctx, `SELECT arn FROM sns_topics WHERE name = $1`, name).Scan(&have)
	if err == nil {
		return true, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sns_topics (arn, name) VALUES ($1, $2)`, arn, name)
	return false, err
}

func (s *snsStore) topicExists(ctx context.Context, arn string) (bool, error) {
	var x int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM sns_topics WHERE arn = $1`, arn).Scan(&x)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *snsStore) topicAttrs(ctx context.Context, arn string) (map[string]string, bool, error) {
	var aj []byte
	err := s.db.QueryRowContext(ctx, `SELECT attributes::text FROM sns_topics WHERE arn = $1`, arn).Scan(&aj)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	m := map[string]string{}
	_ = json.Unmarshal(aj, &m)
	return m, true, nil
}

func (s *snsStore) setTopicAttr(ctx context.Context, arn, key, val string) (bool, error) {
	attrs, ok, err := s.topicAttrs(ctx, arn)
	if err != nil || !ok {
		return ok, err
	}
	attrs[key] = val
	aj, _ := json.Marshal(attrs)
	res, err := s.db.ExecContext(ctx, `UPDATE sns_topics SET attributes = $2::jsonb WHERE arn = $1`, arn, string(aj))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *snsStore) deleteTopic(ctx context.Context, arn string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sns_topics WHERE arn = $1`, arn)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *snsStore) listTopics(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT arn FROM sns_topics ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *snsStore) subscribe(ctx context.Context, arn, topicArn, protocol, endpoint string, raw, confirmed bool) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sns_subscriptions (arn, topic_arn, protocol, endpoint, raw_delivery, confirmed)
		VALUES ($1, $2, $3, $4, $5, $6)`, arn, topicArn, protocol, endpoint, raw, confirmed)
	return err
}

func (s *snsStore) unsubscribe(ctx context.Context, arn string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sns_subscriptions WHERE arn = $1`, arn)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *snsStore) subscriptionsForTopic(ctx context.Context, topicArn string) ([]snsSubscription, error) {
	return s.querySubs(ctx, `SELECT arn, topic_arn, protocol, endpoint, raw_delivery FROM sns_subscriptions WHERE topic_arn = $1 AND confirmed ORDER BY created_at`, topicArn)
}

func (s *snsStore) listSubscriptions(ctx context.Context) ([]snsSubscription, error) {
	return s.querySubs(ctx, `SELECT arn, topic_arn, protocol, endpoint, raw_delivery FROM sns_subscriptions ORDER BY created_at`)
}

func (s *snsStore) subByArn(ctx context.Context, arn string) (snsSubscription, bool, error) {
	subs, err := s.querySubs(ctx, `SELECT arn, topic_arn, protocol, endpoint, raw_delivery FROM sns_subscriptions WHERE arn = $1`, arn)
	if err != nil || len(subs) == 0 {
		return snsSubscription{}, false, err
	}
	return subs[0], true, nil
}

func (s *snsStore) setSubRaw(ctx context.Context, arn string, raw bool) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE sns_subscriptions SET raw_delivery = $2 WHERE arn = $1`, arn, raw)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *snsStore) querySubs(ctx context.Context, q string, args ...any) ([]snsSubscription, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []snsSubscription
	for rows.Next() {
		var sub snsSubscription
		if err := rows.Scan(&sub.Arn, &sub.TopicArn, &sub.Protocol, &sub.Endpoint, &sub.Raw); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}
