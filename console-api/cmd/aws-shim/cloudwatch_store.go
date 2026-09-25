// CloudWatch metrics + alarms state for the aws-shim (polyhedron#170). Shares the SQS/KMS Postgres.
//
// Backend decision (same reasoning as CloudWatch Logs, polyhedron#164): Postgres + an owned evaluator, not
// Prometheus/Mimir. AWS alarm semantics — EvaluationPeriods / DatapointsToAlarm / TreatMissingData /
// ComparisonOperator + SNS actions — do not map onto Prometheus recording/alerting rules, and an alarm that
// is created but never evaluates at AWS's contract is worse than absent. Storing datapoints as SQL rows and
// evaluating them in-process (cloudwatch.go) gives the EXACT statistics/percentile math and the exact alarm
// state machine, which is what an operator trusts.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/lib/pq"
)

type cwStore struct{ db *sql.DB }

type cwAlarm struct {
	Name               string
	Namespace          string
	MetricName         string
	DimsHash           string
	Dims               map[string]string
	Statistic          string // one of the standard stats, or "" if ExtendedStatistic is set
	ExtendedStatistic  string // a percentile "pNN", or ""
	Period             int
	EvaluationPeriods  int
	DatapointsToAlarm  int
	Threshold          float64
	ComparisonOperator string
	TreatMissingData   string // missing | notBreaching | breaching | ignore
	AlarmActions       []string
	State              string // OK | ALARM | INSUFFICIENT_DATA
	StateReason        string
	StateUpdated       time.Time
	Principal          string
}

func (s *cwStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS cw_metrics (
    namespace   text   NOT NULL,
    metric_name text   NOT NULL,
    dims_hash   text   NOT NULL,
    dims        jsonb  NOT NULL DEFAULT '{}',
    ts_ms       bigint NOT NULL,
    value       double precision NOT NULL,
    sum         double precision NOT NULL,
    minv        double precision NOT NULL,
    maxv        double precision NOT NULL,
    sample_count double precision NOT NULL DEFAULT 1,
    unit        text NOT NULL DEFAULT '',
    resolution  int  NOT NULL DEFAULT 60
);
CREATE INDEX IF NOT EXISTS cw_metrics_series ON cw_metrics (namespace, metric_name, dims_hash, ts_ms);
CREATE TABLE IF NOT EXISTS cw_alarms (
    name                text PRIMARY KEY,
    namespace           text NOT NULL,
    metric_name         text NOT NULL,
    dims_hash           text NOT NULL,
    dims                jsonb NOT NULL DEFAULT '{}',
    statistic           text NOT NULL DEFAULT '',
    extended_statistic  text NOT NULL DEFAULT '',
    period              int  NOT NULL,
    evaluation_periods  int  NOT NULL,
    datapoints_to_alarm int  NOT NULL,
    threshold           double precision NOT NULL,
    comparison_operator text NOT NULL,
    treat_missing_data  text NOT NULL DEFAULT 'missing',
    alarm_actions       jsonb NOT NULL DEFAULT '[]',
    state               text NOT NULL DEFAULT 'INSUFFICIENT_DATA',
    state_reason        text NOT NULL DEFAULT '',
    state_updated       timestamptz NOT NULL DEFAULT now(),
    principal           text NOT NULL DEFAULT ''
);`)
	return err
}

// putDatum inserts one datapoint.
func (s *cwStore) putDatum(ctx context.Context, ns, name, dimsHash string, dims map[string]string, tsMs int64, value, sum, minv, maxv, count float64, unit string, resolution int) error {
	dj, _ := json.Marshal(dims)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cw_metrics (namespace, metric_name, dims_hash, dims, ts_ms, value, sum, minv, maxv, sample_count, unit, resolution)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		ns, name, dimsHash, dj, tsMs, value, sum, minv, maxv, count, unit, resolution)
	return err
}

// queryDatapoints returns datapoints for a series in [startMs, endMs).
func (s *cwStore) queryDatapoints(ctx context.Context, ns, name, dimsHash string, startMs, endMs int64) ([]cwDatum, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts_ms, value, sum, minv, maxv, sample_count FROM cw_metrics
		  WHERE namespace=$1 AND metric_name=$2 AND dims_hash=$3 AND ts_ms>=$4 AND ts_ms<$5 ORDER BY ts_ms`,
		ns, name, dimsHash, startMs, endMs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cwDatum
	for rows.Next() {
		var d cwDatum
		if err := rows.Scan(&d.TsMs, &d.Value, &d.Sum, &d.Min, &d.Max, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type cwMetricIdentity struct {
	Namespace  string
	MetricName string
	Dims       map[string]string
}

// listMetrics returns the distinct series (namespace/name/dims), optionally filtered by namespace/name.
func (s *cwStore) listMetrics(ctx context.Context, ns, name string) ([]cwMetricIdentity, error) {
	q := `SELECT DISTINCT namespace, metric_name, dims FROM cw_metrics WHERE 1=1`
	var args []any
	if ns != "" {
		args = append(args, ns)
		q += ` AND namespace=$1`
	}
	if name != "" {
		args = append(args, name)
		q += ` AND metric_name=$` + itoa(len(args))
	}
	q += ` ORDER BY namespace, metric_name LIMIT 500`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cwMetricIdentity
	for rows.Next() {
		var m cwMetricIdentity
		var dj []byte
		if err := rows.Scan(&m.Namespace, &m.MetricName, &dj); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(dj, &m.Dims)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *cwStore) putAlarm(ctx context.Context, a cwAlarm) error {
	dj, _ := json.Marshal(a.Dims)
	aj, _ := json.Marshal(a.AlarmActions)
	_, err := s.db.ExecContext(ctx, `
INSERT INTO cw_alarms (name, namespace, metric_name, dims_hash, dims, statistic, extended_statistic, period,
    evaluation_periods, datapoints_to_alarm, threshold, comparison_operator, treat_missing_data, alarm_actions, principal)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (name) DO UPDATE SET namespace=EXCLUDED.namespace, metric_name=EXCLUDED.metric_name,
    dims_hash=EXCLUDED.dims_hash, dims=EXCLUDED.dims, statistic=EXCLUDED.statistic,
    extended_statistic=EXCLUDED.extended_statistic, period=EXCLUDED.period,
    evaluation_periods=EXCLUDED.evaluation_periods, datapoints_to_alarm=EXCLUDED.datapoints_to_alarm,
    threshold=EXCLUDED.threshold, comparison_operator=EXCLUDED.comparison_operator,
    treat_missing_data=EXCLUDED.treat_missing_data, alarm_actions=EXCLUDED.alarm_actions,
    principal=EXCLUDED.principal`,
		a.Name, a.Namespace, a.MetricName, a.DimsHash, dj, a.Statistic, a.ExtendedStatistic, a.Period,
		a.EvaluationPeriods, a.DatapointsToAlarm, a.Threshold, a.ComparisonOperator, a.TreatMissingData, aj, a.Principal)
	return err
}

func scanAlarm(rows interface {
	Scan(...any) error
}) (cwAlarm, error) {
	var a cwAlarm
	var dj, aj []byte
	err := rows.Scan(&a.Name, &a.Namespace, &a.MetricName, &a.DimsHash, &dj, &a.Statistic, &a.ExtendedStatistic,
		&a.Period, &a.EvaluationPeriods, &a.DatapointsToAlarm, &a.Threshold, &a.ComparisonOperator,
		&a.TreatMissingData, &aj, &a.State, &a.StateReason, &a.StateUpdated, &a.Principal)
	if err != nil {
		return cwAlarm{}, err
	}
	_ = json.Unmarshal(dj, &a.Dims)
	_ = json.Unmarshal(aj, &a.AlarmActions)
	return a, nil
}

const cwAlarmCols = `name, namespace, metric_name, dims_hash, dims, statistic, extended_statistic, period,
    evaluation_periods, datapoints_to_alarm, threshold, comparison_operator, treat_missing_data,
    alarm_actions, state, state_reason, state_updated, principal`

func (s *cwStore) getAlarm(ctx context.Context, name string) (cwAlarm, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+cwAlarmCols+` FROM cw_alarms WHERE name=$1`, name)
	a, err := scanAlarm(row)
	if err == sql.ErrNoRows {
		return cwAlarm{}, false, nil
	}
	return a, err == nil, err
}

func (s *cwStore) listAlarms(ctx context.Context, names []string, stateFilter string) ([]cwAlarm, error) {
	q := `SELECT ` + cwAlarmCols + ` FROM cw_alarms WHERE 1=1`
	var args []any
	if len(names) > 0 {
		q += ` AND name = ANY($1)`
		args = append(args, pq.Array(names))
	}
	if stateFilter != "" {
		args = append(args, stateFilter)
		q += ` AND state=$` + itoa(len(args))
	}
	q += ` ORDER BY name`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cwAlarm
	for rows.Next() {
		a, err := scanAlarm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *cwStore) allAlarms(ctx context.Context) ([]cwAlarm, error) {
	return s.listAlarms(ctx, nil, "")
}

func (s *cwStore) deleteAlarms(ctx context.Context, names []string) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM cw_alarms WHERE name = ANY($1)`, pq.Array(names))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *cwStore) setAlarmStateDB(ctx context.Context, name, state, reason string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE cw_alarms SET state=$2, state_reason=$3, state_updated=now() WHERE name=$1`, name, state, reason)
	return rowsAffected(res, err)
}
