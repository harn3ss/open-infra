package main

// CloudWatch keeps each account's metrics and alarms apart (account-scoped): against a real Postgres store
// (OPENINFRA_TEST_PG_URI; skipped without it).

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn/resourcepolicy"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// recordingSNS records the alarm actions published: the account each acts in, and what it sends.
type recordingSNS struct {
	mu       sync.Mutex
	accepts  []resourcepolicy.Request
	accounts []string
	topics   []string
	messages []string
}

func (s *recordingSNS) topicAccepts(_ context.Context, _ string, req resourcepolicy.Request) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accepts = append(s.accepts, req)
	return true, nil
}

func (s *recordingSNS) publishMessage(ctx context.Context, topicArn, _, message string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts = append(s.accounts, callerAccount(ctx))
	s.topics = append(s.topics, topicArn)
	s.messages = append(s.messages, message)
	return "m-1", nil
}

func cwFixture(t *testing.T) (*cwHandler, *recordingSNS) {
	t.Helper()
	db := freshPGDB(t)
	st := &cwStore{db: db}
	if err := st.ensureSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	sns := &recordingSNS{}
	h := newCWHandler(csWithSAR(true), "authz", testMgmt, "us-east-1", st, sns, discardLogger())
	h.authz = acctAuthz(t)
	h.homeOf = testDirectory().HomeOf
	return h, sns
}

func cwCall(t *testing.T, h *cwHandler, c iam.Claims, op string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return callAs(t, h.serve, c, "GraniteServiceVersion20100801."+op, body)
}

func putDatapoint(t *testing.T, h *cwHandler, c iam.Claims, metric string, v float64) {
	t.Helper()
	if code, out := cwCall(t, h, c, "PutMetricData", map[string]any{"Namespace": "App", "MetricData": []any{
		map[string]any{"MetricName": metric, "Value": v, "Timestamp": time.Now().Add(-time.Second).UTC().Format(time.RFC3339)}}}); code != 200 {
		t.Fatalf("PutMetricData: %d %v", code, out)
	}
}

func sumOf(t *testing.T, h *cwHandler, c iam.Claims, metric string) []any {
	t.Helper()
	code, out := cwCall(t, h, c, "GetMetricStatistics", map[string]any{"Namespace": "App", "MetricName": metric, "Period": 3600,
		"StartTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "EndTime": time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		"Statistics": []any{"Sum"}})
	if code != 200 {
		t.Fatalf("GetMetricStatistics: %d %v", code, out)
	}
	var sums []any
	for _, dp := range sliceOf(out["Datapoints"]) {
		sums = append(sums, dp.(map[string]any)["Sum"])
	}
	return sums
}

func TestServicesPG_CloudWatchAccounts_MetricsAreEachAccountsOwn(t *testing.T) {
	h, _ := cwFixture(t)
	putDatapoint(t, h, acctMgmt, "Errors", 1)
	putDatapoint(t, h, acctMember, "Errors", 100)
	putDatapoint(t, h, acctMember, "Latency", 5)
	if s := sumOf(t, h, acctMgmt, "Errors"); len(s) != 1 || s[0] != float64(1) {
		t.Errorf("the management account's Errors = %v, want its own 1", s)
	}
	if s := sumOf(t, h, acctMember, "Errors"); len(s) != 1 || s[0] != float64(100) {
		t.Errorf("the member's Errors = %v, want its own 100", s)
	}
	if s := sumOf(t, h, acctMgmt, "Latency"); len(s) != 0 {
		t.Errorf("the management account read the member's Latency: %v", s)
	}
	metricNames := func(c iam.Claims) string {
		_, out := cwCall(t, h, c, "ListMetrics", map[string]any{"Namespace": "App"})
		var n []string
		for _, m := range sliceOf(out["Metrics"]) {
			n = append(n, m.(map[string]any)["MetricName"].(string))
		}
		return strings.Join(n, ",")
	}
	if got := metricNames(acctMember); got != "Errors,Latency" {
		t.Errorf("member ListMetrics = %s", got)
	}
	if got := metricNames(acctMgmt); got != "Errors" {
		t.Errorf("management ListMetrics = %s (the member's series must not be listed)", got)
	}
	_, out := cwCall(t, h, acctMember, "GetMetricData", map[string]any{
		"StartTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "EndTime": time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		"MetricDataQueries": []any{map[string]any{"Id": "e", "MetricStat": map[string]any{
			"Metric": map[string]any{"Namespace": "App", "MetricName": "Errors"}, "Period": 3600, "Stat": "Sum"}}}})
	if r := sliceOf(out["MetricDataResults"]); len(r) != 1 || mustJSON(r[0].(map[string]any)["Values"]) != "[100]" {
		t.Errorf("member GetMetricData = %v", out)
	}
}

// The management account's rows keep the account column they always had (""), its ARNs the door's own
// account; a member account's carry its id. The evaluator acts in a member alarm's account.
func TestCloudWatchAccounts_AccountColumnAndARNs(t *testing.T) {
	h := newCWHandler(nil, "authz", testMgmt, "us-east-1", nil, nil, discardLogger())
	h.homeOf = testDirectory().HomeOf
	if cwAccount(context.Background()) != "" || cwAccount(memberCtx()) != testMember {
		t.Fatalf("account column: management %q, member %q", cwAccount(context.Background()), cwAccount(memberCtx()))
	}
	if got := h.alarmARN(cwAlarm{Name: "hot"}); got != "arn:aws:cloudwatch:us-east-1:"+testMgmt+":alarm:hot" {
		t.Errorf("management alarm ARN %s", got)
	}
	if got := h.alarmARN(cwAlarm{Account: testMember, Name: "hot"}); got != "arn:aws:cloudwatch:us-east-1:"+testMember+":alarm:hot" {
		t.Errorf("member alarm ARN %s", got)
	}
	ctx := h.inAccount(context.Background(), testMember)
	if callerAccount(ctx) != testMember || accountNamespace(ctx, "x") != memberHome {
		t.Errorf("the evaluator's context for a member alarm acts in %s / %s", callerAccount(ctx), accountNamespace(ctx, "x"))
	}
	if h.inAccount(context.Background(), "") != context.Background() {
		t.Error("the evaluator's context for a management alarm is unchanged")
	}
}

func alarmBody(threshold float64) map[string]any {
	return map[string]any{"AlarmName": "hot", "Namespace": "App", "MetricName": "Errors", "Statistic": "Sum", "Period": 60,
		"EvaluationPeriods": 1, "Threshold": threshold, "ComparisonOperator": "GreaterThanThreshold",
		"AlarmActions": []any{"arn:aws:sns:us-east-1:" + testMember + ":pager"}}
}

func describeHot(t *testing.T, h *cwHandler, c iam.Claims) []any {
	t.Helper()
	_, out := cwCall(t, h, c, "DescribeAlarms", map[string]any{})
	return sliceOf(out["MetricAlarms"])
}

func TestServicesPG_CloudWatchAccounts_AlarmsAreEachAccountsOwn(t *testing.T) {
	h, sns := cwFixture(t)
	if code, out := cwCall(t, h, acctMgmt, "PutMetricAlarm", alarmBody(1000)); code != 200 {
		t.Fatalf("management PutMetricAlarm: %d %v", code, out)
	}
	if code, out := cwCall(t, h, acctMember, "PutMetricAlarm", alarmBody(10)); code != 200 {
		t.Fatalf("member PutMetricAlarm (the same name, another account): %d %v", code, out)
	}
	m := describeHot(t, h, acctMember)
	if len(m) != 1 || m[0].(map[string]any)["Threshold"] != float64(10) ||
		m[0].(map[string]any)["AlarmArn"] != "arn:aws:cloudwatch:us-east-1:"+testMember+":alarm:hot" {
		t.Fatalf("member DescribeAlarms = %v", m)
	}
	g := describeHot(t, h, acctMgmt)
	if len(g) != 1 || g[0].(map[string]any)["Threshold"] != float64(1000) ||
		g[0].(map[string]any)["AlarmArn"] != "arn:aws:cloudwatch:us-east-1:"+testMgmt+":alarm:hot" {
		t.Fatalf("management DescribeAlarms = %v", g)
	}

	// The evaluator evaluates each alarm over its own account's metric, and the member's fires in its
	// account.
	putDatapoint(t, h, acctMgmt, "Errors", 50)    // under the management alarm's 1000
	putDatapoint(t, h, acctMember, "Errors", 100) // over the member alarm's 10
	h.evaluateAll(context.Background())
	if s := describeHot(t, h, acctMember)[0].(map[string]any)["StateValue"]; s != "ALARM" {
		t.Errorf("the member's alarm is %v, want ALARM (its own 100 > 10)", s)
	}
	if s := describeHot(t, h, acctMgmt)[0].(map[string]any)["StateValue"]; s != "OK" {
		t.Errorf("the management account's alarm is %v, want OK (its own 50 < 1000)", s)
	}
	if len(sns.accounts) != 1 || sns.accounts[0] != testMember || sns.topics[0] != "arn:aws:sns:us-east-1:"+testMember+":pager" {
		t.Fatalf("published %v to %v, want one publish in the member account", sns.accounts, sns.topics)
	}
	var notif map[string]any
	_ = json.Unmarshal([]byte(sns.messages[0]), &notif)
	if notif["AWSAccountId"] != testMember || sns.accepts[0].SourceAccount != testMember ||
		sns.accepts[0].SourceArn != "arn:aws:cloudwatch:us-east-1:"+testMember+":alarm:hot" {
		t.Errorf("notification %v, policy request %+v: want the member account", notif, sns.accepts[0])
	}

	// SetAlarmState and DeleteAlarms act on the caller's account's alarm only.
	if code, out := cwCall(t, h, acctMember, "SetAlarmState", map[string]any{"AlarmName": "hot", "StateValue": "OK", "StateReason": "test"}); code != 200 {
		t.Fatalf("member SetAlarmState: %d %v", code, out)
	}
	if s := describeHot(t, h, acctMgmt)[0].(map[string]any)["StateReason"]; s == "test" {
		t.Error("the member's SetAlarmState changed the management account's alarm")
	}
	if code, out := cwCall(t, h, acctMember, "DeleteAlarms", map[string]any{"AlarmNames": []any{"hot"}}); code != 200 {
		t.Fatalf("member DeleteAlarms: %d %v", code, out)
	}
	if len(describeHot(t, h, acctMember)) != 0 || len(describeHot(t, h, acctMgmt)) != 1 {
		t.Fatal("the member's DeleteAlarms must delete its own alarm and leave the management account's")
	}
	if code, out := cwCall(t, h, acctMember, "SetAlarmState", map[string]any{"AlarmName": "hot", "StateValue": "OK"}); code != 404 {
		t.Fatalf("member SetAlarmState on the management account's alarm name: %d %v, want not found", code, out)
	}
}

// The schema keeps the alarms stored before accounts: they are the management account's, and a member
// account's alarm of the same name is stored beside them.
func TestServicesPG_CloudWatchAccounts_SchemaKeepsEarlierAlarms(t *testing.T) {
	db := freshPGDB(t)
	ctx := context.Background()
	if _, err := db.Exec(`CREATE TABLE cw_alarms (name text PRIMARY KEY, namespace text NOT NULL, metric_name text NOT NULL,
    dims_hash text NOT NULL, dims jsonb NOT NULL DEFAULT '{}', statistic text NOT NULL DEFAULT '', extended_statistic text NOT NULL DEFAULT '',
    period int NOT NULL, evaluation_periods int NOT NULL, datapoints_to_alarm int NOT NULL, threshold double precision NOT NULL,
    comparison_operator text NOT NULL, treat_missing_data text NOT NULL DEFAULT 'missing', alarm_actions jsonb NOT NULL DEFAULT '[]',
    state text NOT NULL DEFAULT 'INSUFFICIENT_DATA', state_reason text NOT NULL DEFAULT '', state_updated timestamptz NOT NULL DEFAULT now(),
    principal text NOT NULL DEFAULT '');
INSERT INTO cw_alarms (name, namespace, metric_name, dims_hash, period, evaluation_periods, datapoints_to_alarm, threshold, comparison_operator)
VALUES ('old', 'App', 'Errors', '', 60, 1, 1, 5, 'GreaterThanThreshold')`); err != nil {
		t.Fatal(err)
	}
	st := &cwStore{db: db}
	for i := 0; i < 2; i++ { // idempotent
		if err := st.ensureSchema(ctx); err != nil {
			t.Fatalf("ensureSchema #%d: %v", i+1, err)
		}
	}
	if a, ok, err := st.getAlarm(ctx, "", "old"); err != nil || !ok || a.Threshold != 5 || a.Account != "" {
		t.Fatalf("the earlier alarm: %+v %v %v", a, ok, err)
	}
	member := cwAlarm{Account: testMember, Name: "old", Namespace: "App", MetricName: "Errors", Period: 60, EvaluationPeriods: 1,
		DatapointsToAlarm: 1, Threshold: 9, ComparisonOperator: "GreaterThanThreshold", TreatMissingData: "missing"}
	if err := st.putAlarm(ctx, member); err != nil {
		t.Fatalf("a member account's alarm of the same name: %v", err)
	}
	member.Threshold = 10
	if err := st.putAlarm(ctx, member); err != nil {
		t.Fatalf("replacing it: %v", err)
	}
	if a, _, _ := st.getAlarm(ctx, "", "old"); a.Threshold != 5 {
		t.Errorf("the management account's alarm became %v", a.Threshold)
	}
	if a, _, _ := st.getAlarm(ctx, testMember, "old"); a.Threshold != 10 {
		t.Errorf("the member's alarm is %v", a.Threshold)
	}
	if all, _ := st.allAlarms(ctx); len(all) != 2 {
		t.Errorf("the evaluator sees %d alarms, want both accounts'", len(all))
	}
}
