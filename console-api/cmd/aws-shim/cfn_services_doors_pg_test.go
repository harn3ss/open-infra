package main

// End to end against REAL Postgres stores and the real front doors (as cfn_services_pg_test.go): a
// stack's EventBridge rule targets the stack's own queue, and its alarm fires the stack's own topic, now
// that both are in the SQS and SNS stores. Run with OPENINFRA_TEST_PG_URI (skipped without it).

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

const doorsMessagingStack = `
Resources:
  Jobs:    { Type: AWS::SQS::Queue, Properties: { QueueName: jobs } }
  Pager:   { Type: AWS::SQS::Queue, Properties: { QueueName: pager } }
  Alerts:  { Type: AWS::SNS::Topic, Properties: { TopicName: alerts } }
  Page:    { Type: AWS::SNS::Subscription, Properties: { TopicArn: !Ref Alerts, Protocol: sqs, Endpoint: !GetAtt Pager.Arn, RawMessageDelivery: true } }
  OnOrder:
    Type: AWS::Events::Rule
    Properties:
      EventPattern: { source: [ app.orders ] }
      Targets: [ { Id: jobs, Arn: !GetAtt Jobs.Arn } ]
  Hot:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: app-hot
      Namespace: App
      MetricName: Errors
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanThreshold
      AlarmActions: [ !Ref Alerts ]
Outputs:
  JobsUrl:  { Value: !Ref Jobs }
  PagerUrl: { Value: !Ref Pager }
  RuleArn:  { Value: !GetAtt OnOrder.Arn }
  AlarmArn: { Value: !GetAtt Hot.Arn }
`

func TestServicesPG_RuleTargetsAndAlarmActionsInTheStack(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	db := f.sqs.store.db
	ebSt, cwSt := &ebStore{db: db}, &cwStore{db: db}
	for _, ensure := range []func(context.Context) error{ebSt.ensureSchema, cwSt.ensureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// The front doors report ARNs in the install's identity, as the stack builds them.
	ident := awsidentity.Current()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cs := f.ap.door.cs
	ebH := newEBHandler(cs, "authz", "default", ident.AccountID, ident.Region, ebSt, nil, f.sqs.store, logger)
	cwH := newCWHandler(cs, "authz", ident.AccountID, ident.Region, cwSt, f.sns, logger)
	f.ap.svc.doors = map[string]awsService{"events": ebH, "monitoring": cwH}

	// The engine's applier over a stack-record client, with the fixture's stores, caller and checks.
	_, ap := cfnTestDoorway(t, "")
	ap.svc, ap.door, ap.user, ap.groups, ap.claims = f.ap.svc, f.ap.door, f.ap.user, f.ap.groups, &f.claims
	opts := cfn.DeployOptions{StackName: "app", Namespace: "open-infra-cfn", Wait: true, Timeout: 10 * time.Second,
		Caps: cfn.Capabilities{SQSAPI: true, SNSAPI: true, EventsAPI: true, CloudWatchAPI: true, SQSURLBase: "http://shim.test:4566"}}
	rec, err := cfn.Deploy(ctx, []byte(doorsMessagingStack), opts, ap)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	out := map[string]string{}
	for _, o := range rec.Outputs {
		out[o.OutputKey] = o.OutputValue
	}
	c := ap.svcCtx("")

	// The rule and the alarm are the ones the stack reports, by ARN.
	if d, err := c.call(ctx, "events", "DescribeRule", map[string]any{"Name": rec.Resources[indexOf(rec, "OnOrder")].Name}); err != nil || d["Arn"] != out["RuleArn"] {
		t.Fatalf("DescribeRule = %v (%v), want the stack's RuleArn %s", d, err, out["RuleArn"])
	}
	if d, err := c.call(ctx, "monitoring", "DescribeAlarms", map[string]any{"AlarmNames": []any{"app-hot"}}); err != nil || !strings.Contains(mustJSON(d), out["AlarmArn"]) {
		t.Fatalf("DescribeAlarms = %v (%v), want the stack's AlarmArn %s", d, err, out["AlarmArn"])
	}

	// An event matching the rule lands in the stack's queue.
	if _, err := c.call(ctx, "events", "PutEvents", map[string]any{"Entries": []any{map[string]any{
		"Source": "app.orders", "DetailType": "OrderPlaced", "Detail": `{"id":"o-1"}`}}}); err != nil {
		t.Fatalf("PutEvents: %v", err)
	}
	if body := receiveOne(t, f, out["JobsUrl"]); !strings.Contains(body, `"o-1"`) {
		t.Fatalf("the rule's queue got %q, want the event", body)
	}

	// A breaching datapoint puts the alarm in ALARM; it publishes to the stack's topic, which delivers to
	// the queue subscribed to it.
	if _, err := c.call(ctx, "monitoring", "PutMetricData", map[string]any{"Namespace": "App", "MetricData": []any{
		map[string]any{"MetricName": "Errors", "Value": 5}}}); err != nil {
		t.Fatalf("PutMetricData: %v", err)
	}
	cwH.evaluateAll(ctx)
	if body := receiveOne(t, f, out["PagerUrl"]); !strings.Contains(body, `"AlarmName":"app-hot"`) || !strings.Contains(body, `"NewStateValue":"ALARM"`) {
		t.Fatalf("the topic's queue got %q, want the ALARM notification", body)
	}

	// The stack's delete removes the rule and the alarm, and their ownership records.
	if _, err := cfn.Destroy(ctx, opts, ap); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := c.call(ctx, "events", "DescribeRule", map[string]any{"Name": rec.Resources[indexOf(rec, "OnOrder")].Name}); !isCode(err, "ResourceNotFoundException") {
		t.Fatalf("the rule outlived its stack: %v", err)
	}
	if d, _ := c.call(ctx, "monitoring", "DescribeAlarms", map[string]any{"AlarmNames": []any{"app-hot"}}); strings.Contains(mustJSON(d), "app-hot") {
		t.Fatalf("the alarm outlived its stack: %v", d)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM cfn_service_resources`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("ownership records left: %d (%v)", n, err)
	}
}

const doorsSecretStack = `
Resources:
  Db:   { Type: AWS::SecretsManager::Secret, Properties: { Name: app/db, Description: db, SecretString: %VALUE% } }
  Gen:
    Type: AWS::SecretsManager::Secret
    Properties: { GenerateSecretString: { SecretStringTemplate: '{"user":"app"}', GenerateStringKey: password, PasswordLength: 24, ExcludePunctuation: true } }
  Logs: { Type: AWS::Logs::LogGroup, Properties: { LogGroupName: /app/web, %RETENTION% } }
Outputs:
  DbArn:  { Value: !Ref Db }
  GenArn: { Value: !Ref Gen }
`

// A stack's secrets are read through Secrets Manager by the ARN the stack reports (a generated one with
// the template filled in), an update writes a new value as a new version without regenerating the other,
// a log group's retention follows the template both ways, and the stack's delete removes them all.
func TestServicesPG_SecretAndLogGroup(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	db := f.sqs.store.db
	smSt, cwlSt := &secretsStore{db: db}, &cwlStore{db: db}
	for _, ensure := range []func(context.Context) error{smSt.ensureSchema, cwlSt.ensureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	ident := awsidentity.Current()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cs := f.ap.door.cs
	smH := newSecretsHandler(cs, "authz", ident.AccountID, ident.Region, fakeVault(t), smSt, logger)
	cwlH := newCWLHandler(cs, "authz", ident.AccountID, ident.Region, cwlSt, logger)
	f.ap.svc.doors = map[string]awsService{"secretsmanager": smH, "logs": cwlH}
	_, ap := cfnTestDoorway(t, "")
	ap.svc, ap.door, ap.user, ap.groups, ap.claims = f.ap.svc, f.ap.door, f.ap.user, f.ap.groups, &f.claims
	opts := cfn.DeployOptions{StackName: "app", Namespace: "open-infra-cfn", Wait: true, Timeout: 10 * time.Second,
		Caps: cfn.Capabilities{SecretsManagerAPI: true, LogsAPI: true}}
	tmpl := func(value, retention string) []byte {
		return []byte(strings.NewReplacer("%VALUE%", value, "%RETENTION%", retention).Replace(doorsSecretStack))
	}
	c := ap.svcCtx("")
	value := func(arn string) string {
		t.Helper()
		out, err := c.call(ctx, "secretsmanager", "GetSecretValue", map[string]any{"SecretId": arn})
		if err != nil {
			t.Fatalf("GetSecretValue %s: %v", arn, err)
		}
		if out["ARN"] != arn {
			t.Fatalf("GetSecretValue answered for %v, want %s", out["ARN"], arn)
		}
		s, _ := out["SecretString"].(string)
		return s
	}
	retention := func() any {
		out, err := c.call(ctx, "logs", "DescribeLogGroups", map[string]any{"logGroupNamePrefix": "/app/web"})
		if err != nil {
			t.Fatal(err)
		}
		gs, _ := out["logGroups"].([]any)
		if len(gs) != 1 {
			t.Fatalf("log groups = %v", out)
		}
		return gs[0].(map[string]any)["retentionInDays"]
	}

	rec, err := cfn.Deploy(ctx, tmpl("one", "RetentionInDays: 7"), opts, ap)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	out := map[string]string{}
	for _, o := range rec.Outputs {
		out[o.OutputKey] = o.OutputValue
	}
	if v := value(out["DbArn"]); v != "one" {
		t.Fatalf("secret value %q, want one", v)
	}
	var gen map[string]string
	if err := json.Unmarshal([]byte(value(out["GenArn"])), &gen); err != nil || gen["user"] != "app" || len(gen["password"]) != 24 {
		t.Fatalf("generated secret = %v (%v), want the template with a 24-character password", gen, err)
	}
	if r := retention(); r != float64(7) {
		t.Fatalf("retention = %v, want 7", r)
	}

	if _, err := cfn.Update(ctx, tmpl("two", "Tags: [ { Key: team, Value: web } ]"), opts, ap); err != nil {
		t.Fatalf("update: %v", err)
	}
	if v := value(out["DbArn"]); v != "two" {
		t.Fatalf("after the update the secret is %q, want two", v)
	}
	var gen2 map[string]string
	_ = json.Unmarshal([]byte(value(out["GenArn"])), &gen2)
	if gen2["password"] != gen["password"] {
		t.Fatal("an update regenerated the generated secret")
	}
	if r := retention(); r != nil {
		t.Fatalf("retention = %v after RetentionInDays was removed, want none (kept forever)", r)
	}

	if _, err := cfn.Destroy(ctx, opts, ap); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := c.call(ctx, "secretsmanager", "DescribeSecret", map[string]any{"SecretId": out["DbArn"]}); !isCode(err, "ResourceNotFoundException") {
		t.Fatalf("the secret outlived its stack: %v", err)
	}
	if out, _ := c.call(ctx, "logs", "DescribeLogGroups", map[string]any{"logGroupNamePrefix": "/app/web"}); len(sliceOf(out["logGroups"])) != 0 {
		t.Fatalf("the log group outlived its stack: %v", out)
	}
}

func indexOf(rec *cfn.StackRecord, id string) int {
	for i, r := range rec.Resources {
		if r.LogicalID == id {
			return i
		}
	}
	return -1
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// receiveOne reads one message from a queue through the SQS front door, waiting briefly for it.
func receiveOne(t *testing.T, f *svcFixture, url string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.ReceiveMessage", map[string]any{"QueueUrl": url, "MaxNumberOfMessages": 1})
		if msgs, _ := out["Messages"].([]any); len(msgs) > 0 {
			m, _ := msgs[0].(map[string]any)
			s, _ := m["Body"].(string)
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("no message on %s (last answer %v)", url, out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
