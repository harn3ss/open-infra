package main

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// userPolicy is a data-plane engine with one policy for User::tester.
func userPolicy(stmts ...policyengine.Statement) *dataplaneauthz.Checker {
	return dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::tester"}, Statements: stmts}}}, nil
	}, time.Minute)
}

var testUser = iam.Claims{Sub: "tester", Groups: []string{"openinfra:powerusers", "openinfra:users"}}

// An op is authorized against the queue it acts on. Every op but CreateQueue/GetQueueUrl acts on
// QueueUrl, so a QueueName sent alongside must not redirect the check to another queue.
func TestSQS_AuthzUsesTheQueueTheOpActsOn(t *testing.T) {
	for _, tc := range []struct {
		op, body, want string
	}{
		{"DeleteQueue", `{"QueueName":"mine","QueueUrl":"http://shim/000000000000/victim"}`, "victim"},
		{"PurgeQueue", `{"QueueName":"mine","QueueUrl":"http://shim/000000000000/victim"}`, "victim"},
		{"ReceiveMessage", `{"QueueName":"mine","QueueUrl":"http://shim/000000000000/victim"}`, "victim"},
		{"SendMessage", `{"QueueName":"mine","QueueUrl":"http://shim/000000000000/victim","MessageBody":"x"}`, "victim"},
		{"CreateQueue", `{"QueueName":"jobs","QueueUrl":"http://shim/000000000000/victim"}`, "jobs"},
		{"GetQueueUrl", `{"QueueName":"jobs"}`, "jobs"},
		{"ListQueues", `{"QueueName":"jobs"}`, ""},
	} {
		if got := sqsAuthzQueue(tc.op, readJSONBody(jsonOp("AmazonSQS."+tc.op, tc.body))); got != tc.want {
			t.Errorf("%s: authz queue %q, want %q", tc.op, got, tc.want)
		}
	}

	// End to end: a policy denying DeleteQueue on the victim holds even when the request also names an
	// allowed queue.
	authz := userPolicy(dpAllow([]string{"sqs:*"}, "*"), dpDeny([]string{"sqs:DeleteQueue"}, "Queue::victim"))
	h := newSQSHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, discardLogger())
	h.authz = authz
	w := serveWith(h, jsonOp("AmazonSQS.DeleteQueue", `{"QueueName":"mine","QueueUrl":"http://shim/000000000000/victim"}`), testUser)
	if !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("DeleteQueue of the victim with a decoy QueueName must be denied: %d %s", w.Code, w.Body.String())
	}
}

// The same for SNS: the check follows the field the op acts on (Publish: TopicArn, else TargetArn).
func TestSNS_AuthzUsesTheTopicTheOpActsOn(t *testing.T) {
	arn := func(n string) string { return "arn:aws:sns:us-east-1:000000000000:" + n }
	for _, tc := range []struct {
		form url.Values
		want string
	}{
		{url.Values{"Action": {"DeleteTopic"}, "Name": {"mine"}, "TopicArn": {arn("victim")}}, "victim"},
		{url.Values{"Action": {"Publish"}, "Name": {"mine"}, "TopicArn": {arn("victim")}, "Message": {"m"}}, "victim"},
		{url.Values{"Action": {"Publish"}, "Name": {"mine"}, "TargetArn": {arn("victim")}, "Message": {"m"}}, "victim"},
		{url.Values{"Action": {"Unsubscribe"}, "Name": {"mine"}, "SubscriptionArn": {arn("victim") + ":abc"}}, "victim"},
		{url.Values{"Action": {"Subscribe"}, "Name": {"mine"}, "TopicArn": {arn("victim")}}, "victim"},
		{url.Values{"Action": {"CreateTopic"}, "Name": {"jobs"}, "TopicArn": {arn("victim")}}, "jobs"},
		{url.Values{"Action": {"ListTopics"}, "Name": {"jobs"}}, ""},
	} {
		r := formOp(tc.form)
		_ = r.ParseForm()
		if got := snsAuthzTopic(tc.form.Get("Action"), r); got != tc.want {
			t.Errorf("%s %v: authz topic %q, want %q", tc.form.Get("Action"), tc.form, got, tc.want)
		}
	}

	authz := userPolicy(dpAllow([]string{"sns:*"}, "*"), dpDeny([]string{"sns:Publish"}, "Topic::victim"))
	h := newSNSHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, nil, discardLogger())
	h.authz = authz
	for _, form := range []url.Values{
		{"Action": {"Publish"}, "Name": {"mine"}, "TopicArn": {arn("victim")}, "Message": {"m"}},
		{"Action": {"Publish"}, "TargetArn": {arn("victim")}, "Message": {"m"}},
	} {
		w := httptest.NewRecorder()
		h.serve(w, formOp(form), testUser, "req")
		if !strings.Contains(w.Body.String(), "AuthorizationError") {
			t.Errorf("Publish to the victim (%v) must be denied: %d %s", form, w.Code, w.Body.String())
		}
	}
}

// EventBridge's target ops act on Rule, so a Name sent alongside cannot redirect the check.
func TestEventBridge_TargetOpsAuthorizeTheRule(t *testing.T) {
	authz := userPolicy(dpAllow([]string{"events:*"}, "*"), dpDeny([]string{"events:PutTargets", "events:RemoveTargets"}, "Rule::victim"))
	h := newEBHandler(csWithSAR(true), "default", "default", "open-infra", "us-east-1", nil, nil, nil, discardLogger())
	h.authz = authz
	for _, op := range []string{"PutTargets", "RemoveTargets"} {
		w := serveWith(h, jsonOp("AWSEvents."+op, `{"Name":"mine","Rule":"victim","Targets":[],"Ids":[]}`), testUser)
		if !strings.Contains(w.Body.String(), "AccessDenied") {
			t.Errorf("%s on the victim rule with a decoy Name must be denied: %d %s", op, w.Code, w.Body.String())
		}
	}
}

// PutEvents is authorized on every bus its entries name, and a rule on a custom bus is <bus>/<name>: a
// grant on the default bus (or on a rule's bare name) never reaches another bus.
func TestEventBridge_AuthorizesTheBusEachEntryAndRuleIsOn(t *testing.T) {
	authz := userPolicy(
		dpAllow([]string{"events:*"}, "EventBus::default", "Rule::myrule"),
		dpDeny([]string{"events:PutEvents"}, "EventBus::payments"))
	h := newEBHandler(csWithSAR(true), "default", "default", "open-infra", "us-east-1", nil, nil, nil, discardLogger())
	h.authz = authz
	for _, body := range []string{
		`{"Entries":[{"Source":"a","DetailType":"t","Detail":"{}","EventBusName":"payments"}]}`,
		`{"Entries":[{"Source":"a","DetailType":"t","Detail":"{}"},{"Source":"a","DetailType":"t","Detail":"{}","EventBusName":"arn:aws:events:us-east-1:000000000000:event-bus/payments"}]}`,
		`{"Entries":[{"Source":"a","DetailType":"t","Detail":"{}","EventBusName":"orders"}]}`, // no grant on that bus at all
	} {
		w := serveWith(h, jsonOp("AWSEvents.PutEvents", body), testUser)
		if !strings.Contains(w.Body.String(), "AccessDenied") {
			t.Errorf("PutEvents %s must be denied: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := serveWith(h, jsonOp("AWSEvents.PutEvents", `{"Entries":[{"Source":"a","DetailType":"t","Detail":"{}"}]}`), testUser); strings.Contains(w.Body.String(), "AccessDenied") {
		t.Errorf("PutEvents to the default bus must pass authorization: %s", w.Body.String())
	}
	// A grant on Rule::myrule is the default bus's rule, not a same-named rule on another bus.
	if w := serveWith(h, jsonOp("AWSEvents.PutRule", `{"Name":"myrule","EventBusName":"payments","EventPattern":"{}"}`), testUser); !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Errorf("PutRule myrule on another bus must be denied: %d %s", w.Code, w.Body.String())
	}
	if w := serveWith(h, jsonOp("AWSEvents.PutTargets", `{"Rule":"myrule","EventBusName":"payments","Targets":[]}`), testUser); !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Errorf("PutTargets on myrule of another bus must be denied: %d %s", w.Code, w.Body.String())
	}
	if w := serveWith(h, jsonOp("AWSEvents.PutRule", `{"Name":"myrule","EventPattern":"{}"}`), testUser); strings.Contains(w.Body.String(), "AccessDenied") {
		t.Errorf("PutRule myrule on the default bus must pass authorization: %s", w.Body.String())
	}
}

// A User's per-table Deny holds for the multi-table ops as for GetItem: each table a batch, transaction
// or restore touches is checked, not only a top-level TableName (which they do not carry).
func TestDynamo_UserDenyHoldsForMultiTableOps(t *testing.T) {
	authz := userPolicy(dpAllow([]string{"dynamodb:*"}, "*"),
		dpDeny([]string{"dynamodb:BatchGetItem", "dynamodb:BatchWriteItem", "dynamodb:PutItem", "dynamodb:RestoreTableToPointInTime"}, "Table::victim"))
	h := newDynamoHandler(csWithSAR(true), "default", nil, nil, "db", discardLogger())
	h.authz = authz
	key := `{"id":{"S":"1"}}`
	for op, body := range map[string]string{
		"BatchGetItem":              `{"RequestItems":{"mine":{"Keys":[` + key + `]},"victim":{"Keys":[` + key + `]}}}`,
		"BatchWriteItem":            `{"RequestItems":{"victim":[{"PutRequest":{"Item":` + key + `}}]}}`,
		"TransactWriteItems":        `{"TransactItems":[{"Put":{"TableName":"mine","Item":` + key + `}},{"Put":{"TableName":"victim","Item":` + key + `}}]}`,
		"RestoreTableToPointInTime": `{"SourceTableName":"victim","TargetTableName":"mine-copy","UseLatestRestorableTime":true}`,
	} {
		w := serveWith(h, jsonOp("DynamoDB_20120810."+op, body), testUser)
		if w.Code != 403 {
			t.Errorf("%s touching a table the User is denied on: %d %s, want 403", op, w.Code, w.Body.String())
		}
	}
	if w := serveWith(h, jsonOp("DynamoDB_20120810.BatchGetItem", `{"RequestItems":{"mine":{"Keys":[`+key+`]}}}`), testUser); w.Code == 403 {
		t.Errorf("BatchGetItem on an allowed table must pass authorization: %s", w.Body.String())
	}
}

// RDS authorizes the snapshot an op makes or reads, not only the instance: a Deny on a snapshot holds for
// CreateDBSnapshot (and a final snapshot), RestoreDBInstanceFromDBSnapshot and DeleteDBSnapshot.
func TestRDS_SnapshotOpsAuthorizeTheSnapshot(t *testing.T) {
	authz := userPolicy(dpAllow([]string{"rds:*"}, "*"),
		dpDeny([]string{"rds:CreateDBSnapshot", "rds:RestoreDBInstanceFromDBSnapshot", "rds:DeleteDBSnapshot"}, "DBSnapshot::prod-nightly"))
	h := newRDSHandler(csWithSAR(true), nil, "default", "open-infra", "us-east-1", discardLogger())
	h.authz = authz
	for _, form := range []url.Values{
		{"Action": {"CreateDBSnapshot"}, "DBInstanceIdentifier": {"mine"}, "DBSnapshotIdentifier": {"prod-nightly"}},
		{"Action": {"RestoreDBInstanceFromDBSnapshot"}, "DBInstanceIdentifier": {"mine-copy"}, "DBSnapshotIdentifier": {"prod-nightly"}},
		{"Action": {"DeleteDBSnapshot"}, "DBSnapshotIdentifier": {"prod-nightly"}},
		{"Action": {"DeleteDBInstance"}, "DBInstanceIdentifier": {"mine"}, "FinalDBSnapshotIdentifier": {"prod-nightly"}},
	} {
		if w := serveWith(h, formOp(form), testUser); w.Code != 403 {
			t.Errorf("%v: %d %s, want 403", form, w.Code, w.Body.String())
		}
	}
	if w := serveWith(h, formOp(url.Values{"Action": {"RestoreDBInstanceFromDBSnapshot"}, "DBInstanceIdentifier": {"mine-copy"}, "DBSnapshotIdentifier": {"mine-nightly"}}), testUser); w.Code == 403 {
		t.Errorf("a restore from an allowed snapshot must pass authorization: %s", w.Body.String())
	}
}

// A list op lists every resource: a name sent with it must not scope the check to one. A role granted
// ListTables / ListStreams on one table or stream only cannot list them all by naming that one.
func TestListOps_IgnoreANameInTheBody(t *testing.T) {
	authz := roleChecker(dpAllow([]string{"dynamodb:ListTables", "kinesis:ListStreams"}, "Table::mine", "Stream::mine"))
	dh := newDynamoHandler(csWithSAR(true), "default", nil, nil, "db", discardLogger())
	dh.authz = authz
	if w := serveWith(dh, jsonOp("DynamoDB_20120810.ListTables", `{"TableName":"mine"}`), ecrRoleClaims()); w.Code != 403 {
		t.Errorf("ListTables scoped by a TableName in the body: %d %s, want 403", w.Code, w.Body.String())
	}
	kh := newKinesisHandler(csWithSAR(true), "default", "open-infra", "us-east-1", &kinesisStore{db: unreachableDB(t)}, discardLogger())
	kh.authz = authz
	if w := serveWith(kh, jsonOp("Kinesis_20131202.ListStreams", `{"StreamName":"mine"}`), ecrRoleClaims()); w.Code != 403 {
		t.Errorf("ListStreams scoped by a StreamName in the body: %d %s, want 403", w.Code, w.Body.String())
	}
}

// A User's op that names no resource is checked on <Type>::* for an explicit Deny: a Deny of ListQueues on
// every queue holds, while a governed User with no grant on "*" is not newly refused (additive).
func TestUserUnscopedOps_ExplicitDenyHolds(t *testing.T) {
	h := newSQSHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, discardLogger())
	h.authz = userPolicy(dpAllow([]string{"sqs:*"}, "*"), dpDeny([]string{"sqs:ListQueues"}, "*"))
	if w := serveWith(h, jsonOp("AmazonSQS.ListQueues", `{}`), testUser); w.Code != 403 {
		t.Errorf("ListQueues explicitly denied to the User: %d %s, want 403", w.Code, w.Body.String())
	}
	h.authz = userPolicy(dpAllow([]string{"sqs:SendMessage"}, "Queue::a"))
	if w := serveWith(h, jsonOp("AmazonSQS.ListQueues", `{}`), testUser); w.Code == 403 {
		t.Errorf("a governed User with no Deny must not be newly refused ListQueues: %s", w.Body.String())
	}
}

// DynamoDB Streams GetRecords reads the table inside its iterator (which a caller can write by hand), so
// it is authorized on that table — not on a TableName or StreamArn sent alongside.
func TestDDBStreams_GetRecordsAuthorizesTheIteratorsTable(t *testing.T) {
	authz := userPolicy(dpAllow([]string{"dynamodb:*"}, "*"), dpDeny([]string{"dynamodb:GetRecords"}, "Table::victim"))
	h := newDDBStreamsHandler(csWithSAR(true), "default", "open-infra", "us-east-1", nil, nil, discardLogger())
	h.authz = authz
	forged := encodeIterator(shardIterator{Stream: "victim", Shard: "shardId-000000000000", NextSeq: 0})
	for _, body := range []string{
		`{"ShardIterator":"` + forged + `"}`,
		`{"TableName":"mine","ShardIterator":"` + forged + `"}`,
	} {
		w := serveWith(h, jsonOp("DynamoDBStreams_20120810.GetRecords", body), testUser)
		if !strings.Contains(w.Body.String(), "AccessDenied") {
			t.Errorf("GetRecords with an iterator for the victim (%s) must be denied: %d %s", body, w.Code, w.Body.String())
		}
	}
}
