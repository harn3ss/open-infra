package main

// Deliveries the shim makes on a caller's behalf are authorized on where they deliver (real Postgres
// stores, OPENINFRA_TEST_PG_URI; see cfn_services_pg_test.go): a RedrivePolicy moves messages into its
// dead-letter queue and an sqs subscription delivers into its queue, so each needs the caller's
// sqs:SendMessage on that queue (or, for a subscription, the queue's own policy granting the topic).

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/policyengine"
)

const testAcct = "123456789012"

func (f *svcFixture) createQueue(t *testing.T, name string) string {
	t.Helper()
	code, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.CreateQueue", map[string]any{"QueueName": name})
	u, _ := out["QueueUrl"].(string)
	if code != 200 || u == "" {
		t.Fatalf("CreateQueue %s = %d %v", name, code, out)
	}
	return u
}

func redrive(dlq string) string {
	return `{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:` + testAcct + `:` + dlq + `","maxReceiveCount":"3"}`
}

func TestServicesPG_SQSRedriveNeedsSendOnTheDeadLetterQueue(t *testing.T) {
	f := newSvcFixture(t)
	src := f.createQueue(t, "jobs")
	f.createQueue(t, "victim-dlq")
	f.createQueue(t, "my-dlq")
	f.sqs.authz = policyFor("alice",
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"sqs:*"}, Resources: []string{"*"}},
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"sqs:SendMessage"}, Resources: []string{"Queue::victim-dlq"}})

	if code, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.SetQueueAttributes", map[string]any{"QueueUrl": src, "Attributes": map[string]any{"RedrivePolicy": redrive("victim-dlq")}}); code != 403 {
		t.Fatalf("SetQueueAttributes redriving into a queue the caller may not send to = %d %v, want 403", code, out)
	}
	if code, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.CreateQueue", map[string]any{"QueueName": "jobs2", "Attributes": map[string]any{"RedrivePolicy": redrive("victim-dlq")}}); code != 403 {
		t.Fatalf("CreateQueue redriving into a queue the caller may not send to = %d %v, want 403", code, out)
	}
	if code, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.SetQueueAttributes", map[string]any{"QueueUrl": src, "Attributes": map[string]any{"RedrivePolicy": redrive("my-dlq")}}); code != 200 {
		t.Fatalf("SetQueueAttributes redriving into the caller's own queue = %d %v, want 200", code, out)
	}

	// A stack queue is checked the same way.
	f.ap.door.authz = f.sqs.authz
	y := svcManifest(cfn.KindSQSQueue, "st-q", "st", map[string]any{"queueName": "st-q", "url": "http://shim.test:4566/" + testAcct + "/st-q",
		"attributes": map[string]any{"RedrivePolicy": redrive("victim-dlq")}})
	if _, err := f.ap.Create(context.Background(), y); err == nil || !strings.Contains(err.Error(), "sqs:SendMessage on Queue::victim-dlq") {
		t.Fatalf("a stack queue redriving into a queue the caller may not send to: %v, want refused", err)
	}
}

func TestServicesPG_SNSSubscribeNeedsSendOnTheQueueOrItsGrant(t *testing.T) {
	f := newSvcFixture(t)
	topic := "arn:aws:sns:us-east-1:" + testAcct + ":orders"
	if code, body := f.callQuery(t, url.Values{"Action": {"CreateTopic"}, "Name": {"orders"}}); code != 200 {
		t.Fatalf("CreateTopic = %d %s", code, body)
	}
	victim := f.createQueue(t, "victim")
	f.createQueue(t, "mine")
	f.sns.authz = policyFor("alice",
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"sns:*", "sqs:*"}, Resources: []string{"*"}},
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"sqs:SendMessage"}, Resources: []string{"Queue::victim"}})
	subscribe := func(queue string) (int, string) {
		return f.callQuery(t, url.Values{"Action": {"Subscribe"}, "TopicArn": {topic}, "Protocol": {"sqs"}, "Endpoint": {"arn:aws:sqs:us-east-1:" + testAcct + ":" + queue}})
	}
	if code, body := subscribe("victim"); code != 403 || !strings.Contains(body, "AuthorizationError") {
		t.Fatalf("Subscribe of a queue the caller may not send to = %d %s, want 403", code, body)
	}
	if code, body := subscribe("mine"); code != 200 {
		t.Fatalf("Subscribe of the caller's own queue = %d %s, want 200", code, body)
	}
	// The queue's owner grants the topic in the queue's policy: the subscription may deliver.
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:` + testAcct + `:victim","Condition":{"ArnEquals":{"aws:SourceArn":"` + topic + `"}}}]}`
	if code, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.SetQueueAttributes", map[string]any{"QueueUrl": victim, "Attributes": map[string]any{"Policy": doc}}); code != 200 {
		t.Fatalf("SetQueueAttributes Policy = %d %v", code, out)
	}
	if code, body := subscribe("victim"); code != 200 {
		t.Fatalf("Subscribe of a queue whose policy grants the topic = %d %s, want 200", code, body)
	}

	// A stack subscription is checked the same way.
	f.ap.door.authz = f.sns.authz
	f.createQueue(t, "victim2")
	y := svcManifest(cfn.KindSNSSubscription, "sub-v2", "st", map[string]any{"protocol": "sqs", "endpoint": "arn:aws:sqs:us-east-1:" + testAcct + ":victim2", "topicArn": topic, "subscriptionArn": topic + ":sub"})
	f.sns.authz = policyFor("alice",
		policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"sns:*", "sqs:*"}, Resources: []string{"*"}},
		policyengine.Statement{Effect: policyengine.Deny, Actions: []string{"sqs:SendMessage"}, Resources: []string{"Queue::victim2"}})
	f.ap.door.authz = f.sns.authz
	if _, err := f.ap.Create(context.Background(), y); err == nil || !strings.Contains(err.Error(), "not authorized to deliver to queue") {
		t.Fatalf("a stack subscription into a queue the caller may not send to: %v, want refused", err)
	}
}
