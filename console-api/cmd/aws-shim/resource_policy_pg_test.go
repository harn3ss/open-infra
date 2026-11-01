package main

// Queue and topic policies against real Postgres stores (OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go): a stack's AWS::SQS::QueuePolicy is the queue's Policy, and it decides which
// topic (or rule) the shim delivers from; the SQS and SNS APIs refuse a policy they cannot honor.

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/cfn/resourcepolicy"
)

func (f *svcFixture) receiveCount(t *testing.T, queueURL string) int {
	t.Helper()
	_, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.ReceiveMessage", map[string]any{"QueueUrl": queueURL, "MaxNumberOfMessages": 10, "VisibilityTimeout": 0})
	msgs, _ := out["Messages"].([]any)
	for _, m := range msgs {
		rh, _ := m.(map[string]any)["ReceiptHandle"].(string)
		f.callJSON(t, f.sqs.serve, "AmazonSQS.DeleteMessage", map[string]any{"QueueUrl": queueURL, "ReceiptHandle": rh})
	}
	return len(msgs)
}

func TestServicesPG_QueuePolicyDecidesSNSDelivery(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	const qURL = "http://shim.test:4566/123456789012/st-q"
	must := func(y []byte) {
		t.Helper()
		if _, err := f.ap.Create(ctx, y); err != nil {
			t.Fatal(err)
		}
	}
	must(svcManifest(cfn.KindSQSQueue, "st-q", "st", map[string]any{"queueName": "st-q", "url": qURL, "attributes": map[string]any{}}))
	for _, tn := range []string{"st-a", "st-b"} {
		arn := "arn:aws:sns:us-east-1:123456789012:" + tn
		must(svcManifest(cfn.KindSNSTopic, tn, "st", map[string]any{"topicName": tn, "topicArn": arn, "attributes": map[string]any{}}))
		must(svcManifest(cfn.KindSNSSubscription, "sub-"+tn, "st", map[string]any{"protocol": "sqs", "endpoint": "arn:aws:sqs:us-east-1:123456789012:st-q", "topicArn": arn, "subscriptionArn": arn + ":sub"}))
	}
	publish := func(topic string) {
		t.Helper()
		if code, body := f.callQuery(t, url.Values{"Action": {"Publish"}, "TopicArn": {"arn:aws:sns:us-east-1:123456789012:" + topic}, "Message": {"m"}}); code != 200 {
			t.Fatalf("Publish %s = %d %s", topic, code, body)
		}
	}
	// No policy: every topic delivers (as before).
	publish("st-a")
	publish("st-b")
	if n := f.receiveCount(t, qURL); n != 2 {
		t.Fatalf("without a policy, %d of 2 delivered", n)
	}
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123456789012:st-q","Condition":{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:123456789012:st-a"}}}]}`
	qp := svcManifest(cfn.KindSQSQueuePolicy, "st-QP-X", "st", map[string]any{"queues": []any{"st-q"}, "document": doc})
	must(qp)
	_, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.GetQueueAttributes", map[string]any{"QueueUrl": qURL, "AttributeNames": []any{"Policy"}})
	if attrs, _ := out["Attributes"].(map[string]any); attrs["Policy"] != doc {
		t.Fatalf("the queue's Policy = %v", out)
	}
	publish("st-a")
	publish("st-b")
	if n := f.receiveCount(t, qURL); n != 1 {
		t.Fatalf("with the policy, %d delivered, want only the allowed topic's", n)
	}
	// An update of the queue keeps its policy; the queue's drift ignores it, the policy's reads it back.
	if err := f.ap.Apply(ctx, svcManifest(cfn.KindSQSQueue, "st-q", "st", map[string]any{"queueName": "st-q", "url": qURL, "attributes": map[string]any{"DelaySeconds": "0"}})); err != nil {
		t.Fatal(err)
	}
	if spec, _, _ := f.ap.GetSpec(ctx, cfn.ServiceAPIVersion, cfn.KindSQSQueue, "st-q"); spec["attributes"].(map[string]any)["Policy"] != nil {
		t.Errorf("the queue's spec carries its policy's document: %v", spec)
	}
	if spec, _, _ := f.ap.GetSpec(ctx, cfn.ServiceAPIVersion, cfn.KindSQSQueuePolicy, "st-QP-X"); spec["document"] != doc {
		t.Errorf("the policy's live document = %v", spec["document"])
	}
	publish("st-b")
	if n := f.receiveCount(t, qURL); n != 0 {
		t.Fatalf("after a queue update the policy no longer applies (%d delivered)", n)
	}
	// Deleting the policy removes it: every topic delivers again.
	if err := f.ap.Delete(ctx, cfn.ServiceAPIVersion, cfn.KindSQSQueuePolicy, "st-QP-X"); err != nil {
		t.Fatal(err)
	}
	_, out = f.callJSON(t, f.sqs.serve, "AmazonSQS.GetQueueAttributes", map[string]any{"QueueUrl": qURL, "AttributeNames": []any{"All"}})
	if attrs, _ := out["Attributes"].(map[string]any); attrs["Policy"] != nil {
		t.Errorf("the policy survived its delete: %v", attrs["Policy"])
	}
	publish("st-b")
	if n := f.receiveCount(t, qURL); n != 1 {
		t.Errorf("after the policy's delete, %d delivered", n)
	}
	// A caller who may not set the queue's attributes cannot apply a policy to it.
	*f.allow = false
	if _, err := f.ap.Create(ctx, qp); !cfn.IsUnauthorized(err) {
		t.Errorf("a caller without sqs:SetQueueAttributes: %v, want Unauthorized", err)
	}
}

// An EventBridge rule's delivery to a queue is decided by the queue's policy the same way.
func TestServicesPG_QueuePolicyDecidesEventBridgeDelivery(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	if code, _ := f.callJSON(t, f.sqs.serve, "AmazonSQS.CreateQueue", map[string]any{"QueueName": "events-q"}); code != 200 {
		t.Fatal("CreateQueue failed")
	}
	qURL, _, _ := f.sqs.store.queueURLByName(ctx, "events-q")
	eb := newEBHandler(nil, "authz", "default", "123456789012", "us-east-1", nil, nil, f.sqs.store, discardLogger())
	allowed := ebRule{Bus: "default", Name: "allowed"}
	other := ebRule{Bus: "default", Name: "other"}
	target := ebTarget{Type: "sqs", Arn: "arn:aws:sqs:us-east-1:123456789012:events-q"}
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:events:*:*:rule/allowed"}}}]}`
	if code, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.SetQueueAttributes", map[string]any{"QueueUrl": qURL, "Attributes": map[string]any{"Policy": doc}}); code != 200 {
		t.Fatalf("SetQueueAttributes Policy = %d %v", code, out)
	}
	if err := eb.deliver(ctx, allowed, target, []byte(`{"a":1}`)); err != nil {
		t.Fatalf("the allowed rule's delivery: %v", err)
	}
	if err := eb.deliver(ctx, other, target, []byte(`{"a":2}`)); err != errQueuePolicy {
		t.Fatalf("another rule's delivery: %v, want the queue policy refusal", err)
	}
	if n := f.receiveCount(t, qURL); n != 1 {
		t.Errorf("%d delivered, want 1", n)
	}
}

// The SQS and SNS APIs keep a policy they honor and refuse one they cannot; an empty Policy removes it.
func TestServicesPG_PolicyAttributesThroughTheAPIs(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	if code, _ := f.callJSON(t, f.sqs.serve, "AmazonSQS.CreateQueue", map[string]any{"QueueName": "api-q"}); code != 200 {
		t.Fatal("CreateQueue failed")
	}
	qURL, _, _ := f.sqs.store.queueURLByName(ctx, "api-q")
	userGrant := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/bob"},"Action":"sqs:SendMessage","Resource":"*"}]}`
	if code, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.SetQueueAttributes", map[string]any{"QueueUrl": qURL, "Attributes": map[string]any{"Policy": userGrant}}); code != 400 || !strings.Contains(out["__type"].(string), "InvalidAttributeValue") {
		t.Errorf("a user grant = %d %v, want InvalidAttributeValue", code, out)
	}
	if code, out := f.callJSON(t, f.sqs.serve, "AmazonSQS.CreateQueue", map[string]any{"QueueName": "api-q2", "Attributes": map[string]any{"Policy": userGrant}}); code != 400 {
		t.Errorf("CreateQueue with a user grant = %d %v", code, out)
	}
	good := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"*"}]}`
	if code, _ := f.callJSON(t, f.sqs.serve, "AmazonSQS.SetQueueAttributes", map[string]any{"QueueUrl": qURL, "Attributes": map[string]any{"Policy": good}}); code != 200 {
		t.Fatal("a service grant was refused")
	}
	if code, _ := f.callJSON(t, f.sqs.serve, "AmazonSQS.SetQueueAttributes", map[string]any{"QueueUrl": qURL, "Attributes": map[string]any{"Policy": ""}}); code != 200 {
		t.Fatal("removing the policy failed")
	}
	if attrs, _, _, _ := f.sqs.store.queueAttrs(ctx, qURL); attrs["Policy"] != "" {
		t.Errorf("an empty Policy left %q", attrs["Policy"])
	}

	if code, body := f.callQuery(t, url.Values{"Action": {"CreateTopic"}, "Name": {"api-t"}}); code != 200 {
		t.Fatalf("CreateTopic = %d %s", code, body)
	}
	topic := "arn:aws:sns:us-east-1:123456789012:api-t"
	set := func(doc string) (int, string) {
		return f.callQuery(t, url.Values{"Action": {"SetTopicAttributes"}, "TopicArn": {topic}, "AttributeName": {"Policy"}, "AttributeValue": {doc}})
	}
	if code, body := set(strings.ReplaceAll(userGrant, "sqs:", "sns:")); code != 400 {
		t.Errorf("a topic user grant = %d %s", code, body)
	}
	cwOnly := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sns:Publish","Resource":"*"}]}`
	if code, body := set(cwOnly); code != 200 {
		t.Fatalf("a service grant on a topic = %d %s", code, body)
	}
	if code, body := f.callQuery(t, url.Values{"Action": {"GetTopicAttributes"}, "TopicArn": {topic}}); code != 200 || !strings.Contains(body, "events.amazonaws.com") {
		t.Errorf("GetTopicAttributes = %d %s, want the Policy", code, body)
	}
	alarm := resourcepolicy.Request{Service: "cloudwatch.amazonaws.com", Action: "sns:Publish", SourceArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:a", SourceAccount: "123456789012"}
	if ok, err := f.sns.topicAccepts(ctx, topic, alarm); err != nil || ok {
		t.Errorf("an alarm may publish to a topic whose policy grants only EventBridge: %v %v", ok, err)
	}
	if code, _ := set(""); code != 200 {
		t.Fatal("removing the topic policy failed")
	}
	if ok, _ := f.sns.topicAccepts(ctx, topic, alarm); !ok {
		t.Error("with no topic policy the alarm may not publish")
	}
}
