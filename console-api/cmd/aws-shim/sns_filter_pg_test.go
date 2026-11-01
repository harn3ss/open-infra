package main

// SNS filter policies against real Postgres stores (OPENINFRA_TEST_PG_URI; see cfn_services_pg_test.go).

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
)

func TestServicesPG_SNSFilterPolicy(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	if code, body := f.callQuery(t, url.Values{"Action": {"CreateTopic"}, "Name": {"orders"}}); code != 200 {
		t.Fatalf("CreateTopic = %d %s", code, body)
	}
	topic := "arn:aws:sns:us-east-1:123456789012:orders"
	queues := map[string]string{}
	for _, q := range []string{"all", "red", "paid", "raw"} {
		_, out := f.sqsCall(t, "CreateQueue", map[string]any{"QueueName": q})
		queues[q] = out["QueueUrl"].(string)
	}
	subscribe := func(q string, attrs map[string]string) (int, string) {
		v := url.Values{"Action": {"Subscribe"}, "TopicArn": {topic}, "Protocol": {"sqs"}, "Endpoint": {"arn:aws:sqs:us-east-1:123456789012:" + q}}
		i := 1
		for k, val := range attrs {
			v.Set("Attributes.entry."+itoa(i)+".key", k)
			v.Set("Attributes.entry."+itoa(i)+".value", val)
			i++
		}
		return f.callQuery(t, v)
	}
	for q, attrs := range map[string]map[string]string{
		"all":  nil,
		"red":  {"FilterPolicy": `{"color":["red"],"size":[{"numeric":[">=",10]}]}`},
		"paid": {"FilterPolicy": `{"order":{"status":["paid"]}}`, "FilterPolicyScope": "MessageBody"},
		"raw":  {"FilterPolicy": `{"color":[{"exists":true}]}`, "RawMessageDelivery": "true"},
	} {
		if code, body := subscribe(q, attrs); code != 200 {
			t.Fatalf("Subscribe %s = %d %s", q, code, body)
		}
	}
	if code, _ := subscribe("all", map[string]string{"FilterPolicy": `{"color":[{"wildcard":"r*"}]}`}); code != 400 {
		t.Error("a filter operator the shim does not apply was accepted")
	}
	if code, _ := subscribe("all", map[string]string{"FilterPolicy": `{"order":{"status":["paid"]}}`}); code != 400 {
		t.Error("a nested policy in the attributes scope was accepted")
	}

	publish := func(msg string, attrs ...[3]string) {
		t.Helper()
		v := url.Values{"Action": {"Publish"}, "TopicArn": {topic}, "Message": {msg}}
		for i, a := range attrs {
			pre := "MessageAttributes.entry." + itoa(i+1) + "."
			v.Set(pre+"Name", a[0])
			v.Set(pre+"Value.DataType", a[1])
			v.Set(pre+"Value.StringValue", a[2])
		}
		if code, body := f.callQuery(t, v); code != 200 {
			t.Fatalf("Publish %s = %d %s", msg, code, body)
		}
	}
	publish("m1", [3]string{"color", "String", "red"}, [3]string{"size", "Number", "12"})
	publish("m2", [3]string{"color", "String", "blue"}, [3]string{"size", "Number", "12"})
	publish(`{"order":{"status":"paid"}}`)
	got := map[string][]string{}
	for q, u := range queues {
		_, out := f.sqsCall(t, "ReceiveMessage", map[string]any{"QueueUrl": u, "MaxNumberOfMessages": 10, "MessageAttributeNames": []any{"All"}})
		msgs, _ := out["Messages"].([]any)
		for _, m := range msgs {
			mm := m.(map[string]any)
			body := mm["Body"].(string)
			if q != "raw" {
				var env map[string]any
				_ = json.Unmarshal([]byte(body), &env)
				body = env["Message"].(string)
				if body == "m1" {
					if ma, _ := env["MessageAttributes"].(map[string]any); ma["color"] == nil {
						t.Errorf("the %s envelope lacks the message attributes: %v", q, env)
					}
				}
			} else if mm["MD5OfMessageAttributes"] == nil || mm["MessageAttributes"] == nil {
				t.Errorf("a raw delivery did not carry the attributes as the SQS message's: %v", mm)
			}
			got[q] = append(got[q], body)
		}
	}
	want := map[string]string{"all": `m1,m2,{"order":{"status":"paid"}}`, "red": "m1", "paid": `{"order":{"status":"paid"}}`, "raw": "m1,m2"}
	for q, w := range want {
		if strings.Join(got[q], ",") != w {
			t.Errorf("queue %s got %v, want %s", q, got[q], w)
		}
	}

	// SetSubscriptionAttributes changes and removes a policy; Get reports it.
	subs, _ := f.sns.store.subscriptionsForTopic(ctx, topic)
	var allSub string
	for _, s := range subs {
		if strings.HasSuffix(s.Endpoint, ":all") {
			allSub = s.Arn
		}
	}
	set := func(name, val string) int {
		code, _ := f.callQuery(t, url.Values{"Action": {"SetSubscriptionAttributes"}, "SubscriptionArn": {allSub}, "AttributeName": {name}, "AttributeValue": {val}})
		return code
	}
	if set("FilterPolicy", `{"color":["green"]}`) != 200 {
		t.Fatal("SetSubscriptionAttributes FilterPolicy failed")
	}
	if _, body := f.callQuery(t, url.Values{"Action": {"GetSubscriptionAttributes"}, "SubscriptionArn": {allSub}}); !strings.Contains(body, "green") || !strings.Contains(body, "MessageAttributes") {
		t.Errorf("GetSubscriptionAttributes = %s", body)
	}
	if set("FilterPolicyScope", "MessageBody") != 200 {
		t.Error("a flat policy is valid in the body scope too")
	}
	if set("FilterPolicy", `{"a":[{"numeric":[">",5,"<",1]}]}`) != 400 {
		t.Error("an empty numeric range was accepted")
	}
	if set("FilterPolicy", "") != 200 {
		t.Fatal("removing the policy failed")
	}
	if s, _, _ := f.sns.store.subByArn(ctx, allSub); s.FilterPolicy != "" {
		t.Errorf("the policy survived its removal: %q", s.FilterPolicy)
	}
	// A message attribute SNS refuses.
	if code, _ := f.callQuery(t, url.Values{"Action": {"Publish"}, "TopicArn": {topic}, "Message": {"x"},
		"MessageAttributes.entry.1.Name": {"a"}, "MessageAttributes.entry.1.Value.DataType": {"Blob"}, "MessageAttributes.entry.1.Value.StringValue": {"x"}}); code != 400 {
		t.Error("an attribute with an invalid DataType was published")
	}

	// A stack's subscription keeps its filter policy.
	stackTopic := "arn:aws:sns:us-east-1:123456789012:st-t"
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindSNSTopic, "st-t", "st", map[string]any{"topicName": "st-t", "topicArn": stackTopic, "attributes": map[string]any{}})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ap.Create(ctx, svcManifest(cfn.KindSNSSubscription, "sub-red", "st", map[string]any{"protocol": "sqs", "endpoint": "arn:aws:sqs:us-east-1:123456789012:red",
		"topicArn": stackTopic, "subscriptionArn": stackTopic + ":sub-red", "filterPolicy": `{"color":["red"]}`})); err != nil {
		t.Fatal(err)
	}
	if s, ok, _ := f.sns.store.subByArn(ctx, stackTopic+":sub-red"); !ok || s.FilterPolicy != `{"color":["red"]}` {
		t.Errorf("the stack subscription = %+v", s)
	}
}
