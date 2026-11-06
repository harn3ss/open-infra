package main

// SNS keeps each account's topics apart (real Postgres stores, OPENINFRA_TEST_PG_URI; see
// cfn_services_pg_test.go): a member account's topics and subscriptions are its own — under its own store
// keys, with ARNs and owners naming its account, listed only for it — and deliver into its own account's
// queues and functions; another account's topic or queue is reached only across accounts, as on AWS: its
// own policy must let the caller (or the delivering topic) in.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/resourcepolicy"
)

// SNS keeps each account's topics apart, so the router marks its requests as an account-scoped door's.
func TestSNS_IsAnAccountScopedDoor(t *testing.T) {
	if !accountScopedServices["sns"] {
		t.Fatalf("accountScopedServices = %v, want sns", accountScopedServices)
	}
}

// snsAs calls the SNS front door (the query protocol) as c.
func (f *svcFixture) snsAs(t *testing.T, c doorCaller, form url.Values) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "http://shim.local:4566/", strings.NewReader(form.Encode())).WithContext(c.ctx)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.sns.serve(w, r, c.claims, "req-1")
	return w.Code, w.Body.String()
}

func topicArnOf(t *testing.T, body string) string {
	t.Helper()
	i, j := strings.Index(body, "<TopicArn>"), strings.Index(body, "</TopicArn>")
	if i < 0 || j < i {
		t.Fatalf("no TopicArn in %s", body)
	}
	return body[i+len("<TopicArn>") : j]
}

func TestServicesPG_SNSKeepsEachAccountsTopicsApart(t *testing.T) {
	f := newSvcFixture(t)
	f.withAccountPolicies(t, "legacy")
	ctx := context.Background()
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()

	_, body := f.snsAs(t, mgmt, url.Values{"Action": {"CreateTopic"}, "Name": {"alerts"}})
	mgmtTopic := topicArnOf(t, body)
	_, body = f.snsAs(t, member, url.Values{"Action": {"CreateTopic"}, "Name": {"alerts"}})
	memberTopic := topicArnOf(t, body)
	if mgmtTopic != "arn:aws:sns:us-east-1:"+testAcct+":alerts" || memberTopic != "arn:aws:sns:us-east-1:"+testMember+":alerts" {
		t.Fatalf("topic ARNs: management %s, member %s", mgmtTopic, memberTopic)
	}
	f.snsAs(t, mgmt, url.Values{"Action": {"CreateTopic"}, "Name": {"mgmt-only"}})
	// No account makes a topic (or queue) under another account's key.
	if code, body := f.snsAs(t, mgmt, url.Values{"Action": {"CreateTopic"}, "Name": {testMember + ":planted"}}); code != 400 {
		t.Errorf("CreateTopic named like a member account's key = %d %s", code, body)
	}
	if code, out := f.sqsAs(t, mgmt, "CreateQueue", map[string]any{"QueueName": testMember + ":planted"}); code != 400 {
		t.Errorf("CreateQueue named like a member account's key = %d %v", code, out)
	}
	if key, _, _ := f.sns.store.topicKeyByARN(ctx, mgmtTopic); key != "alerts" {
		t.Errorf("the management account's topic key = %q, want the bare name", key)
	}
	if key, _, _ := f.sns.store.topicKeyByARN(ctx, memberTopic); key != testMember+":alerts" {
		t.Errorf("the member account's topic key = %q", key)
	}

	// ListTopics lists the caller's account's topics alone.
	if _, body := f.snsAs(t, member, url.Values{"Action": {"ListTopics"}}); !strings.Contains(body, memberTopic) || strings.Contains(body, testAcct) {
		t.Errorf("member ListTopics = %s", body)
	}
	if _, body := f.snsAs(t, mgmt, url.Values{"Action": {"ListTopics"}}); strings.Contains(body, testMember) || !strings.Contains(body, mgmtTopic) || !strings.Contains(body, ":mgmt-only") {
		t.Errorf("management ListTopics = %s", body)
	}
	if _, body := f.snsAs(t, member, url.Values{"Action": {"GetTopicAttributes"}, "TopicArn": {memberTopic}}); !strings.Contains(body, "<value>"+testMember+"</value>") {
		t.Errorf("member GetTopicAttributes = %s, want its account as Owner", body)
	}
	// A topic is its name — within the account its ARN names: a member's ARN (another region) is its own
	// topic, and never the management account's topic of that name.
	if code, body := f.snsAs(t, member, url.Values{"Action": {"GetTopicAttributes"}, "TopicArn": {"arn:aws:sns:eu-west-1:" + testMember + ":alerts"}}); code != 200 || !strings.Contains(body, memberTopic) {
		t.Errorf("member GetTopicAttributes by another region's ARN = %d %s", code, body)
	}
	if code, body := f.snsAs(t, member, url.Values{"Action": {"GetTopicAttributes"}, "TopicArn": {"arn:aws:sns:us-east-1:" + testMember + ":mgmt-only"}}); code != 404 {
		t.Errorf("a member's ARN reached the management account's topic of that name: %d %s", code, body)
	}
	if code, body := f.snsAs(t, member, url.Values{"Action": {"Publish"}, "TopicArn": {"arn:aws:sns:us-east-1:" + testMember + ":mgmt-only"}, "Message": {"leak"}}); code != 404 {
		t.Errorf("a member published by name to the management account's topic: %d %s", code, body)
	}
	// Without a request (CloudFormation's, an alarm's), a member account's ARN names its account's topic.
	if arn, found, err := f.sns.canonicalTopicArn(ctx, "arn:aws:sns:eu-west-1:"+testMember+":mgmt-only"); err != nil || found {
		t.Errorf("canonicalTopicArn resolved a member account's ARN to %q (%v)", arn, err)
	}
	if arn, found, _ := f.sns.canonicalTopicArn(ctx, "arn:aws:sns:eu-west-1:"+testMember+":alerts"); !found || arn != memberTopic {
		t.Errorf("canonicalTopicArn of the member's ARN in another region = %q %v", arn, found)
	}
	if arn, found, _ := f.sns.canonicalTopicArn(ctx, "arn:aws:sns:eu-west-1:"+testAcct+":alerts"); !found || arn != mgmtTopic {
		t.Errorf("canonicalTopicArn of the management account's ARN in another region = %q %v", arn, found)
	}

	// Each account's subscription delivers to its own account's queue; the same-named queue of the other
	// account gets nothing.
	mgmtInbox := f.createQueueAs(t, mgmt, "inbox", nil)
	memberInbox := f.createQueueAs(t, member, "inbox", nil)
	if code, body := f.snsAs(t, member, url.Values{"Action": {"Subscribe"}, "TopicArn": {memberTopic}, "Protocol": {"sqs"},
		"Endpoint": {"arn:aws:sqs:us-east-1:" + testMember + ":inbox"}, "Attributes.entry.1.key": {"RawMessageDelivery"}, "Attributes.entry.1.value": {"true"}}); code != 200 {
		t.Fatalf("member Subscribe = %d %s", code, body)
	}
	if code, body := f.snsAs(t, member, url.Values{"Action": {"Publish"}, "TopicArn": {memberTopic}, "Message": {"member-msg"}}); code != 200 {
		t.Fatalf("member Publish = %d %s", code, body)
	}
	if got := f.drain(t, mgmt, mgmtInbox); len(got) != 0 {
		t.Errorf("the member's publish reached the management account's queue: %v", got)
	}
	if got := f.drain(t, member, memberInbox); strings.Join(got, ",") != "member-msg" {
		t.Errorf("member inbox = %v", got)
	}
	_, body = f.snsAs(t, member, url.Values{"Action": {"ListSubscriptions"}})
	if !strings.Contains(body, memberTopic+":") || !strings.Contains(body, "<Owner>"+testMember+"</Owner>") {
		t.Errorf("member ListSubscriptions = %s", body)
	}
	if _, body := f.snsAs(t, mgmt, url.Values{"Action": {"ListSubscriptions"}}); strings.Contains(body, testMember) {
		t.Errorf("management ListSubscriptions listed the member's subscription: %s", body)
	}

	// A publish without a request (an alarm's) delivers in the topic's own account.
	if _, err := f.sns.publishMessage(ctx, memberTopic, "", "from-an-alarm"); err != nil {
		t.Fatal(err)
	}
	if got := f.drain(t, member, memberInbox); strings.Join(got, ",") != "from-an-alarm" {
		t.Errorf("a background publish to the member's topic = %v", got)
	}
	alarm := resourcepolicy.Request{Service: "cloudwatch.amazonaws.com", Action: "sns:Publish", SourceArn: "arn:aws:cloudwatch:us-east-1:" + testAcct + ":alarm:a", SourceAccount: testAcct}
	if ok, err := f.sns.topicAccepts(ctx, memberTopic, alarm); err != nil || ok {
		t.Errorf("another account's alarm may publish to a member's topic with no policy: %v %v", ok, err)
	}
	if ok, err := f.sns.topicAccepts(ctx, mgmtTopic, alarm); err != nil || !ok {
		t.Errorf("the management account's alarm may not publish to its own topic: %v %v", ok, err)
	}

	// Across accounts: the management account's topic cannot be subscribed to a member's queue without
	// that queue's policy, nor published to by the member without the topic's.
	subscribeMemberInbox := func() (int, string) {
		return f.snsAs(t, mgmt, url.Values{"Action": {"Subscribe"}, "TopicArn": {mgmtTopic}, "Protocol": {"sqs"},
			"Endpoint": {"arn:aws:sqs:us-east-1:" + testMember + ":inbox"}, "Attributes.entry.1.key": {"RawMessageDelivery"}, "Attributes.entry.1.value": {"true"}})
	}
	if code, body := subscribeMemberInbox(); code != 403 {
		t.Errorf("the management account subscribed a member's queue without its policy: %d %s", code, body)
	}
	if code, body := f.snsAs(t, member, url.Values{"Action": {"Publish"}, "TopicArn": {mgmtTopic}, "Message": {"x"}}); code != 403 {
		t.Errorf("a member published to the management account's topic without its policy: %d %s", code, body)
	}
	// The member's queue policy granting the management account's topic: subscribed, and delivered.
	grant := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:` + testMember +
		`:inbox","Condition":{"ArnEquals":{"aws:SourceArn":"` + mgmtTopic + `"}}}]}`
	if code, out := f.sqsAs(t, member, "SetQueueAttributes", map[string]any{"QueueUrl": memberInbox, "Attributes": map[string]any{"Policy": grant}}); code != 200 {
		t.Fatalf("member SetQueueAttributes Policy = %d %v", code, out)
	}
	if code, body := subscribeMemberInbox(); code != 200 {
		t.Fatalf("Subscribe the member's queue its policy grants = %d %s", code, body)
	}
	if code, body := f.snsAs(t, mgmt, url.Values{"Action": {"Publish"}, "TopicArn": {mgmtTopic}, "Message": {"across"}}); code != 200 {
		t.Fatalf("management Publish = %d %s", code, body)
	}
	if got := f.drain(t, member, memberInbox); strings.Join(got, ",") != "across" {
		t.Errorf("the member's queue = %v, want the cross-account delivery its policy grants", got)
	}
	if got := f.drain(t, mgmt, mgmtInbox); len(got) != 0 {
		t.Errorf("the management account's queue of the same name got %v", got)
	}
	// Without the policy, another account's topic delivers nothing (a queue with no policy takes only its
	// own account's deliveries).
	if code, out := f.sqsAs(t, member, "SetQueueAttributes", map[string]any{"QueueUrl": memberInbox, "Attributes": map[string]any{"Policy": ""}}); code != 200 {
		t.Fatalf("removing the policy = %d %v", code, out)
	}
	f.snsAs(t, mgmt, url.Values{"Action": {"Publish"}, "TopicArn": {mgmtTopic}, "Message": {"refused"}})
	if got := f.drain(t, member, memberInbox); len(got) != 0 {
		t.Errorf("another account's topic delivered into a queue with no policy: %v", got)
	}

	// The member deleting its topic leaves the management account's of the same name.
	if code, body := f.snsAs(t, member, url.Values{"Action": {"DeleteTopic"}, "TopicArn": {memberTopic}}); code != 200 {
		t.Fatalf("member DeleteTopic = %d %s", code, body)
	}
	if ok, _ := f.sns.store.topicExists(ctx, mgmtTopic); !ok {
		t.Error("deleting the member's topic deleted the management account's")
	}
}

// A member account's lambda subscription delivers to its own account's Function, in its home; one naming
// another account's function is refused (its function policy is not honored here).
func TestServicesPG_SNSLambdaSubscriptionInTheMembersHome(t *testing.T) {
	f := newSvcFixture(t)
	f.withAccountPolicies(t, "legacy")
	member := memberDoorCaller()
	_, body := f.snsAs(t, member, url.Values{"Action": {"CreateTopic"}, "Name": {"events"}})
	topic := topicArnOf(t, body)
	if code, body := f.snsAs(t, member, url.Values{"Action": {"Subscribe"}, "TopicArn": {topic}, "Protocol": {"lambda"},
		"Endpoint": {"arn:aws:lambda:us-east-1:" + testAcct + ":function:handler"}}); code != 400 {
		t.Errorf("a member subscribed another account's function: %d %s", code, body)
	}
	if code, body := f.snsAs(t, member, url.Values{"Action": {"Subscribe"}, "TopicArn": {topic}, "Protocol": {"lambda"},
		"Endpoint": {"arn:aws:lambda:us-east-1:" + testMember + ":function:handler"}}); code != 200 {
		t.Fatalf("member lambda Subscribe = %d %s", code, body)
	}
	if code, body := f.snsAs(t, member, url.Values{"Action": {"Publish"}, "TopicArn": {topic}, "Message": {"hi"}}); code != 200 {
		t.Fatalf("Publish = %d %s", code, body)
	}
	f.fn.waitFor(t, 1)
	f.fn.mu.Lock()
	host := f.fn.hosts[0]
	f.fn.mu.Unlock()
	if host != "handler."+memberHome+".svc.test" {
		t.Errorf("the member's lambda delivery went to %s, want its home's Function", host)
	}

	// The management account's topic: a member account's function ARN is that account's function, never
	// the management account's of that name; any other account id still means its own, as before.
	mgmt := mgmtDoorCaller()
	_, body = f.snsAs(t, mgmt, url.Values{"Action": {"CreateTopic"}, "Name": {"events"}})
	mgmtTopic := topicArnOf(t, body)
	if code, body := f.snsAs(t, mgmt, url.Values{"Action": {"Subscribe"}, "TopicArn": {mgmtTopic}, "Protocol": {"lambda"},
		"Endpoint": {"arn:aws:lambda:us-east-1:" + testMember + ":function:handler"}}); code != 400 {
		t.Errorf("the management account subscribed a member account's function: %d %s", code, body)
	}
	if code, body := f.snsAs(t, mgmt, url.Values{"Action": {"Subscribe"}, "TopicArn": {mgmtTopic}, "Protocol": {"lambda"},
		"Endpoint": {"arn:aws:lambda:us-east-1:555555555555:function:handler"}}); code != 200 {
		t.Errorf("the management account's lambda Subscribe naming another account id = %d %s, want its own function as before", code, body)
	}
}
