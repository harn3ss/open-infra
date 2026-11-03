package resourcepolicy

import (
	"strings"
	"testing"
)

const (
	queueARN = "arn:aws:sqs:us-east-1:123456789012:orders"
	topicARN = "arn:aws:sns:us-east-1:123456789012:events"
)

func snsDelivery(source string) Request {
	return Request{Service: "sns.amazonaws.com", Action: "sqs:SendMessage", SourceArn: source, SourceAccount: "123456789012"}
}

// The SNS fan-out queue policy, in its common shapes, lets that topic deliver and no other.
func TestQueuePolicy_SNSFanOut(t *testing.T) {
	docs := map[string]string{
		"service principal": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},
			"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123456789012:orders",
			"Condition":{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:123456789012:events"}}}]}`,
		"every principal, narrowed to the topic": `{"Statement":{"Effect":"Allow","Principal":"*","Action":["sqs:SendMessage"],
			"Resource":"*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:sns:*:*:events"}}}}`,
		"AWS:* principal, StringEquals": `{"Statement":[{"Sid":"a","Effect":"Allow","Principal":{"AWS":"*"},"Action":"SQS:*",
			"Resource":"arn:aws:sqs:us-east-1:123456789012:orders","Condition":{"StringEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:123456789012:events"}}}]}`,
	}
	for name, doc := range docs {
		p, err := Parse(doc, queueARN)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !p.Allows(snsDelivery(topicARN)) {
			t.Errorf("%s: the topic may not deliver", name)
		}
		if p.Allows(snsDelivery("arn:aws:sns:us-east-1:123456789012:other")) {
			t.Errorf("%s: another topic may deliver", name)
		}
		if p.Allows(Request{Service: "sns.amazonaws.com", Action: "sqs:DeleteMessage", SourceArn: topicARN, SourceAccount: "123456789012"}) && !strings.Contains(doc, "SQS:*") {
			t.Errorf("%s: an action it does not grant is allowed", name)
		}
	}
}

// The topic is matched by name: the shim addresses a topic by its name whatever account or region an ARN
// names (a stack's topic ARN and the shim's own).
func TestQueuePolicy_SourceArnMatchesByName(t *testing.T) {
	p, err := Parse(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage",
		"Resource":"arn:aws:sqs:us-east-1:000000000000:orders","Condition":{"ArnEquals":{"aws:SourceArn":"arn:aws:sns:us-east-1:000000000000:events"}}}]}`, queueARN)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allows(snsDelivery(topicARN)) {
		t.Error("the same topic under another account's ARN was refused")
	}
}

// A service grant is for that service: an SNS grant does not let EventBridge deliver.
func TestQueuePolicy_ServiceMustMatch(t *testing.T) {
	p, err := Parse(`{"Statement":[{"Effect":"Allow","Principal":{"Service":["sns.amazonaws.com"]},"Action":"sqs:SendMessage","Resource":"*"}]}`, queueARN)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allows(snsDelivery(topicARN)) {
		t.Error("sns refused")
	}
	if p.Allows(Request{Service: "events.amazonaws.com", Action: "sqs:SendMessage", SourceArn: "arn:aws:events:us-east-1:123456789012:rule/r", SourceAccount: "123456789012"}) {
		t.Error("events allowed by an sns grant")
	}
}

// Deny wins; no matching Allow refuses; the delegate-to-IAM root statement is skipped.
func TestQueuePolicy_DenyAndDefault(t *testing.T) {
	p, err := Parse(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sqs:*","Resource":"*"},
		{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"*"},
		{"Effect":"Deny","Principal":"*","Action":"sqs:SendMessage","Resource":"*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:sns:*:*:blocked-*"}}}]}`, queueARN)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Statements) != 2 {
		t.Errorf("statements = %d, want the root statement skipped", len(p.Statements))
	}
	if !p.Allows(snsDelivery(topicARN)) {
		t.Error("allowed topic refused")
	}
	if p.Allows(snsDelivery("arn:aws:sns:us-east-1:123456789012:blocked-1")) {
		t.Error("a denied topic delivered")
	}
	only, _ := Parse(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"sqs:*","Resource":"*"}]}`, queueARN)
	if only.Allows(snsDelivery(topicARN)) {
		t.Error("a policy with only the account statement grants SNS nothing")
	}
}

// The SNS default-like topic policy (every principal of the account) lets an account's service publish.
func TestTopicPolicy_AccountOwner(t *testing.T) {
	p, err := Parse(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["SNS:Publish","SNS:Subscribe","SNS:GetTopicAttributes"],
		"Resource":"arn:aws:sns:us-east-1:123456789012:events","Condition":{"StringEquals":{"AWS:SourceOwner":"123456789012"}}},
		{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sns:Publish","Resource":"*"}]}`, topicARN)
	if err != nil {
		t.Fatal(err)
	}
	alarm := Request{Service: "cloudwatch.amazonaws.com", Action: "sns:Publish", SourceArn: "arn:aws:cloudwatch:us-east-1:123456789012:alarm:a", SourceAccount: "123456789012"}
	if !p.Allows(alarm) {
		t.Error("an alarm of the account may not publish")
	}
	alarm.SourceAccount = "999999999999"
	if p.Allows(alarm) {
		t.Error("another account's alarm may publish")
	}
}

// What cannot be honored refuses the whole policy.
func TestParse_Refusals(t *testing.T) {
	cases := map[string]string{
		"a user grant":          `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/bob"},"Action":"sqs:SendMessage","Resource":"*"}]}`,
		"a role grant":          `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:role/app"]},"Action":"sqs:*","Resource":"*"}]}`,
		"public":                `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":"*"}]}`,
		"another condition":     `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`,
		"an IfExists operator":  `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Resource":"*","Condition":{"ArnEqualsIfExists":{"aws:SourceArn":"x"}}}]}`,
		"another resource":      `{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123456789012:other"}]}`,
		"another service":       `{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sns:Publish","Resource":"*"}]}`,
		"NotPrincipal":          `{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":"x"},"Action":"sqs:SendMessage","Resource":"*"}]}`,
		"a Deny to the account": `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"123456789012"},"Action":"sqs:*","Resource":"*"}]}`,
		"a federated principal": `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"cognito-identity.amazonaws.com"},"Action":"sqs:*","Resource":"*"}]}`,
		"no statement":          `{"Version":"2012-10-17"}`,
		"not JSON":              `Statement: []`,
	}
	for name, doc := range cases {
		if _, err := Parse(doc, queueARN); err == nil {
			t.Errorf("%s: accepted, want a refusal", name)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		p, s string
		want bool
	}{
		{"arn:aws:sns:*:*:events", "arn:aws:sns:us-east-1:1:events", true},
		{"arn:aws:events:*:*:rule/*", "arn:aws:events:us-east-1:1:rule/bus/name", true},
		{"a?c", "abc", true},
		{"a?c", "abbc", false},
		{"*", "", true},
		{"abc", "abcd", false},
		{"*x*y", "aaxbby", true},
	} {
		if got := Glob(c.p, c.s); got != c.want {
			t.Errorf("Glob(%q, %q) = %v", c.p, c.s, got)
		}
	}
}

// One policy attached to several queues: a statement applies to the queues its Resource names, and a
// statement for another queue of the policy does not apply here (it is not refused).
func TestParse_PolicyOverSeveralQueues(t *testing.T) {
	doc := `{"Statement":[
		{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":["arn:aws:sqs:us-east-1:123456789012:orders","arn:aws:sqs:us-east-1:123456789012:other"]},
		{"Effect":"Deny","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"arn:aws:sqs:us-east-1:123456789012:other"}]}`
	p, err := Parse(doc, queueARN)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Statements) != 1 || !p.Allows(Request{Service: "sns.amazonaws.com", Action: "sqs:SendMessage"}) {
		t.Fatalf("only the statement naming this queue applies: %+v", p.Statements)
	}
	if _, err := Parse(doc, "arn:aws:sqs:us-east-1:123456789012:other"); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"arn:aws:sns:us-east-1:123456789012:t"}]}`, queueARN); err == nil {
		t.Fatal("a Resource of another service must still refuse")
	}
}
