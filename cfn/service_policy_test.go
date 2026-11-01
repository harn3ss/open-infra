package cfn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/resourcepolicy"
)

// The SNS fan-out template: a topic, a queue subscribed to it, and the QueuePolicy that lets the topic
// SendMessage. The policy is the queue's, with its Ref/GetAtt resolved, and it lets that topic deliver.
const fanOutTmpl = `
Resources:
  T: { Type: AWS::SNS::Topic }
  Q: { Type: AWS::SQS::Queue }
  S: { Type: AWS::SNS::Subscription, Properties: { TopicArn: !Ref T, Protocol: sqs, Endpoint: !GetAtt Q.Arn } }
  QP:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [ !Ref Q ]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: { Service: sns.amazonaws.com }
            Action: sqs:SendMessage
            Resource: !GetAtt Q.Arn
            Condition: { ArnEquals: { aws:SourceArn: !Ref T } }
  TP:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [ !Ref T ]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: { Service: cloudwatch.amazonaws.com }
            Action: sns:Publish
            Resource: !Ref T
  Out: { Type: AWS::SSM::Parameter, Properties: { Type: String, Value: !Join [ "|", [ !Ref QP, !Ref TP ] ] } }
`

func TestService_QueuePolicyIsTheQueuesPolicy(t *testing.T) {
	got := buildWith(t, fanOutTmpl, svcCaps, nil)
	qp := got["QP"].res
	if qp.APIVersion != ServiceAPIVersion || qp.Kind != KindSQSQueuePolicy || !strings.HasPrefix(qp.Name, "st-QP-") {
		t.Fatalf("queue policy = %s/%s %s", qp.APIVersion, qp.Kind, qp.Name)
	}
	if qs, _ := qp.Spec["queues"].([]any); len(qs) != 1 || qs[0] != "st-q" {
		t.Errorf("queues = %v", qp.Spec["queues"])
	}
	doc, _ := qp.Spec["document"].(string)
	var d map[string]any
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatalf("document %q: %v", doc, err)
	}
	if !strings.Contains(doc, `"arn:aws:sns:us-east-1:000000000000:st-t"`) || !strings.Contains(doc, `"arn:aws:sqs:us-east-1:000000000000:st-q"`) {
		t.Errorf("the document's Ref/GetAtt are not resolved: %s", doc)
	}
	p, err := resourcepolicy.Parse(doc, "arn:aws:sqs:us-east-1:000000000000:st-q")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allows(resourcepolicy.Request{Service: "sns.amazonaws.com", Action: "sqs:SendMessage", SourceArn: "arn:aws:sns:us-east-1:000000000000:st-t", SourceAccount: "000000000000"}) {
		t.Error("the stack's topic may not deliver")
	}
	tp := got["TP"].res
	if tp.Kind != KindSNSTopicPolicy {
		t.Fatalf("topic policy kind = %s", tp.Kind)
	}
	if ts, _ := tp.Spec["topics"].([]any); len(ts) != 1 || ts[0] != "arn:aws:sns:us-east-1:000000000000:st-t" {
		t.Errorf("topics = %v", tp.Spec["topics"])
	}
	if v := got["Out"].res.Spec["value"]; v != qp.Name+"|"+tp.Name {
		t.Errorf("Ref of the policies = %v, want their ids", v)
	}
	// The policy id is stable for the stack and logical id.
	if again := buildWith(t, fanOutTmpl, svcCaps, nil)["QP"].res.Name; again != qp.Name {
		t.Errorf("policy id changed: %s then %s", qp.Name, again)
	}
}

func TestService_ResourcePolicyRefusals(t *testing.T) {
	refuses(t, `
Resources:
  Q: { Type: AWS::SQS::Queue }
  QP:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [ !Ref Q ]
      PolicyDocument: { Statement: [ { Effect: Allow, Principal: { AWS: "arn:aws:iam::000000000000:role/app" }, Action: "sqs:*", Resource: "*" } ] }
`, svcCaps, "decided by IAM here")
	refuses(t, `
Resources:
  Q: { Type: AWS::SQS::Queue }
  QP:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [ !Ref Q ]
      PolicyDocument: { Statement: [ { Effect: Allow, Principal: "*", Action: sqs:SendMessage, Resource: "*" } ] }
`, svcCaps, "make the resource public")
	refuses(t, `
Resources:
  T: { Type: AWS::SNS::Topic }
  TP:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [ !Ref T ]
      PolicyDocument: { Statement: [ { Effect: Allow, Principal: "*", Action: sns:Publish, Resource: "*", Condition: { IpAddress: { aws:SourceIp: 10.0.0.0/8 } } } ] }
`, svcCaps, "not honored here")
	refuses(t, `
Resources:
  QP:
    Type: AWS::SQS::QueuePolicy
    Properties: { Queues: [ "http://x/0/q" ], PolicyDocument: { Statement: [ { Effect: Allow, Principal: { Service: sns.amazonaws.com }, Action: sqs:SendMessage } ] } }
`, Capabilities{}, "does not serve")
	refuses(t, `
Resources:
  QP:
    Type: AWS::SQS::QueuePolicy
    Properties: { Queues: [], PolicyDocument: { Statement: [ { Effect: Allow, Principal: { Service: sns.amazonaws.com }, Action: sqs:SendMessage } ] } }
`, svcCaps, "at least one queue")
}

// A queue named by URL outside the stack takes the policy too (the queue must exist at deploy).
func TestService_QueuePolicyOnAQueueByURL(t *testing.T) {
	got := buildWith(t, `
Resources:
  QP:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [ "https://sqs.us-east-1.amazonaws.com/000000000000/shared-q" ]
      PolicyDocument: '{"Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":"sqs:SendMessage","Resource":"*"}]}'
`, svcCaps, nil)
	if qs, _ := got["QP"].res.Spec["queues"].([]any); len(qs) != 1 || qs[0] != "shared-q" {
		t.Errorf("queues = %v", got["QP"].res.Spec["queues"])
	}
}

// A stack's Outputs resolve a queue or topic policy's Ref to its id, as recorded.
func TestOutputs_ResourcePolicyRef(t *testing.T) {
	tmpl := fanOutTmpl + "Outputs:\n  QP: { Value: !Ref QP }\n  TP: { Value: !Ref TP }\n"
	rec, err := Deploy(context.Background(), []byte(tmpl), DeployOptions{StackName: "st", Namespace: "open-infra-cfn", Caps: svcCaps}, &fakeApplier{})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	ids := map[string]string{}
	for _, r := range rec.Resources {
		ids[r.LogicalID] = r.Name
	}
	got := outputMap(rec)
	for _, k := range []string{"QP", "TP"} {
		if got[k].OutputValue == "" || got[k].OutputValue != ids[k] {
			t.Errorf("Output %s = %q, want the policy's id %q", k, got[k].OutputValue, ids[k])
		}
	}
}
