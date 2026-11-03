package cfn

import (
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/resourcepolicy"
)

// #350 X: one AWS::SQS::QueuePolicy over several queues, each statement naming the queues it is for, is
// accepted (it was refused, "… is not this resource"); each queue honors the statements that name it, as
// on AWS. A statement naming a queue the policy is not attached to is still refused.
func TestShapes_OneQueuePolicyOverSeveralQueues(t *testing.T) {
	tmpl := `
Resources:
  T: { Type: AWS::SNS::Topic }
  A: { Type: AWS::SQS::Queue }
  B: { Type: AWS::SQS::Queue }
  QP:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [ !Ref A, !Ref B ]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: { Service: sns.amazonaws.com }
            Action: sqs:SendMessage
            Resource: [ !GetAtt A.Arn, !GetAtt B.Arn ]
            Condition: { ArnEquals: { aws:SourceArn: !Ref T } }
          - Sid: OnlyB
            Effect: Allow
            Principal: { Service: events.amazonaws.com }
            Action: sqs:SendMessage
            Resource: !GetAtt B.Arn
            Condition: { ArnEquals: { aws:SourceArn: "arn:aws:events:us-east-1:000000000000:rule/r" } }
`
	got := buildWith(t, tmpl, svcCaps, nil)
	qp := got["QP"].res
	if qs, _ := qp.Spec["queues"].([]any); len(qs) != 2 {
		t.Fatalf("queues = %v", qp.Spec["queues"])
	}
	doc, _ := qp.Spec["document"].(string)
	const arnA, arnB = "arn:aws:sqs:us-east-1:000000000000:st-a", "arn:aws:sqs:us-east-1:000000000000:st-b"
	rule := resourcepolicy.Request{Service: "events.amazonaws.com", Action: "sqs:SendMessage", SourceArn: "arn:aws:events:us-east-1:000000000000:rule/r", SourceAccount: "000000000000"}
	topic := resourcepolicy.Request{Service: "sns.amazonaws.com", Action: "sqs:SendMessage", SourceArn: "arn:aws:sns:us-east-1:000000000000:st-t", SourceAccount: "000000000000"}
	for arn, wantRule := range map[string]bool{arnA: false, arnB: true} {
		p, err := resourcepolicy.Parse(doc, arn)
		if err != nil {
			t.Fatalf("%s: %v", arn, err)
		}
		if !p.Allows(topic) {
			t.Errorf("%s: the topic may not deliver", arn)
		}
		if p.Allows(rule) != wantRule {
			t.Errorf("%s: the OnlyB statement applies = %v, want %v", arn, p.Allows(rule), wantRule)
		}
	}

	refuses(t, `
Resources:
  A: { Type: AWS::SQS::Queue }
  C: { Type: AWS::SQS::Queue }
  QP:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [ !Ref A ]
      PolicyDocument:
        Statement:
          - { Effect: Allow, Principal: { Service: sns.amazonaws.com }, Action: sqs:SendMessage, Resource: [ !GetAtt A.Arn, !GetAtt C.Arn ] }
`, svcCaps, "a queue this policy is not attached to")
}

// #350 X: a CloudWatch alarm whose Dimensions name an in-stack instance (Value: !Ref <instance>, or its
// InstanceId) is accepted (it was refused, "needs a concrete Name and Value"): the dimension is the
// instance's id, its Ref.
func TestShapes_AlarmOnAnInStackInstance(t *testing.T) {
	rs, err := buildService(t, `
Resources:
  Web: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04 } }
  Cpu:
    Type: AWS::CloudWatch::Alarm
    Properties:
      Namespace: AWS/EC2
      MetricName: CPUUtilization
      Statistic: Average
      Period: 300
      EvaluationPeriods: 2
      Threshold: 80
      ComparisonOperator: GreaterThanThreshold
      Dimensions: [ { Name: InstanceId, Value: !Ref Web } ]
  Cpu2:
    Type: AWS::CloudWatch::Alarm
    Properties:
      Namespace: AWS/EC2
      MetricName: CPUUtilization
      Statistic: Average
      EvaluationPeriods: 1
      Threshold: 80
      ComparisonOperator: GreaterThanThreshold
      Dimensions: [ { Name: InstanceId, Value: !GetAtt Web.InstanceId } ]
`, serviceCaps)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"Cpu", "Cpu2"} {
		dims, _ := rs[id].Spec["dimensions"].([]any)
		if len(dims) != 1 || dims[0].(map[string]any)["Value"] != rs["Web"].Name {
			t.Fatalf("%s: dimensions = %v, want InstanceId = %s", id, rs[id].Spec["dimensions"], rs["Web"].Name)
		}
	}
	// A Ref to something that is not an in-stack instance still refuses.
	_, err = buildService(t, `
Resources:
  Web: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04 } }
  Cpu:
    Type: AWS::CloudWatch::Alarm
    Properties:
      Namespace: AWS/EC2
      MetricName: CPUUtilization
      Statistic: Average
      EvaluationPeriods: 1
      Threshold: 80
      ComparisonOperator: GreaterThanThreshold
      Dimensions: [ { Name: InstanceId, Value: !GetAtt Web.PrivateIp } ]
`, serviceCaps)
	if err == nil || !strings.Contains(err.Error(), "needs a concrete Name and Value") {
		t.Fatalf("a dimension that resolves to nothing concrete must still refuse: %v", err)
	}
}
