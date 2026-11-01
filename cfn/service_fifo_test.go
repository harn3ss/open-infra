package cfn

import (
	"strings"
	"testing"
)

// With the SQS API served, a FIFO queue is a FIFO queue in that store: an unnamed one gets the .fifo
// suffix (as CloudFormation names it), and its FIFO settings are its attributes; Ref/GetAtt name it.
func TestService_FIFOQueue(t *testing.T) {
	got := buildWith(t, `
Resources:
  DLQ: { Type: AWS::SQS::Queue, Properties: { FifoQueue: true } }
  Q:
    Type: AWS::SQS::Queue
    Properties:
      FifoQueue: true
      ContentBasedDeduplication: true
      DeduplicationScope: messageGroup
      FifoThroughputLimit: perMessageGroupId
      RedrivePolicy: { deadLetterTargetArn: !GetAtt DLQ.Arn, maxReceiveCount: 2 }
  P: { Type: AWS::SSM::Parameter, Properties: { Type: String, Value: !GetAtt Q.QueueName } }
`, svcCaps, nil)
	q := got["Q"].res
	if q.Name != "st-q.fifo" || q.Spec["url"] != "http://shim.test:4566/000000000000/st-q.fifo" {
		t.Fatalf("queue = %s %v", q.Name, q.Spec["url"])
	}
	attrs, _ := q.Spec["attributes"].(map[string]any)
	for k, want := range map[string]string{"FifoQueue": "true", "ContentBasedDeduplication": "true", "DeduplicationScope": "messageGroup", "FifoThroughputLimit": "perMessageGroupId"} {
		if attrs[k] != want {
			t.Errorf("%s = %v, want %s", k, attrs[k], want)
		}
	}
	if !strings.Contains(attrs["RedrivePolicy"].(string), "st-dlq.fifo") {
		t.Errorf("RedrivePolicy = %v", attrs["RedrivePolicy"])
	}
	if got["P"].res.Spec["value"] != "st-q.fifo" {
		t.Errorf("GetAtt QueueName = %v", got["P"].res.Spec["value"])
	}
}

func TestService_FIFORefusals(t *testing.T) {
	refuses(t, `
Resources:
  DLQ: { Type: AWS::SQS::Queue }
  Q: { Type: AWS::SQS::Queue, Properties: { FifoQueue: true, RedrivePolicy: { deadLetterTargetArn: !GetAtt DLQ.Arn, maxReceiveCount: 2 } } }
`, svcCaps, "dead-letter queue of a FIFO queue")
	refuses(t, `
Resources:
  Q: { Type: AWS::SQS::Queue, Properties: { FifoQueue: true, FifoThroughputLimit: perMessageGroupId } }
`, svcCaps, "requires DeduplicationScope messageGroup")
	refuses(t, `
Resources:
  Q: { Type: AWS::SQS::Queue, Properties: { FifoQueue: true, DeduplicationScope: everything } }
`, svcCaps, "DeduplicationScope must be")
	refuses(t, `
Resources:
  Q: { Type: AWS::SQS::Queue, Properties: { FifoQueue: true } }
  T: { Type: AWS::SNS::Topic, Properties: { Subscription: [ { Protocol: sqs, Endpoint: !GetAtt Q.Arn } ] } }
`, svcCaps, "FIFO queue cannot subscribe to a standard SNS topic")
}
