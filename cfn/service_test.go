package cfn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// svcCaps is an environment that serves SQS, SNS, SSM and KMS from its own stores.
var svcCaps = Capabilities{SQSAPI: true, SNSAPI: true, SSMAPI: true, KMSAPI: true, SQSURLBase: "http://shim.test:4566"}

const fixedKeyID = "11111111-2222-4333-8444-555555555555"

// withFixedKeyIDs makes a stack KMS key's minted id deterministic for the test.
func withFixedKeyIDs(t *testing.T) {
	t.Helper()
	old := newKeyID
	newKeyID = func() string { return fixedKeyID }
	t.Cleanup(func() { newKeyID = old })
}

func buildWith(t *testing.T, tmpl string, caps Capabilities, prior []StackResource) map[string]builtResource {
	t.Helper()
	order, err := buildManifests([]byte(tmpl), DeployOptions{StackName: "st", Namespace: "open-infra-cfn", Caps: caps, prior: prior})
	if err != nil {
		t.Fatalf("buildManifests: %v", err)
	}
	out := map[string]builtResource{}
	for _, b := range order {
		out[b.res.LogicalID] = b
	}
	return out
}

func refuses(t *testing.T, tmpl string, caps Capabilities, want string) {
	t.Helper()
	_, err := buildManifests([]byte(tmpl), DeployOptions{StackName: "st", Namespace: "open-infra-cfn", Caps: caps})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want a refusal mentioning %q, got %v", want, err)
	}
}

// With the SQS API served, a stack queue is a queue in that store, its attributes the queue's
// attributes, and a Ref/GetAtt elsewhere in the stack names it.
func TestService_SQSQueueIsAnAPIQueue(t *testing.T) {
	got := buildWith(t, `
Resources:
  DLQ: { Type: AWS::SQS::Queue }
  Q:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: 60
      MessageRetentionPeriod: 86400
      RedrivePolicy: { deadLetterTargetArn: !GetAtt DLQ.Arn, maxReceiveCount: 3 }
  P:
    Type: AWS::SSM::Parameter
    Properties: { Type: String, Value: !Join [ "|", [ !Ref Q, !GetAtt Q.Arn, !GetAtt Q.QueueName ] ] }
`, svcCaps, nil)
	q := got["Q"]
	if q.res.APIVersion != ServiceAPIVersion || q.res.Kind != KindSQSQueue || q.res.Name != "st-q" {
		t.Fatalf("queue = %s/%s %s, want %s/%s st-q", q.res.APIVersion, q.res.Kind, q.res.Name, ServiceAPIVersion, KindSQSQueue)
	}
	if url, _ := q.res.Spec["url"].(string); url != "http://shim.test:4566/000000000000/st-q" {
		t.Errorf("url = %q", url)
	}
	attrs, _ := q.res.Spec["attributes"].(map[string]any)
	if attrs["VisibilityTimeout"] != "60" || attrs["MessageRetentionPeriod"] != "86400" {
		t.Errorf("attributes = %v", attrs)
	}
	var rp map[string]any
	_ = json.Unmarshal([]byte(attrs["RedrivePolicy"].(string)), &rp)
	if rp["deadLetterTargetArn"] != "arn:aws:sqs:openinfra:000000000000:st-dlq" || rp["maxReceiveCount"] != float64(3) {
		t.Errorf("RedrivePolicy = %v", rp)
	}
	if v := got["P"].res.Spec["value"]; v != "http://shim.test:4566/000000000000/st-q|arn:aws:sqs:openinfra:000000000000:st-q|st-q" {
		t.Errorf("Ref/GetAtt of the queue resolved to %v", v)
	}
}

func TestService_SQSRefusesWhatTheAPICannotServe(t *testing.T) {
	refuses(t, `
Resources:
  Q: { Type: AWS::SQS::Queue, Properties: { FifoQueue: true } }
`, svcCaps, "FIFO queue is not served")
	refuses(t, `
Resources:
  Q: { Type: AWS::SQS::Queue, Properties: { QueueName: "bad name!" } }
`, svcCaps, "not a valid SQS queue name")
	refuses(t, `
Resources:
  Q: { Type: AWS::SQS::Queue, Properties: { RedrivePolicy: { deadLetterTargetArn: nope, maxReceiveCount: 3 } } }
`, svcCaps, "deadLetterTargetArn must resolve to an SQS queue ARN")
}

// Without the capability (the CLI), a queue keeps its kind mapping.
func TestService_CLIKeepsKindMappings(t *testing.T) {
	got := buildWith(t, `
Resources:
  Q: { Type: AWS::SQS::Queue }
  T: { Type: AWS::SNS::Topic }
  P: { Type: AWS::SSM::Parameter, Properties: { Name: /a/b, Type: String, Value: v } }
`, Capabilities{}, nil)
	for id, kind := range map[string]string{"Q": "Queue", "T": "Queue", "P": "Parameter"} {
		if got[id].res.Kind != kind || got[id].res.APIVersion != "openinfra.dev/v1" {
			t.Errorf("%s = %s/%s, want openinfra.dev/v1/%s", id, got[id].res.APIVersion, got[id].res.Kind, kind)
		}
	}
}

// A topic's inline subscriptions and a standalone one become subscriptions in the SNS store: sqs to a
// stack queue, lambda to a stack Function (delivered by the SNS front door — the Function reads no
// stream, so it gets no spec.queues).
func TestService_SNSTopicAndSubscriptions(t *testing.T) {
	got := buildWith(t, `
Resources:
  Q: { Type: AWS::SQS::Queue }
  Fn: { Type: AWS::Lambda::Function, Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" } } }
  T:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Orders
      Subscription: [ { Protocol: sqs, Endpoint: !GetAtt Q.Arn } ]
  S: { Type: AWS::SNS::Subscription, Properties: { TopicArn: !Ref T, Protocol: lambda, Endpoint: !GetAtt Fn.Arn, RawMessageDelivery: true } }
`, svcCaps, nil)
	topic := got["T"]
	if topic.res.Kind != KindSNSTopic || topic.res.Name != "st-t" || topic.res.Spec["topicArn"] != "arn:aws:sns:openinfra:000000000000:st-t" {
		t.Fatalf("topic = %s %s %v", topic.res.Kind, topic.res.Name, topic.res.Spec)
	}
	var inline *builtResource
	for id, b := range got {
		if strings.HasPrefix(id, "T/") {
			b := b
			inline = &b
		}
	}
	if inline == nil || inline.res.Kind != KindSNSSubscription || inline.res.Spec["protocol"] != "sqs" ||
		inline.res.Spec["endpoint"] != "arn:aws:sqs:openinfra:000000000000:st-q" {
		t.Fatalf("inline subscription = %+v", inline)
	}
	s := got["S"].res
	if s.Kind != KindSNSSubscription || s.Spec["protocol"] != "lambda" || s.Spec["inStack"] != true || s.Spec["raw"] != true {
		t.Fatalf("lambda subscription = %+v", s)
	}
	if fn, _ := s.Spec["function"].(string); fn == "" || !strings.HasSuffix(s.Spec["endpoint"].(string), ":function:"+fn) {
		t.Errorf("lambda endpoint %v / function %v", s.Spec["endpoint"], s.Spec["function"])
	}
	if !strings.HasPrefix(s.Spec["subscriptionArn"].(string), "arn:aws:sns:openinfra:000000000000:st-t:") {
		t.Errorf("subscriptionArn = %v", s.Spec["subscriptionArn"])
	}
	if qs, ok := got["Fn"].res.Spec["queues"]; ok {
		t.Errorf("the Function reads %v — with the SNS API served, the topic delivers to it instead", qs)
	}
}

func TestService_SNSRefusesUndeliverableProtocols(t *testing.T) {
	refuses(t, `
Resources:
  T: { Type: AWS::SNS::Topic, Properties: { Subscription: [ { Protocol: email, Endpoint: a@example.com } ] } }
`, svcCaps, `"email" SNS protocol has no delivery surface`)
	refuses(t, `
Resources:
  T: { Type: AWS::SNS::Topic }
  S: { Type: AWS::SNS::Subscription, Properties: { TopicArn: !Ref T, Protocol: sqs, Endpoint: !Ref T, FilterPolicy: { a: [ b ] } } }
`, svcCaps, "FilterPolicy")
}

// AWS::SSM::Parameter's Name is optional, as on AWS: the stack generates one, stable for the stack and
// logical id, and a Ref resolves to it.
func TestService_SSMParameterWithoutName(t *testing.T) {
	tmpl := `
Resources:
  P: { Type: AWS::SSM::Parameter, Properties: { Type: String, Value: hello } }
  Q: { Type: AWS::SSM::Parameter, Properties: { Type: String, Value: !Ref P } }
`
	a, b := buildWith(t, tmpl, svcCaps, nil), buildWith(t, tmpl, svcCaps, nil)
	name := a["P"].res.Name
	if !strings.HasPrefix(name, "st-P-") || len(name) != len("st-P-")+12 || name != b["P"].res.Name {
		t.Fatalf("generated name %q (again %q)", name, b["P"].res.Name)
	}
	if a["Q"].res.Spec["value"] != name {
		t.Errorf("Ref of the parameter = %v, want %s", a["Q"].res.Spec["value"], name)
	}
	if a["P"].res.Kind != KindSSMParameter || a["P"].res.Spec["value"] != "hello" || a["P"].res.Spec["type"] != "String" {
		t.Errorf("parameter = %+v", a["P"].res)
	}
	// An update keeps the recorded name.
	prior := []StackResource{{LogicalID: "P", APIVersion: ServiceAPIVersion, Kind: KindSSMParameter, Name: "st-P-OLDNAMEOLDNA"}}
	if got := buildWith(t, tmpl, svcCaps, prior)["P"].res.Name; got != "st-P-OLDNAMEOLDNA" {
		t.Errorf("an update renamed the parameter to %s", got)
	}
	refuses(t, `
Resources:
  P: { Type: AWS::SSM::Parameter, Properties: { Type: String, Value: v, Policies: "[{\"Type\":\"Expiration\",\"Version\":\"1.0\",\"Attributes\":{\"Timestamp\":\"2030-01-01T00:00:00Z\"}}]" } }
`, svcCaps, "parameter Policies")
}

// A stack KMS key is the volume-encryption EncryptionKey (unchanged, what an encrypted disk names) and,
// with the KMS API served, a key in that store under the id its Ref resolves to; an alias targets it.
func TestService_KMSKeyAndAlias(t *testing.T) {
	withFixedKeyIDs(t)
	tmpl := `
Resources:
  K: { Type: AWS::KMS::Key, Properties: { Description: app key, EnableKeyRotation: true, PendingWindowInDays: 7 } }
  A: { Type: AWS::KMS::Alias, Properties: { AliasName: alias/app, TargetKeyId: !Ref K } }
  P: { Type: AWS::SSM::Parameter, Properties: { Type: String, Value: !GetAtt K.Arn } }
`
	got := buildWith(t, tmpl, svcCaps, nil)
	if k := got["K"].res; k.Kind != "EncryptionKey" || k.Name != "st-k" {
		t.Fatalf("primary = %s %s, want the EncryptionKey st-k", k.Kind, k.Name)
	}
	comp, ok := got["K/"+fixedKeyID]
	if !ok || comp.res.Kind != KindKMSKey || comp.res.Spec["rotation"] != true || comp.res.Spec["pendingWindowInDays"] != 7 {
		t.Fatalf("KMS companion = %+v (present %v)", comp.res, ok)
	}
	if a := got["A"].res; a.Kind != KindKMSAlias || a.Name != "alias/app" || a.Spec["targetKeyId"] != fixedKeyID {
		t.Errorf("alias = %+v", a)
	}
	if v := got["P"].res.Spec["value"]; v != "arn:aws:kms:openinfra:000000000000:key/"+fixedKeyID {
		t.Errorf("GetAtt K.Arn = %v", v)
	}
	// An update keeps the key the stack recorded (its companion), and the alias still targets it.
	prior := []StackResource{
		{LogicalID: "K", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: "st-k"},
		{LogicalID: "K/aaaaaaaa-0000-4000-8000-000000000000", APIVersion: ServiceAPIVersion, Kind: KindKMSKey, Name: "aaaaaaaa-0000-4000-8000-000000000000"},
	}
	upd := buildWith(t, tmpl, svcCaps, prior)
	if _, ok := upd["K/aaaaaaaa-0000-4000-8000-000000000000"]; !ok {
		t.Errorf("the update did not keep the recorded key id")
	}
	if _, minted := upd["K/"+fixedKeyID]; minted {
		t.Errorf("the update created a second key")
	}
	if a := upd["A"].res; a.Spec["targetKeyId"] != "aaaaaaaa-0000-4000-8000-000000000000" {
		t.Errorf("after the update the alias targets %v", a.Spec["targetKeyId"])
	}
	refuses(t, `
Resources:
  K: { Type: AWS::KMS::Key, Properties: { KeyUsage: SIGN_VERIFY } }
`, svcCaps, "ENCRYPT_DECRYPT keys only")
	refuses(t, `
Resources:
  A: { Type: AWS::KMS::Alias, Properties: { AliasName: alias/x, TargetKeyId: k } }
`, Capabilities{}, "needs the KMS API")
}

// The engine treats a service resource like any other: created in order, deleted on teardown, kept by
// Retain.
func TestService_DeployAndDestroyThroughTheApplier(t *testing.T) {
	withFixedKeyIDs(t)
	f := &fakeApplier{}
	tmpl := []byte(`
Resources:
  Q: { Type: AWS::SQS::Queue }
  Keep: { Type: AWS::SQS::Queue, DeletionPolicy: Retain }
  T: { Type: AWS::SNS::Topic, Properties: { Subscription: [ { Protocol: sqs, Endpoint: !GetAtt Q.Arn } ] } }
`)
	opts := DeployOptions{StackName: "st", Namespace: "open-infra-cfn", Caps: svcCaps}
	if _, err := Deploy(context.Background(), tmpl, opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	applied := strings.Join(f.applied, ",")
	for _, want := range []string{"SQSQueue/st-q", "SQSQueue/st-keep", "SNSTopic/st-t", "SNSSubscription/"} {
		if !strings.Contains(applied, want) {
			t.Errorf("applied %s, missing %s", applied, want)
		}
	}
	if strings.Index(applied, "SQSQueue/st-q") > strings.Index(applied, "SNSSubscription/") {
		t.Errorf("the subscription was applied before its queue: %s", applied)
	}
	if _, err := Destroy(context.Background(), opts, f); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	deleted := strings.Join(f.deleted, ",")
	if !strings.Contains(deleted, "SQSQueue/st-q") || !strings.Contains(deleted, "SNSTopic/st-t") || !strings.Contains(deleted, "SNSSubscription/") {
		t.Errorf("deleted %s", deleted)
	}
	if strings.Contains(deleted, "SQSQueue/st-keep") {
		t.Errorf("a Retain queue was deleted: %s", deleted)
	}
}

// With the service APIs served, every property a service-backed translator accepts is used or
// reported (the fidelity guard, run with those capabilities).
func TestFidelityGuard_ServiceBackedTypes(t *testing.T) {
	withFixedKeyIDs(t)
	old := guardCaps
	guardCaps = svcCaps
	t.Cleanup(func() { guardCaps = old })
	guardCheck(t, []guardBaseline{
		yamlBaseline("AWS::SQS::Queue", `{}`, ""),
		yamlBaseline("AWS::SNS::Topic", `{}`, ""),
		yamlBaseline("AWS::SNS::Subscription", `{ TopicArn: !Ref T, Protocol: lambda, Endpoint: !GetAtt Fn.Arn }`, `
  T: { Type: AWS::SNS::Topic }
  Fn: { Type: AWS::Lambda::Function, Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" } } }`),
		yamlBaseline("AWS::SSM::Parameter", `{ Type: String, Value: v }`, ""),
		yamlBaseline("AWS::KMS::Key", `{}`, ""),
		yamlBaseline("AWS::KMS::Alias", `{ AliasName: alias/x, TargetKeyId: !Ref K }`, `
  K: { Type: AWS::KMS::Key }`),
	})
}
