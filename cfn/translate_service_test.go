package cfn

import (
	"fmt"
	"strings"
	"testing"
)

var serviceCaps = Capabilities{SecretsManagerAPI: true, LogsAPI: true, EventsAPI: true, ECRAPI: true, CloudWatchAPI: true,
	ECRRepositoryHost: "registry.site"}

// serviceStoreBaselines are the fidelity-guard baselines of the service-store types. They translate only
// with their APIs served, so TestFidelityGuard_ServiceStoreTypes runs them with those capabilities.
var serviceStoreBaselines = []guardBaseline{
	yamlBaseline("AWS::SecretsManager::Secret", `{ SecretString: s }`, ""),
	yamlBaseline("AWS::SecretsManager::Secret", `{ GenerateSecretString: { PasswordLength: 20 } }`, ""),
	yamlBaseline("AWS::Logs::LogGroup", `{}`, ""),
	yamlBaseline("AWS::Events::Rule", `{ ScheduleExpression: "rate(5 minutes)", Targets: [ { Id: t, Arn: !GetAtt F.Arn } ] }`, "\n  F: { Type: AWS::Lambda::Function, Properties: { PackageType: Image, Code: { ImageUri: \"registry.example/fn:1\" } } }"),
	yamlBaseline("AWS::Events::EventBus", `{ Name: b }`, ""),
	yamlBaseline("AWS::ECR::Repository", `{}`, ""),
	yamlBaseline("AWS::CloudWatch::Alarm", `{ Namespace: N, MetricName: M, ComparisonOperator: GreaterThanThreshold, EvaluationPeriods: 1, Threshold: 1, Statistic: Sum }`, ""),
}

// With their APIs served, every property a service-store translator accepts is used or reported.
func TestFidelityGuard_ServiceStoreTypes(t *testing.T) {
	old := guardCaps
	guardCaps = serviceCaps
	t.Cleanup(func() { guardCaps = old })
	guardCheck(t, serviceStoreBaselines)
}

// buildService translates a template the way a front-door deploy does (service stores available).
func buildService(t *testing.T, tmpl string, caps Capabilities) (map[string]StackResource, error) {
	t.Helper()
	order, err := buildManifests([]byte(tmpl), DeployOptions{StackName: "app", Namespace: "open-infra-cfn", Caps: caps})
	if err != nil {
		return nil, err
	}
	out := map[string]StackResource{}
	for _, b := range order {
		out[b.res.LogicalID] = b.res
	}
	return out, nil
}

// The cfn CLI has no service stores: each service type refuses there, naming the front door.
func TestServiceResources_RefuseWithoutTheFrontDoor(t *testing.T) {
	_, err := buildService(t, `
Resources:
  S: { Type: AWS::SecretsManager::Secret, Properties: { SecretString: x } }
`, Capabilities{})
	if err == nil || !strings.Contains(err.Error(), "aws-shim CloudFormation front door") {
		t.Fatalf("want a refusal naming the front door, got %v", err)
	}
}

// Ref and Fn::GetAtt of each service type resolve before deploy, from the name and the stack's own
// partition, region and account — so a dependent (here a Lambda environment) carries the real value.
func TestServiceResources_RefAndGetAttResolveStatically(t *testing.T) {
	rs, err := buildService(t, `
Resources:
  Db: { Type: AWS::SecretsManager::Secret, Properties: { Name: app/db, GenerateSecretString: { PasswordLength: 24 } } }
  Logs: { Type: AWS::Logs::LogGroup, Properties: { LogGroupName: /app/web, RetentionInDays: 14 } }
  Bus: { Type: AWS::Events::EventBus, Properties: { Name: orders } }
  Tick:
    Type: AWS::Events::Rule
    Properties: { EventBusName: !Ref Bus, EventPattern: { source: [ app ] }, Targets: [ { Id: fn, Arn: !GetAtt Fn.Arn } ] }
  Repo: { Type: AWS::ECR::Repository, Properties: { RepositoryName: web } }
  Hot: { Type: AWS::CloudWatch::Alarm, Properties: { Namespace: App, MetricName: Errors, Statistic: Sum, Period: 60, EvaluationPeriods: 1, Threshold: 5, ComparisonOperator: GreaterThanThreshold } }
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: Image
      Code: { ImageUri: !Sub "${Repo.RepositoryUri}:1" }
      Environment:
        Variables:
          SECRET: !Ref Db
          SECRET_ID: !GetAtt Db.Id
          GROUP: !Ref Logs
          GROUP_ARN: !GetAtt Logs.Arn
          BUS_ARN: !GetAtt Bus.Arn
          REPO_ARN: !GetAtt Repo.Arn
          ALARM_ARN: !GetAtt Hot.Arn
  Reader:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: Image
      Code: { ImageUri: "r/reader:1" }
      Environment: { Variables: { RULE: !Ref Tick, RULE_ARN: !GetAtt Tick.Arn } }
`, serviceCaps)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, fn := range []string{"Fn", "Reader"} {
		switch e := rs[fn].Spec["env"].(type) {
		case map[string]any:
			for k, v := range e {
				got[k], _ = v.(string)
			}
		case []any:
			for _, x := range e {
				m, _ := x.(map[string]any)
				got[m["name"].(string)], _ = m["value"].(string)
			}
		}
	}
	secret := rs["Db"].Spec["arn"].(string)
	pseudo := pseudoParams("app") // the install's region and account, as the stack's ARNs carry them
	ra := pseudo["AWS::Region"].(string) + ":" + pseudo["AWS::AccountId"].(string)
	want := map[string]string{
		"SECRET": secret, "SECRET_ID": secret,
		"GROUP": "/app/web", "GROUP_ARN": "arn:aws:logs:" + ra + ":log-group:/app/web:*",
		"RULE": "orders|" + rs["Tick"].Name, "RULE_ARN": "arn:aws:events:" + ra + ":rule/orders/" + rs["Tick"].Name,
		"BUS_ARN":   "arn:aws:events:" + ra + ":event-bus/orders",
		"REPO_ARN":  "arn:aws:ecr:" + ra + ":repository/web",
		"ALARM_ARN": "arn:aws:cloudwatch:" + ra + ":alarm:" + rs["Hot"].Name,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if !strings.HasPrefix(secret, "arn:aws:secretsmanager:"+ra+":secret:app/db-") || len(secret) != len("arn:aws:secretsmanager:"+ra+":secret:app/db-")+6 {
		t.Errorf("secret ARN %q is not <prefix>:secret:<name>-XXXXXX", secret)
	}
	if img := rs["Fn"].Spec["image"]; img != "registry.site/web:1" {
		t.Errorf("image = %v, want the repository URI", img)
	}
	// The rule's in-stack Function target names the function, so the front door invokes it in the stack.
	tg, _ := rs["Tick"].Spec["targets"].([]any)
	if len(tg) != 1 || tg[0].(map[string]any)["function"] != rs["Fn"].Name {
		t.Errorf("targets = %v, want the in-stack function %s", tg, rs["Fn"].Name)
	}
	if rs["Tick"].Spec["eventBusName"] != "orders" || !strings.Contains(rs["Tick"].Spec["eventPattern"].(string), `"source"`) {
		t.Errorf("rule spec = %v", rs["Tick"].Spec)
	}
	if rs["Db"].Spec["generateSecretString"].(map[string]any)["PasswordLength"] != 24 {
		t.Errorf("generate spec = %v", rs["Db"].Spec["generateSecretString"])
	}
	// The same stack translated again gives the same secret ARN (an update re-creates nothing).
	again, _ := buildService(t, `
Resources:
  Db: { Type: AWS::SecretsManager::Secret, Properties: { Name: app/db, GenerateSecretString: { PasswordLength: 24 } } }
`, serviceCaps)
	if again["Db"].Spec["arn"] != secret {
		t.Errorf("secret ARN not stable: %v vs %v", again["Db"].Spec["arn"], secret)
	}
}

// What the front doors cannot do refuses rather than being dropped.
func TestServiceResources_Refusals(t *testing.T) {
	for name, c := range map[string]struct{ tmpl, want string }{
		"secret both values": {`S: { Type: AWS::SecretsManager::Secret, Properties: { SecretString: a, GenerateSecretString: {} } }`, "cannot both be set"},
		"secret custom key":  {`S: { Type: AWS::SecretsManager::Secret, Properties: { SecretString: a, KmsKeyId: alias/mine } }`, "default managed key"},
		"secret replica":     {`S: { Type: AWS::SecretsManager::Secret, Properties: { SecretString: a, ReplicaRegions: [ { Region: us-west-2 } ] } }`, "one region"},
		"secret empty":       {`S: { Type: AWS::SecretsManager::Secret, Properties: {} }`, "empty secret"},
		"log kms":            {`L: { Type: AWS::Logs::LogGroup, Properties: { KmsKeyId: k } }`, "no per-group encryption"},
		"log retention":      {`L: { Type: AWS::Logs::LogGroup, Properties: { RetentionInDays: 2 } }`, "RetentionInDays 2"},
		"rule no source":     {`R: { Type: AWS::Events::Rule, Properties: { State: ENABLED } }`, "ScheduleExpression or an EventPattern"},
		"rule sns target":    {`R: { Type: AWS::Events::Rule, Properties: { ScheduleExpression: "rate(1 hour)", Targets: [ { Id: t, Arn: "arn:aws:sns:x:1:t" } ] } }`, "Lambda function or an SQS queue"},
		"rule transformer":   {`R: { Type: AWS::Events::Rule, Properties: { ScheduleExpression: "rate(1 hour)", Targets: [ { Id: t, Arn: "arn:aws:lambda:x:1:function:f", InputTransformer: { InputTemplate: x } } ] } }`, "InputTransformer"},
		"rule ecs params":    {`R: { Type: AWS::Events::Rule, Properties: { ScheduleExpression: "rate(1 hour)", Targets: [ { Id: t, Arn: "arn:aws:lambda:x:1:function:f", EcsParameters: { TaskDefinitionArn: x } } ] } }`, "EcsParameters is not translatable"},
		"rule stack queue": {`R: { Type: AWS::Events::Rule, Properties: { ScheduleExpression: "rate(1 hour)", Targets: [ { Id: t, Arn: !GetAtt Q.Arn } ] } }
  Q: { Type: AWS::SQS::Queue }`, "not a queue of the SQS API"},
		"repo kms":         {`E: { Type: AWS::ECR::Repository, Properties: { EncryptionConfiguration: { EncryptionType: KMS } } }`, "per-repository key"},
		"repo aes256":      {`E: { Type: AWS::ECR::Repository, Properties: { EncryptionConfiguration: { EncryptionType: AES256 } } }`, "does not encrypt object storage"},
		"repo deny policy": {`E: { Type: AWS::ECR::Repository, Properties: { RepositoryPolicyText: { Statement: [ { Effect: Deny, Principal: "*", Action: "ecr:*" } ] } } }`, "Deny"},
		"alarm math":       {`A: { Type: AWS::CloudWatch::Alarm, Properties: { ComparisonOperator: GreaterThanThreshold, EvaluationPeriods: 1, Threshold: 1, Metrics: [ { Id: m } ] } }`, "metric math"},
		"alarm ok actions": {`A: { Type: AWS::CloudWatch::Alarm, Properties: { Namespace: N, MetricName: M, Statistic: Sum, ComparisonOperator: GreaterThanThreshold, EvaluationPeriods: 1, Threshold: 1, OKActions: [ "arn:aws:sns:x:1:t" ] } }`, "OKActions"},
		"alarm band":       {`A: { Type: AWS::CloudWatch::Alarm, Properties: { Namespace: N, MetricName: M, Statistic: Sum, ComparisonOperator: LessThanLowerOrGreaterThanUpperThreshold, EvaluationPeriods: 1, Threshold: 1 } }`, "anomaly-band"},
		"alarm stack topic": {`A: { Type: AWS::CloudWatch::Alarm, Properties: { Namespace: N, MetricName: M, Statistic: Sum, ComparisonOperator: GreaterThanThreshold, EvaluationPeriods: 1, Threshold: 1, AlarmActions: [ !Ref T ] } }
  T: { Type: AWS::SNS::Topic }`, "not a topic of the SNS API"},
		"permission account": {`P: { Type: AWS::Lambda::Permission, Properties: { Action: "lambda:InvokeFunction", FunctionName: !Ref F, Principal: "111122223333" } }
  F: { Type: AWS::Lambda::Function, Properties: { PackageType: Image, Code: { ImageUri: "r/f:1" } } }`, "account or role principal"},
		"permission url": {`P: { Type: AWS::Lambda::Permission, Properties: { Action: "lambda:InvokeFunctionUrl", FunctionName: !Ref F, Principal: "*", FunctionUrlAuthType: NONE } }
  F: { Type: AWS::Lambda::Function, Properties: { PackageType: Image, Code: { ImageUri: "r/f:1" } } }`, "function URLs"},
		"permission outside": {`P: { Type: AWS::Lambda::Permission, Properties: { Action: "lambda:InvokeFunction", FunctionName: other, Principal: events.amazonaws.com } }`, "in-stack AWS::Lambda::Function"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildService(t, "Resources:\n  "+c.tmpl+"\n", serviceCaps)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a refusal containing %q, got %v", c.want, err)
			}
		})
	}
}

// A permission for an AWS service principal on an in-stack Function provisions nothing.
func TestLambdaPermission_ServicePrincipalIsANoOp(t *testing.T) {
	rs, err := buildService(t, `
Resources:
  F: { Type: AWS::Lambda::Function, Properties: { PackageType: Image, Code: { ImageUri: "r/f:1" } } }
  P: { Type: AWS::Lambda::Permission, Properties: { Action: "lambda:InvokeFunction", FunctionName: !GetAtt F.Arn, Principal: events.amazonaws.com, SourceArn: "arn:aws:events:x:1:rule/r" } }
`, serviceCaps)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rs["P"]; ok {
		t.Fatalf("a permission provisions nothing, got %v", rs["P"])
	}
}

// With the SQS and SNS APIs served, a stack's queue and topic are in those APIs' stores (service.go): a
// rule targets the queue by the ARN SQS knows it by, and an alarm fires the topic by its SNS ARN — each
// created after the queue or topic it names.
func TestServiceResources_StackMessagingWhenServed(t *testing.T) {
	caps := serviceCaps
	caps.SQSAPI, caps.SNSAPI = true, true
	order, err := buildManifests([]byte(`
Resources:
  Q: { Type: AWS::SQS::Queue }
  T: { Type: AWS::SNS::Topic }
  R: { Type: AWS::Events::Rule, Properties: { ScheduleExpression: "rate(5 minutes)", Targets: [ { Id: q, Arn: !GetAtt Q.Arn } ] } }
  A: { Type: AWS::CloudWatch::Alarm, Properties: { Namespace: N, MetricName: M, Statistic: Sum, ComparisonOperator: GreaterThanThreshold, EvaluationPeriods: 1, Threshold: 1, AlarmActions: [ !Ref T ] } }
`), DeployOptions{StackName: "app", Namespace: "open-infra-cfn", Caps: caps})
	if err != nil {
		t.Fatal(err)
	}
	pos, rs := map[string]int{}, map[string]StackResource{}
	for i, b := range order {
		pos[b.res.LogicalID], rs[b.res.LogicalID] = i, b.res
	}
	q, topic := rs["Q"], rs["T"]
	if q.Kind != KindSQSQueue || topic.Kind != KindSNSTopic {
		t.Fatalf("queue/topic kinds = %s/%s, want the SQS and SNS store kinds", q.Kind, topic.Kind)
	}
	ident := pseudoParams("app")
	region, acct := ident["AWS::Region"], ident["AWS::AccountId"]
	wantQ := "arn:aws:sqs:" + region.(string) + ":" + acct.(string) + ":" + q.Name
	targets, _ := rs["R"].Spec["targets"].([]any)
	if len(targets) != 1 || targets[0].(map[string]any)["arn"] != wantQ {
		t.Fatalf("rule targets = %v, want the queue's SQS ARN %s", targets, wantQ)
	}
	wantT := "arn:aws:sns:" + region.(string) + ":" + acct.(string) + ":" + topic.Name
	if acts := fmt.Sprint(rs["A"].Spec["alarmActions"]); acts != "["+wantT+"]" {
		t.Fatalf("alarm actions = %v, want the topic's SNS ARN %s", rs["A"].Spec["alarmActions"], wantT)
	}
	if pos["Q"] > pos["R"] || pos["T"] > pos["A"] {
		t.Fatalf("order %v: the queue and topic must be created before the rule and alarm naming them", pos)
	}
}
