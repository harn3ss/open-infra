package cfn

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// The fidelity guard: for each covered resource type, every property its translator accepts must change
// what the translator produces — the manifest, a caveat (a fidelity line), or a refusal. A property that
// is accepted and changes nothing is a silent loss: a plan would read as covering it when it did not.
// Adding a property to a translator's accepted set without using or reporting it fails this test.
//
// inertProps are the only exceptions, each with the reason it can carry no behavior on open-infra.
var inertProps = map[string]string{
	"Tags":                 "resource tags are labels only: no open-infra authorization or data-plane condition reads them",
	"Description":          "free text for people; where a kind has a description field the translator copies it",
	"PropagateTags":        "copies tags onto tasks — tags are labels only (see Tags)",
	"EnableECSManagedTags": "adds ECS-managed tags — tags are labels only (see Tags)",
	"Region":               "one site is one region; a subscription's Region names the topic's, which is this one",
}

// reportedElsewhere are properties a translator reports on another resource's manifest, keyed
// "<type>.<property>", with where.
var reportedElsewhere = map[string]string{
	"AWS::EC2::EIP.NetworkBorderGroup": "the Elastic IP folds into its instance; the instance's manifest carries the caveat",
	"AWS::EC2::EIP.Domain":             "every address is a VPC (LAN) address; standard (EC2-Classic) addresses no longer exist on AWS either",
}

// guardBaselines are minimal valid resources (so the translator runs its full path) for the covered types,
// with any companion resources (others) the resource must reference.
var guardBaselines = []struct{ typ, props, others string }{
	{"AWS::ECS::Service", `{ Cluster: !Ref C, TaskDefinition: !Ref TD }`, `
  C: { Type: AWS::ECS::Cluster }
  TD:
    Type: AWS::ECS::TaskDefinition
    Properties: { ContainerDefinitions: [ { Name: app, Image: "registry.example/app:1", PortMappings: [ { ContainerPort: 8080 } ] } ] }`},
	{"AWS::AppSync::GraphQLApi", `{ Name: a, AuthenticationType: API_KEY }`, `
  S:
    Type: AWS::AppSync::GraphQLSchema
    Properties: { ApiId: !GetAtt R.ApiId, Definition: "type Query @aws_api_key { x: Int }" }
  D:
    Type: AWS::AppSync::DataSource
    Properties: { ApiId: !GetAtt R.ApiId, Name: none, Type: NONE }
  Q:
    Type: AWS::AppSync::Resolver
    Properties: { ApiId: !GetAtt R.ApiId, TypeName: Query, FieldName: x, DataSourceName: none, RequestMappingTemplate: "{}", ResponseMappingTemplate: "$util.toJson($ctx.result)" }`},
	{"AWS::EC2::EIP", `{ InstanceId: !Ref I }`, `
  G: { Type: AWS::EC2::SecurityGroup, Properties: { GroupDescription: x } }
  I: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref G ] } }`},
	{"AWS::EC2::VPC", `{ CidrBlock: 10.0.0.0/16 }`, ""},
	{"AWS::EC2::Subnet", `{ VpcId: !Ref V, CidrBlock: 10.0.1.0/24 }`, `
  V: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }`},
	{"AWS::IAM::Policy", `{ PolicyName: p, Roles: [ !Ref Ro ], PolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*" } ] } }`, `
  Ro:
    Type: AWS::IAM::Role
    Properties: { AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ] } }`},
	{"AWS::SNS::Subscription", `{ TopicArn: !Ref T, Protocol: sqs, Endpoint: !GetAtt Qu.Arn }`, `
  T: { Type: AWS::SNS::Topic }
  Qu: { Type: AWS::SQS::Queue }`},
	{"AWS::EC2::Instance", `{ ImageId: ubuntu-24.04 }`, ""},
	{"AWS::EC2::SecurityGroup", `{ GroupDescription: x }`, ""},
	{"AWS::EC2::Volume", `{ Size: 10, AvailabilityZone: us-east-1a }`, ""},
	{"AWS::S3::Bucket", `{}`, ""},
	{"AWS::Lambda::Function", `{ PackageType: Image, Code: { ImageUri: "registry.example/fn:1" } }`, ""},
	{"AWS::KMS::Key", `{}`, ""},
	{"AWS::IAM::Role", `{ AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ] } }`, ""},
	{"AWS::DynamoDB::Table", `{ BillingMode: PAY_PER_REQUEST, KeySchema: [ { AttributeName: id, KeyType: HASH } ], AttributeDefinitions: [ { AttributeName: id, AttributeType: S } ] }`, ""},
	{"AWS::SQS::Queue", `{}`, ""},
	{"AWS::SNS::Topic", `{}`, ""},
	{"AWS::SSM::Parameter", `{ Name: /app/x, Type: String, Value: v }`, ""},
	{"AWS::StepFunctions::StateMachine", `{ DefinitionString: "{\"StartAt\":\"A\",\"States\":{\"A\":{\"Type\":\"Pass\",\"End\":true}}}" }`, ""},
	{"AWS::RDS::DBInstance", `{ Engine: postgres, DBInstanceClass: db.t3.micro, AllocatedStorage: 20 }`, ""},
	{"AWS::IAM::User", `{}`, ""},
	{"AWS::Cognito::UserPool", `{}`, ""},
}

// guardSamples are tried in turn: a property that changes the output for any of them is used.
var guardSamples = []any{
	"x", true, false, 3, []any{"x"}, map[string]any{"Key": "v", "Enabled": true}, []any{map[string]any{"Key": "v"}},
}

// guardShapedSamples are realistic values for properties a translator reads only in their AWS shape.
var guardShapedSamples = map[string]any{
	"LifecycleConfiguration":  map[string]any{"Rules": []any{map[string]any{"Status": "Enabled", "ExpirationInDays": 30}}},
	"VersioningConfiguration": map[string]any{"Status": "Enabled"},
	"Environment":             map[string]any{"Variables": map[string]any{"A": "b"}},
	"Definition":              map[string]any{"StartAt": "B", "States": map[string]any{"B": map[string]any{"Type": "Pass", "End": true}}},
	"SchedulingStrategy":      "DAEMON",
	"Visibility":              "PRIVATE",
	"IntrospectionConfig":     "DISABLED",
}

func TestFidelityGuard_EveryAcceptedPropertyIsUsedOrReported(t *testing.T) {
	for _, b := range guardBaselines {
		tmpl := "Resources:\n  R:\n    Type: " + b.typ + "\n    Properties: " + b.props + "\n" + b.others + "\n"
		var known map[string]bool
		knownPropsSeen = func(id string, k map[string]bool) {
			if id == "R" && known == nil {
				known = k
			}
		}
		base := guardRun(t, tmpl, "", nil)
		knownPropsSeen = nil
		if known == nil {
			t.Errorf("%s: translator did not report its accepted properties", b.typ)
			continue
		}
		baseProps := mustParse(t, []byte(tmpl)).Resources["R"].Properties
		var silent []string
		for _, p := range sortedBoolKeys(known) {
			if _, set := baseProps[p]; set || inertProps[p] != "" || reportedElsewhere[b.typ+"."+p] != "" {
				continue
			}
			used := false
			samples := guardSamples
			if s, ok := guardShapedSamples[p]; ok {
				samples = append([]any{s}, guardSamples...)
			}
			for _, s := range samples {
				if guardRun(t, tmpl, p, s) != base {
					used = true
					break
				}
			}
			if !used {
				silent = append(silent, p)
			}
		}
		if len(silent) > 0 {
			t.Errorf("%s accepts %s but neither uses nor reports them — map each one, refuse it, or add a fidelity caveat", b.typ, strings.Join(silent, ", "))
		}
	}
}

// guardRun translates resource R of tmpl with property prop set to val (prop "" = as written) and
// renders everything the translator produced. A panic counts as a change (the property was read).
func guardRun(t *testing.T, tmpl, prop string, val any) (out string) {
	t.Helper()
	tm := mustParse(t, []byte(tmpl))
	res := tm.Resources["R"]
	if prop != "" {
		p := map[string]any{}
		for k, v := range res.Properties {
			p[k] = v
		}
		p[prop] = val
		res.Properties = p
		tm.Resources["R"] = res
	}
	r := newResolver(tm, resolveParams(tm, nil), nil, pseudoParams("s"))
	r.evalConditions()
	ctx := &stackCtx{template: tm, resolver: r}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, ctx) }
	defer func() {
		if rec := recover(); rec != nil {
			out = fmt.Sprintf("panic: %v", rec)
		}
	}()
	resolved, _ := r.resolve(res.Properties).(map[string]any)
	m, fs := translatorFor(res.Type)("R", resolved, ctx)
	var reasons []string
	for _, f := range fs {
		reasons = append(reasons, f.Reason)
	}
	sort.Strings(reasons)
	view := map[string]any{"findings": reasons}
	if m != nil {
		var extras []any
		for _, x := range m.Extra {
			extras = append(extras, map[string]any{"kind": x.Kind, "name": x.Name, "spec": x.Spec, "caveats": x.Caveats})
		}
		view["manifest"] = map[string]any{"kind": m.Kind, "name": m.Name, "spec": m.Spec, "caveats": m.Caveats,
			"extra": extras, "requires": m.Requires, "protected": m.Protected, "shared": m.Shared}
	}
	js, _ := json.Marshal(view)
	return string(js)
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
