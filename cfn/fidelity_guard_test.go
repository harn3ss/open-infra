package cfn

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The fidelity guard: for every create-translatable resource type, every property its translator accepts
// — at the top level and in each nested block it checks (a MetadataOptions, a BlockDeviceMappings[0].Ebs,
// a method's Integration) — must, for some realistic value, change what the STACK produces (a manifest,
// a caveat), or be refused for every value. A property that some value is accepted for with no effect is
// a silent loss: a plan would read as covering it when it did not. Refusing a malformed sample does not
// count as using the property (the realistic value might still be dropped), and a panic fails.
//
// inertProps are the only exceptions, each with the reason it can carry no behavior on open-infra.
var inertProps = map[string]string{
	"Tags":                 "resource tags are labels only: no open-infra authorization or data-plane condition reads them",
	"Description":          "free text for people; where a kind has a description field the translator copies it",
	"PropagateTags":        "copies tags onto tasks — tags are labels only (see Tags)",
	"EnableECSManagedTags": "adds ECS-managed tags — tags are labels only (see Tags)",
	"Region":               "one site is one region; a subscription's Region names the topic's, which is this one",
}

// reportedElsewhere are properties whose effect is on another resource (or that only wire two resources
// together), keyed "<type>.<property>" (nested: "<type>.<path>.<property>"), with where.
var reportedElsewhere = map[string]string{
	"AWS::EC2::EIP.NetworkBorderGroup": "the Elastic IP folds into its instance; the instance's manifest carries the caveat",
	"AWS::EC2::EIP.Domain":             "every address is a VPC (LAN) address; standard (EC2-Classic) addresses no longer exist on AWS either",
	// Structural no-ops provision nothing; their properties name the resources they join, which are
	// translated in their own right.
	"AWS::EC2::VPCGatewayAttachment.VpcId":                                                         "the attachment is structural — the VPC is translated on its own",
	"AWS::EC2::VPCGatewayAttachment.InternetGatewayId":                                             "the attachment is structural — the border device is a kind: NatGateway",
	"AWS::EC2::SubnetRouteTableAssociation.SubnetId":                                               "routes are VPC-scoped on kind: Vpc; the association joins nothing",
	"AWS::EC2::SubnetRouteTableAssociation.RouteTableId":                                           "routes are VPC-scoped on kind: Vpc; the association joins nothing",
	"AWS::EC2::RouteTable.VpcId":                                                                   "a route table is a pure container; its routes are translated on their own",
	"AWS::ECS::Cluster.ClusterName":                                                                "an ECS cluster is structural: every service runs on the one Kubernetes cluster",
	"AWS::IAM::InstanceProfile.InstanceProfileName":                                                "the profile is followed to its role (the VM binds the kind: Role); the profile's own name names nothing",
	"AWS::IAM::InstanceProfile.Path":                                                               "IAM paths name nothing on open-infra",
	"AWS::CloudFront::CloudFrontOriginAccessIdentity.CloudFrontOriginAccessIdentityConfig.Comment": "free text for people",
	// A Lambda permission provisions nothing: the integration that invokes the Function (an EventBridge
	// target, an API Gateway integration) is authorized when it is created, against its creator's own
	// lambda:InvokeFunction, so which source may invoke is decided there, not by these conditions.
	"AWS::ECS::TaskDefinition.Family":       "a task definition family groups its revisions; the Application is the one live revision, named after the service",
	"AWS::Lambda::Permission.SourceArn":     "the invoking integration is authorized against its creator's own lambda:InvokeFunction when it is created",
	"AWS::Lambda::Permission.SourceAccount": "one account; the invoking integration is authorized against its creator when it is created",
}

// guardDeferred are silent losses the guard found and that are not fixed yet, keyed like reportedElsewhere.
// Each is a property read leniently — a value of the wrong shape, outside the AWS enum, or alongside a
// property that already decides the outcome is ignored rather than refused. They are listed so that a NEW
// silent loss still fails; fixing one means deleting its line (the guard then holds it).
var guardDeferred = map[string]string{}

func init() {
	lenient := "a value of the wrong shape (or outside the AWS enum) is ignored rather than refused"
	for _, k := range []string{
		"AWS::S3::Bucket.ObjectLockConfiguration", "AWS::S3::Bucket.LifecycleConfiguration.Rules[0].Filter",
		"AWS::S3::Bucket.LifecycleConfiguration.Rules[0].NoncurrentVersionExpiration",
		"AWS::SNS::Topic.Subscription", "AWS::SSM::Parameter.Policies",
	} {
		guardDeferred[k] = lenient
	}
	for _, p := range []string{"MetricsConfig", "ServiceRoleArn"} {
		guardDeferred["AWS::AppSync::DataSource."+p] = "accepted and neither mapped nor reported (the engine reaches a source with its own credentials and emits no per-source metrics)"
	}
	for _, p := range []string{"CachingConfig", "Code", "Kind", "MaxBatchSize", "MetricsConfig", "PipelineConfig", "Runtime", "SyncConfig"} {
		guardDeferred["AWS::AppSync::Resolver."+p] = lenient
	}
	for _, p := range []string{"Code", "CodeS3Location", "MaxBatchSize", "RequestMappingTemplateS3Location", "ResponseMappingTemplateS3Location", "Runtime", "SyncConfig"} {
		guardDeferred["AWS::AppSync::FunctionConfiguration."+p] = lenient
	}
}

// guardUnreported are collated types whose properties another translator reads without reporting the
// accepted set — not yet checked property by property (deferred, like guardDeferred).
var guardUnreported = map[string]string{
	"AWS::AppSync::GraphQLSchema": "its Definition is read by the GraphQLApi; its own property set is not reported",
	"AWS::S3::BucketPolicy":       "its PolicyDocument is read by the bucket; its own property set is not reported",
}

// guardBaseline is a minimal valid stack for one type: target is the logical id whose properties the guard
// varies (and whose translator, or the translator it collates into, must react). tmpl is the whole stack.
type guardBaseline struct{ typ, target, tmpl string }

// yamlBaseline builds a baseline whose target is a resource "R" of typ with props, plus others.
func yamlBaseline(typ, props, others string) guardBaseline {
	return guardBaseline{typ, "R", "Resources:\n  R:\n    Type: " + typ + "\n    Properties: " + props + "\n" + others + "\n"}
}

const guardSG = "\n  G: { Type: AWS::EC2::SecurityGroup, Properties: { GroupDescription: x } }"

var guardRestAPI = `
  Api: { Type: AWS::ApiGateway::RestApi, Properties: { Name: api } }
  Res: { Type: AWS::ApiGateway::Resource, Properties: { RestApiId: !Ref Api, ParentId: !GetAtt Api.RootResourceId, PathPart: items } }
  Get:
    Type: AWS::ApiGateway::Method
    Properties:
      RestApiId: !Ref Api
      ResourceId: !Ref Res
      HttpMethod: GET
      AuthorizationType: NONE
      Integration: { Type: MOCK, RequestTemplates: { "application/json": "{}" }, IntegrationResponses: [ { StatusCode: "200" } ] }
      MethodResponses: [ { StatusCode: "200" } ]
  Dep: { Type: AWS::ApiGateway::Deployment, Properties: { RestApiId: !Ref Api } }
  Prod: { Type: AWS::ApiGateway::Stage, Properties: { RestApiId: !Ref Api, DeploymentId: !Ref Dep, StageName: prod } }
  Key: { Type: AWS::ApiGateway::ApiKey, Properties: { Name: k } }
  Plan: { Type: AWS::ApiGateway::UsagePlan, Properties: { UsagePlanName: p, ApiStages: [ { ApiId: !Ref Api, Stage: prod } ] } }
  PlanKey: { Type: AWS::ApiGateway::UsagePlanKey, Properties: { KeyId: !Ref Key, KeyType: API_KEY, UsagePlanId: !Ref Plan } }`

// apiChild makes a baseline whose target R is an API Gateway resource of the stack above (the
// stack's own resource of that type renamed R, so nothing else in it changes).
func apiChild(typ, from string) guardBaseline {
	stack := "Resources:" + guardRestAPI + "\n"
	re := regexp.MustCompile(`(?m)^  ` + from + `:`)
	stack = re.ReplaceAllString(stack, "  R:")
	for _, end := range []string{",", " ", "\n"} {
		stack = strings.ReplaceAll(stack, "!Ref "+from+end, "!Ref R"+end)
	}
	stack = strings.ReplaceAll(stack, "!GetAtt "+from+".", "!GetAtt R.")
	return guardBaseline{typ, "R", stack}
}

var guardBaselines = []guardBaseline{
	yamlBaseline("AWS::ECS::Service", `{ Cluster: !Ref C, TaskDefinition: !Ref TD }`, `
  C: { Type: AWS::ECS::Cluster }
  TD:
    Type: AWS::ECS::TaskDefinition
    Properties: { ContainerDefinitions: [ { Name: app, Image: "registry.example/app:1", PortMappings: [ { ContainerPort: 8080 } ] } ] }`),
	yamlBaseline("AWS::ECS::TaskDefinition", `{ ContainerDefinitions: [ { Name: app, Image: "registry.example/app:1", PortMappings: [ { ContainerPort: 8080 } ] } ] }`, `
  C: { Type: AWS::ECS::Cluster }
  S: { Type: AWS::ECS::Service, Properties: { Cluster: !Ref C, TaskDefinition: !Ref R } }`),
	yamlBaseline("AWS::ECS::Cluster", `{}`, `
  TD:
    Type: AWS::ECS::TaskDefinition
    Properties: { ContainerDefinitions: [ { Name: app, Image: "registry.example/app:1" } ] }
  S: { Type: AWS::ECS::Service, Properties: { Cluster: !Ref R, TaskDefinition: !Ref TD } }`),
	yamlBaseline("AWS::AppSync::GraphQLApi", `{ Name: a, AuthenticationType: API_KEY }`, `
  S:
    Type: AWS::AppSync::GraphQLSchema
    Properties: { ApiId: !GetAtt R.ApiId, Definition: "type Query @aws_api_key { x: Int }" }
  D:
    Type: AWS::AppSync::DataSource
    Properties: { ApiId: !GetAtt R.ApiId, Name: none, Type: NONE }
  Q:
    Type: AWS::AppSync::Resolver
    Properties: { ApiId: !GetAtt R.ApiId, TypeName: Query, FieldName: x, DataSourceName: none, RequestMappingTemplate: "{}", ResponseMappingTemplate: "$util.toJson($ctx.result)" }`),
	yamlBaseline("AWS::AppSync::GraphQLSchema", `{ ApiId: !GetAtt A.ApiId, Definition: "type Query @aws_api_key { x: Int }" }`, `
  A: { Type: AWS::AppSync::GraphQLApi, Properties: { Name: a, AuthenticationType: API_KEY } }
  D:
    Type: AWS::AppSync::DataSource
    Properties: { ApiId: !GetAtt A.ApiId, Name: none, Type: NONE }
  Q:
    Type: AWS::AppSync::Resolver
    Properties: { ApiId: !GetAtt A.ApiId, TypeName: Query, FieldName: x, DataSourceName: none, RequestMappingTemplate: "{}", ResponseMappingTemplate: "$util.toJson($ctx.result)" }`),
	yamlBaseline("AWS::AppSync::DataSource", `{ ApiId: !GetAtt A.ApiId, Name: none, Type: NONE }`, `
  A: { Type: AWS::AppSync::GraphQLApi, Properties: { Name: a, AuthenticationType: API_KEY } }
  S:
    Type: AWS::AppSync::GraphQLSchema
    Properties: { ApiId: !GetAtt A.ApiId, Definition: "type Query @aws_api_key { x: Int }" }
  Q:
    Type: AWS::AppSync::Resolver
    Properties: { ApiId: !GetAtt A.ApiId, TypeName: Query, FieldName: x, DataSourceName: none, RequestMappingTemplate: "{}", ResponseMappingTemplate: "$util.toJson($ctx.result)" }`),
	yamlBaseline("AWS::AppSync::Resolver", `{ ApiId: !GetAtt A.ApiId, TypeName: Query, FieldName: x, DataSourceName: none, RequestMappingTemplate: "{}", ResponseMappingTemplate: "$util.toJson($ctx.result)" }`, `
  A: { Type: AWS::AppSync::GraphQLApi, Properties: { Name: a, AuthenticationType: API_KEY } }
  S:
    Type: AWS::AppSync::GraphQLSchema
    Properties: { ApiId: !GetAtt A.ApiId, Definition: "type Query @aws_api_key { x: Int }" }
  D:
    Type: AWS::AppSync::DataSource
    Properties: { ApiId: !GetAtt A.ApiId, Name: none, Type: NONE }`),
	yamlBaseline("AWS::AppSync::FunctionConfiguration", `{ ApiId: !GetAtt A.ApiId, Name: f, DataSourceName: none, FunctionVersion: "2018-05-29", RequestMappingTemplate: "{}", ResponseMappingTemplate: "$util.toJson($ctx.result)" }`, `
  A: { Type: AWS::AppSync::GraphQLApi, Properties: { Name: a, AuthenticationType: API_KEY } }
  S:
    Type: AWS::AppSync::GraphQLSchema
    Properties: { ApiId: !GetAtt A.ApiId, Definition: "type Query @aws_api_key { x: Int }" }
  D:
    Type: AWS::AppSync::DataSource
    Properties: { ApiId: !GetAtt A.ApiId, Name: none, Type: NONE }
  Q:
    Type: AWS::AppSync::Resolver
    Properties: { ApiId: !GetAtt A.ApiId, TypeName: Query, FieldName: x, Kind: PIPELINE, PipelineConfig: { Functions: [ !GetAtt R.FunctionId ] }, RequestMappingTemplate: "{}", ResponseMappingTemplate: "$util.toJson($ctx.result)" }`),
	yamlBaseline("AWS::EC2::EIP", `{ InstanceId: !Ref I }`, guardSG+`
  I: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref G ] } }`),
	yamlBaseline("AWS::EC2::EIPAssociation", `{ AllocationId: !GetAtt E.AllocationId, InstanceId: !Ref I }`, guardSG+`
  E: { Type: AWS::EC2::EIP }
  I: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref G ] } }`),
	yamlBaseline("AWS::EC2::VPC", `{ CidrBlock: 10.0.0.0/16 }`, ""),
	yamlBaseline("AWS::EC2::Subnet", `{ VpcId: !Ref V, CidrBlock: 10.0.1.0/24 }`, `
  V: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }`),
	yamlBaseline("AWS::EC2::VPCEndpoint", `{ ServiceName: com.amazonaws.us-east-1.s3, VpcId: !Ref V }`, `
  V: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }`),
	yamlBaseline("AWS::EC2::InternetGateway", `{}`, ""),
	yamlBaseline("AWS::EC2::VPCGatewayAttachment", `{ VpcId: !Ref V, InternetGatewayId: !Ref IGW }`, `
  V: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  IGW: { Type: AWS::EC2::InternetGateway }`),
	yamlBaseline("AWS::EC2::SubnetRouteTableAssociation", `{ SubnetId: !Ref S, RouteTableId: !Ref RT }`, `
  V: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  S: { Type: AWS::EC2::Subnet, Properties: { VpcId: !Ref V, CidrBlock: 10.0.1.0/24 } }
  RT: { Type: AWS::EC2::RouteTable, Properties: { VpcId: !Ref V } }`),
	yamlBaseline("AWS::EC2::RouteTable", `{ VpcId: !Ref V }`, `
  V: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }`),
	yamlBaseline("AWS::EC2::Route", `{ RouteTableId: !Ref RT, DestinationCidrBlock: 0.0.0.0/0, GatewayId: !Ref IGW }`, `
  V: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  RT: { Type: AWS::EC2::RouteTable, Properties: { VpcId: !Ref V } }
  IGW: { Type: AWS::EC2::InternetGateway }`),
	yamlBaseline("AWS::IAM::Policy", `{ PolicyName: p, Roles: [ !Ref Ro ], PolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*" } ] } }`, `
  Ro:
    Type: AWS::IAM::Role
    Properties: { AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ] } }`),
	yamlBaseline("AWS::IAM::ManagedPolicy", `{ Roles: [ !Ref Ro ], PolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*" } ] } }`, `
  Ro:
    Type: AWS::IAM::Role
    Properties: { AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ] } }`),
	yamlBaseline("AWS::IAM::InstanceProfile", `{ Roles: [ !Ref Ro ] }`, guardSG+`
  Ro:
    Type: AWS::IAM::Role
    Properties: { AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ] } }
  I: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04, IamInstanceProfile: !Ref R, SecurityGroupIds: [ !Ref G ] } }`),
	yamlBaseline("AWS::SNS::Subscription", `{ TopicArn: !Ref T, Protocol: lambda, Endpoint: !GetAtt Fn.Arn }`, `
  T: { Type: AWS::SNS::Topic }
  Fn: { Type: AWS::Lambda::Function, Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" } } }`),
	yamlBaseline("AWS::EC2::Instance", `{ ImageId: ubuntu-24.04, MetadataOptions: { HttpTokens: required }, BlockDeviceMappings: [ { DeviceName: /dev/sdf, Ebs: { VolumeSize: 10 } } ], NetworkInterfaces: [ { DeviceIndex: "0", GroupSet: [ !Ref G ] } ] }`, guardSG),
	yamlBaseline("AWS::EC2::SecurityGroup", `{ GroupDescription: x }`, ""),
	yamlBaseline("AWS::EC2::SecurityGroupIngress", `{ GroupId: !Ref G, IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 10.0.0.0/8 }`, guardSG),
	yamlBaseline("AWS::EC2::SecurityGroupEgress", `{ GroupId: !Ref G, IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 10.0.0.0/8 }`, guardSG),
	yamlBaseline("AWS::EC2::Volume", `{ Size: 10, AvailabilityZone: us-east-1a }`, ""),
	yamlBaseline("AWS::S3::Bucket", `{ LifecycleConfiguration: { Rules: [ { Id: r, Status: Enabled, ExpirationInDays: 30 } ] } }`, ""),
	yamlBaseline("AWS::S3::BucketPolicy", `{ Bucket: !Ref B, PolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*" } ] } }`, `
  B: { Type: AWS::S3::Bucket }`),
	yamlBaseline("AWS::Lambda::Function", `{ PackageType: Image, Code: { ImageUri: "registry.example/fn:1" } }`, ""),
	yamlBaseline("AWS::KMS::Key", `{}`, ""),
	yamlBaseline("AWS::IAM::Role", `{ AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ] } }`, ""),
	yamlBaseline("AWS::DynamoDB::Table", `{ BillingMode: PAY_PER_REQUEST, KeySchema: [ { AttributeName: id, KeyType: HASH } ], AttributeDefinitions: [ { AttributeName: id, AttributeType: S } ] }`, ""),
	yamlBaseline("AWS::SQS::Queue", `{}`, ""),
	yamlBaseline("AWS::EC2::VolumeAttachment", `{ InstanceId: !Ref W, VolumeId: !Ref V }`, `
  W: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04 } }
  V: { Type: AWS::EC2::Volume, Properties: { Size: 20 } }`),
	yamlBaseline("AWS::Lambda::Permission", `{ Action: "lambda:InvokeFunction", FunctionName: !Ref F, Principal: events.amazonaws.com }`, "\n  F: { Type: AWS::Lambda::Function, Properties: { PackageType: Image, Code: { ImageUri: \"registry.example/fn:1\" } } }"),
	yamlBaseline("AWS::SNS::Topic", `{}`, ""),
	yamlBaseline("AWS::SSM::Parameter", `{ Name: /app/x, Type: String, Value: v }`, ""),
	yamlBaseline("AWS::CloudFormation::WaitCondition", `{ Handle: !Ref H, Count: 1, Timeout: "300" }`, `
  H: { Type: AWS::CloudFormation::WaitConditionHandle }`),
	yamlBaseline("AWS::CloudFormation::WaitConditionHandle", `{}`, `
  W: { Type: AWS::CloudFormation::WaitCondition, Properties: { Handle: !Ref R, Timeout: "300" } }`),
	yamlBaseline("AWS::StepFunctions::StateMachine", `{ DefinitionString: "{\"StartAt\":\"A\",\"States\":{\"A\":{\"Type\":\"Pass\",\"End\":true}}}" }`, ""),
	yamlBaseline("AWS::RDS::DBInstance", `{ Engine: postgres, DBInstanceClass: db.t3.micro, AllocatedStorage: 20 }`, ""),
	yamlBaseline("AWS::IAM::User", `{}`, ""),
	yamlBaseline("AWS::Cognito::UserPool", `{}`, ""),
	yamlBaseline("AWS::Cognito::UserPoolClient", `{ UserPoolId: !Ref P }`, `
  P: { Type: AWS::Cognito::UserPool }`),
	{"AWS::ApiGateway::RestApi", "Api", "Resources:" + guardRestAPI + "\n"},
	apiChild("AWS::ApiGateway::Resource", "Res"),
	apiChild("AWS::ApiGateway::Method", "Get"),
	apiChild("AWS::ApiGateway::Deployment", "Dep"),
	apiChild("AWS::ApiGateway::Stage", "Prod"),
	apiChild("AWS::ApiGateway::ApiKey", "Key"),
	apiChild("AWS::ApiGateway::UsagePlan", "Plan"),
	apiChild("AWS::ApiGateway::UsagePlanKey", "PlanKey"),
	{"AWS::ApiGateway::Model", "R", "Resources:" + guardRestAPI + "\n  R: { Type: AWS::ApiGateway::Model, Properties: { RestApiId: !Ref Api, Name: Item, ContentType: application/json, Schema: { type: object } } }\n"},
	{"AWS::ApiGateway::RequestValidator", "R", "Resources:" + guardRestAPI + "\n  R: { Type: AWS::ApiGateway::RequestValidator, Properties: { RestApiId: !Ref Api, Name: v } }\n"},
	{"AWS::ApiGateway::Authorizer", "R", "Resources:" + guardRestAPI + "\n  R: { Type: AWS::ApiGateway::Authorizer, Properties: { RestApiId: !Ref Api, Name: a, Type: COGNITO_USER_POOLS, ProviderARNs: [ \"arn:aws:cognito-idp:us-east-1:1:userpool/us-east-1_x\" ], IdentitySource: method.request.header.Authorization } }\n"},
}

// cloudFrontBaselines are the CloudFront site stack (translate_cloudfront_test.go) with each of its
// resources as the target in turn.
func cloudFrontBaselines(t *testing.T) []guardBaseline {
	js, err := json.Marshal(cfSiteTemplate())
	if err != nil {
		t.Fatal(err)
	}
	return []guardBaseline{
		{"AWS::CloudFront::Distribution", "SiteDistribution", string(js)},
		{"AWS::CloudFront::OriginAccessControl", "SiteOAC", string(js)},
		{"AWS::CloudFront::ResponseHeadersPolicy", "SecurityHeaders", string(js)},
		{"AWS::CertificateManager::Certificate", "SiteCertificate", string(js)},
	}
}

// guardSamples are tried in turn: a property that changes the output for any of them is used.
var guardSamples = []any{
	"x", true, false, 3, []any{"x"}, map[string]any{"Key": "v", "Enabled": true}, []any{map[string]any{"Key": "v"}},
}

// guardShapedSamples are realistic values for properties a translator reads only in their AWS shape.
var guardShapedSamples = map[string][]any{
	"QueueName":               {"guard.fifo"}, // a FIFO queue's name (a standard queue's takes the generic samples)
	"FilterPolicyScope":       {"MessageBody"},
	"FilterPolicy":            {map[string]any{"color": []any{"red"}}},
	"LifecycleConfiguration":  {map[string]any{"Rules": []any{map[string]any{"Status": "Enabled", "ExpirationInDays": 30}}}},
	"VersioningConfiguration": {map[string]any{"Status": "Enabled"}},
	"Environment":             {map[string]any{"Variables": map[string]any{"A": "b"}}},
	"Definition":              {map[string]any{"StartAt": "B", "States": map[string]any{"B": map[string]any{"Type": "Pass", "End": true}}}},
	"SchedulingStrategy":      {"DAEMON"},
	"Visibility":              {"PRIVATE"},
	"IntrospectionConfig":     {"DISABLED"},
	"Device":                  {"/dev/sdh"}, // a VolumeAttachment's device, aliased in the guest
}

// The guard covers every type with a create translator (a type added without a baseline fails here).
func TestFidelityGuard_CoversEveryTranslator(t *testing.T) {
	have := map[string]bool{}
	for _, b := range append(append(append([]guardBaseline{}, guardBaselines...), cloudFrontBaselines(t)...), serviceStoreBaselines...) {
		have[b.typ] = true
	}
	// The child types a distribution reads by id only (no properties of their own to translate), and a
	// type every instance of which refuses (so no property of it is ever accepted).
	// A KMS alias and an SQS queue / SNS topic policy refuse without their API; with it,
	// TestFidelityGuard_ServiceBackedTypes guards them.
	for _, typ := range []string{"AWS::CloudFront::CloudFrontOriginAccessIdentity", "AWS::CloudFront::CachePolicy", "AWS::CloudFront::OriginRequestPolicy",
		"AWS::EC2::SubnetNetworkAclAssociation", "AWS::KMS::Alias", "AWS::SQS::QueuePolicy", "AWS::SNS::TopicPolicy",
		// A nested stack refuses where stacks cannot be created; TestFidelityGuard_NestedStack guards it.
		"AWS::CloudFormation::Stack"} {
		have[typ] = true
	}
	var missing []string
	for typ := range translators {
		if !have[typ] {
			missing = append(missing, typ)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("no fidelity-guard baseline for %s — add one to guardBaselines", strings.Join(missing, ", "))
	}
}

// A network ACL association always refuses: the ACL's rules cannot be in the template, and dropping the
// association would leave the subnet without them.
func TestFidelityGuard_NetworkAclAssociationRefuses(t *testing.T) {
	tm := mustParse(t, []byte(`
Resources:
  V: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  S: { Type: AWS::EC2::Subnet, Properties: { VpcId: !Ref V, CidrBlock: 10.0.1.0/24 } }
  R: { Type: AWS::EC2::SubnetNetworkAclAssociation, Properties: { SubnetId: !Ref S, NetworkAclId: acl-0123 } }
`))
	if r := guardRunAll(tm); !strings.Contains(strings.Join(sortedSet(r.findings), "\n"), "a network ACL association has no open-infra form") {
		t.Fatalf("want a refusal, got %v", sortedSet(r.findings))
	}
}

func TestFidelityGuard_EveryAcceptedPropertyIsUsedOrReported(t *testing.T) {
	guardCheck(t, append(append([]guardBaseline{}, guardBaselines...), cloudFrontBaselines(t)...))
}

// guardCaps are the Capabilities the guard translates with (zero = the CLI's; a test may set them).
var guardCaps Capabilities

// guardCheck proves, for each baseline, that every property its translator accepts is used or reported.
func guardCheck(t *testing.T, baselines []guardBaseline) {
	t.Helper()
	for _, b := range baselines {
		tm := mustParse(t, []byte(b.tmpl))
		if tm.Resources[b.target].Type != b.typ {
			t.Errorf("%s: baseline target %s is a %s", b.typ, b.target, tm.Resources[b.target].Type)
			continue
		}
		known := map[string]map[string]bool{} // path below the target ("" = its own properties) -> accepted set
		knownPropsSeen = func(id string, k map[string]bool) {
			path := ""
			switch {
			case id == b.target:
			case strings.HasPrefix(id, b.target+"."):
				path = strings.TrimPrefix(id, b.target+".")
			default:
				return
			}
			if known[path] == nil {
				known[path] = k
			}
		}
		base := guardRunAll(tm)
		knownPropsSeen = nil
		if base.panic != "" {
			t.Errorf("%s: the baseline panics: %s", b.typ, base.panic)
			continue
		}
		if len(base.findings) > 0 {
			t.Errorf("%s: the baseline is refused: %v", b.typ, sortedSet(base.findings))
			continue
		}
		if known[""] == nil {
			if guardUnreported[b.typ] == "" {
				t.Errorf("%s: translator did not report its accepted properties", b.typ)
			}
			continue
		}
		var silent, panics []string
		for _, path := range sortedPaths(known) {
			container, ok := guardLookup(tm.Resources[b.target].Properties, path)
			if !ok {
				continue // a nested block the baseline does not carry
			}
			for _, p := range sortedBoolKeys(known[path]) {
				full := strings.TrimPrefix(path+"."+p, ".")
				if _, set := container[p]; set || inertProps[p] != "" || reportedElsewhere[b.typ+"."+full] != "" || guardDeferred[b.typ+"."+full] != "" {
					continue
				}
				// A sample is used (the output changed with nothing new refused), refused, or silent. One
				// silent boolean is the property's default (true for Enabled, false for most flags) and
				// rightly changes nothing; any other silent sample with no used one is a silent loss.
				used, silentBools, silentOther, panicked := false, 0, 0, ""
				for _, s := range append(append([]any{}, guardShapedSamples[p]...), guardSamples...) {
					r := guardRunAll(guardWith(t, b.tmpl, b.target, path, p, s))
					_, isBool := s.(bool)
					outcome := "silent"
					switch {
					case r.panic != "":
						panicked, outcome = r.panic, "panic"
					case newFindings(r, base):
						outcome = "refused"
					case r.out != base.out:
						used, outcome = true, "used"
					case isBool:
						silentBools++
					default:
						silentOther++
					}
					if testing.Verbose() && outcome != "used" {
						t.Logf("%s %s = %v: %s", b.typ, full, s, outcome)
					}
					if used {
						break
					}
				}
				switch {
				case panicked != "":
					panics = append(panics, full+" ("+panicked+")")
				case !used && (silentOther > 0 || silentBools > 1):
					silent = append(silent, full)
				}
			}
		}
		if len(panics) > 0 {
			t.Errorf("%s panics on %s", b.typ, strings.Join(panics, "; "))
		}
		if len(silent) > 0 {
			t.Errorf("%s accepts %s but neither uses nor reports them — map each one, refuse it, or add a fidelity caveat", b.typ, strings.Join(silent, ", "))
		}
	}
}

type guardResult struct {
	out      string
	findings map[string]bool
	panic    string
}

// guardRunAll translates every included resource of the stack and renders everything the translators
// produced: each manifest (kind, name, spec, caveats, companions, requirements, protection) and each
// finding.
func guardRunAll(tm *Template) (res guardResult) {
	res.findings = map[string]bool{}
	defer func() {
		if rec := recover(); rec != nil {
			res.panic = fmt.Sprint(rec)
		}
	}()
	r := newResolver(tm, resolveParams(tm, nil), nil, pseudoParams("s"))
	r.evalConditions()
	ctx := &stackCtx{template: tm, resolver: r, caps: guardCaps}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, ctx) }
	r.staticAtt = func(id, attr string) (string, bool) { return serviceAtt(id, attr, ctx) }
	view := map[string]any{}
	for _, id := range sortedResourceIDs(tm) {
		rs := tm.Resources[id]
		if !ctx.included(rs) {
			continue
		}
		tr := translatorFor(rs.Type)
		if tr == nil {
			continue
		}
		r.where = "Resource " + id
		resolved, _ := r.resolve(rs.Properties).(map[string]any)
		m, fs := tr(id, resolved, ctx)
		for _, f := range fs {
			res.findings[f.Where+": "+f.Reason] = true
		}
		if m != nil {
			var extras []any
			for _, x := range m.Extra {
				extras = append(extras, map[string]any{"kind": x.Kind, "name": x.Name, "spec": x.Spec, "caveats": x.Caveats})
			}
			view[id] = map[string]any{"kind": m.Kind, "name": m.Name, "spec": m.Spec, "caveats": m.Caveats,
				"extra": extras, "requires": m.Requires, "protected": m.Protected, "shared": m.Shared}
		}
	}
	for _, f := range r.findings {
		res.findings[f.Where+": "+f.Reason] = true
	}
	js, _ := json.Marshal(view)
	res.out = string(js)
	return res
}

// newFindings reports whether r refuses something base does not.
func newFindings(r, base guardResult) bool {
	for f := range r.findings {
		if !base.findings[f] {
			return true
		}
	}
	return false
}

// guardWith re-parses tmpl with property p of the block at path (below resource target) set to val.
func guardWith(t *testing.T, tmpl, target, path, p string, val any) *Template {
	t.Helper()
	tm := mustParse(t, []byte(tmpl))
	res := tm.Resources[target]
	props := deepCopy(res.Properties).(map[string]any)
	container, ok := guardLookup(props, path)
	if !ok {
		t.Fatalf("no block %s in %s", path, target)
	}
	container[p] = val
	res.Properties = props
	tm.Resources[target] = res
	return tm
}

var guardSegRE = regexp.MustCompile(`^([A-Za-z0-9]+)(?:\[(\d+)\])?$`)

// guardLookup follows a dotted path ("Integration.IntegrationResponses[0]") from props to an object.
func guardLookup(props map[string]any, path string) (map[string]any, bool) {
	cur := props
	if path == "" {
		return cur, true
	}
	for _, seg := range strings.Split(path, ".") {
		m := guardSegRE.FindStringSubmatch(seg)
		if m == nil {
			return nil, false
		}
		v := cur[m[1]]
		if m[2] != "" {
			l, ok := v.([]any)
			i, _ := strconv.Atoi(m[2])
			if !ok || i >= len(l) {
				return nil, false
			}
			v = l[i]
		}
		next, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	}
	return v
}

func sortedResourceIDs(tm *Template) []string {
	ids := make([]string, 0, len(tm.Resources))
	for id := range tm.Resources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sortedPaths(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedBoolKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
