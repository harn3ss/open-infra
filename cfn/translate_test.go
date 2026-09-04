package main

import (
	"strings"
	"testing"
)

func findingsText(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Reason)
		b.WriteString("\n")
	}
	return b.String()
}

func TestTranslate_KMSKey_Faithful(t *testing.T) {
	m, fs := translateKMSKey("AppKey", map[string]any{
		"Description":       "app data key",
		"EnableKeyRotation": true,
		"KeySpec":           "SYMMETRIC_DEFAULT",
		"KeyPolicy":         map[string]any{"Version": "2012-10-17"},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "EncryptionKey" || m.Name != "appkey" {
		t.Fatalf("bad manifest head: %+v", m)
	}
	if m.Spec["description"] != "app data key" || m.Spec["rotationDays"] != 365 || m.Spec["keyType"] != "aes256-gcm96" {
		t.Fatalf("spec not faithful: %#v", m.Spec)
	}
	// KeyPolicy has no equivalent — it must be a declared caveat, not silently dropped.
	if len(m.Caveats) == 0 || !strings.Contains(m.Caveats[0], "KeyPolicy") {
		t.Fatalf("KeyPolicy should surface a caveat, caveats: %v", m.Caveats)
	}
}

func TestTranslate_KMSKey_UnknownPropertyBlocks(t *testing.T) {
	_, fs := translateKMSKey("K", map[string]any{"MultiRegion": true}, nil)
	if findingsText(fs) == "" || !strings.Contains(findingsText(fs), "MultiRegion") {
		t.Fatalf("an unhandled property must block, findings: %s", findingsText(fs))
	}
}

func TestTranslate_LambdaImage_Faithful(t *testing.T) {
	m, fs := translateLambdaFunction("Api", map[string]any{
		"PackageType": "Image",
		"Code":        map[string]any{"ImageUri": "registry.example/api:1"},
		"MemorySize":  float64(512),
		"Timeout":     float64(30),
		"Environment": map[string]any{"Variables": map[string]any{"LOG": "info", "TIER": "b"}},
		"Role":        "arn:aws:iam::x:role/r",
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "Function" || m.Spec["image"] != "registry.example/api:1" {
		t.Fatalf("bad manifest: %+v", m)
	}
	if m.Spec["memory"] != "512Mi" || m.Spec["timeout"] != 30 {
		t.Fatalf("mem/timeout not faithful: %#v", m.Spec)
	}
	env, _ := m.Spec["env"].([]any)
	if len(env) != 2 {
		t.Fatalf("env should have 2 vars, got %#v", m.Spec["env"])
	}
	if len(m.Caveats) == 0 || !strings.Contains(m.Caveats[0], "Role") {
		t.Fatalf("Lambda Role should surface a caveat: %v", m.Caveats)
	}
}

func TestTranslate_LambdaZip_Refused(t *testing.T) {
	_, fs := translateLambdaFunction("Zip", map[string]any{
		"Runtime": "python3.12",
		"Handler": "index.handler",
		"Code":    map[string]any{"S3Bucket": "b", "S3Key": "k"},
	}, nil)
	txt := findingsText(fs)
	if !strings.Contains(txt, "PackageType: Image") {
		t.Fatalf("a zip Lambda must be refused (no image to run), findings: %s", txt)
	}
}

// An env var whose value is a cross-resource attribute (no concrete open-infra value) blocks
// rather than being provisioned with a wrong value.
func TestTranslate_Lambda_CrossRefEnvBlocks(t *testing.T) {
	_, fs := translateLambdaFunction("Api", map[string]any{
		"PackageType": "Image",
		"Code":        map[string]any{"ImageUri": "img:1"},
		"Environment": map[string]any{"Variables": map[string]any{"BUCKET": "<ref:Assets>"}},
	}, nil)
	if !strings.Contains(findingsText(fs), "BUCKET") {
		t.Fatalf("a cross-resource env value must block, findings: %s", findingsText(fs))
	}
}

// A state machine whose ASL already uses open-infra's "function:<name>" Resource convention
// translates faithfully — the definition maps byte-for-byte.
func TestTranslate_StateMachine_Faithful(t *testing.T) {
	def := `{"StartAt":"Go","States":{"Go":{"Type":"Task","Resource":"function:validate","End":true}}}`
	m, fs := translateStateMachine("Flow", map[string]any{
		"DefinitionString": def,
		"RoleArn":          "arn:aws:iam::x:role/sfn",
		"StateMachineType": "STANDARD",
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "StateMachine" || m.Spec["definition"] != def {
		t.Fatalf("definition should map byte-for-byte: %#v", m.Spec)
	}
	if len(m.Caveats) == 0 || !strings.Contains(m.Caveats[0], "RoleArn") {
		t.Fatalf("RoleArn should surface a caveat: %v", m.Caveats)
	}
}

// The fidelity boundary: an ASL with AWS Lambda ARNs can't run on open-infra and must be
// refused (not deployed to fail at execution).
func TestTranslate_StateMachine_AWSArnRefused(t *testing.T) {
	def := `{"StartAt":"Go","States":{"Go":{"Type":"Task","Resource":"arn:aws:lambda:us-east-1:1:function:v","End":true}}}`
	_, fs := translateStateMachine("Flow", map[string]any{"DefinitionString": def}, nil)
	if !strings.Contains(findingsText(fs), "arn:aws") {
		t.Fatalf("an AWS-ARN Task Resource must be refused, findings: %s", findingsText(fs))
	}
}

// A definition carrying an unresolved cross-resource ref (a sibling Lambda's Arn) blocks.
func TestTranslate_StateMachine_UnresolvedRefBlocks(t *testing.T) {
	_, fs := translateStateMachine("Flow", map[string]any{
		"DefinitionString": `{"StartAt":"Go","States":{"Go":{"Resource":"<Lambda.Arn>"}}}`,
	}, nil)
	if findingsText(fs) == "" {
		t.Fatalf("an unresolved cross-resource definition must block")
	}
}

func TestTranslate_StateMachine_ExpressRefused(t *testing.T) {
	_, fs := translateStateMachine("Flow", map[string]any{
		"DefinitionString": `{"StartAt":"Go","States":{}}`,
		"StateMachineType": "EXPRESS",
	}, nil)
	if !strings.Contains(findingsText(fs), "EXPRESS") {
		t.Fatalf("EXPRESS should be refused, findings: %s", findingsText(fs))
	}
}

func TestTranslate_Volume_Faithful(t *testing.T) {
	m, fs := translateVolume("Data", map[string]any{
		"Size":               float64(20),
		"MultiAttachEnabled": true,
		"VolumeType":         "gp3",
		"AvailabilityZone":   "us-east-1a",
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "Volume" || m.Spec["size"] != "20Gi" || m.Spec["shared"] != true {
		t.Fatalf("volume spec not faithful: %#v", m.Spec)
	}
	// VolumeType + AZ have no counterpart — declared caveats, not silent drops.
	caveats := strings.Join(m.Caveats, " ")
	if !strings.Contains(caveats, "VolumeType") || !strings.Contains(caveats, "AvailabilityZone") {
		t.Fatalf("VolumeType/AZ should surface caveats: %v", m.Caveats)
	}
}

func TestTranslate_Volume_EncryptionAndSnapshotBlock(t *testing.T) {
	_, fs := translateVolume("Data", map[string]any{"Size": float64(10), "Encrypted": true}, nil)
	if !strings.Contains(findingsText(fs), "Encrypted") {
		t.Fatalf("an encrypted volume must block, findings: %s", findingsText(fs))
	}
	_, fs2 := translateVolume("Data", map[string]any{"Size": float64(10), "SnapshotId": "snap-123"}, nil)
	if !strings.Contains(findingsText(fs2), "SnapshotId") {
		t.Fatalf("a SnapshotId must block, findings: %s", findingsText(fs2))
	}
}

// An IAM user that gets its permissions from group membership (the AWS best practice) maps: the
// identity + groups translate. (kind: User reports readiness after polyhedron#102.)
func TestTranslate_IAMUser_Faithful(t *testing.T) {
	m, fs := translateIAMUser("Alice", map[string]any{
		"UserName": "alice",
		"Groups":   []any{"engineers", "oncall"},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "User" || m.Spec["displayName"] != "alice" || m.Spec["source"] != "local" {
		t.Fatalf("user spec not faithful: %#v", m.Spec)
	}
	// IAM kinds live under iam.openinfra.dev, not openinfra.dev — getting this wrong fails apply.
	if m.APIVersion != "iam.openinfra.dev/v1" {
		t.Fatalf("User must be iam.openinfra.dev/v1, got %s", m.APIVersion)
	}
	if groups, _ := m.Spec["groups"].([]any); len(groups) != 2 {
		t.Fatalf("groups should map: %#v", m.Spec["groups"])
	}
}

// An IAM user's attached policies are the permission model, which has no faithful RBAC form —
// dropping them would silently strip permissions, so they block.
func TestTranslate_IAMUser_PoliciesBlock(t *testing.T) {
	_, fs := translateIAMUser("Alice", map[string]any{
		"UserName":          "alice",
		"ManagedPolicyArns": []any{"arn:aws:iam::aws:policy/AdministratorAccess"},
	}, nil)
	if !strings.Contains(findingsText(fs), "ManagedPolicyArns") {
		t.Fatalf("attached policies must block, findings: %s", findingsText(fs))
	}
}

// A basic Cognito pool maps to a hosted OIDC pool (Keycloak realm).
func TestTranslate_CognitoUserPool_Faithful(t *testing.T) {
	m, fs := translateCognitoUserPool("Pool", map[string]any{
		"UserPoolName":     "MyApp Users",
		"MfaConfiguration": "OFF",
		"Policies":         map[string]any{"PasswordPolicy": map[string]any{"MinimumLength": float64(8)}},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "UserPool" || m.Spec["realm"] != "myapp-users" {
		t.Fatalf("pool spec not faithful: %#v", m.Spec)
	}
	// The Cognito password policy is a declared caveat (the realm applies its own).
	if len(m.Caveats) == 0 || !strings.Contains(strings.Join(m.Caveats, " "), "Policies") {
		t.Fatalf("Policies should surface a caveat: %v", m.Caveats)
	}
}

// MFA enforcement and Lambda triggers are behavior-bearing with no faithful mapping — they block.
func TestTranslate_CognitoUserPool_MfaAndTriggersBlock(t *testing.T) {
	_, fs := translateCognitoUserPool("Pool", map[string]any{"MfaConfiguration": "ON"}, nil)
	if !strings.Contains(findingsText(fs), "MfaConfiguration") {
		t.Fatalf("MFA ON must block, findings: %s", findingsText(fs))
	}
	_, fs2 := translateCognitoUserPool("Pool", map[string]any{
		"LambdaConfig": map[string]any{"PreSignUp": "arn:aws:lambda:x"},
	}, nil)
	if !strings.Contains(findingsText(fs2), "LambdaConfig") {
		t.Fatalf("Lambda triggers must block, findings: %s", findingsText(fs2))
	}
}

// ecsCtx parses an ECS template and returns the stack context a collating translator needs.
func ecsCtx(t *testing.T, tmpl string) *stackCtx {
	tt, err := Parse([]byte(tmpl))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := newResolver(tt, resolveParams(tt, nil), pseudoParams("s"))
	r.evalConditions()
	return &stackCtx{template: tt, resolver: r}
}

func ecsResolvedService(t *testing.T, ctx *stackCtx, id string) map[string]any {
	res := ctx.template.Resources[id]
	ctx.resolver.where = "Resource " + id
	m, _ := ctx.resolver.resolve(res.Properties).(map[string]any)
	return m
}

// An ECS Service + its referenced TaskDefinition collate into one Application.
func TestTranslate_ECSService_Collates(t *testing.T) {
	tmpl := `
Resources:
  Web:
    Type: AWS::ECS::Cluster
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Cpu: "256"
      ContainerDefinitions:
        - Name: app
          Image: registry/app:1
          PortMappings: [{ ContainerPort: 8080 }]
          Environment: [{ Name: TIER, Value: prod }]
  Svc:
    Type: AWS::ECS::Service
    Properties:
      Cluster: !Ref Web
      TaskDefinition: !Ref Task
      DesiredCount: 3
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateECSService("Svc", ecsResolvedService(t, ctx, "Svc"), ctx)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "Application" || m.Spec["image"] != "registry/app:1" || m.Spec["port"] != 8080 {
		t.Fatalf("collation not faithful: %#v", m.Spec)
	}
	sc, _ := m.Spec["scaling"].(map[string]any)
	if sc["min"] != 3 || sc["max"] != 3 {
		t.Fatalf("DesiredCount should map to a fixed replica count: %#v", m.Spec["scaling"])
	}
	if env, _ := m.Spec["env"].([]any); len(env) != 1 {
		t.Fatalf("container env should map: %#v", m.Spec["env"])
	}
	if !strings.Contains(strings.Join(m.Caveats, " "), "Cpu") {
		t.Fatalf("task Cpu should surface a caveat: %v", m.Caveats)
	}
	// The Cluster and a bare TaskDefinition are no-ops (nil manifest, no findings).
	if mc, fc := translateECSCluster("Web", nil, ctx); mc != nil || len(fc) != 0 {
		t.Fatalf("ECS Cluster should be a no-op, got %v / %v", mc, fc)
	}
	if mt, ft := translateECSTaskDefinition("Task", nil, ctx); mt != nil || len(ft) != 0 {
		t.Fatalf("a bare TaskDefinition should be a no-op, got %v / %v", mt, ft)
	}
}

// A multi-container task can't map (Application runs one container) — refuse.
func TestTranslate_ECSService_MultiContainerRefused(t *testing.T) {
	tmpl := `
Resources:
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - { Name: app, Image: a:1 }
        - { Name: sidecar, Image: b:1 }
  Svc:
    Type: AWS::ECS::Service
    Properties: { TaskDefinition: !Ref Task, DesiredCount: 1 }
`
	ctx := ecsCtx(t, tmpl)
	_, fs := translateECSService("Svc", ecsResolvedService(t, ctx, "Svc"), ctx)
	if !strings.Contains(findingsText(fs), "one container") {
		t.Fatalf("a multi-container task must refuse, findings: %s", findingsText(fs))
	}
}

// A container Command override has no Application field — refuse rather than ignore.
func TestTranslate_ECSService_CommandRefused(t *testing.T) {
	tmpl := `
Resources:
  Task:
    Type: AWS::ECS::TaskDefinition
    Properties:
      ContainerDefinitions:
        - { Name: app, Image: a:1, Command: ["/bin/run"] }
  Svc:
    Type: AWS::ECS::Service
    Properties: { TaskDefinition: !Ref Task, DesiredCount: 1 }
`
	ctx := ecsCtx(t, tmpl)
	_, fs := translateECSService("Svc", ecsResolvedService(t, ctx, "Svc"), ctx)
	if !strings.Contains(findingsText(fs), "Command") {
		t.Fatalf("a Command override must refuse, findings: %s", findingsText(fs))
	}
}

// ---- AWS::DynamoDB::Table ----

func TestTranslate_DynamoDBTable_Faithful(t *testing.T) {
	m, fs := translateDynamoDBTable("Sessions", map[string]any{
		"TableName": "sessions",
		"AttributeDefinitions": []any{
			map[string]any{"AttributeName": "pk", "AttributeType": "S"},
			map[string]any{"AttributeName": "sk", "AttributeType": "N"},
		},
		"KeySchema": []any{
			map[string]any{"AttributeName": "pk", "KeyType": "HASH"},
			map[string]any{"AttributeName": "sk", "KeyType": "RANGE"},
		},
		"BillingMode":             "PAY_PER_REQUEST",
		"TimeToLiveSpecification": map[string]any{"Enabled": true, "AttributeName": "exp"},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "Table" || m.Name != "sessions" || m.APIVersion != "openinfra.dev/v1" {
		t.Fatalf("bad manifest head: %+v", m)
	}
	if m.Spec["tableName"] != "sessions" || m.Spec["ttlAttribute"] != "exp" || m.Spec["billingMode"] != "PAY_PER_REQUEST" {
		t.Fatalf("spec not faithful: %#v", m.Spec)
	}
	hk, _ := m.Spec["hashKey"].(map[string]any)
	rk, _ := m.Spec["rangeKey"].(map[string]any)
	if hk["name"] != "pk" || hk["type"] != "S" || rk["name"] != "sk" || rk["type"] != "N" {
		t.Fatalf("key schema not faithful: hash=%#v range=%#v", hk, rk)
	}
	// The opt-in / data-plane caveat must always be surfaced.
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "aws-shim DynamoDB front door is enabled") {
		t.Fatalf("the opt-in caveat must be declared, caveats: %v", m.Caveats)
	}
}

func TestTranslate_DynamoDBTable_MissingKeyTypeBlocks(t *testing.T) {
	// KeySchema names a key attribute that AttributeDefinitions never types — unguessable, blocks.
	_, fs := translateDynamoDBTable("T", map[string]any{
		"AttributeDefinitions": []any{map[string]any{"AttributeName": "other", "AttributeType": "S"}},
		"KeySchema":            []any{map[string]any{"AttributeName": "id", "KeyType": "HASH"}},
	}, nil)
	if !strings.Contains(findingsText(fs), "no matching AttributeDefinitions") {
		t.Fatalf("an untyped key attribute must block, findings: %s", findingsText(fs))
	}
}

func TestTranslate_DynamoDBTable_ProvisionedThroughputIsCaveatNotBlock(t *testing.T) {
	m, fs := translateDynamoDBTable("T", map[string]any{
		"AttributeDefinitions":  []any{map[string]any{"AttributeName": "id", "AttributeType": "S"}},
		"KeySchema":             []any{map[string]any{"AttributeName": "id", "KeyType": "HASH"}},
		"ProvisionedThroughput": map[string]any{"ReadCapacityUnits": float64(5), "WriteCapacityUnits": float64(5)},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("throughput must not block (it is inert here), findings: %s", findingsText(fs))
	}
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "ProvisionedThroughput") {
		t.Fatalf("ProvisionedThroughput must be a declared caveat, caveats: %v", m.Caveats)
	}
}

// ---- AWS::AppSync::* collation ----

func appsyncStack() string {
	return `
Resources:
  Api:
    Type: AWS::AppSync::GraphQLApi
    Properties:
      Name: todo-api
      AuthenticationType: API_KEY
  Schema:
    Type: AWS::AppSync::GraphQLSchema
    Properties:
      ApiId: !GetAtt Api.ApiId
      Definition: "type Query { getTodo(id: ID!): Todo } type Todo { id: ID! title: String }"
  TodoDS:
    Type: AWS::AppSync::DataSource
    Properties:
      ApiId: !GetAtt Api.ApiId
      Name: todo_table
      Type: AMAZON_DYNAMODB
      DynamoDBConfig: { TableName: todos }
  GetTodo:
    Type: AWS::AppSync::Resolver
    Properties:
      ApiId: !GetAtt Api.ApiId
      TypeName: Query
      FieldName: getTodo
      DataSourceName: !GetAtt TodoDS.Name
      RequestMappingTemplate: '{"version":"2017-02-28","operation":"GetItem"}'
      ResponseMappingTemplate: '$util.toJson($ctx.result)'
`
}

func TestTranslate_AppSync_Collation(t *testing.T) {
	ctx := ecsCtx(t, appsyncStack())
	m, fs := translateAppSyncGraphQLApi("Api", ecsResolvedService(t, ctx, "Api"), ctx)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "GraphQLApi" || m.Name != "api" {
		t.Fatalf("bad manifest head: %+v", m)
	}
	if s, _ := m.Spec["schema"].(string); !strings.Contains(s, "getTodo") {
		t.Fatalf("schema not collated: %v", m.Spec["schema"])
	}
	ds, _ := m.Spec["dataSources"].([]any)
	if len(ds) != 1 {
		t.Fatalf("want 1 data source, got %#v", m.Spec["dataSources"])
	}
	d0, _ := ds[0].(map[string]any)
	if d0["name"] != "todo_table" || d0["type"] != "dynamodb" || d0["collection"] != "todos" {
		t.Fatalf("data source not faithful: %#v", d0)
	}
	rs, _ := m.Spec["resolvers"].([]any)
	if len(rs) != 1 {
		t.Fatalf("want 1 resolver, got %#v", m.Spec["resolvers"])
	}
	r0, _ := rs[0].(map[string]any)
	if r0["type"] != "Query" || r0["field"] != "getTodo" || r0["dataSource"] != "todo_table" || r0["runtime"] != "appsync-vtl" {
		t.Fatalf("resolver not faithful: %#v", r0)
	}
	// The whole point: VTL carries over byte-for-byte.
	if req, _ := r0["request"].(string); !strings.Contains(req, `"operation":"GetItem"`) {
		t.Fatalf("request VTL not verbatim: %#v", r0["request"])
	}
	if resp, _ := r0["response"].(string); !strings.Contains(resp, "$util.toJson") {
		t.Fatalf("response VTL not verbatim: %#v", r0["response"])
	}
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "mongoURI") {
		t.Fatalf("a dynamodb source must surface the mongoURI caveat, caveats: %v", m.Caveats)
	}
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "AuthenticationType") {
		t.Fatalf("AuthenticationType must be a declared caveat, caveats: %v", m.Caveats)
	}
}

func TestTranslate_AppSync_Pipeline(t *testing.T) {
	tmpl := `
Resources:
  Api:
    Type: AWS::AppSync::GraphQLApi
    Properties: { Name: p, AuthenticationType: AWS_IAM }
  HttpDS:
    Type: AWS::AppSync::DataSource
    Properties:
      ApiId: !GetAtt Api.ApiId
      Name: backend
      Type: HTTP
      HttpConfig: { Endpoint: "https://svc.internal" }
  Fn1:
    Type: AWS::AppSync::FunctionConfiguration
    Properties:
      ApiId: !GetAtt Api.ApiId
      Name: step1
      DataSourceName: !GetAtt HttpDS.Name
      RequestMappingTemplate: 'REQ1'
      ResponseMappingTemplate: 'RESP1'
  Pipe:
    Type: AWS::AppSync::Resolver
    Properties:
      ApiId: !GetAtt Api.ApiId
      TypeName: Mutation
      FieldName: doThing
      Kind: PIPELINE
      RequestMappingTemplate: 'BEFORE'
      ResponseMappingTemplate: 'AFTER'
      PipelineConfig: { Functions: [ !GetAtt Fn1.FunctionId ] }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateAppSyncGraphQLApi("Api", ecsResolvedService(t, ctx, "Api"), ctx)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	rs, _ := m.Spec["resolvers"].([]any)
	if len(rs) != 1 {
		t.Fatalf("want 1 resolver, got %#v", m.Spec["resolvers"])
	}
	r0, _ := rs[0].(map[string]any)
	if r0["before"] != "BEFORE" || r0["after"] != "AFTER" {
		t.Fatalf("pipeline before/after not mapped: %#v", r0)
	}
	fns, _ := r0["functions"].([]any)
	if len(fns) != 1 {
		t.Fatalf("want 1 pipeline function, got %#v", r0["functions"])
	}
	f0, _ := fns[0].(map[string]any)
	if f0["dataSource"] != "backend" || f0["request"] != "REQ1" || f0["response"] != "RESP1" {
		t.Fatalf("pipeline function not faithful: %#v", f0)
	}
}

func TestTranslate_AppSync_LambdaDataSourceBlocks(t *testing.T) {
	tmpl := `
Resources:
  Api:
    Type: AWS::AppSync::GraphQLApi
    Properties: { Name: l, AuthenticationType: API_KEY }
  LDS:
    Type: AWS::AppSync::DataSource
    Properties:
      ApiId: !GetAtt Api.ApiId
      Name: fn
      Type: AWS_LAMBDA
      LambdaConfig: { LambdaFunctionArn: "arn:aws:lambda:us-east-1:1:function:x" }
  R:
    Type: AWS::AppSync::Resolver
    Properties: { ApiId: !GetAtt Api.ApiId, TypeName: Query, FieldName: f, DataSourceName: !GetAtt LDS.Name, RequestMappingTemplate: x, ResponseMappingTemplate: y }
`
	ctx := ecsCtx(t, tmpl)
	_, fs := translateAppSyncGraphQLApi("Api", ecsResolvedService(t, ctx, "Api"), ctx)
	if !strings.Contains(findingsText(fs), "Lambda data source") {
		t.Fatalf("a Lambda-ARN data source must block, findings: %s", findingsText(fs))
	}
}

func TestTranslate_AppSync_NoResolverBlocks(t *testing.T) {
	tmpl := `
Resources:
  Api:
    Type: AWS::AppSync::GraphQLApi
    Properties: { Name: n, AuthenticationType: API_KEY }
`
	ctx := ecsCtx(t, tmpl)
	_, fs := translateAppSyncGraphQLApi("Api", ecsResolvedService(t, ctx, "Api"), ctx)
	if !strings.Contains(findingsText(fs), "at least one") {
		t.Fatalf("a GraphQLApi with no resolver must block, findings: %s", findingsText(fs))
	}
}

func TestTranslate_AppSync_ChildNoopVsExternal(t *testing.T) {
	ctx := ecsCtx(t, appsyncStack())
	// A child whose ApiId points at the in-stack API is a collated no-op.
	if m, fs := translateAppSyncChild("TodoDS", ecsResolvedService(t, ctx, "TodoDS"), ctx); m != nil || len(fs) != 0 {
		t.Fatalf("an in-stack child must be a no-op, got manifest=%v findings=%s", m, findingsText(fs))
	}
	// A child pointing at an API not in the stack must refuse (no silent drop).
	ext := ecsCtx(t, `
Resources:
  Orphan:
    Type: AWS::AppSync::DataSource
    Properties: { ApiId: "external-api-id", Name: x, Type: NONE }
`)
	if _, fs := translateAppSyncChild("Orphan", ecsResolvedService(t, ext, "Orphan"), ext); !strings.Contains(findingsText(fs), "in-stack API") {
		t.Fatalf("a child of an external API must refuse, findings: %s", findingsText(fs))
	}
}

// ---- data-only Application translators: RDS / S3 / SQS / SNS ----

func TestTranslate_RDS_Faithful(t *testing.T) {
	m, fs := translateRDSDBInstance("Db", map[string]any{
		"Engine": "postgres", "DBName": "app", "MultiAZ": true,
		"AllocatedStorage": float64(20), "DBInstanceClass": "db.t3.medium",
		"MasterUsername": "admin", "MasterUserPassword": "x",
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Kind != "Application" || m.Name != "db" {
		t.Fatalf("bad manifest head: %+v", m)
	}
	db, _ := m.Spec["database"].(map[string]any)
	if db["engine"] != "postgres" || db["name"] != "app" || db["highAvailability"] != true {
		t.Fatalf("database not faithful: %#v", db)
	}
	joined := strings.Join(m.Caveats, "\n")
	if !strings.Contains(joined, "AllocatedStorage") || !strings.Contains(joined, "MasterUsername") {
		t.Fatalf("capacity/credentials must be declared caveats: %v", m.Caveats)
	}
}

func TestTranslate_RDS_EncryptedBlocks(t *testing.T) {
	_, fs := translateRDSDBInstance("Db", map[string]any{"Engine": "mysql", "StorageEncrypted": true}, nil)
	if !strings.Contains(findingsText(fs), "StorageEncrypted") {
		t.Fatalf("StorageEncrypted must block, findings: %s", findingsText(fs))
	}
}

func TestTranslate_RDS_UnmappableEngineBlocks(t *testing.T) {
	_, fs := translateRDSDBInstance("Db", map[string]any{"Engine": "oracle-ee"}, nil)
	if !strings.Contains(findingsText(fs), "no open-infra engine") {
		t.Fatalf("an unmappable engine must block, findings: %s", findingsText(fs))
	}
}

func TestTranslate_S3_Faithful(t *testing.T) {
	m, fs := translateS3Bucket("Assets", map[string]any{"BucketName": "my-assets"}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	st, _ := m.Spec["storage"].(map[string]any)
	b, _ := st["buckets"].([]any)
	if len(b) != 1 || b[0] != "my-assets" {
		t.Fatalf("bucket not faithful: %#v", m.Spec["storage"])
	}
}

func TestTranslate_S3_VersioningBlocks(t *testing.T) {
	_, fs := translateS3Bucket("B", map[string]any{
		"BucketName": "b", "VersioningConfiguration": map[string]any{"Status": "Enabled"},
	}, nil)
	if !strings.Contains(findingsText(fs), "VersioningConfiguration") {
		t.Fatalf("a behavior-bearing S3 feature must block, findings: %s", findingsText(fs))
	}
}

// ---- AWS::Cognito::UserPoolClient collation ----

func cognitoStack() string {
	return `
Resources:
  Pool:
    Type: AWS::Cognito::UserPool
    Properties: { UserPoolName: my-pool }
  Client:
    Type: AWS::Cognito::UserPoolClient
    Properties:
      UserPoolId: !Ref Pool
      ClientName: web-app
      GenerateSecret: true
      CallbackURLs: [ "https://app.example/cb" ]
`
}

func TestTranslate_Cognito_ClientCollation(t *testing.T) {
	ctx := ecsCtx(t, cognitoStack())
	m, fs := translateCognitoUserPool("Pool", ecsResolvedService(t, ctx, "Pool"), ctx)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	if m.Spec["realm"] != "my-pool" || m.Spec["clientId"] != "web-app" {
		t.Fatalf("client not collated into the pool: %#v", m.Spec)
	}
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "OAuth config") {
		t.Fatalf("the dropped client OAuth config must be a caveat: %v", m.Caveats)
	}
	// The client itself is a collated no-op.
	if cm, cfs := translateCognitoUserPoolClient("Client", ecsResolvedService(t, ctx, "Client"), ctx); cm != nil || len(cfs) != 0 {
		t.Fatalf("an in-stack client must be a no-op, got manifest=%v findings=%s", cm, findingsText(cfs))
	}
}

func TestTranslate_Cognito_MultipleClientsBlock(t *testing.T) {
	tmpl := `
Resources:
  Pool:
    Type: AWS::Cognito::UserPool
    Properties: { UserPoolName: p }
  C1:
    Type: AWS::Cognito::UserPoolClient
    Properties: { UserPoolId: !Ref Pool, ClientName: a }
  C2:
    Type: AWS::Cognito::UserPoolClient
    Properties: { UserPoolId: !Ref Pool, ClientName: b }
`
	ctx := ecsCtx(t, tmpl)
	_, fs := translateCognitoUserPool("Pool", ecsResolvedService(t, ctx, "Pool"), ctx)
	if !strings.Contains(findingsText(fs), "more than one") {
		t.Fatalf("multiple clients must block (pool has one app client), findings: %s", findingsText(fs))
	}
}

func TestTranslate_Cognito_ExternalClientRefused(t *testing.T) {
	ext := ecsCtx(t, `
Resources:
  Orphan:
    Type: AWS::Cognito::UserPoolClient
    Properties: { UserPoolId: "us-east-1_external", ClientName: x }
`)
	if _, fs := translateCognitoUserPoolClient("Orphan", ecsResolvedService(t, ext, "Orphan"), ext); !strings.Contains(findingsText(fs), "in-stack pool") {
		t.Fatalf("a client of an external pool must refuse, findings: %s", findingsText(fs))
	}
}

func TestTranslate_DynamoDBTable_GSI_Faithful(t *testing.T) {
	m, fs := translateDynamoDBTable("Users", map[string]any{
		"AttributeDefinitions": []any{
			map[string]any{"AttributeName": "id", "AttributeType": "S"},
			map[string]any{"AttributeName": "email", "AttributeType": "S"},
			map[string]any{"AttributeName": "created", "AttributeType": "N"},
		},
		"KeySchema": []any{map[string]any{"AttributeName": "id", "KeyType": "HASH"}},
		"GlobalSecondaryIndexes": []any{
			map[string]any{
				"IndexName": "by-email",
				"KeySchema": []any{
					map[string]any{"AttributeName": "email", "KeyType": "HASH"},
					map[string]any{"AttributeName": "created", "KeyType": "RANGE"},
				},
				"Projection":            map[string]any{"ProjectionType": "ALL"},
				"ProvisionedThroughput": map[string]any{"ReadCapacityUnits": float64(5), "WriteCapacityUnits": float64(5)},
			},
		},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %s", findingsText(fs))
	}
	gsis, _ := m.Spec["globalSecondaryIndexes"].([]any)
	if len(gsis) != 1 {
		t.Fatalf("want 1 GSI, got %#v", m.Spec["globalSecondaryIndexes"])
	}
	g0, _ := gsis[0].(map[string]any)
	hk, _ := g0["hashKey"].(map[string]any)
	rk, _ := g0["rangeKey"].(map[string]any)
	if g0["name"] != "by-email" || hk["name"] != "email" || hk["type"] != "S" || rk["name"] != "created" || rk["type"] != "N" {
		t.Fatalf("GSI not faithful: %#v", g0)
	}
	// per-GSI throughput is a caveat, not a block.
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "ProvisionedThroughput") {
		t.Fatalf("per-GSI throughput must be a caveat: %v", m.Caveats)
	}
}

func TestTranslate_DynamoDBTable_GSI_UntypedKeyBlocks(t *testing.T) {
	_, fs := translateDynamoDBTable("T", map[string]any{
		"AttributeDefinitions": []any{map[string]any{"AttributeName": "id", "AttributeType": "S"}},
		"KeySchema":            []any{map[string]any{"AttributeName": "id", "KeyType": "HASH"}},
		"GlobalSecondaryIndexes": []any{map[string]any{
			"IndexName": "bad", "KeySchema": []any{map[string]any{"AttributeName": "ghost", "KeyType": "HASH"}},
		}},
	}, nil)
	if !strings.Contains(findingsText(fs), "no matching AttributeDefinitions") {
		t.Fatalf("a GSI key with no typed AttributeDefinition must block, findings: %s", findingsText(fs))
	}
}

// Local secondary indexes still block (not modeled).
func TestTranslate_DynamoDBTable_LSIBlocks(t *testing.T) {
	_, fs := translateDynamoDBTable("T", map[string]any{
		"AttributeDefinitions":  []any{map[string]any{"AttributeName": "id", "AttributeType": "S"}},
		"KeySchema":             []any{map[string]any{"AttributeName": "id", "KeyType": "HASH"}},
		"LocalSecondaryIndexes": []any{map[string]any{"IndexName": "lsi"}},
	}, nil)
	if !strings.Contains(findingsText(fs), "LocalSecondaryIndexes") {
		t.Fatalf("LSI must still block, findings: %s", findingsText(fs))
	}
}
