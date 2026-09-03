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
