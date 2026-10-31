package cfn

import (
	"strings"
	"testing"
)

// The shared collation helper (every uniform collator — cognito clients, appsync/apigw children, SG
// standalone rules — delegates to it) excludes a child the template gates OFF with a false Condition,
// and includes it when the condition is ON. This is the fail-open guard generalized across collations.
func TestCollatedChildren_ExcludesConditionedOff(t *testing.T) {
	tmpl := `
Parameters:
  Extra: { Type: String, Default: "false" }
Conditions:
  ExtraOn: !Equals [!Ref Extra, "true"]
Resources:
  Pool:
    Type: AWS::Cognito::UserPool
    Properties: { UserPoolName: p }
  ClientA:
    Type: AWS::Cognito::UserPoolClient
    Properties: { UserPoolId: !Ref Pool }
  ClientB:
    Type: AWS::Cognito::UserPoolClient
    Condition: ExtraOn
    Properties: { UserPoolId: !Ref Pool }
`
	off := ecsCtx(t, tmpl).collatedChildren("AWS::Cognito::UserPoolClient", "UserPoolId", "Pool")
	if len(off) != 1 || off[0] != "ClientA" {
		t.Fatalf("a conditioned-OFF child must be excluded — want [ClientA], got %v", off)
	}
	on := ctxWithParams(t, tmpl, map[string]string{"Extra": "true"}).collatedChildren("AWS::Cognito::UserPoolClient", "UserPoolId", "Pool")
	if len(on) != 2 {
		t.Fatalf("with the condition ON both children collate — want 2, got %v", on)
	}
}

// SECURITY (same class as the SG rule): a conditioned-OFF AWS::S3::BucketPolicy must NOT be collated
// into the bucket. Because the translator only accepts public "*" principals, a leaked policy is public
// by construction — so this is a real fail-open.
func TestTranslate_S3BucketPolicy_ConditionedOffNotCollated(t *testing.T) {
	tmpl := `
Parameters:
  MakePublic: { Type: String, Default: "false" }
Conditions:
  PublicOn: !Equals [!Ref MakePublic, "true"]
Resources:
  Assets:
    Type: AWS::S3::Bucket
    Properties: { BucketName: example-assets }
  AssetsPublicRead:
    Type: AWS::S3::BucketPolicy
    Condition: PublicOn
    Properties:
      Bucket: !Ref Assets
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::example-assets/*" }
`
	// OFF (default): the public policy must be absent.
	ctx := ecsCtx(t, tmpl)
	m, fs := translateS3Bucket("Assets", ecsResolvedService(t, ctx, "Assets"), ctx)
	if len(fs) != 0 {
		t.Fatalf("must translate cleanly: %s", findingsText(fs))
	}
	if _, has := m.Spec["policy"]; has {
		t.Fatalf("a conditioned-OFF BucketPolicy must NOT be collated, got spec.policy=%v", m.Spec["policy"])
	}
	// ON: the policy IS collated (proving the skip is condition-driven).
	on := ctxWithParams(t, tmpl, map[string]string{"MakePublic": "true"})
	mOn, _ := translateS3Bucket("Assets", ecsResolvedService(t, on, "Assets"), on)
	if _, has := mOn.Spec["policy"]; !has {
		t.Fatalf("with the condition ON the BucketPolicy must collate into spec.policy")
	}
}

// A BucketPolicy whose Resource is an intrinsic that only resolves to a generated bucket name (!Sub
// over a bucket with no explicit BucketName) refuses, rather than emitting a policy with a literal
// "<ref:...>" placeholder that would never match the real bucket.
func TestTranslate_S3BucketPolicy_UnresolvedArnRefuses(t *testing.T) {
	tmpl := `
Resources:
  Assets:
    Type: AWS::S3::Bucket
    Properties: {}
  AssetsPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Assets
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: "*", Action: "s3:GetObject", Resource: !Sub "arn:aws:s3:::${Assets}/*" }
`
	ctx := ecsCtx(t, tmpl)
	_, fs := translateS3Bucket("Assets", ecsResolvedService(t, ctx, "Assets"), ctx)
	if !strings.Contains(findingsText(fs), "unresolved intrinsic") {
		t.Fatalf("an unresolved !Sub ARN in a BucketPolicy must refuse, got: %s", findingsText(fs))
	}
}

// SECURITY (#347 Phase 0.3): the API Gateway collation walks — apigwAllOfType, apigwRestAPICount
// and apigwUsagePlanKeys — are bespoke (they predate collatedChildren), so each must filter
// conditioned-OFF resources itself. A gated-off ApiKey or UsagePlan attached anyway is a rule the
// template said to leave out, deployed silently; a gated-off second RestApi miscounts single-vs-multi.
func TestApigwCollation_ExcludesConditionedOff(t *testing.T) {
	tmpl := `
Parameters:
  Premium: { Type: String, Default: "false" }
Conditions:
  PremiumOn: !Equals [!Ref Premium, "true"]
Resources:
  Api:
    Type: AWS::ApiGateway::RestApi
    Properties: { Name: main }
  SecondApi:
    Type: AWS::ApiGateway::RestApi
    Condition: PremiumOn
    Properties: { Name: premium }
  KeyA:
    Type: AWS::ApiGateway::ApiKey
    Properties: { Name: base }
  KeyPremium:
    Type: AWS::ApiGateway::ApiKey
    Condition: PremiumOn
    Properties: { Name: premium }
  Plan:
    Type: AWS::ApiGateway::UsagePlan
    Properties: { UsagePlanName: plan }
  LinkBase:
    Type: AWS::ApiGateway::UsagePlanKey
    Properties: { UsagePlanId: !Ref Plan, KeyId: !Ref KeyA, KeyType: API_KEY }
  LinkPremium:
    Type: AWS::ApiGateway::UsagePlanKey
    Condition: PremiumOn
    Properties: { UsagePlanId: !Ref Plan, KeyId: !Ref KeyPremium, KeyType: API_KEY }
`
	// OFF (default): one API, one key, one plan-key link.
	off := ecsCtx(t, tmpl)
	if keys := off.apigwAllOfType("AWS::ApiGateway::ApiKey"); len(keys) != 1 || keys[0] != "KeyA" {
		t.Errorf("conditioned-OFF ApiKey must be excluded — want [KeyA], got %v", keys)
	}
	if n := off.apigwRestAPICount(); n != 1 {
		t.Errorf("conditioned-OFF RestApi must not be counted — want 1, got %d", n)
	}
	if pk := off.apigwUsagePlanKeys("Plan"); len(pk) != 1 || pk[0] != "KeyA" {
		t.Errorf("conditioned-OFF UsagePlanKey must be excluded — want [KeyA], got %v", pk)
	}
	// ON: both of each collate (proving the skip is condition-driven, not a parse miss).
	on := ctxWithParams(t, tmpl, map[string]string{"Premium": "true"})
	if keys := on.apigwAllOfType("AWS::ApiGateway::ApiKey"); len(keys) != 2 {
		t.Errorf("with the condition ON both ApiKeys collate — want 2, got %v", keys)
	}
	if n := on.apigwRestAPICount(); n != 2 {
		t.Errorf("with the condition ON both RestApis count — want 2, got %d", n)
	}
	if pk := on.apigwUsagePlanKeys("Plan"); len(pk) != 2 {
		t.Errorf("with the condition ON both UsagePlanKeys collate — want 2, got %v", pk)
	}
}

// snsQueuesForFunction (a bespoke collation) also excludes a conditioned-OFF subscription/topic.
func TestSnsQueuesForFunction_ExcludesConditionedOff(t *testing.T) {
	tmpl := `
Parameters:
  Wire: { Type: String, Default: "false" }
Conditions:
  WireOn: !Equals [!Ref Wire, "true"]
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/fn:latest } }
  Topic:
    Type: AWS::SNS::Topic
    Properties: { TopicName: events }
  Sub:
    Type: AWS::SNS::Subscription
    Condition: WireOn
    Properties: { Protocol: lambda, TopicArn: !Ref Topic, Endpoint: !GetAtt Fn.Arn }
`
	off := ecsCtx(t, tmpl).snsQueuesForFunction("Fn")
	if len(off) != 0 {
		t.Fatalf("a conditioned-OFF SNS subscription must fold no queue into the Function, got %v", off)
	}
	on := ctxWithParams(t, tmpl, map[string]string{"Wire": "true"}).snsQueuesForFunction("Fn")
	if len(on) != 1 || on[0] != "events" {
		t.Fatalf("with the condition ON the topic stream collates — want [events], got %v", on)
	}
}
