package cfn

import (
	"strings"
	"testing"
)

const lambdaRoleTmpl = `
Resources:
  Queue: { Type: AWS::SQS::Queue, Properties: { QueueName: jobs } }
  ExecRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [ { Effect: Allow, Principal: { Service: lambda.amazonaws.com }, Action: sts:AssumeRole } ]
      Policies:
        - PolicyName: send
          PolicyDocument:
            Version: "2012-10-17"
            Statement: [ { Effect: Allow, Action: sqs:SendMessage, Resource: !GetAtt Queue.Arn } ]
  InstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole } ]
  ByGetAtt:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, Role: !GetAtt ExecRole.Arn }
  BySub:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, Role: !Sub "arn:aws:iam::${AWS::AccountId}:role/shared-reader" }
  ByRef:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, Role: !Ref ExecRole }
  NotLambdaTrusted:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, Role: !GetAtt InstanceRole.Arn }
  OtherAccount:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, Role: "arn:aws:iam::210987654321:role/reader" }
  NotARole:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, Role: "arn:aws:iam::000000000000:user/alice" }
  NoRole:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" } }
`

// A Lambda function's Role is the execution role its code runs as: an in-stack role by !GetAtt <Role>.Arn
// is that role's kind: Role; a role ARN of the stack's account is kept as written. Lambda's own refusals
// are kept: a role named by !Ref (its name, not an ARN), a role that does not trust Lambda, another
// account's role, an ARN that is not a role.
func TestTranslate_LambdaRole(t *testing.T) {
	ctx := ecsCtx(t, lambdaRoleTmpl)
	fn := func(id string) (*Manifest, string) {
		t.Helper()
		m, fs := translateLambdaFunction(id, resolvedProps(t, ctx, id), ctx)
		return m, findingsText(fs)
	}
	if m, fs := fn("ByGetAtt"); fs != "" || m.Spec["role"] != ctx.name("ExecRole") {
		t.Errorf("!GetAtt ExecRole.Arn must name the in-stack role %q: role=%v findings=%s", ctx.name("ExecRole"), m.Spec["role"], fs)
	}
	if m, fs := fn("BySub"); fs != "" || m.Spec["role"] != "arn:aws:iam::"+ctx.account()+":role/shared-reader" {
		t.Errorf("a role ARN of the stack's account is kept as written: role=%v findings=%s", m.Spec["role"], fs)
	}
	for id, want := range map[string]string{
		"ByRef":            "!Ref gives the role's name",
		"NotLambdaTrusted": "does not trust lambda.amazonaws.com",
		"OtherAccount":     "must be a role of the stack's account",
		"NotARole":         "is not an IAM role ARN",
	} {
		if m, fs := fn(id); !strings.Contains(fs, want) || m.Spec["role"] != nil {
			t.Errorf("%s must refuse with %q: role=%v findings=%s", id, want, m.Spec["role"], fs)
		}
	}
	if m, fs := fn("NoRole"); fs != "" || m.Spec["role"] != nil {
		t.Errorf("a function with no Role has none: role=%v findings=%s", m.Spec["role"], fs)
	}
}

// A whole stack — an image function, its execution role trusting Lambda with an inline policy on an
// in-stack queue — plans with no blocker: the role is a kind: Role trusting the Lambda service, its policy a
// companion kind: Policy governing the role's sessions, and the function names the role.
func TestPlan_LambdaWithInStackExecutionRole(t *testing.T) {
	tmpl := `
Resources:
  Queue: { Type: AWS::SQS::Queue, Properties: { QueueName: jobs } }
  ExecRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [ { Effect: Allow, Principal: { Service: lambda.amazonaws.com }, Action: sts:AssumeRole } ]
      Policies:
        - PolicyName: send
          PolicyDocument:
            Version: "2012-10-17"
            Statement: [ { Effect: Allow, Action: sqs:SendMessage, Resource: !GetAtt Queue.Arn } ]
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, Role: !GetAtt ExecRole.Arn }
`
	p := mustPlan(t, []byte(tmpl), nil, "jobs")
	if p.Verdict == Rejected {
		t.Fatalf("a Lambda with an in-stack execution role must plan: %s", blockersJoined(p))
	}
	if a, b := idx(p.Order, "ExecRole"), idx(p.Order, "Fn"); a == -1 || b == -1 || a > b {
		t.Errorf("the role is provisioned before the function that names it: %v", p.Order)
	}
	ctx := ecsCtx(t, tmpl)
	role, fs := translateIAMRole("ExecRole", resolvedProps(t, ctx, "ExecRole"), ctx)
	if len(fs) != 0 {
		t.Fatalf("the execution role: %s", findingsText(fs))
	}
	if trust, _ := role.Spec["trust"].([]any); len(trust) != 1 || trust[0] != "Service::lambda.amazonaws.com" {
		t.Errorf("the execution role trusts the Lambda service: %#v", role.Spec["trust"])
	}
	if len(role.Extra) != 1 || role.Extra[0].Kind != "Policy" {
		t.Fatalf("its inline policy is a companion kind: Policy, got %d extras", len(role.Extra))
	}
	fn, fs := translateLambdaFunction("Fn", resolvedProps(t, ctx, "Fn"), ctx)
	if len(fs) != 0 || fn.Spec["role"] != role.Name {
		t.Errorf("the function names the role %q: %#v %s", role.Name, fn.Spec["role"], findingsText(fs))
	}
}
