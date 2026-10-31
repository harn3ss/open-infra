package cfn

import (
	"strings"
	"testing"
)

const iamRoleTmpl = `
Resources:
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      Description: app instance role
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" }
      ManagedPolicyArns: [arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore]
      Policies:
        - PolicyName: app-access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - { Effect: Allow, Action: ["s3:GetObject", "s3:ListBucket"], Resource: "arn:aws:s3:::app-config/*" }
              - { Effect: Allow, Action: ["sqs:SendMessage", "sqs:ReceiveMessage"], Resource: "arn:aws:sqs:us-east-1:1:app-queue" }
  UserRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { AWS: "arn:aws:iam::123456789012:root" }, Action: "sts:AssumeRole" }
  AppProfile:
    Type: AWS::IAM::InstanceProfile
    Properties: { Roles: [ { Ref: AppRole } ] }
  AppInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      IamInstanceProfile: { Ref: AppProfile }
`

// An EC2 instance-trust role (Principal: ec2.amazonaws.com) translates to a kind: Role that trusts the
// "vm" service principal, and its inline Policies become companion kind: Policy objects (data-plane)
// that govern the role's assumed sessions — so a VM booted from it actually HAS s3/sqs permissions.
// ManagedPolicyArns (AWS-service plumbing) stay a loud caveat.
func TestTranslate_IAMRole_Ec2TrustToVm(t *testing.T) {
	ctx := ecsCtx(t, iamRoleTmpl)
	m, fs := translateIAMRole("AppRole", resolvedProps(t, ctx, "AppRole"), ctx)
	if len(fs) != 0 {
		t.Fatalf("an ec2-trust role with an s3/sqs inline policy must translate cleanly: %s", findingsText(fs))
	}
	if m.Kind != "Role" || m.APIVersion != "iam.openinfra.dev/v1" {
		t.Fatalf("bad head: %+v", m)
	}
	trust, _ := m.Spec["trust"].([]any)
	if len(trust) != 1 || trust[0] != "vm" {
		t.Fatalf("ec2.amazonaws.com trust must map to spec.trust: [vm], got %#v", m.Spec["trust"])
	}
	// The inline policy is now a companion kind: Policy (data-plane), applied to this role.
	if len(m.Extra) != 1 {
		t.Fatalf("the inline Policy must become 1 companion kind: Policy, got %d", len(m.Extra))
	}
	pol := m.Extra[0]
	if pol.Kind != "Policy" || pol.Name != "approle-app-access" {
		t.Fatalf("companion policy head wrong: kind=%q name=%q", pol.Kind, pol.Name)
	}
	dp, _ := pol.Spec["dataPlane"].(map[string]any)
	at, _ := dp["appliesTo"].([]any)
	if len(at) != 1 || at[0] != "Role::approle" {
		t.Fatalf("companion policy must applyTo Role::approle, got %#v", dp["appliesTo"])
	}
	flat := strings.ToLower(strings.Join(deepStrings(dp["statements"]), " "))
	if !strings.Contains(flat, "s3:getobject") || !strings.Contains(flat, "sqs:sendmessage") {
		t.Fatalf("companion policy must carry the s3/sqs statements, got %#v", dp["statements"])
	}
	cav := strings.Join(m.Caveats, "\n")
	if !strings.Contains(cav, "inline Policies translated to 1 companion") || !strings.Contains(cav, "ManagedPolicyArns are NOT attached") {
		t.Fatalf("inline-translated + managed-deferred must surface as caveats: %v", m.Caveats)
	}
}

// An inline policy whose Resource is an in-stack resource's !GetAtt <X>.Arn (a bucket, a queue) is
// resolved to that resource's ARN before import, so the companion Policy scopes to the real resource
// instead of refusing an unresolvable <X.Arn> (#344 4.5).
func TestTranslate_IAMRole_InStackArnInInlinePolicy(t *testing.T) {
	tmpl := `
Resources:
  Config:
    Type: AWS::S3::Bucket
    Properties: { BucketName: app-config }
  Jobs:
    Type: AWS::SQS::Queue
    Properties: { QueueName: app-jobs }
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
      Policies:
        - PolicyName: app
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - { Effect: Allow, Action: "s3:GetObject", Resource: !GetAtt Config.Arn }
              - { Effect: Allow, Action: "sqs:SendMessage", Resource: !GetAtt Jobs.Arn }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateIAMRole("AppRole", resolvedProps(t, ctx, "AppRole"), ctx)
	if len(fs) != 0 {
		t.Fatalf("an in-stack !GetAtt .Arn Resource must resolve, not refuse: %s", findingsText(fs))
	}
	if len(m.Extra) != 1 {
		t.Fatalf("want 1 companion Policy, got %d", len(m.Extra))
	}
	dp, _ := m.Extra[0].Spec["dataPlane"].(map[string]any)
	flat := strings.ToLower(strings.Join(deepStrings(dp["statements"]), " "))
	// The companion policy must scope to the in-stack bucket + queue by their AWS names.
	if !strings.Contains(flat, "app-config") || !strings.Contains(flat, "app-jobs") {
		t.Fatalf("the in-stack ARNs must resolve to the bucket/queue names, got %#v", dp["statements"])
	}
}

// #347 Phase 0.4 (regression): an inline Policies entry wrapped in !If must resolve to its chosen
// branch, not be read as a literal {Fn::If: ...} map with no PolicyDocument and refused. The fix
// resolves the WHOLE raw Policies list (synthInStackARNs + resolve) before reading entries, so the
// !If evaluates and an AWS::NoValue branch drops out.
func TestTranslate_IAMRole_InlinePolicyIfResolves(t *testing.T) {
	tmpl := `
Parameters:
  Extra: { Type: String, Default: "true" }
Conditions:
  ExtraOn: !Equals [!Ref Extra, "true"]
Resources:
  Config:
    Type: AWS::S3::Bucket
    Properties: { BucketName: app-config }
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
      Policies:
        - !If
          - ExtraOn
          - PolicyName: app
            PolicyDocument:
              Version: "2012-10-17"
              Statement:
                - { Effect: Allow, Action: "s3:GetObject", Resource: !GetAtt Config.Arn }
          - !Ref AWS::NoValue
`
	// ON (default): the !If resolves to its first branch and becomes a companion Policy. Before
	// the fix the raw entry was the literal {Fn::If: ...} with no PolicyDocument, so it refused.
	on := ecsCtx(t, tmpl)
	m, fs := translateIAMRole("AppRole", resolvedProps(t, on, "AppRole"), on)
	if len(fs) != 0 {
		t.Fatalf("an !If-wrapped inline policy must resolve, not refuse: %s", findingsText(fs))
	}
	if len(m.Extra) != 1 {
		t.Fatalf("want 1 companion Policy from the ON branch, got %d", len(m.Extra))
	}
	dp, _ := m.Extra[0].Spec["dataPlane"].(map[string]any)
	flat := strings.ToLower(strings.Join(deepStrings(dp["statements"]), " "))
	if !strings.Contains(flat, "app-config") {
		t.Fatalf("the resolved policy must scope to the in-stack bucket, got %#v", dp["statements"])
	}
	// OFF: the entry resolves to AWS::NoValue and drops out — no companion, and no finding (a
	// conditioned-off inline policy is absent, not an error).
	off := ctxWithParams(t, tmpl, map[string]string{"Extra": "false"})
	mOff, fsOff := translateIAMRole("AppRole", resolvedProps(t, off, "AppRole"), off)
	if len(fsOff) != 0 {
		t.Fatalf("a conditioned-OFF inline policy must not produce a finding: %s", findingsText(fsOff))
	}
	if len(mOff.Extra) != 0 {
		t.Fatalf("the OFF branch must yield no companion Policy, got %d", len(mOff.Extra))
	}
}

// A role trusting anything other than the ec2 service (here an AWS account principal) refuses —
// no template-derivable open-infra trust.
func TestTranslate_IAMRole_NonEc2TrustRefuses(t *testing.T) {
	ctx := ecsCtx(t, iamRoleTmpl)
	_, fs := translateIAMRole("UserRole", resolvedProps(t, ctx, "UserRole"), ctx)
	if !strings.Contains(findingsText(fs), "ec2.amazonaws.com service principal") {
		t.Fatalf("a non-ec2-trust role must refuse with help, got: %s", findingsText(fs))
	}
}

// An instance profile provisions nothing on its own (implicit) — the binding is on the VM.
func TestTranslate_IAMInstanceProfile_Implicit(t *testing.T) {
	m, fs := translateIAMInstanceProfile("AppProfile", map[string]any{"Roles": []any{map[string]any{"Ref": "AppRole"}}}, nil)
	if m != nil || len(fs) != 0 {
		t.Fatalf("an instance profile must be an implicit no-op, got m=%v fs=%s", m, findingsText(fs))
	}
}

// An EC2 instance whose IamInstanceProfile !Refs an in-stack profile binds spec.instanceRole to the
// profile's in-stack role — the EC2 instance-profile → VM role analog.
func TestTranslate_EC2Instance_IamInstanceProfileToRole(t *testing.T) {
	ctx := ecsCtx(t, iamRoleTmpl)
	m, fs := translateEC2Instance("AppInstance", resolvedProps(t, ctx, "AppInstance"), ctx)
	if len(fs) != 0 {
		t.Fatalf("the instance must translate cleanly: %s", findingsText(fs))
	}
	if m.Spec["instanceRole"] != "approle" {
		t.Fatalf("IamInstanceProfile should resolve to spec.instanceRole=approle, got %#v", m.Spec["instanceRole"])
	}
}

// Plan-level: with the Role/InstanceProfile translators, a role+profile+instance stack has no gated
// IAM resources — the Role is create-deployable, the profile implicit.
func TestPlan_InstanceRoleChainDeployable(t *testing.T) {
	p := mustPlan(t, []byte(iamRoleTmpl), nil, "s")
	for _, r := range p.Resources {
		if r.CFNType == "AWS::IAM::Role" && r.LogicalID == "AppRole" && !r.Deployable {
			t.Errorf("an ec2-trust Role should be create-deployable")
		}
		if r.CFNType == "AWS::IAM::InstanceProfile" && !r.Deployable {
			t.Errorf("an InstanceProfile should be create-deployable (implicit)")
		}
	}
}

// resolvedProps resolves a resource's properties through the stack's resolver (so a literal field is
// usable and a !Ref stays followable via ctx.rawProps).
func resolvedProps(t *testing.T, ctx *stackCtx, id string) map[string]any {
	t.Helper()
	ctx.resolver.where = "Resource " + id
	m, _ := ctx.resolver.resolve(ctx.template.Resources[id].Properties).(map[string]any)
	return m
}
