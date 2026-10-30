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
          PolicyDocument: { Version: "2012-10-17", Statement: [] }
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

// An EC2 instance-trust role (Principal: ec2.amazonaws.com) translates to a kind: Role that trusts
// the "vm" service principal — the derivable part. Its inline/managed policies are deferred as loud
// caveats (a Role aggregates named Policies; one manifest per translator), never silently granted.
func TestTranslate_IAMRole_Ec2TrustToVm(t *testing.T) {
	ctx := ecsCtx(t, iamRoleTmpl)
	m, fs := translateIAMRole("AppRole", resolvedProps(t, ctx, "AppRole"), ctx)
	if len(fs) != 0 {
		t.Fatalf("an ec2-trust role must translate cleanly: %s", findingsText(fs))
	}
	if m.Kind != "Role" || m.APIVersion != "iam.openinfra.dev/v1" {
		t.Fatalf("bad head: %+v", m)
	}
	trust, _ := m.Spec["trust"].([]any)
	if len(trust) != 1 || trust[0] != "vm" {
		t.Fatalf("ec2.amazonaws.com trust must map to spec.trust: [vm], got %#v", m.Spec["trust"])
	}
	cav := strings.Join(m.Caveats, "\n")
	if !strings.Contains(cav, "inline Policies are NOT attached") || !strings.Contains(cav, "ManagedPolicyArns are NOT attached") {
		t.Fatalf("inline + managed policies must surface as caveats: %v", m.Caveats)
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
