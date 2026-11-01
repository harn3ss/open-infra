package cfn

import (
	"strings"
	"testing"
)

// The AWS managed policies an instance role commonly attaches become companion data-plane policies of the
// role (the part open-infra serves); one it does not map stays a caveat, attaching nothing.
func TestRole_ManagedPolicyArnsAttachTheMappedOnes(t *testing.T) {
	order, err := buildManifests([]byte(`
Resources:
  R:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ]
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
        - arn:aws:iam::aws:policy/AdministratorAccess
`), DeployOptions{StackName: "app", Namespace: "n"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var cav string
	for _, b := range order {
		names = append(names, b.res.Name)
		cav += strings.Join(b.cav, "\n")
	}
	got := strings.Join(names, ",")
	if !strings.Contains(got, "-managed-amazonec2containerregistryreadonly") || !strings.Contains(got, "-managed-amazonssmmanagedinstancecore") {
		t.Fatalf("companions = %s", got)
	}
	if strings.Contains(got, "administratoraccess") {
		t.Fatalf("an unmapped managed policy must attach nothing: %s", got)
	}
	if !strings.Contains(cav, "AdministratorAccess are NOT attached") || !strings.Contains(cav, "Session Manager") {
		t.Fatalf("caveats = %s", cav)
	}
}

// A long stack name and a long policy name still give companion policy names that fit, unique per policy,
// and a name that already fits is left exactly as it was.
func TestRole_CompanionPolicyNamesFit(t *testing.T) {
	order, err := buildManifests([]byte(`
Resources:
  InstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: "sts:AssumeRole" } ]
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
        - arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
      Policies:
        - PolicyName: read-the-application-configuration-parameters-for-this-environment
          PolicyDocument: { Statement: [ { Effect: Allow, Action: "ssm:GetParameter", Resource: "*" } ] }
        - PolicyName: read-the-application-configuration-parameters-for-this-environment-too
          PolicyDocument: { Statement: [ { Effect: Allow, Action: "ssm:GetParameters", Resource: "*" } ] }
`), DeployOptions{StackName: "lsfix-0123abcd-with-a-long-name", Namespace: "n"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	n := 0
	for _, b := range order {
		if b.res.Kind != "Policy" {
			continue
		}
		n++
		name := b.res.Name
		if len(name) > 63 || !fnNameRE.MatchString(name) {
			t.Fatalf("companion policy name %q (%d chars) is not a valid 63-character name", name, len(name))
		}
		if seen[name] {
			t.Fatalf("companion policy name %q is not unique", name)
		}
		seen[name] = true
	}
	if n != 5 {
		t.Fatalf("got %d companion policies, want 5", n)
	}
	if got := companionPolicyName("approle", "managed-amazonssmmanagedinstancecore"); got != "approle-managed-amazonssmmanagedinstancecore" {
		t.Fatalf("a name that fits must not change: %q", got)
	}
}
