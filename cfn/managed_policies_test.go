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
