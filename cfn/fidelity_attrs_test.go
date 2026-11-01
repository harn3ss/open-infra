package cfn

import (
	"context"
	"strings"
	"testing"
)

func fidelityText(p *Plan) string {
	var b strings.Builder
	for _, f := range p.Fidelity {
		b.WriteString(f.Resource + ": " + f.Detail + "\n")
	}
	return b.String()
}

// Resource attributes open-infra does not act on are listed in the fidelity summary; an undefined
// resource key or DeletionPolicy value is refused, as CloudFormation refuses it.
func TestAttributes_ListedOrRefused(t *testing.T) {
	p := mustPlan(t, []byte(`
Resources:
  K:
    Type: AWS::KMS::Key
    UpdateReplacePolicy: Retain
    CreationPolicy: { ResourceSignal: { Count: 1, Timeout: PT5M } }
    UpdatePolicy: { AutoScalingRollingUpdate: {} }
    Metadata:
      AWS::CloudFormation::Init: { config: { packages: {} } }
      AWS::CloudFormation::Interface: { ParameterGroups: [] }
      team: payments
`), nil, "s")
	got := fidelityText(p)
	for _, want := range []string{"CreationPolicy ResourceSignal is not waited for", "UpdatePolicy is not honored",
		"UpdateReplacePolicy Retain has no effect", "AWS::CloudFormation::Init is not run", "Metadata (team) is not kept"} {
		if !strings.Contains(got, want) {
			t.Errorf("fidelity summary is missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Interface") {
		t.Errorf("authoring-only metadata must not be listed:\n%s", got)
	}
	if p.Verdict != ProvisionableWithCaveats {
		t.Errorf("a stack with fidelity lines is never cleanly PROVISIONABLE, got %s", p.Verdict)
	}

	bad := mustPlan(t, []byte(`
Resources:
  K:
    Type: AWS::KMS::Key
    DeletionPolicy: Keep
    Propertys: {}
`), nil, "s")
	all := strings.Join(bad.Blockers, "\n")
	if bad.Verdict != Rejected || !strings.Contains(all, `DeletionPolicy "Keep"`) || !strings.Contains(all, `"Propertys" is not a CloudFormation resource attribute`) {
		t.Errorf("want both refusals, got %s:\n%s", bad.Verdict, all)
	}
}

// When the translate gate cannot run, the summary says property-level fidelity was not checked rather
// than reading as "no losses".
func TestPlan_GateSkippedIsStated(t *testing.T) {
	p := mustPlan(t, []byte(`
Parameters:
  Need: { Type: String }
Resources:
  K: { Type: AWS::KMS::Key, Properties: { Description: !Ref Need } }
`), nil, "s")
	if p.GateSkipped == "" || !strings.Contains(fidelityText(p), "property-level fidelity was not checked") {
		t.Fatalf("want the skipped gate stated, got %q:\n%s", p.GateSkipped, fidelityText(p))
	}
}

// RetainExceptOnCreate keeps a resource through a stack delete, but a failed create removes it.
func TestDeletionPolicy_RetainExceptOnCreate(t *testing.T) {
	tmpl := []byte(`
Resources:
  KeyA:
    Type: AWS::KMS::Key
    DeletionPolicy: RetainExceptOnCreate
    Properties: { Description: a }
  KeyB:
    Type: AWS::KMS::Key
    DependsOn: KeyA
    Properties: { Description: b }
`)
	f := &fakeApplier{failOn: "EncryptionKey/s-keyb"}
	if _, err := Deploy(context.Background(), tmpl, deployOpts(), f); err == nil {
		t.Fatal("the create must fail")
	}
	if !contains(f.deleted, "EncryptionKey/s-keya") {
		t.Errorf("a failed create removes a RetainExceptOnCreate resource it created, deleted=%v", f.deleted)
	}
	f = deployTemplate(t, tmpl)
	if _, err := Destroy(context.Background(), deployOpts(), f); err != nil {
		t.Fatal(err)
	}
	if contains(f.deleted, "EncryptionKey/s-keya") || !contains(f.deleted, "EncryptionKey/s-keyb") {
		t.Errorf("a stack delete keeps the RetainExceptOnCreate resource, deleted=%v", f.deleted)
	}
}

// RDS DeletionProtection is honored: a stack delete, or an update that removes the database, refuses.
func TestDeletionProtection_RefusesDeleteAndRemoval(t *testing.T) {
	tmpl := []byte(`
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties: { Engine: postgres, DBInstanceClass: db.t3.micro, AllocatedStorage: 20, DeletionProtection: true }
  K:
    Type: AWS::KMS::Key
`)
	f := deployTemplate(t, tmpl)
	if _, err := Destroy(context.Background(), deployOpts(), f); err == nil || !strings.Contains(err.Error(), "deletion protection") {
		t.Fatalf("want a refused delete, got %v", err)
	}
	if len(f.deleted) != 0 {
		t.Fatalf("nothing may be deleted, deleted=%v", f.deleted)
	}
	_, err := Update(context.Background(), []byte("Resources:\n  K:\n    Type: AWS::KMS::Key\n"), deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "deletion protection") {
		t.Fatalf("want a refused update, got %v", err)
	}
}

// Disk and key settings that would silently lose a guarantee refuse.
func TestDisksAndKeys_RefuseLosses(t *testing.T) {
	for name, c := range map[string]struct{ tmpl, id, want string }{
		"encrypted root": {`
Resources:
  I:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      BlockDeviceMappings: [ { DeviceName: /dev/sda1, Ebs: { VolumeSize: 30, Encrypted: true } } ]
`, "I", "root disk is not encrypted"},
		"encrypted root as a string": {`
Resources:
  I:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      BlockDeviceMappings: [ { DeviceName: /dev/xvda, Ebs: { VolumeSize: 30, Encrypted: "true" } } ]
`, "I", "root disk is not encrypted"},
		"snapshot data disk": {`
Resources:
  I:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      BlockDeviceMappings: [ { DeviceName: /dev/sdf, Ebs: { VolumeSize: 10, SnapshotId: snap-0123 } } ]
`, "I", "cannot restore an EBS snapshot"},
		"disabled key": {`
Resources:
  K: { Type: AWS::KMS::Key, Properties: { Enabled: false } }
`, "K", "a disabled key"},
		"daemon service": {`
Resources:
  C: { Type: AWS::ECS::Cluster }
  TD:
    Type: AWS::ECS::TaskDefinition
    Properties: { ContainerDefinitions: [ { Name: app, Image: "registry.example/app:1" } ] }
  S:
    Type: AWS::ECS::Service
    Properties: { Cluster: !Ref C, TaskDefinition: !Ref TD, SchedulingStrategy: DAEMON }
`, "S", "SchedulingStrategy DAEMON"},
		"filtered subscription": {`
Resources:
  T: { Type: AWS::SNS::Topic }
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" } }
  Sub:
    Type: AWS::SNS::Subscription
    Properties: { TopicArn: !Ref T, Protocol: lambda, Endpoint: !GetAtt Fn.Arn, FilterPolicy: { kind: [ order ] } }
`, "Sub", "subscriber would receive every message"},
	} {
		if _, fs := translateIn(t, c.tmpl, c.id, nil); !strings.Contains(findingsText(fs), c.want) {
			t.Errorf("%s: want a refusal containing %q, got %q", name, c.want, findingsText(fs))
		}
	}
}
