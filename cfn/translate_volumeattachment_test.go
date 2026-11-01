package cfn

import (
	"strings"
	"testing"
)

// A volume attachment folds into its instance: the VM lists the volume in spec.volumes and is created after
// it — even when the volume takes its Availability Zone from the instance, the usual template shape.
func TestVolumeAttachment_FoldsIntoTheInstance(t *testing.T) {
	order, err := buildManifests([]byte(`
Resources:
  Web: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04 } }
  Data: { Type: AWS::EC2::Volume, Properties: { Size: 20, AvailabilityZone: !GetAtt Web.AvailabilityZone } }
  Attach: { Type: AWS::EC2::VolumeAttachment, Properties: { InstanceId: !Ref Web, VolumeId: !Ref Data, Device: /dev/sdf } }
`), DeployOptions{StackName: "app", Namespace: "n"})
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]int{}
	var vm StackResource
	var cav string
	for i, b := range order {
		pos[b.res.LogicalID] = i
		if b.res.LogicalID == "Web" {
			vm, cav = b.res, strings.Join(b.cav, "\n")
		}
	}
	if pos["Data"] > pos["Web"] {
		t.Fatalf("the volume must be created before the instance it attaches to: %v", pos)
	}
	vols, _ := vm.Spec["volumes"].([]any)
	if len(vols) != 1 || vols[0].(map[string]any)["name"] != order[pos["Data"]].res.Name {
		t.Fatalf("spec.volumes = %v", vm.Spec["volumes"])
	}
	if !strings.Contains(cav, "/dev/sdf") || !strings.Contains(cav, "next restart") {
		t.Fatalf("caveats = %s", cav)
	}
}

// An attachment to an instance outside the stack, or of an EBS volume id, refuses.
func TestVolumeAttachment_Refusals(t *testing.T) {
	for name, tmpl := range map[string]string{
		"outside instance": `
Resources:
  Data: { Type: AWS::EC2::Volume, Properties: { Size: 20 } }
  Attach: { Type: AWS::EC2::VolumeAttachment, Properties: { InstanceId: i-0123, VolumeId: !Ref Data, Device: /dev/sdf } }
`,
		"ebs volume id": `
Resources:
  Web: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04 } }
  Attach: { Type: AWS::EC2::VolumeAttachment, Properties: { InstanceId: !Ref Web, VolumeId: vol-0123456789abcdef0, Device: /dev/sdf } }
`,
	} {
		if _, err := buildManifests([]byte(tmpl), DeployOptions{StackName: "app", Namespace: "n"}); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}
