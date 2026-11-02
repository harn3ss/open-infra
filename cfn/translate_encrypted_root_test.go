package cfn

import (
	"strings"
	"testing"
)

// An Encrypted root BlockDeviceMapping maps to spec.rootDisk — LUKS on longhorn-encrypted — keyed with
// no KmsKeyId by the default kind: EncryptionKey (emitted as a companion, the aws/ebs analog), never an
// unencrypted root and never a refusal.
func TestTranslate_EC2Instance_EncryptedRootUsesTheDefaultKey(t *testing.T) {
	for _, enc := range []any{true, "true"} {
		m, fs := translateEC2Instance("App", map[string]any{
			"ImageId": "ubuntu-24.04",
			"BlockDeviceMappings": []any{
				map[string]any{"DeviceName": "/dev/sda1", "Ebs": map[string]any{"VolumeSize": float64(30), "Encrypted": enc}},
			},
		}, nil)
		if len(fs) != 0 {
			t.Fatalf("an encrypted root must map, got: %s", findingsText(fs))
		}
		rd, _ := m.Spec["rootDisk"].(map[string]any)
		if rd["encrypted"] != true || rd["encryptionKey"] != defaultEBSKeyName {
			t.Fatalf("rootDisk = %#v, want encrypted with the default key %q", m.Spec["rootDisk"], defaultEBSKeyName)
		}
		if m.Spec["diskSize"] != "30Gi" {
			t.Errorf("the root's VolumeSize still sets diskSize, got %v", m.Spec["diskSize"])
		}
		found := false
		for _, e := range m.Extra {
			found = found || (e.Kind == "EncryptionKey" && e.Name == defaultEBSKeyName)
		}
		if !found {
			t.Fatalf("the default kind: EncryptionKey must be emitted, Extra: %+v", m.Extra)
		}
		if !strings.Contains(strings.Join(m.Caveats, "\n"), "root disk: encrypted at rest with LUKS") {
			t.Errorf("the encrypted root must be reported: %v", m.Caveats)
		}
	}
}

// A root KmsKeyId that !Refs (or GetAtts) an in-stack AWS::KMS::Key keys the root disk with that key's
// kind: EncryptionKey.
func TestTranslate_EC2Instance_EncryptedRootInStackKey(t *testing.T) {
	m, fs := translateIn(t, `
Resources:
  Key: { Type: AWS::KMS::Key, Properties: {} }
  App:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      BlockDeviceMappings:
        - DeviceName: /dev/xvda
          Ebs: { Encrypted: true, KmsKeyId: !GetAtt Key.Arn }
`, "App", nil)
	if len(fs) != 0 {
		t.Fatalf("an in-stack key must map, got: %s", findingsText(fs))
	}
	rd, _ := m.Spec["rootDisk"].(map[string]any)
	if rd["encrypted"] != true || !strings.HasSuffix(rd["encryptionKey"].(string), "key") {
		t.Fatalf("rootDisk = %#v, want the in-stack key's EncryptionKey", m.Spec["rootDisk"])
	}
}

// A VolumeAttachment's Device becomes the attached volume's deviceName (the guest alias); a Device that is
// no sd/xvd name is reported, not silently dropped.
func TestTranslate_VolumeAttachment_DeviceName(t *testing.T) {
	for dev, want := range map[string]string{"/dev/sdh": "/dev/sdh", "/dev/nvme1n1": ""} {
		ctx := ctxWithParams(t, `
Resources:
  V: { Type: AWS::EC2::Volume, Properties: { Size: 20 } }
  W: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04 } }
  A: { Type: AWS::EC2::VolumeAttachment, Properties: { InstanceId: !Ref W, VolumeId: !Ref V, Device: `+dev+` } }
`, nil)
		vols, cav, _ := ctx.attachedVolumes("W")
		if len(vols) != 1 {
			t.Fatalf("%s: want one attached volume, got %#v", dev, vols)
		}
		got, _ := vols[0].(map[string]any)["deviceName"].(string)
		if got != want {
			t.Errorf("%s: deviceName = %q, want %q", dev, got, want)
		}
		if want == "" && !strings.Contains(strings.Join(cav, "\n"), "is not an sd/xvd name") {
			t.Errorf("%s: a non-aliasable Device must be reported: %v", dev, cav)
		}
	}
}
