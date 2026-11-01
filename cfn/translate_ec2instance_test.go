package cfn

import (
	"encoding/base64"
	"strings"
	"testing"
)

// #115: an EC2::Instance naming a catalog OS translates to a running-shaped VirtualMachine —
// InstanceType -> cpu/memory, root BlockDeviceMapping -> diskSize, UserData script -> cloud-init.
func TestTranslate_EC2Instance_CatalogOS_Faithful(t *testing.T) {
	ud := base64.StdEncoding.EncodeToString([]byte("#!/bin/bash\napt-get update -y\n"))
	m, fs := translateEC2Instance("Web", map[string]any{
		"ImageId":      "ubuntu-22.04",
		"InstanceType": "t3.medium",
		"UserData":     ud,
		"BlockDeviceMappings": []any{
			map[string]any{"DeviceName": "/dev/sda1", "Ebs": map[string]any{"VolumeSize": float64(40)}},
		},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("a catalog-OS instance must translate cleanly: %s", findingsText(fs))
	}
	if m.Kind != "VirtualMachine" || m.Name != "web" {
		t.Fatalf("bad head: %+v", m)
	}
	if m.Spec["os"] != "ubuntu-22.04" {
		t.Fatalf("os not mapped: %#v", m.Spec["os"])
	}
	if m.Spec["cpu"] != 2 || m.Spec["memory"] != "4Gi" {
		t.Fatalf("t3.medium should map to 2 vCPU / 4Gi: cpu=%v mem=%v", m.Spec["cpu"], m.Spec["memory"])
	}
	if m.Spec["diskSize"] != "40Gi" {
		t.Fatalf("root device size should map to diskSize 40Gi: %#v", m.Spec["diskSize"])
	}
	if s, _ := m.Spec["userData"].(string); !strings.Contains(s, "apt-get update") {
		t.Fatalf("UserData script should map to userData: %#v", m.Spec["userData"])
	}
}

// Extra EBS BlockDeviceMappings become boot-time data disks: the root device sets diskSize, each
// other device → spec.dataDisks (named from its DeviceName), with the virtio device-name caveat.
func TestTranslate_EC2Instance_ExtraBDMsToDataDisks(t *testing.T) {
	m, fs := translateEC2Instance("Db", map[string]any{
		"ImageId": "ubuntu-24.04",
		"BlockDeviceMappings": []any{
			map[string]any{"DeviceName": "/dev/sda1", "Ebs": map[string]any{"VolumeSize": float64(20)}},
			map[string]any{"DeviceName": "/dev/sdf", "Ebs": map[string]any{"VolumeSize": float64(50), "VolumeType": "gp3"}},
		},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("a root + one unencrypted data disk must translate cleanly: %s", findingsText(fs))
	}
	if m.Spec["diskSize"] != "20Gi" {
		t.Fatalf("root device should set diskSize=20Gi, got %#v", m.Spec["diskSize"])
	}
	dds, _ := m.Spec["dataDisks"].([]map[string]any)
	if len(dds) != 1 || dds[0]["size"] != "50Gi" || dds[0]["name"] != "sdf" {
		t.Fatalf("the /dev/sdf device should map to a dataDisk {name: sdf, size: 50Gi}, got %#v", m.Spec["dataDisks"])
	}
	caveats := strings.Join(m.Caveats, "\n")
	if !strings.Contains(caveats, "virtio") || !strings.Contains(caveats, "/dev/vdb") {
		t.Fatalf("a device-name divergence caveat (virtio /dev/vdb, not the AWS name) is required: %v", m.Caveats)
	}
	if !strings.Contains(caveats, "VolumeType") {
		t.Fatalf("VolumeType on a data disk should be a dropped-knob caveat: %v", m.Caveats)
	}
}

// #347 Phase 1.7 (#344 4.2): an Encrypted data disk with NO KmsKeyId maps to the per-namespace default
// kind: EncryptionKey (the AWS aws/ebs analog), emitted as a companion — not a refusal.
func TestTranslate_EC2Instance_EncryptedDataDiskNoKeyUsesDefault(t *testing.T) {
	m, fs := translateEC2Instance("Db", map[string]any{
		"ImageId": "ubuntu-24.04",
		"BlockDeviceMappings": []any{
			map[string]any{"DeviceName": "/dev/sda1", "Ebs": map[string]any{"VolumeSize": float64(20)}},
			map[string]any{"DeviceName": "/dev/sdf", "Ebs": map[string]any{"VolumeSize": float64(50), "Encrypted": true}},
		},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("an encrypted data disk with no KmsKeyId must NOT refuse (uses the default key), got: %s", findingsText(fs))
	}
	disks, _ := m.Spec["dataDisks"].([]map[string]any)
	if len(disks) != 1 || disks[0]["encrypted"] != true || disks[0]["encryptionKey"] != defaultEBSKeyName {
		t.Fatalf("the data disk must be encrypted with the default key %q, disks: %#v", defaultEBSKeyName, disks)
	}
	foundKey := false
	for _, e := range m.Extra {
		if e.Kind == "EncryptionKey" && e.Name == defaultEBSKeyName {
			foundKey = true
		}
	}
	if !foundKey {
		t.Fatalf("must emit the default kind: EncryptionKey %q as a companion, got Extra: %+v", defaultEBSKeyName, m.Extra)
	}
}

// An Encrypted data disk whose KmsKeyId !Refs an in-stack AWS::KMS::Key maps to a LUKS data disk keyed
// by that key's kind: EncryptionKey — the EC2 encrypted-EBS → kind: Volume-style encryption analog.
func TestTranslate_EC2Instance_EncryptedDataDiskToEncryptionKey(t *testing.T) {
	tmpl := `
Resources:
  DataKey:
    Type: AWS::KMS::Key
    Properties: { Description: db }
  Db:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      BlockDeviceMappings:
        - { DeviceName: /dev/sda1, Ebs: { VolumeSize: 20 } }
        - { DeviceName: /dev/sdf,  Ebs: { VolumeSize: 50, Encrypted: true, KmsKeyId: !Ref DataKey } }
`
	ctx := ecsCtx(t, tmpl)
	m, fs := translateEC2Instance("Db", resolvedProps(t, ctx, "Db"), ctx)
	if len(fs) != 0 {
		t.Fatalf("an encrypted data disk with an in-stack KMS key must translate cleanly: %s", findingsText(fs))
	}
	dds, _ := m.Spec["dataDisks"].([]map[string]any)
	if len(dds) != 1 || dds[0]["encrypted"] != true || dds[0]["encryptionKey"] != "datakey" {
		t.Fatalf("the encrypted device should map to {encrypted: true, encryptionKey: datakey}, got %#v", m.Spec["dataDisks"])
	}
}

// A raw ami- id is opaque: refuse with a message that names the catalog.
func TestTranslate_EC2Instance_RawAmiRefusesWithHelp(t *testing.T) {
	_, fs := translateEC2Instance("Web", map[string]any{"ImageId": "ami-0abc1234"}, nil)
	txt := findingsText(fs)
	if !strings.Contains(txt, "raw AMI") || !strings.Contains(txt, "ubuntu-24.04") {
		t.Fatalf("a raw ami must refuse AND list the catalog, got: %s", txt)
	}
}

// A public image SSM-parameter path is recognized and mapped (the prove/disprove case).
func TestTranslate_EC2Instance_SSMPathMaps(t *testing.T) {
	m, fs := translateEC2Instance("Web", map[string]any{
		"ImageId": "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("a recognized SSM path must map, got: %s", findingsText(fs))
	}
	if m.Spec["os"] != "ubuntu-22.04" {
		t.Fatalf("ubuntu 22.04 SSM path should map to ubuntu-22.04: %#v", m.Spec["os"])
	}
}

// A Windows public SSM path maps to the windows catalog entry.
func TestTranslate_EC2Instance_WindowsSSMPathMaps(t *testing.T) {
	m, fs := translateEC2Instance("Win", map[string]any{
		"ImageId": "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base",
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("windows SSM path must map: %s", findingsText(fs))
	}
	if m.Spec["os"] != "windows-server-2022" {
		t.Fatalf("want windows-server-2022, got %#v", m.Spec["os"])
	}
}

// An OS that isn't in the catalog (e.g. Amazon Linux) refuses with help — never a guess.
func TestTranslate_EC2Instance_OutOfCatalogRefusesWithHelp(t *testing.T) {
	_, fs := translateEC2Instance("Web", map[string]any{
		"ImageId": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64",
	}, nil)
	txt := findingsText(fs)
	if !strings.Contains(txt, "matches no catalog OS") || !strings.Contains(txt, "debian-12") {
		t.Fatalf("an out-of-catalog OS must refuse AND list the catalog, got: %s", txt)
	}
}

// An unknown InstanceType is a caveat (VM uses defaults), not a block — consistent with RDS #114.
func TestTranslate_EC2Instance_UnknownInstanceTypeCaveat(t *testing.T) {
	m, fs := translateEC2Instance("Web", map[string]any{
		"ImageId": "ubuntu-24.04", "InstanceType": "x99.mega",
	}, nil)
	if !strings.Contains(findingsText(fs), "not in the mapping table") {
		t.Fatalf("an unknown instance type must surface a caveat, got: %s", findingsText(fs))
	}
	if _, ok := m.Spec["cpu"]; ok {
		t.Fatalf("an unknown type must NOT set cpu (no guess): %#v", m.Spec)
	}
}

// A raw AWS subnet id is opaque and refuses; a raw AWS security-group id likewise refuses (opaque),
// rather than being silently dropped — both must be named as in-stack resources or kind: names.
func TestTranslate_EC2Instance_RawSubnetAndSGRefuse(t *testing.T) {
	_, fs := translateEC2Instance("Web", map[string]any{
		"ImageId": "ubuntu-24.04", "SubnetId": "subnet-123", "SecurityGroupIds": []any{"sg-1"},
	}, nil)
	txt := findingsText(fs)
	if !strings.Contains(txt, "raw AWS subnet id") {
		t.Fatalf("a raw subnet- id must refuse with help, got: %s", txt)
	}
	if !strings.Contains(txt, "raw AWS security-group id") {
		t.Fatalf("a raw sg- id must refuse with help, got: %s", txt)
	}
}

// A SecurityGroupIds naming a kind: SecurityGroup (plain name, not a raw sg- id) attaches it to the
// VM via spec.securityGroups — the isolation is honored, not dropped.
func TestTranslate_EC2Instance_SecurityGroupNameAttaches(t *testing.T) {
	m, fs := translateEC2Instance("Web", map[string]any{
		"ImageId": "ubuntu-24.04", "SecurityGroupIds": []any{"app-tier-sg"},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("a kind: SecurityGroup name must attach cleanly: %s", findingsText(fs))
	}
	sgs, _ := m.Spec["securityGroups"].([]string)
	if len(sgs) != 1 || sgs[0] != "app-tier-sg" {
		t.Fatalf("SecurityGroupIds should attach to spec.securityGroups=[app-tier-sg], got %#v", m.Spec["securityGroups"])
	}
}

// #120 subnet half: a SubnetId naming a kind: Subnet places the VM in it (real OVN isolation).
func TestTranslate_EC2Instance_SubnetNameMaps(t *testing.T) {
	m, fs := translateEC2Instance("Web", map[string]any{
		"ImageId": "ubuntu-24.04", "SubnetId": "app-tier",
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("a kind: Subnet name must map cleanly: %s", findingsText(fs))
	}
	if m.Spec["subnet"] != "app-tier" {
		t.Fatalf("SubnetId should map to spec.subnet=app-tier, got %#v", m.Spec["subnet"])
	}
}

// A #cloud-config UserData is not merged — caveat, not a silent drop or a broken VM.
func TestTranslate_EC2Instance_CloudConfigUserDataCaveat(t *testing.T) {
	ud := base64.StdEncoding.EncodeToString([]byte("#cloud-config\npackages: [nginx]\n"))
	m, fs := translateEC2Instance("Web", map[string]any{
		"ImageId": "ubuntu-24.04", "UserData": ud,
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("a #cloud-config UserData should caveat, not block: %s", findingsText(fs))
	}
	if _, ok := m.Spec["userData"]; ok {
		t.Fatalf("a #cloud-config must NOT be applied as userData: %#v", m.Spec)
	}
	if !strings.Contains(strings.Join(m.Caveats, "\n"), "cloud-config") {
		t.Fatalf("a #cloud-config must surface a caveat: %v", m.Caveats)
	}
}

// #347 item 14: MetadataOptions maps 1:1 onto spec.metadataOptions (the in-guest instance metadata
// service): HttpTokens, HttpEndpoint, and HttpPutResponseHopLimit (as a JSON number or a string).
func TestTranslate_EC2Instance_MetadataOptionsMap(t *testing.T) {
	for _, hop := range []any{float64(3), "3", 3} {
		m, fs := translateEC2Instance("Web", map[string]any{
			"ImageId": "ubuntu-24.04",
			"MetadataOptions": map[string]any{
				"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": hop,
				"HttpProtocolIpv6": "disabled", "InstanceMetadataTags": "disabled",
			},
		}, nil)
		if len(fs) != 0 {
			t.Fatalf("a valid MetadataOptions must translate cleanly (hop %#v): %s", hop, findingsText(fs))
		}
		got, _ := m.Spec["metadataOptions"].(map[string]any)
		if len(got) != 3 || got["httpTokens"] != "required" || got["httpEndpoint"] != "enabled" || got["httpPutResponseHopLimit"] != 3 {
			t.Fatalf("MetadataOptions should map to {httpTokens: required, httpEndpoint: enabled, httpPutResponseHopLimit: 3}, got %#v", m.Spec["metadataOptions"])
		}
		if c := strings.Join(m.Caveats, "\n"); strings.Contains(c, "MetadataOptions") {
			t.Fatalf("disabled IPv6/tags options need no caveat: %v", m.Caveats)
		}
	}
	// No MetadataOptions -> no spec.metadataOptions (the VM's defaults: optional tokens, hop limit 2).
	m, _ := translateEC2Instance("Web", map[string]any{"ImageId": "ubuntu-24.04"}, nil)
	if _, ok := m.Spec["metadataOptions"]; ok {
		t.Fatalf("no MetadataOptions must leave spec.metadataOptions unset: %#v", m.Spec)
	}
}

// The IPv6 endpoint and instance tags in metadata are not served: enabling them is a caveat (the IPv4
// endpoint still answers), and the rest of the block still maps.
func TestTranslate_EC2Instance_MetadataOptionsUnservedCaveats(t *testing.T) {
	m, fs := translateEC2Instance("Web", map[string]any{
		"ImageId":         "ubuntu-24.04",
		"MetadataOptions": map[string]any{"HttpTokens": "required", "HttpProtocolIpv6": "enabled", "InstanceMetadataTags": "enabled"},
	}, nil)
	if len(fs) != 0 {
		t.Fatalf("unserved MetadataOptions must caveat, not block: %s", findingsText(fs))
	}
	c := strings.Join(m.Caveats, "\n")
	if !strings.Contains(c, "fd00:ec2::254") || !strings.Contains(c, "tags/instance") {
		t.Fatalf("HttpProtocolIpv6 / InstanceMetadataTags enabled must each surface a caveat: %v", m.Caveats)
	}
	if mo, _ := m.Spec["metadataOptions"].(map[string]any); mo["httpTokens"] != "required" {
		t.Fatalf("HttpTokens must still map alongside the caveats: %#v", m.Spec["metadataOptions"])
	}
	w, _ := translateEC2Instance("Win", map[string]any{
		"ImageId": "windows-server-2022", "MetadataOptions": map[string]any{"HttpTokens": "required"},
	}, nil)
	if !strings.Contains(strings.Join(w.Caveats, "\n"), "Windows") {
		t.Fatalf("MetadataOptions on a Windows guest must caveat that it has no effect: %v", w.Caveats)
	}
}

// Values outside the AWS enum/range — or an unknown sub-property — refuse rather than being guessed.
func TestTranslate_EC2Instance_MetadataOptionsInvalidRefuses(t *testing.T) {
	for name, mo := range map[string]map[string]any{
		"tokens":   {"HttpTokens": "sometimes"},
		"endpoint": {"HttpEndpoint": "on"},
		"hop-0":    {"HttpPutResponseHopLimit": float64(0)},
		"hop-65":   {"HttpPutResponseHopLimit": float64(65)},
		"hop-text": {"HttpPutResponseHopLimit": "two"},
		"unknown":  {"HttpTokens": "required", "HttpFoo": "bar"},
	} {
		_, fs := translateEC2Instance("Web", map[string]any{"ImageId": "ubuntu-24.04", "MetadataOptions": mo}, nil)
		if len(fs) == 0 {
			t.Errorf("%s: an invalid MetadataOptions %#v must refuse", name, mo)
		}
	}
	if _, fs := translateEC2Instance("Web", map[string]any{"ImageId": "ubuntu-24.04", "MetadataOptions": "nope"}, nil); len(fs) == 0 {
		t.Errorf("a non-object MetadataOptions must refuse")
	}
}
