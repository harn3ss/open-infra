package main

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

// Network fields surface a SECURITY caveat (deferred half), never a silent drop.
func TestTranslate_EC2Instance_NetworkFieldsSecurityCaveat(t *testing.T) {
	m, _ := translateEC2Instance("Web", map[string]any{
		"ImageId": "ubuntu-24.04", "SubnetId": "subnet-123", "SecurityGroupIds": []any{"sg-1"},
	}, nil)
	joined := strings.Join(m.Caveats, "\n")
	if !strings.Contains(joined, "SubnetId") || !strings.Contains(joined, "SECURITY") {
		t.Fatalf("network fields must surface a SECURITY caveat: %v", m.Caveats)
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
