package render

import (
	"strings"
	"testing"
)

// Regression guard: a VM with NO dataDisks must render exactly as before — one root DataVolume, no
// blank volumes, no extra disks. The data-disk feature must be a true no-op for every existing VM
// (the composition re-renders for all VMs on reconcile).
func TestVM_NoDataDisks_Unchanged(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	if !strings.Contains(out, "name: myvm-root") {
		t.Fatalf("root DataVolume must still render:\n%s", grepCtx(out, "dataVolumeTemplates"))
	}
	if strings.Contains(out, "blank: {}") {
		t.Errorf("a VM with no dataDisks must emit no blank data volume; got:\n%s", grepCtx(out, "blank"))
	}
	if strings.Contains(out, "myvm-data1") || strings.Contains(out, "name: data1") {
		t.Errorf("a VM with no dataDisks must emit no data disk; got:\n%s", grepCtx(out, "data1"))
	}
}

// A Linux VM with two data disks: the first unnamed (→ data1), the second named. Each renders a
// blank DataVolume, a virtio disk, and a volume binding — in order, on the non-HA storage class.
func TestVM_DataDisks_ProvisionInOrder(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"dataDisks": []any{
			map[string]any{"size": "50Gi"},
			map[string]any{"name": "extra", "size": "30Gi"},
		},
	}))
	for _, want := range []string{
		"name: myvm-root",  // root still present
		"name: myvm-data1", // unnamed → data1 (DataVolume)
		"name: myvm-extra", // named disk (DataVolume)
		"blank: {}",        // data disks are blank-sourced
		"storage: 50Gi",
		"storage: 30Gi",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("data-disk render missing %q; got:\n%s", want, grepCtx(out, "dataVolumeTemplates"))
		}
	}
	// A virtio disk device and a volume binding for each (name appears in devices.disks AND volumes).
	if strings.Count(out, "name: data1") < 2 {
		t.Errorf("data1 must appear as both a disk device and a volume; got:\n%s", grepCtx(out, "data1"))
	}
	if strings.Count(out, "name: extra") < 2 {
		t.Errorf("extra must appear as both a disk device and a volume; got:\n%s", grepCtx(out, "extra"))
	}
	// Non-HA → local-path, no Block mode on the data disks.
	if !strings.Contains(out, "storageClassName: local-path") {
		t.Errorf("non-HA data disks must use local-path; got:\n%s", grepCtx(out, "storageClassName"))
	}
}

// spec.instanceRole labels the VMI/launcher pod so the metadata responder can map the caller pod to
// its role. No instanceRole → no such label (a VM with no AWS identity).
func TestVM_InstanceRole_LabelsForMetadataResponder(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	with := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"}))
	if !strings.Contains(with, "openinfra.dev/instance-role: app-role") {
		t.Errorf("instanceRole must label the VMI/launcher pod; got:\n%s", grepCtx(with, "labels"))
	}
	// cloud-init must point the AWS SDK's metadata flow at the shim (so the VM fetches role creds).
	if !strings.Contains(with, "AWS_EC2_METADATA_SERVICE_ENDPOINT=http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566") {
		t.Errorf("instanceRole must inject the IMDS endpoint into /etc/environment; got:\n%s", grepCtx(with, "environment"))
	}
	without := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	if strings.Contains(without, "openinfra.dev/instance-role") {
		t.Errorf("a VM with no instanceRole must carry no instance-role label; got:\n%s", grepCtx(without, "instance-role"))
	}
	if strings.Contains(without, "AWS_EC2_METADATA_SERVICE_ENDPOINT") {
		t.Errorf("a VM with no instanceRole must not inject the IMDS endpoint; got:\n%s", grepCtx(without, "METADATA"))
	}
}

// An HA VM's data disks must follow the root's storage policy — longhorn-migratable RWX Block — so
// they live-migrate with the VM (a local-path data disk would pin the VM and break migration).
func TestVM_DataDisks_FollowHAStoragePolicy(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"highAvailability": true,
		"dataDisks":        []any{map[string]any{"name": "db", "size": "100Gi"}},
	}))
	if !strings.Contains(out, "name: myvm-db") {
		t.Fatalf("HA data disk must render; got:\n%s", grepCtx(out, "dataVolumeTemplates"))
	}
	// root + 1 data disk both on longhorn-migratable Block.
	if n := strings.Count(out, "storageClassName: longhorn-migratable"); n < 2 {
		t.Errorf("HA root + data disk must both be longhorn-migratable (>=2); got %d:\n%s", n, grepCtx(out, "storageClassName"))
	}
	if n := strings.Count(out, "volumeMode: Block"); n < 2 {
		t.Errorf("HA root + data disk must both be Block mode (>=2); got %d:\n%s", n, grepCtx(out, "volumeMode"))
	}
}
