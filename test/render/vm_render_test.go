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

// An encrypted data disk renders as a longhorn-encrypted RWO Block volume carrying the
// openinfra.dev/encryption-key annotation (what the volume-crypto reconciler selects on), regardless
// of the VM's HA policy — there is no encrypted+migratable class.
func TestVM_DataDisks_Encrypted(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"dataDisks": []any{
			map[string]any{"name": "db", "size": "100Gi", "encrypted": true, "encryptionKey": "db-key"},
		},
	}))
	for _, want := range []string{
		"name: myvm-db",
		"storageClassName: longhorn-encrypted",
		"openinfra.dev/encryption-key: \"db-key\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("encrypted data disk missing %q; got:\n%s", want, grepCtx(out, "db"))
		}
	}
	// An encrypted disk is RWO even though nothing forced HA here (no RWX migratable encrypted class).
	if strings.Contains(grepCtx(out, "myvm-db"), "ReadWriteMany") {
		t.Errorf("an encrypted data disk must be RWO, not RWX; got:\n%s", grepCtx(out, "myvm-db"))
	}
}

// A UserData script is EXEC'd (its shebang honored), not passed to `sh` — otherwise a `#!/bin/bash`
// script with the standard `set -euxo pipefail` opener would run under dash and die on line 1.
func TestVM_UserData_ExecNotSh(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"userData": "#!/bin/bash\nset -euxo pipefail\necho hi\n"}))
	if !strings.Contains(out, "- [/opt/openinfra-userdata]") {
		t.Errorf("UserData must be exec'd directly (honoring its shebang); got:\n%s", grepCtx(out, "openinfra-userdata"))
	}
	if strings.Contains(out, "/bin/sh, /opt/openinfra-userdata") {
		t.Errorf("UserData must NOT be passed to /bin/sh (that ignores #!/bin/bash); got:\n%s", grepCtx(out, "openinfra-userdata"))
	}
}

// Data disks get AWS Nitro device-name aliases so an unmodified lift-and-shift UserData script that
// formats/mounts /dev/nvme1n1 works on KubeVirt virtio disks (/dev/vdb). The composition drops a udev
// rules file and triggers udev before the user's script runs.
func TestVM_DataDisks_NitroDeviceNameAliases(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"dataDisks": []any{
			map[string]any{"size": "50Gi"},                  // → /dev/vdb → nvme1n1
			map[string]any{"name": "extra", "size": "30Gi"}, // → /dev/vdc → nvme2n1
		},
	}))
	for _, want := range []string{
		"99-openinfra-aws-device-names.rules",
		`KERNEL=="vdb", SYMLINK+="nvme1n1"`,
		`KERNEL=="vdb[0-9]*", SYMLINK+="nvme1n1p%n"`, // partitions too
		`KERNEL=="vdc", SYMLINK+="nvme2n1"`,
		`KERNEL=="vda", SYMLINK+="nvme0n1"`, // root alias
		"udevadm",                           // udev is reloaded/triggered before UserData
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Nitro device-name aliasing missing %q; got:\n%s", want, grepCtx(out, "nvme"))
		}
	}
	// A VM with NO data disks must not carry the alias rules file.
	none := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	if strings.Contains(none, "aws-device-names") {
		t.Errorf("a VM with no data disks must not emit the Nitro alias rules; got:\n%s", grepCtx(none, "device-names"))
	}
}

// spec.instanceRole wires the VM's workload identity: a per-VM ServiceAccount (annotated with the
// role), its token projected onto an "identity" serviceAccount disk, and cloud-init pointing the AWS
// container-credentials provider at the shim. No instanceRole → none of this (a VM with no identity).
func TestVM_InstanceRole_WorkloadIdentityWiring(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	with := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{"instanceRole": "app-role"}))
	for _, want := range []string{
		"kind: ServiceAccount",                  // the per-VM SA object
		"name: vm-myvm",                         // SA named for the VM
		"openinfra.dev/instance-role: app-role", // SA annotation the shim reads
		"serviceAccountName: vm-myvm",           // the projected SA volume
		"serial: SATOKEN",                       // the identity disk's stable serial
		// cloud-init lives in a Secret (KubeVirt's 2048-byte inline cap), referenced by the VMI:
		"secretRef",
		"name: myvm-cloudinit",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI=http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566/v1/vm-credentials",
		"AWS_CONTAINER_CREDENTIALS_TOKEN_FILE=/run/openinfra-identity/token",
		"/dev/disk/by-id/virtio-SATOKEN", // the boot-time mount
	} {
		if !strings.Contains(with, want) {
			t.Errorf("instanceRole wiring missing %q; got:\n%s", want, grepCtx(with, "identity"))
		}
	}
	// A VM with no instanceRole still uses the cloud-init Secret (Linux), but carries none of the
	// workload-identity wiring.
	without := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	if !strings.Contains(without, "name: myvm-cloudinit") {
		t.Errorf("every Linux VM should render a cloud-init Secret; got:\n%s", grepCtx(without, "cloudinit"))
	}
	for _, absent := range []string{"vm-myvm", "SATOKEN", "AWS_CONTAINER_CREDENTIALS", "instance-role"} {
		if strings.Contains(without, absent) {
			t.Errorf("a VM with no instanceRole must not render %q; got:\n%s", absent, grepCtx(without, absent))
		}
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
