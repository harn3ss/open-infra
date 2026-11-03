package render

import (
	"regexp"
	"strings"
	"testing"
)

// The OS image cache (#354, platform/abstraction/vm-bases.yaml): with a base recorded for an Ubuntu
// version, a NEW VM of it never imports its image from the registry — an HA root is a thin volume on
// the base, a non-HA or encrypted root is filled by a copy from a thin, node-local volume on it — and
// a VM made before the cache keeps exactly the root it was made with.

var vmBasesEnv = map[string]any{
	"vmBases": map[string]any{
		"ubuntu-24.04": map[string]any{"backingImage": "openinfra-ubuntu-24-04-aaaaaaaaaaaa", "size": "4Gi",
			"haStorageClass": "openinfra-ubuntu-24-04-aaaaaaaaaaaa-ha", "readerStorageClass": "openinfra-ubuntu-24-04-aaaaaaaaaaaa-reader"},
		"ubuntu-22.04": map[string]any{"backingImage": "openinfra-ubuntu-22-04-bbbbbbbbbbbb", "size": "4Gi",
			"haStorageClass": "openinfra-ubuntu-22-04-bbbbbbbbbbbb-ha", "readerStorageClass": "openinfra-ubuntu-22-04-bbbbbbbbbbbb-reader"},
	},
}

func vmBaseCtx(os string, extra map[string]any) map[string]any {
	ctx := vmCtxFW(os, extra)
	ctx["context"] = map[string]any{"apiextensions.crossplane.io/environment": vmBasesEnv}
	return ctx
}

func withObserved(ctx map[string]any, res map[string]any) map[string]any {
	ctx["observed"].(map[string]any)["resources"] = res
	return ctx
}

func withStatus(ctx map[string]any, st map[string]any) map[string]any {
	ctx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["status"] = st
	return ctx
}

// docNamed returns the rendered document carrying composition-resource-name name ("" if none).
func docNamed(out, name string) string {
	for _, d := range strings.Split(out, "\n---") {
		if strings.Contains(d, "composition-resource-name: "+name+"\n") {
			return d
		}
	}
	return ""
}

var registryImport = regexp.MustCompile(`registry:\s*\n\s*url:|docker://quay\.io`)

func TestVMBases_NoPerVMRegistryImport(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	for _, os := range []string{"ubuntu-24.04", "ubuntu-22.04"} {
		for name, extra := range map[string]map[string]any{
			"default":   {},
			"ha":        {"highAvailability": true},
			"encrypted": {"rootDisk": map[string]any{"encrypted": true, "encryptionKey": "k"}},
		} {
			out := render(t, tmpl, vmBaseCtx(os, extra))
			if registryImport.MatchString(out) {
				t.Errorf("%s %s: a new VM with a recorded base must not import its image from the registry:\n%s", os, name, grepCtx(out, "registry"))
			}
			if !strings.Contains(out, `rootSource: "base"`) {
				t.Errorf("%s %s: status.rootSource must record the base", os, name)
			}
		}
	}
}

func TestVMBases_DefaultRootIsALocalCopy(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmBaseCtx("ubuntu-24.04", nil))
	root := docNamed(out, "root-base")
	if !strings.Contains(root, "storageClassName: local-path") || !strings.Contains(root, "name: myvm-root") {
		t.Fatalf("a non-HA root stays on local-path (the local disk's speed):\n%s", root)
	}
	img := docNamed(out, "root-image")
	if !strings.Contains(img, "kind: PersistentVolumeClaim") || !strings.Contains(img, `storageClassName: "openinfra-ubuntu-24-04-aaaaaaaaaaaa-reader"`) || !strings.Contains(img, "volumeMode: Block") {
		t.Fatalf("the copy's source is a thin Block volume of the base's reader class:\n%s", img)
	}
	if !strings.Contains(out, "runStrategy: Halted") {
		t.Errorf("the VM waits for its root to be filled")
	}
	if !regexp.MustCompile(`- name: root\s*\n\s*persistentVolumeClaim:\s*\n\s*claimName: myvm-root`).MatchString(out) {
		t.Errorf("the VM's root volume is the PVC:\n%s", grepCtx(out, "- name: root"))
	}
	if strings.Contains(out, "dataVolumeTemplates:") {
		t.Errorf("no root DataVolume (and no data disks here):\n%s", grepCtx(out, "dataVolumeTemplates"))
	}
	// A thin volume on the base is whole from the start: the copy pod is made in the same render (no
	// wait for a reconcile that sees the volume Bound): block source, the local root mounted, placed where
	// the VM can run.
	pop := docNamed(out, "root-populate")
	for _, want := range []string{
		"devicePath: /dev/openinfra-image", "mountPath: /dst", "kubevirt.io/schedulable", "openinfra.dev/disk-class",
		`memory: "4Gi"`, "CHOWN", "chmod 0660 /dst/disk.img.part && chown 107:107", `value: "20Gi"`,
	} {
		if !strings.Contains(pop, want) {
			t.Errorf("the copy pod must have %q:\n%s", want, pop)
		}
	}
	if strings.Contains(pop, "/dev/openinfra-root") && strings.Contains(pop, "devicePath: /dev/openinfra-root") {
		t.Errorf("a local-path root is a mounted directory, not a block device")
	}
	// Once populated: no source, no copy, the VM runs.
	done := render(t, tmpl, withStatus(vmBaseCtx("ubuntu-24.04", nil), map[string]any{"rootSource": "base", "rootPopulated": true,
		"rootBase": map[string]any{"image": "openinfra-ubuntu-24-04-aaaaaaaaaaaa", "ha": "x-ha", "reader": "x-reader", "size": "4Gi"}}))
	if docNamed(done, "root-image") != "" || docNamed(done, "root-populate") != "" || !strings.Contains(done, "runStrategy: Always") {
		t.Errorf("a populated root keeps no source or copy, and the VM runs")
	}
}

func TestVMBases_HARootIsAThinVolume(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmBaseCtx("ubuntu-22.04", map[string]any{"highAvailability": true}))
	root := docNamed(out, "root-base")
	for _, want := range []string{"ReadWriteMany", "volumeMode: Block", `storageClassName: "openinfra-ubuntu-22-04-bbbbbbbbbbbb-ha"`} {
		if !strings.Contains(root, want) {
			t.Errorf("an HA root is a thin live-migratable volume on the base (%q):\n%s", want, root)
		}
	}
	if docNamed(out, "root-image") != "" || !strings.Contains(out, "runStrategy: Always") {
		t.Errorf("an HA root needs no copy: the VM starts at once")
	}
}

func TestVMBases_EncryptedRootCopiesFromTheBase(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	enc := map[string]any{"rootDisk": map[string]any{"encrypted": true, "encryptionKey": "k"}}
	out := render(t, tmpl, vmBaseCtx("ubuntu-24.04", enc))
	if !strings.Contains(docNamed(out, "root-encrypted"), "storageClassName: longhorn-encrypted") || docNamed(out, "root-base") != "" {
		t.Fatalf("an encrypted root stays a LUKS volume of its own")
	}
	if !strings.Contains(docNamed(out, "root-image"), `-reader"`) {
		t.Errorf("its copy reads the base's thin volume")
	}
	bound := map[string]any{"root-image": map[string]any{"resource": map[string]any{
		"spec":   map[string]any{"forProvider": map[string]any{"manifest": map[string]any{"kind": "PersistentVolumeClaim"}}},
		"status": map[string]any{"atProvider": map[string]any{"manifest": map[string]any{"status": map[string]any{"phase": "Bound"}}}},
	}}}
	pop := docNamed(render(t, tmpl, withObserved(vmBaseCtx("ubuntu-24.04", enc), bound)), "root-populate")
	if !strings.Contains(pop, "devicePath: /dev/openinfra-image") || !strings.Contains(pop, "devicePath: /dev/openinfra-root") || strings.Contains(pop, "mountPath: /src") {
		t.Errorf("block to block: the base's volume onto the encrypted root:\n%s", pop)
	}
}

// A VM made before the cache (its KubeVirt VM already exists, no rootSource) keeps importing: its root
// DataVolume is re-rendered unchanged, so nothing about it is re-provisioned or restarted.
func TestVMBases_ExistingVMKeepsItsRoot(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	before := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	ctx := withObserved(vmBaseCtx("ubuntu-24.04", nil), map[string]any{"virtualmachine": map[string]any{"resource": map[string]any{}}})
	after := render(t, tmpl, ctx)
	if !registryImport.MatchString(after) || docNamed(after, "root-base") != "" || !strings.Contains(after, `rootSource: "image"`) {
		t.Fatalf("an existing VM keeps its registry import:\n%s", grepCtx(after, "root"))
	}
	if docNamed(before, "virtualmachine") != docNamed(after, "virtualmachine") {
		t.Errorf("an existing VM's KubeVirt VM must render byte-for-byte as before")
	}
	// Recorded either way, it stays: an image VM never moves to a base, a base VM never moves back.
	kept := render(t, tmpl, withStatus(vmBaseCtx("ubuntu-24.04", nil), map[string]any{"rootSource": "image"}))
	if docNamed(kept, "root-base") != "" {
		t.Errorf("status.rootSource=image is kept")
	}
}

// Windows (its own golden clone), an adopted root, and an OS with no recorded base are unaffected.
func TestVMBases_OtherVMsUnaffected(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	for name, ctx := range map[string]map[string]any{
		"windows":       vmBaseCtx("windows-server-2022", nil),
		"debian":        vmBaseCtx("debian-12", nil),
		"adopted":       vmBaseCtx("ubuntu-24.04", map[string]any{"existingRootClaim": "old-root", "firmware": map[string]any{"mode": "bios"}}),
		"arm64-pinned":  vmBaseCtx("ubuntu-24.04", nil),
		"no base (env)": vmCtx("ubuntu-24.04", ""),
	} {
		if name == "arm64-pinned" {
			ctx["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["metadata"].(map[string]any)["annotations"] = map[string]any{"openinfra.dev/arch": "arm64"}
		}
		out := render(t, tmpl, ctx)
		if docNamed(out, "root-base") != "" || strings.Contains(out, `rootSource: "base"`) {
			t.Errorf("%s: must not be made from a base", name)
		}
	}
}

var asgBasesEnv = map[string]any{"vmBases": map[string]any{
	"ubuntu-24.04": map[string]any{"backingImage": "openinfra-ubuntu-24-04-aaaaaaaaaaaa", "haStorageClass": "openinfra-ubuntu-24-04-aaaaaaaaaaaa-ha",
		"goldenNamespace": "openinfra-images", "golden": "openinfra-ubuntu-24-04-aaaaaaaaaaaa", "pristine": "openinfra-ubuntu-24-04-aaaaaaaaaaaa-pristine"},
	"ubuntu-22.04": map[string]any{"backingImage": "openinfra-ubuntu-22-04-bbbbbbbbbbbb", "haStorageClass": "openinfra-ubuntu-22-04-bbbbbbbbbbbb-ha",
		"goldenNamespace": "openinfra-images", "golden": "openinfra-ubuntu-22-04-bbbbbbbbbbbb", "pristine": "openinfra-ubuntu-22-04-bbbbbbbbbbbb-pristine"},
}}

func asgBaseCtx(lt map[string]any) map[string]any {
	ctx := asgCtx(map[string]any{"minSize": int64(1), "maxSize": int64(3), "launchTemplate": lt})
	ctx["context"] = map[string]any{"apiextensions.crossplane.io/environment": asgBasesEnv}
	return ctx
}

// A new fleet of an Ubuntu version with a recorded base clones it for every member — no per-member
// registry import — and a fleet made before the cache keeps its template (no rolling replacement).
func TestVMBases_AutoScalingGroupMembersCloneTheBase(t *testing.T) {
	tmpl := extractInlineTemplate(t, asgCompositionPath)
	for _, os := range []string{"ubuntu-24.04", "ubuntu-22.04"} {
		short := strings.ReplaceAll(strings.TrimPrefix(os, "ubuntu-"), ".", "-")
		local := render(t, tmpl, asgBaseCtx(map[string]any{"os": os}))
		if registryImport.MatchString(local) {
			t.Errorf("%s: a new fleet's members must not import from the registry:\n%s", os, grepCtx(local, "registry"))
		}
		if !strings.Contains(local, `namespace: "openinfra-images"`) || !regexp.MustCompile(`name: "openinfra-ubuntu-`+short+`-[ab]{12}"`).MatchString(local) || !strings.Contains(local, "storageClassName: local-path") {
			t.Errorf("%s: a non-HA member clones the base's import onto local-path:\n%s", os, grepCtx(local, "source:"))
		}
		ha := render(t, tmpl, asgBaseCtx(map[string]any{"os": os, "highAvailability": true}))
		if registryImport.MatchString(ha) || !strings.Contains(ha, `-pristine"`) || !strings.Contains(ha, `-ha"`) {
			t.Errorf("%s: an HA member clones the base's pristine thin volume in its -ha class:\n%s", os, grepCtx(ha, "source:"))
		}
	}
	before := render(t, tmpl, asgCtx(map[string]any{"minSize": int64(1), "maxSize": int64(3), "launchTemplate": map[string]any{"os": "ubuntu-24.04"}}))
	ctx := asgBaseCtx(map[string]any{"os": "ubuntu-24.04"})
	ctx["observed"].(map[string]any)["resources"] = map[string]any{"pool": map[string]any{"resource": map[string]any{}}}
	after := render(t, tmpl, ctx)
	if docNamed(before, "pool") != docNamed(after, "pool") || !strings.Contains(after, `rootSource: "image"`) {
		t.Errorf("an existing fleet's pool must render byte-for-byte as before")
	}
	if win := render(t, tmpl, asgBaseCtx(map[string]any{"os": "windows-server-2022"})); strings.Contains(win, `rootSource: "base"`) {
		t.Errorf("Windows fleets keep their golden clone")
	}
}
