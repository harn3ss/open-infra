package render

import (
	"strings"
	"testing"
)

// spec.volumes attaches existing kind: Volumes (the EC2 VolumeAttachment equivalent): each renders a
// virtio disk after the data disks and a volume bound to the Volume's own PVC, named after the Volume.
func TestVM_AttachedVolumes(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-24.04", map[string]any{
		"dataDisks": []any{map[string]any{"size": "10Gi"}},
		"volumes":   []any{map[string]any{"name": "app-data"}},
	}))
	if strings.Count(out, `name: "vol-app-data"`) < 2 {
		t.Fatalf("the attached volume must appear as a disk and a volume; got:\n%s", grepCtx(out, "vol-app-data"))
	}
	if !strings.Contains(out, `claimName: "app-data"`) {
		t.Fatalf("the attached volume must bind the Volume's PVC; got:\n%s", grepCtx(out, "app-data"))
	}
	// After the data disk in device order (vdb is data1, vdc the attached volume).
	if i, j := strings.Index(out, "name: data1"), strings.Index(out, `name: "vol-app-data"`); i < 0 || j < i {
		t.Fatalf("the attached volume must come after the data disks; got:\n%s", grepCtx(out, "disks"))
	}
	// No volumes: the render is unchanged (no vol- entries).
	plain := render(t, tmpl, vmCtx("ubuntu-24.04", ""))
	if strings.Contains(plain, "vol-") {
		t.Fatalf("a VM with no volumes must attach none; got:\n%s", grepCtx(plain, "vol-"))
	}
}
