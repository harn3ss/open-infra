package render

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// guestDisk is one block device as the guest kernel sees it: its kernel name, the serial KubeVirt gives
// it (from the VM's disk list), and, for a partition, its number.
type guestDisk struct {
	kernel, serial string
	part           int
}

// renderedDisks reads the VM's domain.devices.disks list from a rendered composition: each disk's name
// and serial, in order.
func renderedDisks(t *testing.T, out string) [][2]string {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range docs {
		m := digMap(d, "spec", "forProvider", "manifest")
		if m == nil || m["kind"] != "VirtualMachine" {
			continue
		}
		dom := digMap(m, "spec", "template", "spec", "domain", "devices")
		var disks [][2]string
		for _, x := range asList(dom["disks"]) {
			dm, _ := x.(map[string]any)
			if _, cd := dm["cdrom"]; cd {
				continue // a SATA CD is /dev/sr*, not a virtio disk
			}
			name, _ := dm["name"].(string)
			serial, _ := dm["serial"].(string)
			disks = append(disks, [2]string{name, serial})
		}
		return disks
	}
	t.Fatal("no VirtualMachine in the render")
	return nil
}

func digMap(v any, keys ...string) map[string]any {
	m, _ := dig(v, keys...).(map[string]any)
	return m
}

var udevRuleRE = regexp.MustCompile(`^KERNEL=="([^"]+)", ATTRS\{serial\}=="([^"]+)", SYMLINK\+="([^"]+)"$`)

// applyUdevRules evaluates the rules file's lines (the KERNEL / ATTRS{serial} / SYMLINK+= subset the
// composition renders) against the guest's devices and returns link -> kernel name. A partition matches
// ATTRS{serial} through its parent disk, as udev walks up the device path; %n is the partition number.
func applyUdevRules(t *testing.T, rules string, devs []guestDisk) map[string]string {
	t.Helper()
	links := map[string]string{}
	for _, ln := range strings.Split(strings.TrimSpace(rules), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		m := udevRuleRE.FindStringSubmatch(ln)
		if m == nil {
			t.Fatalf("unexpected rule line %q", ln)
		}
		glob := strings.ReplaceAll(m[1], "[!", "[^")
		for _, d := range devs {
			if ok, err := path.Match(glob, d.kernel); err != nil || !ok || d.serial != m[2] {
				continue
			}
			for _, l := range strings.Fields(m[3]) {
				l = strings.ReplaceAll(l, "%n", fmt.Sprint(d.part))
				if prev, dup := links[l]; dup && prev != d.kernel {
					t.Errorf("link %s claimed by %s and %s", l, prev, d.kernel)
				}
				links[l] = d.kernel
			}
		}
	}
	return links
}

// The rules file the composition writes, as the guest gets it.
func renderedRules(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "99-openinfra-aws-device-names.rules")
	if i < 0 {
		return ""
	}
	rest := out[i:]
	j := strings.Index(rest, "content: |")
	if j < 0 {
		t.Fatal("rules file without content")
	}
	var lines []string
	for _, ln := range strings.Split(rest[j+len("content: |"):], "\n")[1:] {
		tl := strings.TrimSpace(ln)
		if !strings.HasPrefix(tl, "KERNEL==") {
			break
		}
		lines = append(lines, tl)
	}
	return strings.Join(lines, "\n")
}

// The AWS device names a lift-and-shift UserData uses resolve to the right virtio disk: the Nitro names
// (/dev/nvme0n1 root, /dev/nvme1n1… data disks then attached volumes) and each mapping's DeviceName with
// its sd/xvd twin, partitions included. They are keyed by serial, so the cloud-init seed disk — a virtio
// disk listed right after the root, so the guest's /dev/vdb — never takes a data disk's name.
func TestVM_AWSDeviceNamesBySerial(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	out := render(t, tmpl, vmCtxFW("ubuntu-22.04", map[string]any{
		"dataDisks": []any{
			map[string]any{"name": "sdf", "size": "1Gi", "deviceName": "/dev/sdf"},
			map[string]any{"name": "extra", "size": "30Gi"},
		},
		"volumes": []any{map[string]any{"name": "logs", "deviceName": "/dev/xvdh"}},
	}))
	disks := renderedDisks(t, out)
	// The guest kernel names virtio disks in the order the VM lists them.
	var devs []guestDisk
	kernel := map[string]string{}
	for i, d := range disks {
		k := "vd" + string(rune('a'+i))
		kernel[d[0]] = k
		devs = append(devs, guestDisk{kernel: k, serial: d[1]}, guestDisk{kernel: k + "1", serial: d[1], part: 1})
	}
	if kernel["cloudinit"] != "vdb" {
		t.Fatalf("expected the cloud-init disk second (vdb), the case serial keying exists for; disks: %v", disks)
	}
	rules := renderedRules(t, out)
	if rules == "" {
		t.Fatalf("no device-name rules rendered:\n%s", grepCtx(out, "nvme"))
	}
	got := applyUdevRules(t, rules, devs)
	want := map[string]string{
		"nvme0n1": kernel["root"], "nvme0n1p1": kernel["root"] + "1",
		"nvme1n1": kernel["sdf"], "nvme1n1p1": kernel["sdf"] + "1",
		"sdf": kernel["sdf"], "xvdf": kernel["sdf"], "sdf1": kernel["sdf"] + "1", "xvdf1": kernel["sdf"] + "1",
		"nvme2n1": kernel["extra"], "nvme2n1p1": kernel["extra"] + "1",
		"nvme3n1": kernel["vol-logs"], "nvme3n1p1": kernel["vol-logs"] + "1",
		"sdh": kernel["vol-logs"], "xvdh": kernel["vol-logs"], "sdh1": kernel["vol-logs"] + "1", "xvdh1": kernel["vol-logs"] + "1",
	}
	for l, k := range want {
		if got[l] != k {
			t.Errorf("/dev/%s -> %q, want %q", l, got[l], k)
		}
	}
	var extra []string
	for l, k := range got {
		if _, ok := want[l]; !ok {
			extra = append(extra, l+"->"+k)
		}
		if k == "vdb" || k == "vdb1" {
			t.Errorf("/dev/%s points at the cloud-init disk", l)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("unexpected links: %v", extra)
	}
	if !strings.Contains(out, "udevadm") {
		t.Error("udev must be reloaded and triggered before the UserData runs")
	}
	// A VM with no data disks or volumes carries no rules file.
	if strings.Contains(render(t, tmpl, vmCtx("ubuntu-24.04", "")), "aws-device-names") {
		t.Error("a VM with no data disks must not emit the alias rules")
	}
}
