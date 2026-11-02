package render

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const vmCompositionPath = "../../platform/abstraction/vm-composition.yaml"

// withImportDone marks the temporary image DataVolume Succeeded in the observed resources.
func withImportDone(ctx map[string]any) map[string]any {
	ctx["observed"].(map[string]any)["resources"] = map[string]any{
		"root-image": map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{
			"manifest": map[string]any{"metadata": map[string]any{"name": "myvm-root-image"}, "status": map[string]any{"phase": "Succeeded"}}}}}},
	}
	return ctx
}

func encRootCtx(extra map[string]any) map[string]any {
	spec := map[string]any{"rootDisk": map[string]any{"encrypted": true, "encryptionKey": "app-ebs-default"}}
	for k, v := range extra {
		spec[k] = v
	}
	return vmCtxFW("ubuntu-22.04", spec)
}

// manifestsByKind returns the composed manifests of a render, by kind.
func manifestsByKind(t *testing.T, out string) map[string][]map[string]any {
	t.Helper()
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string][]map[string]any{}
	for _, d := range docs {
		if m := digMap(d, "spec", "forProvider", "manifest"); m != nil {
			k, _ := m["kind"].(string)
			by[k] = append(by[k], m)
		}
	}
	return by
}

// An encrypted root disk is a Block PVC on longhorn-encrypted, keyed by the named EncryptionKey (the
// annotation the volume-crypto reconciler keys by), with no CDI root DataVolume (CDI cannot write a
// dm-crypt device). Until the OS image has been copied onto it, the VM is Halted and the composition
// renders the temporary image import — and the copy pod only once that import has Succeeded, so it never
// copies a partial image.
func TestVM_EncryptedRoot_BeforeTheCopy(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmCompositionPath)
	out := render(t, tmpl, encRootCtx(nil))
	by := manifestsByKind(t, out)
	var root map[string]any
	for _, p := range by["PersistentVolumeClaim"] {
		if digMap(p, "metadata")["name"] == "myvm-root" {
			root = p
		}
	}
	if root == nil {
		t.Fatalf("no encrypted root PVC:\n%s", grepCtx(out, "myvm-root"))
	}
	spec := digMap(root, "spec")
	if spec["storageClassName"] != "longhorn-encrypted" || spec["volumeMode"] != "Block" {
		t.Errorf("root PVC must be a Block PVC on longhorn-encrypted: %v", spec)
	}
	if digMap(root, "metadata", "annotations")["openinfra.dev/encryption-key"] != "app-ebs-default" {
		t.Errorf("root PVC must name its EncryptionKey: %v", digMap(root, "metadata", "annotations"))
	}
	vm := by["VirtualMachine"][0]
	if _, has := digMap(vm, "spec")["dataVolumeTemplates"]; has {
		t.Errorf("an encrypted root has no CDI root DataVolume:\n%s", grepCtx(out, "dataVolumeTemplates"))
	}
	if digMap(vm, "spec")["runStrategy"] != "Halted" {
		t.Errorf("the VM must stay Halted until the image is on the encrypted root, got %v", digMap(vm, "spec")["runStrategy"])
	}
	var rootVol map[string]any
	for _, v := range asList(digMap(vm, "spec", "template", "spec")["volumes"]) {
		if vm, _ := v.(map[string]any); vm["name"] == "root" {
			rootVol = vm
		}
	}
	if digMap(rootVol, "persistentVolumeClaim")["claimName"] != "myvm-root" {
		t.Errorf("the VM's root volume must be the encrypted PVC, got %v", rootVol)
	}
	var dv, job bool
	for _, d := range by["DataVolume"] {
		if digMap(d, "metadata")["name"] == "myvm-root-image" {
			dv = true
			if digMap(d, "spec", "storage")["storageClassName"] != "longhorn" {
				t.Errorf("the temporary image disk is unencrypted Longhorn (bound at once, so CDI imports without a consumer): %v", digMap(d, "spec", "storage"))
			}
			if digMap(d, "metadata", "annotations")["cdi.kubevirt.io/storage.deleteAfterCompletion"] != "false" {
				t.Error("CDI must not garbage-collect the image before the copy reads it")
			}
		}
	}
	for _, j := range by["Pod"] {
		if digMap(j, "metadata")["name"] == "myvm-root-populate" {
			job = true
		}
	}
	if !dv || job {
		t.Fatalf("before the import completes, the image import must render (%v) and the copy pod must not (%v)", dv, job)
	}
	// Once CDI reports the import Succeeded, the copy pod renders (and the import stays until the copy is done).
	done := manifestsByKind(t, render(t, tmpl, withImportDone(encRootCtx(nil))))
	job, dv = false, false
	for _, j := range done["Pod"] {
		job = job || digMap(j, "metadata")["name"] == "myvm-root-populate"
	}
	for _, d := range done["DataVolume"] {
		dv = dv || digMap(d, "metadata")["name"] == "myvm-root-image"
	}
	if !job || !dv {
		t.Fatalf("after the import, the copy pod (%v) and the image (%v) must render", job, dv)
	}
	if !strings.Contains(out, "rootPopulated: false") {
		t.Errorf("status.rootPopulated must report false before the copy:\n%s", grepCtx(out, "rootPopulated"))
	}
}

// Once the copy pod has succeeded — or once status.rootPopulated says so, after the pod is gone — the VM
// runs and the temporary image and the pod are no longer rendered (Crossplane deletes them); the status
// keeps saying populated, so the image is never copied over the disk again.
func TestVM_EncryptedRoot_AfterTheCopy(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmCompositionPath)
	viaJob := encRootCtx(nil)
	viaJob["observed"].(map[string]any)["resources"] = map[string]any{
		"root-populate": map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{
			"manifest": map[string]any{"metadata": map[string]any{"name": "myvm-root-populate"}, "status": map[string]any{"phase": "Succeeded"}}}}}},
	}
	viaStatus := encRootCtx(nil)
	viaStatus["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["status"] = map[string]any{"rootPopulated": true}
	for name, ctx := range map[string]map[string]any{"copy pod succeeded": viaJob, "status kept": viaStatus} {
		out := render(t, tmpl, ctx)
		by := manifestsByKind(t, out)
		if got := digMap(by["VirtualMachine"][0], "spec")["runStrategy"]; got != "Always" {
			t.Errorf("%s: the VM must run once the image is on the encrypted root, got %v", name, got)
		}
		if strings.Contains(out, "myvm-root-image") || strings.Contains(out, "myvm-root-populate") {
			t.Errorf("%s: the image import and the copy pod must no longer render:\n%s", name, grepCtx(out, "root-"))
		}
		if !strings.Contains(out, "rootPopulated: true") {
			t.Errorf("%s: status.rootPopulated must be kept true", name)
		}
		if !strings.Contains(out, "name: myvm-root\n") {
			t.Errorf("%s: the encrypted root PVC must stay", name)
		}
	}
	// A stopped VM stays Halted, populated or not.
	stopped := encRootCtx(map[string]any{"running": false})
	stopped["observed"].(map[string]any)["composite"].(map[string]any)["resource"].(map[string]any)["status"] = map[string]any{"rootPopulated": true}
	if got := digMap(manifestsByKind(t, render(t, tmpl, stopped))["VirtualMachine"][0], "spec")["runStrategy"]; got != "Halted" {
		t.Errorf("spec.running false keeps the VM Halted, got %v", got)
	}
	// An unencrypted VM renders no populate machinery and no status field.
	plain := render(t, tmpl, vmCtx("ubuntu-22.04", ""))
	if strings.Contains(plain, "root-populate") || strings.Contains(plain, "longhorn-encrypted") || strings.Contains(plain, "rootPopulated") {
		t.Errorf("an unencrypted root must render as before:\n%s", grepCtx(plain, "root-"))
	}
}

// An encrypted root refuses what it cannot honor, instead of booting an unencrypted or wrong disk.
func TestVM_EncryptedRoot_RefusesWhatItCannotHonor(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmCompositionPath)
	for name, ctx := range map[string]map[string]any{
		"no key":  vmCtxFW("ubuntu-22.04", map[string]any{"rootDisk": map[string]any{"encrypted": true}}),
		"HA":      encRootCtx(map[string]any{"highAvailability": true}),
		"adopted": encRootCtx(map[string]any{"existingRootClaim": "old-root", "firmware": map[string]any{"mode": "bios"}}),
	} {
		if err := renderErr(tmpl, ctx); err == nil || !strings.Contains(err.Error(), "rootDisk.encrypted") {
			t.Errorf("%s: want a rootDisk.encrypted refusal, got %v", name, err)
		}
	}
}

// The copy pod's script, run under the setup image's shells with files standing in for the image and
// the encrypted device: it copies the image onto a fresh (noise-filled) device, refuses an image larger
// than the device, and never writes over a device that already holds a boot record.
func TestVM_EncryptedRoot_CopyScript(t *testing.T) {
	tmpl := extractInlineTemplate(t, vmCompositionPath)
	out := render(t, tmpl, withImportDone(encRootCtx(nil)))
	docs, err := parseYAMLDocs(out)
	if err != nil {
		t.Fatal(err)
	}
	var script string
	for _, d := range docs {
		if m := digMap(d, "spec", "forProvider", "manifest"); m != nil && m["kind"] == "Pod" {
			var s []string
			scriptTexts(m, "copy", &s)
			if len(s) == 1 {
				script = strings.TrimPrefix(s[0], "copy: ")
			}
		}
	}
	if script == "" || !strings.Contains(script, "/dev/openinfra-root") {
		t.Fatalf("copy script not found:\n%s", grepCtx(out, "root-populate"))
	}
	// The boot record (the image's first MiB) is written after everything else, so a copy interrupted
	// part-way leaves none and is copied again rather than taken for a populated disk.
	bulk, boot := strings.Index(script, "skip=1 seek=1"), strings.Index(script, "bs=1M count=1")
	if bulk < 0 || boot < 0 || boot < bulk {
		t.Fatalf("the image's first MiB must be written last (bulk at %d, boot record at %d):\n%s", bulk, boot, script)
	}
	noise := func(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); b[510], b[511] = 0x12, 0x34; return b }
	image := func(n int) []byte {
		b := bytes.Repeat([]byte{0xab}, n)
		copy(b[512:], "EFI PART") // a GPT disk image
		b[510], b[511] = 0x55, 0xaa
		return b
	}
	mbrDisk := func(n int) []byte {
		b := noise(n)
		b[446], b[450], b[510], b[511] = 0x80, 0x83, 0x55, 0xaa // active, Linux, boot signature
		return b
	}
	// An interrupted copy: everything but the first MiB (written last) is already there.
	interrupted := func() []byte {
		b := noise(4 << 20)
		copy(b[1<<20:], image(3 << 20)[1<<20:])
		return b
	}
	cases := []struct {
		name          string
		img, dev      []byte
		wantOK        bool
		wantCopied    bool
		wantOutSubstr string
	}{
		{"fresh encrypted disk gets the image", image(3 << 20), noise(4 << 20), true, true, "copied the OS image"},
		{"an interrupted copy is copied again", image(3 << 20), interrupted(), true, true, "copied the OS image"},
		{"an image larger than the disk is refused", image(5 << 20), noise(4 << 20), false, false, "larger than the encrypted root"},
		{"a disk with a GPT boot record is left alone", image(3 << 20), image(4 << 20), true, false, "already holds a boot record"},
		{"a disk with an MBR boot record is left alone", image(3 << 20), mbrDisk(4 << 20), true, false, "already holds a boot record"},
	}
	for _, sh := range posixShells(t) {
		for _, c := range cases {
			dir := t.TempDir()
			img, dev := filepath.Join(dir, "disk.img"), filepath.Join(dir, "dev")
			if err := os.WriteFile(img, c.img, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dev, c.dev, 0o600); err != nil {
				t.Fatal(err)
			}
			// A regular file stands in for the device: blockdev cannot size it, so the script's stat fallback does.
			s := strings.ReplaceAll(strings.ReplaceAll(script, "/src/disk.img", img), "/dev/openinfra-root", dev)
			args := append(append([]string{}, sh[1:]...), "-c", s)
			cmd := exec.Command(sh[0], args...)
			o, err := cmd.CombinedOutput()
			if (err == nil) != c.wantOK {
				t.Errorf("%s/%s: ok=%v, want %v\n%s", shellName(sh), c.name, err == nil, c.wantOK, o)
				continue
			}
			if !strings.Contains(string(o), c.wantOutSubstr) {
				t.Errorf("%s/%s: output lacks %q:\n%s", shellName(sh), c.name, c.wantOutSubstr, o)
			}
			got, _ := os.ReadFile(dev)
			if c.wantCopied && (len(got) < len(c.img) || !bytes.Equal(got[:len(c.img)], c.img)) {
				t.Errorf("%s/%s: the image was not copied onto the device", shellName(sh), c.name)
			}
			if !c.wantCopied && !bytes.Equal(got, c.dev) {
				t.Errorf("%s/%s: the device was written", shellName(sh), c.name)
			}
		}
	}
}

// The encrypted root's copy is a bare Pod the provider must be allowed to manage, and the two steps the
// VM waits on (the image import, the copy) are watched, so each is seen when it finishes rather than on
// the provider's drift poll (about 10 minutes apiece — a stack's instance waited past its deadline).
func TestVM_EncryptedRoot_ProviderCanRunAndSeeTheCopy(t *testing.T) {
	setup := string(mustRead(t, providerSetupPath))
	if !regexp.MustCompile(`resources: \[[^\]]*\bpods\b[^\]]*\]`).MatchString(setup) {
		t.Error("provider-kubernetes must be allowed to manage pods (the encrypted root's copy Pod)")
	}
	if !strings.Contains(setup, `args: ["--enable-watches"]`) {
		t.Error("provider-kubernetes must run with --enable-watches, or spec.watch is ignored")
	}
	comp := string(mustRead(t, "../../platform/abstraction/vm-composition.yaml"))
	for _, rn := range []string{"root-image", "root-populate"} {
		i := strings.Index(comp, "composition-resource-name: "+rn+"\n")
		if i < 0 {
			t.Fatalf("no %s resource in the VM composition", rn)
		}
		if !strings.Contains(comp[i:i+600], "watch: true") {
			t.Errorf("the %s Object must be watched", rn)
		}
	}
}

// The VM's private IP (an EC2 instance's PrivateIp, and its PrivateDnsName) is the running instance's first
// interface address: the composition observes the VirtualMachineInstance (watched, never managed, never
// blocking readiness) and reports it as status.ip.
func TestVM_PrivateIPFromTheRunningInstance(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	ctx := vmCtx("ubuntu-24.04", "")
	none := render(t, tmpl, ctx)
	if !strings.Contains(none, "composition-resource-name: vmi-observe") || !strings.Contains(none, `ip: ""`) {
		t.Fatalf("a VM must observe its instance and report an empty status.ip until it runs:\n%s", grepCtx(none, "vmi-observe"))
	}
	i := strings.Index(none, "composition-resource-name: vmi-observe")
	blk := none[i : i+600]
	for _, want := range []string{`managementPolicies: ["Observe"]`, "watch: true", "kind: VirtualMachineInstance", `gotemplating.fn.crossplane.io/ready: "True"`} {
		if !strings.Contains(none[i-200:i+600], want) {
			t.Errorf("the instance observation lacks %q:\n%s", want, blk)
		}
	}
	obs := ctx["observed"].(map[string]any)
	obs["resources"] = map[string]any{"vmi-observe": map[string]any{"resource": map[string]any{"status": map[string]any{
		"atProvider": map[string]any{"manifest": map[string]any{"status": map[string]any{
			"interfaces": []any{map[string]any{"ipAddress": "10.16.4.7", "name": "default"}},
		}}},
	}}}}
	if got := render(t, tmpl, ctx); !strings.Contains(got, `ip: "10.16.4.7"`) {
		t.Fatalf("status.ip must be the instance's first interface address:\n%s", grepCtx(got, "ip:"))
	}
}
