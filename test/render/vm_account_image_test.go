package render

import (
	"regexp"
	"strings"
	"testing"
)

// An instance launched from an account's EC2 image (spec.imageId, the aws-shim's CreateImage / CopyImage)
// clones its root from the image's disk in openinfra-images — and only once its account may launch the image
// (it owns it, or the launch permission names its account or all) and the image is available, as EC2's
// RunInstances checks. Until then it has no root disk and stays stopped; once launched it never reads the
// image again.

const acctImage = "ami-0123456789abcdef0"

const (
	mgmtAccount  = "111122223333"
	otherAccount = "444455556666"
)

// observedImage is the image's record as provider-kubernetes observes its DataVolume.
func observedImage(owner, launch, phase string) map[string]any {
	return map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{"manifest": map[string]any{
		"metadata": map[string]any{
			"labels":      map[string]any{"openinfra.dev/ec2-image": "true", "openinfra.dev/image-owner": owner},
			"annotations": map[string]any{"openinfra.dev/image-launch-permission": launch, "openinfra.dev/image-state": "pending"},
		},
		"status": map[string]any{"phase": phase},
	}}}}}
}

// observedNamespace is the VM's namespace as observed: labelled with a member account's id, or (account
// "") unlabelled, the management account's.
func observedNamespace(account string) map[string]any {
	md := map[string]any{"name": "default"}
	if account != "" {
		md["labels"] = map[string]any{"openinfra.dev/account-id": account}
	}
	return map[string]any{"resource": map[string]any{"status": map[string]any{"atProvider": map[string]any{"manifest": map[string]any{"metadata": md}}}}}
}

func imageCtx(os string, extra map[string]any) map[string]any {
	spec := map[string]any{"imageId": acctImage}
	for k, v := range extra {
		spec[k] = v
	}
	ctx := vmCtxFW(os, spec)
	ctx["context"] = map[string]any{"apiextensions.crossplane.io/environment": map[string]any{"awsAccountId": mgmtAccount}}
	return ctx
}

var imageClone = regexp.MustCompile(`pvc:\s*\n\s*namespace: openinfra-images\s*\n\s*name: "` + acctImage + `"`)

func launchedFromImage(t *testing.T, what, out string) {
	t.Helper()
	vm := docNamed(out, "virtualmachine")
	if !strings.Contains(vm, "name: myvm-root") || !imageClone.MatchString(vm) {
		t.Errorf("%s: the root must be cloned from the image's disk:\n%s", what, grepCtx(vm, "source:"))
	}
	if !strings.Contains(vm, "runStrategy: RerunOnFailure") {
		t.Errorf("%s: the launched instance runs", what)
	}
	if docNamed(out, "account-image") != "" || docNamed(out, "account-image-namespace") != "" {
		t.Errorf("%s: a launched instance reads the image no more", what)
	}
	if !strings.Contains(out, "imageLaunched: true") {
		t.Errorf("%s: status.imageLaunched must record the launch", what)
	}
	if registryImport.MatchString(out) || strings.Contains(out, "-golden") {
		t.Errorf("%s: an image's instance imports no catalog image", what)
	}
}

func waitsForImage(t *testing.T, what, out string) {
	t.Helper()
	vm := docNamed(out, "virtualmachine")
	if strings.Contains(vm, "dataVolumeTemplates:") || imageClone.MatchString(out) {
		t.Errorf("%s: no root disk until the image may be launched:\n%s", what, grepCtx(vm, "dataVolumeTemplates"))
	}
	if !strings.Contains(vm, "runStrategy: Halted") {
		t.Errorf("%s: the instance stays stopped until it launches", what)
	}
	img, ns := docNamed(out, "account-image"), docNamed(out, "account-image-namespace")
	if !strings.Contains(img, `managementPolicies: ["Observe"]`) || !strings.Contains(img, "kind: DataVolume") ||
		!strings.Contains(img, `name: "`+acctImage+`", namespace: openinfra-images`) {
		t.Errorf("%s: the image's record is observed, never managed:\n%s", what, img)
	}
	if !strings.Contains(ns, `managementPolicies: ["Observe"]`) || !strings.Contains(ns, "kind: Namespace") {
		t.Errorf("%s: the VM's namespace (its account) is observed:\n%s", what, ns)
	}
	if !strings.Contains(out, "imageLaunched: false") {
		t.Errorf("%s: status.imageLaunched is false while it waits", what)
	}
}

func TestVMAccountImage_LaunchPermission(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	obs := func(img, ns map[string]any) map[string]any {
		res := map[string]any{}
		if img != nil {
			res["account-image"] = img
		}
		if ns != nil {
			res["account-image-namespace"] = ns
		}
		return res
	}
	waitsForImage(t, "nothing observed yet", render(t, tmpl, imageCtx("ubuntu-24.04", nil)))
	for name, c := range map[string]map[string]any{
		"its own image":                obs(observedImage(otherAccount, "", "Succeeded"), observedNamespace(otherAccount)),
		"shared with its account":      obs(observedImage(mgmtAccount, otherAccount+",999988887777", "Succeeded"), observedNamespace(otherAccount)),
		"public":                       obs(observedImage(mgmtAccount, "all", "Succeeded"), observedNamespace(otherAccount)),
		"the management account's own": obs(observedImage(mgmtAccount, "", "Succeeded"), observedNamespace("")),
	} {
		launchedFromImage(t, name, render(t, tmpl, withObserved(imageCtx("ubuntu-24.04", nil), c)))
	}
	for name, c := range map[string]map[string]any{
		"another account's, not shared":     obs(observedImage(mgmtAccount, "", "Succeeded"), observedNamespace(otherAccount)),
		"shared with a third account":       obs(observedImage(mgmtAccount, "999988887777", "Succeeded"), observedNamespace(otherAccount)),
		"a member's, from the mgmt account": obs(observedImage(otherAccount, "", "Succeeded"), observedNamespace("")),
		"still being copied":                obs(observedImage(otherAccount, "", "CloneInProgress"), observedNamespace(otherAccount)),
		"the namespace not yet observed":    obs(observedImage(otherAccount, "", "Succeeded"), nil),
		"the image not found":               obs(nil, observedNamespace(otherAccount)),
	} {
		waitsForImage(t, name, render(t, tmpl, withObserved(imageCtx("ubuntu-24.04", nil), c)))
	}
	failed := observedImage(otherAccount, "", "Succeeded")
	failed["resource"].(map[string]any)["status"].(map[string]any)["atProvider"].(map[string]any)["manifest"].(map[string]any)["metadata"].(map[string]any)["annotations"].(map[string]any)["openinfra.dev/image-state"] = "failed"
	waitsForImage(t, "a failed image", render(t, tmpl, withObserved(imageCtx("ubuntu-24.04", nil), obs(failed, observedNamespace(otherAccount)))))
}

// Once launched, the instance keeps its root whatever becomes of the image (deregistered, unshared): the
// launch is kept in status, or read from the root the VM already has.
func TestVMAccountImage_LaunchedInstanceOutlivesTheImage(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	launchedFromImage(t, "status.imageLaunched", render(t, tmpl, withStatus(imageCtx("ubuntu-24.04", nil), map[string]any{"imageLaunched": true})))
	// The status lost: the VM's own root, cloned from the image, says it launched.
	vmObs := map[string]any{"virtualmachine": map[string]any{"resource": map[string]any{"spec": map[string]any{"forProvider": map[string]any{
		"manifest": map[string]any{"spec": map[string]any{"dataVolumeTemplates": []any{map[string]any{"metadata": map[string]any{"name": "myvm-root"}}}}}}}}}}
	launchedFromImage(t, "a root already made", render(t, tmpl, withObserved(imageCtx("ubuntu-24.04", nil), vmObs)))
}

// A Windows image's instance: cloned from the image (never the catalog's golden), its root diskSize but never
// below 100Gi; a UEFI image boots UEFI. A Linux image's instance is never made from the OS image cache.
func TestVMAccountImage_WindowsAndLinux(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	launched := map[string]any{"imageLaunched": true}
	out := render(t, tmpl, withStatus(imageCtx("windows-server-2022", map[string]any{"diskSize": "106Gi"}), launched))
	launchedFromImage(t, "windows", out)
	if !strings.Contains(docNamed(out, "virtualmachine"), `storage: "106Gi"`) {
		t.Errorf("a Windows image's root is its diskSize:\n%s", grepCtx(out, "storage:"))
	}
	out = render(t, tmpl, withStatus(imageCtx("windows-server-2022", map[string]any{"diskSize": "20Gi"}), launched))
	if !strings.Contains(docNamed(out, "virtualmachine"), `storage: "100Gi"`) {
		t.Errorf("a Windows root is never below 100Gi:\n%s", grepCtx(out, "storage:"))
	}
	if err := renderErr(tmpl, withStatus(imageCtx("windows-server-2022", map[string]any{"diskSize": "106Gi",
		"firmware": map[string]any{"mode": "uefi"}}), launched)); err != nil {
		t.Errorf("a UEFI Windows image boots UEFI: %v", err)
	}
	// The OS image cache is the catalog's: an image's instance is cloned from the image.
	ctx := withStatus(imageCtx("ubuntu-24.04", map[string]any{"diskSize": "22Gi"}), launched)
	ctx["context"].(map[string]any)["apiextensions.crossplane.io/environment"].(map[string]any)["vmBases"] = vmBasesEnv["vmBases"]
	out = render(t, tmpl, ctx)
	launchedFromImage(t, "linux with the OS image cache", out)
	if !strings.Contains(out, `rootSource: "image"`) || docNamed(out, "root-base") != "" {
		t.Errorf("an image's instance is not made from the OS image cache")
	}
	// The guest's instance metadata reports the image it was launched from.
	if !strings.Contains(docNamed(out, "vm-cloudinit"), acctImage) {
		t.Errorf("the metadata agent's config must carry the image id:\n%s", grepCtx(docNamed(out, "vm-cloudinit"), "imageId"))
	}
}

// An encrypted root launched from an image: the image's disk is copied onto it once the instance may launch
// it, never before.
func TestVMAccountImage_EncryptedRoot(t *testing.T) {
	tmpl := extractInlineTemplate(t, "../../platform/abstraction/vm-composition.yaml")
	enc := map[string]any{"rootDisk": map[string]any{"encrypted": true, "encryptionKey": "k"}}
	waiting := render(t, tmpl, imageCtx("ubuntu-24.04", enc))
	if docNamed(waiting, "root-image") != "" || !strings.Contains(waiting, "runStrategy: Halted") {
		t.Errorf("an encrypted root waits for the image before anything is copied:\n%s", docNamed(waiting, "root-image"))
	}
	out := render(t, tmpl, withObserved(imageCtx("ubuntu-24.04", enc), map[string]any{
		"account-image": observedImage(otherAccount, "", "Succeeded"), "account-image-namespace": observedNamespace(otherAccount)}))
	img := docNamed(out, "root-image")
	if !strings.Contains(img, "kind: DataVolume") || !imageClone.MatchString(img) {
		t.Errorf("the encrypted root's source is the image's disk:\n%s", img)
	}
}
