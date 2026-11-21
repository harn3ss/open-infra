package cfn

import (
	"strings"
	"testing"
)

const imageInstanceTmpl = `
Parameters:
  Image: { Type: String }
  Size: { Type: Number, Default: 0 }
Conditions:
  Sized: !Not [!Equals [!Ref Size, 0]]
Resources:
  Build:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !Ref Image
      InstanceType: t3.large
      BlockDeviceMappings: !If
        - Sized
        - - DeviceName: /dev/sda1
            Ebs: { VolumeSize: !Ref Size }
        - !Ref AWS::NoValue
`

const (
	winImage     = "ami-0aaaaaaaaaaaaaaa1"
	linuxImage   = "ami-0bbbbbbbbbbbbbbb2"
	pendingImage = "ami-0ccccccccccccccc3"
	uefiImage    = "ami-0ddddddddddddddd4"
)

// accountImages are the images the stack's account may launch: a Windows one, a Linux one, one still being
// made, and a UEFI one.
func accountImages() map[string]AccountImage {
	return map[string]AccountImage{
		winImage:     {OS: "windows-server-2022", State: "available", RootGiB: 106},
		linuxImage:   {OS: "ubuntu-24.04", State: "available", RootGiB: 22},
		pendingImage: {OS: "ubuntu-24.04", State: "pending", RootGiB: 22},
		uefiImage:    {OS: "debian-12", State: "available", RootGiB: 30, BootMode: "uefi"},
	}
}

func translateImageInstance(t *testing.T, params map[string]string, images map[string]AccountImage) (*Manifest, []Finding) {
	t.Helper()
	ctx := ctxWithParams(t, imageInstanceTmpl, params)
	ctx.caps.Images = images
	return translatorFor("AWS::EC2::Instance")("Build", ecsResolvedService(t, ctx, "Build"), ctx)
}

// An ImageId naming one of the account's images launches from it: spec.imageId names the image, spec.os is
// the OS its instance ran, and the root holds it (at least its size; a Windows root at least 100 GiB).
func TestTranslate_EC2Instance_FromAccountImage(t *testing.T) {
	for _, c := range []struct {
		image, size, os, disk string
	}{
		{winImage, "", "windows-server-2022", "106Gi"},
		{linuxImage, "", "ubuntu-24.04", "22Gi"},
		{linuxImage, "40", "ubuntu-24.04", "40Gi"},
		{strings.ToUpper(linuxImage[:4]) + linuxImage[4:], "", "ubuntu-24.04", "22Gi"},
	} {
		params := map[string]string{"Image": c.image}
		if c.size != "" {
			params["Size"] = c.size
		}
		m, fs := translateImageInstance(t, params, accountImages())
		if len(fs) != 0 {
			t.Errorf("%s: findings %v", c.image, fs)
			continue
		}
		if m.Spec["imageId"] != strings.ToLower(c.image) || m.Spec["os"] != c.os || m.Spec["diskSize"] != c.disk {
			t.Errorf("%s (size %q): imageId=%v os=%v diskSize=%v, want %s %s", c.image, c.size, m.Spec["imageId"], m.Spec["os"], m.Spec["diskSize"], c.os, c.disk)
		}
		if m.Spec["firmware"] != nil {
			t.Errorf("%s: a BIOS image sets no firmware: %v", c.image, m.Spec["firmware"])
		}
	}
	// A UEFI image boots its instance UEFI.
	m, fs := translateImageInstance(t, map[string]string{"Image": uefiImage}, accountImages())
	if fw, _ := m.Spec["firmware"].(map[string]any); len(fs) != 0 || fw["mode"] != "uefi" {
		t.Errorf("a UEFI image: firmware=%v findings=%v", m.Spec["firmware"], fs)
	}
	// A catalog image's id is still the catalog's.
	m, fs = translateImageInstance(t, map[string]string{"Image": ImageIDForOS("debian-12")}, accountImages())
	if len(fs) != 0 || m.Spec["os"] != "debian-12" || m.Spec["imageId"] != nil {
		t.Errorf("a catalog image id: os=%v imageId=%v findings=%v", m.Spec["os"], m.Spec["imageId"], fs)
	}
}

// An image the account may not launch (another account's not shared with it, or none) does not exist for it,
// in EC2's words; one not yet available refuses as unavailable; a root smaller than the image refuses.
func TestTranslate_EC2Instance_AccountImageRefusals(t *testing.T) {
	for _, c := range []struct {
		params map[string]string
		want   string
	}{
		{map[string]string{"Image": "ami-0eeeeeeeeeeeeeee5"}, "The image id '[ami-0eeeeeeeeeeeeeee5]' does not exist (InvalidAMIID.NotFound)"},
		{map[string]string{"Image": pendingImage}, "The image id '[" + pendingImage + "]' is not available (InvalidAMIID.Unavailable)"},
		{map[string]string{"Image": linuxImage, "Size": "8"}, "Volume of size 8GB is smaller than the root volume of image '" + linuxImage + "', expect size >= 22GB"},
	} {
		m, fs := translateImageInstance(t, c.params, accountImages())
		if len(fs) != 1 || !strings.Contains(fs[0].Reason, c.want) {
			t.Errorf("%v must refuse with %q: findings=%v", c.params, c.want, fs)
		}
		if m != nil && m.Spec["imageId"] != nil && c.params["Size"] == "" {
			t.Errorf("%v must not launch from the image: %v", c.params, m.Spec["imageId"])
		}
	}
	// Without the image store (the CLI), a raw ami- id that is not the catalog's stays opaque.
	_, fs := translateImageInstance(t, map[string]string{"Image": linuxImage}, nil)
	if len(fs) != 1 || !strings.Contains(fs[0].Reason, "is a raw AMI id") {
		t.Errorf("without the image store: %v", fs)
	}
}

// An instance the stack already launched from an image keeps it when the image is deregistered or no longer
// shared with the account: an update does not refuse it, and the instance keeps its root.
func TestTranslate_EC2Instance_LaunchedImageOutlivesIt(t *testing.T) {
	ctx := ctxWithParams(t, imageInstanceTmpl, map[string]string{"Image": winImage})
	ctx.caps.Images = map[string]AccountImage{}
	ctx.namer = newPhysNamer("s", []StackResource{{LogicalID: "Build", Kind: "VirtualMachine", Name: "s-build",
		Spec: map[string]any{"os": "windows-server-2022", "imageId": winImage, "diskSize": "106Gi"}}})
	m, fs := translatorFor("AWS::EC2::Instance")("Build", ecsResolvedService(t, ctx, "Build"), ctx)
	if len(fs) != 0 || m.Spec["imageId"] != winImage || m.Spec["os"] != "windows-server-2022" || m.Spec["diskSize"] != "106Gi" {
		t.Errorf("a launched instance keeps its image: spec=%v findings=%v", m.Spec, fs)
	}
	// Another instance (another logical id) cannot launch from it.
	ctx.namer = newPhysNamer("s", []StackResource{{LogicalID: "Other", Kind: "VirtualMachine", Spec: map[string]any{"imageId": winImage}}})
	if _, fs := translatorFor("AWS::EC2::Instance")("Build", ecsResolvedService(t, ctx, "Build"), ctx); len(fs) != 1 ||
		!strings.Contains(fs[0].Reason, "does not exist") {
		t.Errorf("a new instance from a deregistered image must refuse: %v", fs)
	}
}
