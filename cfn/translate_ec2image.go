package cfn

import (
	"fmt"
	"strconv"
	"strings"
)

// An AWS::EC2::Instance whose ImageId is one of the account's EC2 images (Capabilities.Images: made with the
// aws-shim's CreateImage or CopyImage, its own or shared with it) launches from that image, as EC2 does:
// spec.imageId names the image, whose disk the VM's root is cloned from, and spec.os is the OS the image's
// instance ran (which decides Windows or Linux). The root is at least the image's size (a smaller root
// VolumeSize refuses, as EC2 refuses a volume smaller than its snapshot); a Windows root keeps its 100 GiB
// minimum. An image the account may not launch — another account's not shared with it, or none at all —
// refuses with EC2's words (InvalidAMIID.NotFound), as does one not yet available.
//
// An instance the stack already launched from an image keeps it when the image is later deregistered or no
// longer shared with the account, as on AWS: the instance does not need the image once it runs.

// windowsMinRootGiB is a Windows root's fixed minimum (vm-composition.yaml): the catalog's Windows images are
// cloned into a 100 GiB root.
const windowsMinRootGiB = 100

// ec2AccountImage resolves an ImageId naming an account image. handled=false when imageID is not one this
// deploy knows of as an account image (a catalog image's id, an SSM path, or a deploy path without the image
// store), so the catalog's resolution applies.
func ec2AccountImage(id, imageID string, ctx *stackCtx, spec map[string]any) (img *AccountImage, f []Finding, handled bool) {
	lc := strings.ToLower(strings.TrimSpace(imageID))
	if !strings.HasPrefix(lc, "ami-") || catalogOSForImageID(lc) != "" || ctx == nil || ctx.caps.Images == nil {
		return nil, nil, false
	}
	found, ok := ctx.caps.Images[lc]
	if !ok {
		if prior := ctx.recordedImageSpec(id, lc); prior != nil {
			// Launched from it already: keep what the instance was launched with.
			for _, k := range []string{"os", "imageId", "diskSize", "firmware"} {
				if v, has := prior[k]; has {
					spec[k] = v
				}
			}
			os, _ := prior["os"].(string)
			return &AccountImage{OS: os, State: "available", RootGiB: giB(fmt.Sprint(prior["diskSize"]))}, nil, true
		}
		return nil, []Finding{{"Resource " + id, "ImageId " + imageID + ": The image id '[" + lc + "]' does not exist (InvalidAMIID.NotFound) — " +
			"it is neither a catalog image nor an image of this account or shared with it (aws ec2 describe-images --image-ids " + lc + ")"}}, true
	}
	if found.State != "available" {
		return nil, []Finding{{"Resource " + id, "ImageId " + imageID + ": The image id '[" + lc + "]' is not available (InvalidAMIID.Unavailable): the image is " +
			found.State + "; an instance launches from it once it is available (aws ec2 wait image-available --image-ids " + lc + ")"}}, true
	}
	spec["os"] = found.OS
	spec["imageId"] = lc
	if found.BootMode == "uefi" {
		spec["firmware"] = map[string]any{"mode": "uefi"}
	}
	return &found, nil, true
}

// ec2ImageRootSize sizes the root of an instance launched from img: at least the image's size (and a
// Windows root's minimum); a smaller root BlockDeviceMapping VolumeSize refuses, as EC2 refuses a volume
// smaller than its snapshot.
func ec2ImageRootSize(id, imageID string, spec map[string]any, img AccountImage) []Finding {
	min := img.RootGiB
	if strings.HasPrefix(img.OS, "windows-") && min < windowsMinRootGiB {
		min = windowsMinRootGiB
	}
	if ds, ok := spec["diskSize"].(string); ok && ds != "" {
		n := giB(ds)
		if n < img.RootGiB {
			return []Finding{{"Resource " + id, fmt.Sprintf("BlockDeviceMappings: Volume of size %dGB is smaller than the root volume of image '%s', expect size >= %dGB (InvalidBlockDeviceMapping)",
				n, strings.ToLower(imageID), img.RootGiB)}}
		}
		if n >= min {
			return nil
		}
	}
	if min > 0 {
		spec["diskSize"] = fmt.Sprintf("%dGi", min)
	}
	return nil
}

// giB is a "<n>Gi" size's n (0 for any other form).
func giB(s string) int {
	n, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(s), "Gi"))
	if err != nil {
		return 0
	}
	return n
}

// recordedImageSpec is the recorded spec of instance id when the stack already launched it from image
// imageID, else nil.
func (c *stackCtx) recordedImageSpec(id, imageID string) map[string]any {
	if c == nil || c.namer == nil {
		return nil
	}
	for _, r := range c.namer.priorRes {
		if r.LogicalID == id && r.Kind == "VirtualMachine" && r.Spec["imageId"] == imageID {
			return r.Spec
		}
	}
	return nil
}
