package cfn

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Data volumes an instance keeps past its own end: an AWS::EC2::Instance BlockDeviceMapping with
// Ebs.DeleteOnTermination: false. On AWS the volume survives the instance's termination (a stack delete, a
// rolled-back create, an update that replaces or removes the instance) as an unattached volume that no
// stack owns. Here it is a kind: Volume of its own, attached to the VM through spec.volumes and recorded
// with DeletionPolicy: Retain, so every path that removes the instance leaves it (and the stack's default
// key that encrypts it, defaultEBSKey) in place, unmanaged.

// ec2RootDeviceNames are the DeviceNames that name an instance's root device: a mapping with one of them
// overrides the root volume; any other DeviceName attaches another volume.
var ec2RootDeviceNames = map[string]bool{
	"/dev/sda1": true, "/dev/sda": true, "/dev/xvda": true, "/dev/xvda1": true, "/dev/nvme0n1": true,
}

// maxAttachedVolumeName is the longest kind: Volume name a VM attaches (spec.volumes[].name).
const maxAttachedVolumeName = 58

// keptVolume is the kind: Volume for instance id's data mapping disk (named nm) that outlives the instance:
// its size and encryption, retained when the instance goes.
func (c *stackCtx) keptVolume(id, nm string, disk map[string]any) *Manifest {
	spec := map[string]any{"size": disk["size"]}
	if enc, _ := disk["encrypted"].(bool); enc {
		spec["encrypted"] = true
		spec["encryptionKey"] = disk["encryptionKey"]
	}
	return &Manifest{APIVersion: "openinfra.dev/v1", Kind: "Volume", Name: c.keptVolumeName(id, nm), Spec: spec, DeletionPolicy: "Retain"}
}

// keptVolumeName is <instance's name>-vol-<disk>: within the VM's attachable-volume name limit (shortened
// with a hash of the stack, instance and disk past it), and named around a volume an earlier stack of this
// name kept (physNamer.fresh) — that one belongs to no stack, so a re-created instance gets a new volume, as
// on AWS.
func (c *stackCtx) keptVolumeName(id, nm string) string {
	base := c.name(id) + "-vol-" + nm
	stack := ""
	if c != nil && c.namer != nil {
		stack = c.namer.stack
	}
	if len(base) > maxAttachedVolumeName {
		sum := sha256.Sum256([]byte(stack + "\x00" + id + "\x00" + nm))
		base = strings.Trim(base[:maxAttachedVolumeName-9], "-") + "-" + hex.EncodeToString(sum[:])[:8]
	}
	if c == nil || c.namer == nil {
		return base
	}
	return c.namer.fresh(id+"/vol/"+nm, base, maxAttachedVolumeName)
}

// recordedDataDisk reports whether the stack already created instance id with a data disk named nm (its
// recorded VirtualMachine spec lists it in dataDisks). Such an instance keeps the disk even where the
// template now maps it as a kept volume: moving it would replace the disk and lose what it holds.
func (c *stackCtx) recordedDataDisk(id, nm string) bool {
	if c == nil || c.namer == nil {
		return false
	}
	for _, r := range c.namer.priorRes {
		if r.LogicalID != id || r.Kind != "VirtualMachine" {
			continue
		}
		dds, _ := r.Spec["dataDisks"].([]any)
		for _, d := range dds {
			if m, _ := d.(map[string]any); m != nil && m["name"] == nm {
				return true
			}
		}
	}
	return false
}

// keepsDefaultKeyedVolume reports whether instance id launches a data volume it keeps past its end
// (DeleteOnTermination: false) that is encrypted with no KmsKeyId — keyed by the stack's default key, which
// must then outlive the stack too (defaultEBSKey).
func (c *stackCtx) keepsDefaultKeyedVolume(id string) bool {
	if c == nil || c.resolver == nil {
		return false
	}
	where := c.resolver.where
	p, ok := c.resolveProps(id)
	c.resolver.where = where
	if !ok {
		return false
	}
	bdms, _ := p["BlockDeviceMappings"].([]any)
	for i, raw := range bdms {
		bdm, _ := raw.(map[string]any)
		ebs, _ := bdm["Ebs"].(map[string]any)
		if ebs == nil {
			continue
		}
		dn, _ := concrete(bdm["DeviceName"])
		if ec2RootDeviceNames[dn] || !isExplicitFalse(ebs["DeleteOnTermination"]) || ebs["KmsKeyId"] != nil {
			continue
		}
		if enc, ok := cfnBoolValue(ebs["Encrypted"]); !ok || !enc {
			continue
		}
		nm := k8sName(strings.TrimPrefix(dn, "/dev/"))
		if nm == "" {
			nm = "disk" + strconv.Itoa(i)
		}
		if !c.recordedDataDisk(id, nm) {
			return true
		}
	}
	return false
}
