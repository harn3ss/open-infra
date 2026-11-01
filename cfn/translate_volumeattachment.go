package cfn

import (
	"fmt"
	"regexp"
	"sort"
)

// k8sNameRe is a Kubernetes object name a parameter may give a kind: Volume (a DNS label); ebsVolumeIDRe is
// an EBS volume id, which names no open-infra volume.
var (
	k8sNameRe     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	ebsVolumeIDRe = regexp.MustCompile(`^vol-[0-9a-f]{8,17}$`)
)

// volumeNameParam reports whether v names a kind: Volume (not an EBS volume id).
func volumeNameParam(v string) bool { return k8sNameRe.MatchString(v) && !ebsVolumeIDRe.MatchString(v) }

// AWS::EC2::VolumeAttachment folds into the instance it attaches to: the instance's kind: VirtualMachine
// lists the volume in spec.volumes, so its VM starts with the volume's disk (after its data disks). The
// attachment itself provisions nothing.

func init() {
	translators["AWS::EC2::VolumeAttachment"] = translateEC2VolumeAttachment
	mappingTable["AWS::EC2::VolumeAttachment"] = MapEntry{Kind: "VirtualMachine(spec.volumes)", Status: Partial,
		Note: "attaches a kind: Volume (an in-stack AWS::EC2::Volume, or one named by a parameter) to an in-stack instance: the VM lists it in spec.volumes and starts with it as a virtio disk after its data disks. The Device name is not used (virtio order: /dev/vdb, …), and the volume is attached when the VM starts — an attachment added to or removed from a running instance takes effect at its next restart."}
}

func translateEC2VolumeAttachment(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
	f := blockUnknownProps(id, props, map[string]bool{"InstanceId": true, "VolumeId": true, "Device": true})
	var raw map[string]any
	if ctx != nil {
		raw, _ = ctx.rawProps(id)
	}
	if _, ok := inStackOfType(raw["InstanceId"], "AWS::EC2::Instance", ctx); !ok {
		f = append(f, Finding{"Resource " + id, "InstanceId must !Ref an in-stack AWS::EC2::Instance — the attachment is part of the instance's kind: VirtualMachine (an instance outside the stack is another stack's)"})
	}
	if _, ok := inStackOfType(raw["VolumeId"], "AWS::EC2::Volume", ctx); !ok {
		if v, ok := concrete(props["VolumeId"]); !ok || !volumeNameParam(v) {
			f = append(f, Finding{"Resource " + id, "VolumeId must !Ref an in-stack AWS::EC2::Volume or name a kind: Volume (a parameter) — an EBS volume id has no open-infra form"})
		}
	}
	return nil, f
}

// attachedVolumes is the spec.volumes of instance id: the volumes its included VolumeAttachments attach,
// in logical-id order, with the caveats and requirements (a volume named from outside the stack must exist).
func (c *stackCtx) attachedVolumes(id string) ([]any, []string, []Requirement) {
	if c == nil || c.template == nil {
		return nil, nil, nil
	}
	var ids []string
	for aid, r := range c.template.Resources {
		if r.Type != "AWS::EC2::VolumeAttachment" || !c.included(r) {
			continue
		}
		if inst, _ := refTarget(r.Properties["InstanceId"]); inst == id {
			ids = append(ids, aid)
		}
	}
	sort.Strings(ids)
	var vols []any
	var cav []string
	var req []Requirement
	for _, aid := range ids {
		r := c.template.Resources[aid]
		name := ""
		if vol, ok := inStackOfType(r.Properties["VolumeId"], "AWS::EC2::Volume", c); ok {
			name = c.name(vol)
		} else if v, ok := concrete(c.resolveVal(r.Properties["VolumeId"])); ok && volumeNameParam(v) {
			name = v
			req = append(req, Requirement{APIVersion: "openinfra.dev/v1", Kind: "Volume", Name: v, Why: "a volume " + aid + " attaches"})
		}
		if name == "" {
			continue // the attachment's own translator refuses it
		}
		vols = append(vols, map[string]any{"name": name})
		dev, _ := concrete(c.resolveVal(r.Properties["Device"]))
		cav = append(cav, fmt.Sprintf("%s attaches kind: Volume %s as a virtio disk after the instance's data disks — not as %s (the Device name is not used; mount it by filesystem UUID or label), and it is attached when the VM starts: added to or removed from a running instance, it takes effect at the next restart", aid, name, cfOr(dev, "its Device")))
	}
	return vols, cav, req
}
