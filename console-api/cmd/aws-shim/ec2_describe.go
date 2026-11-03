// The EC2 front door's Describe operations over the platform's kinds (ec2.go).
package main

import (
	"context"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// --- instances ---

// ec2Disk is one of an instance's block devices.
type ec2Disk struct {
	volumeID, device, size         string
	encrypted, deleteOnTermination bool
	kept                           bool // a kind: Volume of its own (spec.volumes), which outlives the VM
}

// ec2Instance is a kind: VirtualMachine as EC2 describes it.
type ec2Instance struct {
	id, name, os, imageID, state, stateReason          string
	code                                               int
	privateIP, publicIP, instanceType, keyName, subnet string
	vpc, role, arch                                    string
	windows                                            bool
	groups                                             []string
	launch                                             time.Time
	tags                                               map[string]string
	disks                                              []ec2Disk
	httpTokens, httpEndpoint                           string
	hopLimit                                           int64
	claim                                              *unstructured.Unstructured
}

// ec2State maps a VM's powerState (KubeVirt's printableStatus) to EC2's instance state.
func ec2State(power string, running, deleting bool) (code int, name string) {
	switch {
	case deleting:
		return 32, "shutting-down"
	case power == "Running" || power == "Migrating":
		return 16, "running"
	case power == "Stopping":
		return 64, "stopping"
	case power == "Stopped" || power == "Paused" || (power == "" && !running):
		return 80, "stopped"
	case power == "Terminating":
		return 32, "shutting-down"
	}
	return 0, "pending" // Provisioning, Starting, WaitingForVolumeBinding, an error state, or not reported yet
}

// instancesAsCaller describes the account's VMs the caller may read. VPCs come from the VMs' subnets.
func (h *ec2Handler) instancesAsCaller(ctx context.Context, claims iam.Claims) ([]ec2Instance, bool, error) {
	vms, denied, err := h.listAsCaller(ctx, claims, vmClaimGVR)
	if err != nil {
		return nil, denied, err
	}
	subnetVPC := map[string]string{}
	if subs, _, serr := h.listAsCaller(ctx, claims, subnetGVR); serr == nil {
		for i := range subs {
			v, _, _ := unstructured.NestedString(subs[i].Object, "spec", "vpc")
			subnetVPC[subs[i].GetName()] = v
		}
	}
	out := make([]ec2Instance, 0, len(vms))
	for i := range vms {
		out = append(out, h.instanceOf(ctx, &vms[i], subnetVPC))
	}
	return out, false, nil
}

func (h *ec2Handler) instanceOf(ctx context.Context, u *unstructured.Unstructured, subnetVPC map[string]string) ec2Instance {
	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	st, _, _ := unstructured.NestedMap(u.Object, "status")
	view := cfn.ParseAWSView(u.GetAnnotations())
	in := ec2Instance{name: u.GetName(), os: str(spec, "os"), claim: u, launch: u.GetCreationTimestamp().Time,
		privateIP: str(st, "ip"), publicIP: str(st, "lanIp"), keyName: view.KeyName, subnet: str(spec, "subnet"),
		role: str(spec, "instanceRole"), arch: "x86_64", tags: view.Tags}
	var xr = h.door.shimDyn
	in.id = vmInstanceID(ctx, u, xr)
	if in.os == "" {
		in.os = "ubuntu-24.04"
	}
	in.imageID = imageIDForOS(in.os)
	in.windows = strings.HasPrefix(in.os, "windows-")
	if a := u.GetAnnotations()["openinfra.dev/arch"]; a == "arm64" {
		in.arch = "arm64"
	}
	running := true
	if v, ok := spec["running"].(bool); ok {
		running = v
	}
	in.code, in.state = ec2State(str(st, "powerState"), running, u.GetDeletionTimestamp() != nil)
	if p := str(st, "powerState"); in.state == "pending" && strings.HasPrefix(p, "Err") {
		in.stateReason = p
	}
	in.instanceType = view.InstanceType
	if in.instanceType == "" {
		cpu, _ := spec["cpu"].(int64)
		if cpu == 0 {
			cpu = 2
		}
		mem := str(spec, "memory")
		if mem == "" {
			mem = "2Gi"
		}
		in.instanceType = cfn.InstanceTypeForShape(int(cpu), mem)
	}
	if in.subnet != "" {
		in.vpc = subnetVPC[in.subnet]
	}
	if gs, ok := spec["securityGroups"].([]any); ok {
		for _, g := range gs {
			if s, _ := g.(string); s != "" {
				in.groups = append(in.groups, s)
			}
		}
	}
	md, _ := spec["metadataOptions"].(map[string]any)
	in.httpTokens, in.httpEndpoint, in.hopLimit = str(md, "httpTokens"), str(md, "httpEndpoint"), 1
	if in.httpTokens == "" {
		in.httpTokens = "optional"
	}
	if in.httpEndpoint == "" {
		in.httpEndpoint = "enabled"
	}
	if v, ok := md["httpPutResponseHopLimit"].(int64); ok && v > 0 {
		in.hopLimit = v
	}
	// Block devices: the root, the data disks, then the attached kind: Volumes.
	uid := string(u.GetUID())
	rd, _ := spec["rootDisk"].(map[string]any)
	enc, _ := rd["encrypted"].(bool)
	root := str(spec, "diskSize")
	if root == "" {
		root = "20Gi"
	}
	in.disks = append(in.disks, ec2Disk{volumeID: shortHashID("vol-", uid+"-root", 17), device: "/dev/sda1", size: root, encrypted: enc, deleteOnTermination: true})
	if dd, ok := spec["dataDisks"].([]any); ok {
		for i, d := range dd {
			m, _ := d.(map[string]any)
			name := str(m, "name")
			if name == "" {
				name = "data" + strconv.Itoa(i+1)
			}
			dev := str(m, "deviceName")
			if dev == "" {
				dev = "/dev/sd" + string(rune('f'+i))
			}
			e, _ := m["encrypted"].(bool)
			in.disks = append(in.disks, ec2Disk{volumeID: shortHashID("vol-", uid+"-"+name, 17), device: dev, size: str(m, "size"), encrypted: e, deleteOnTermination: true})
		}
	}
	if vs, ok := spec["volumes"].([]any); ok {
		for i, v := range vs {
			m, _ := v.(map[string]any)
			dev := str(m, "deviceName")
			if dev == "" {
				dev = "/dev/sd" + string(rune('p'+i))
			}
			in.disks = append(in.disks, ec2Disk{volumeID: str(m, "name"), device: dev, kept: true})
		}
	}
	return in
}

func (in ec2Instance) record(region, account string) ec2Record {
	f := map[string][]string{
		"instance-id": {in.id}, "instance-state-name": {in.state}, "instance-state-code": {strconv.Itoa(in.code)},
		"instance-type": {in.instanceType}, "image-id": {in.imageID}, "availability-zone": {region + "a"},
		"architecture": {in.arch}, "root-device-type": {"ebs"}, "root-device-name": {"/dev/sda1"},
		"virtualization-type": {"hvm"}, "hypervisor": {"xen"}, "tenancy": {"default"},
		"placement-group-name": {""}, "owner-id": {account}, "reservation-id": {in.reservationID()},
	}
	add := func(k, v string) {
		if v != "" {
			f[k] = append(f[k], v)
		}
	}
	add("private-ip-address", in.privateIP)
	add("network-interface.addresses.private-ip-address", in.privateIP)
	add("ip-address", in.publicIP)
	add("network-interface.association.public-ip", in.publicIP)
	if in.privateIP != "" {
		add("private-dns-name", awsidentity.PrivateDNSName(in.privateIP, region))
	}
	add("dns-name", awsidentity.Current().PublicDNSName(in.publicIP))
	add("key-name", in.keyName)
	add("subnet-id", in.subnet)
	add("vpc-id", in.vpc)
	if in.windows {
		add("platform", "windows")
		add("platform-details", "Windows")
	} else {
		add("platform-details", "Linux/UNIX")
	}
	for _, g := range in.groups {
		add("instance.group-id", g)
		add("instance.group-name", g)
		add("group-id", g)
		add("group-name", g)
	}
	for _, d := range in.disks {
		add("block-device-mapping.volume-id", d.volumeID)
		add("block-device-mapping.device-name", d.device)
	}
	add("metadata-options.http-tokens", in.httpTokens)
	add("metadata-options.http-endpoint", in.httpEndpoint)
	add("launch-time", ec2Time(in.launch))
	if in.role != "" {
		add("iam-instance-profile.arn", "arn:aws:iam::"+account+":instance-profile/"+in.role)
	}
	return ec2Record{fields: f, tags: in.tags}
}

func (in ec2Instance) reservationID() string { return shortHashID("r-", in.id, 17) }

var instanceFilters = []string{
	"instance-id", "instance-state-name", "instance-state-code", "instance-type", "image-id", "availability-zone",
	"architecture", "root-device-type", "root-device-name", "virtualization-type", "hypervisor", "tenancy",
	"placement-group-name", "owner-id", "reservation-id", "private-ip-address",
	"network-interface.addresses.private-ip-address", "ip-address", "network-interface.association.public-ip",
	"private-dns-name", "dns-name", "key-name", "subnet-id", "vpc-id", "platform", "platform-details",
	"instance.group-id", "instance.group-name", "group-id", "group-name", "block-device-mapping.volume-id",
	"block-device-mapping.device-name", "metadata-options.http-tokens", "metadata-options.http-endpoint",
	"launch-time", "iam-instance-profile.arn",
}

func (h *ec2Handler) describeInstances(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, instanceFilters); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	ids := ec2List(r.Form, "InstanceId")
	for _, id := range ids {
		if !instanceIDRe.MatchString(id) {
			writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.Malformed", requestID, "Invalid id: \""+id+"\"")
			return
		}
	}
	if len(ids) > 0 && r.Form.Get("MaxResults") != "" {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterCombination", requestID, "The parameter instancesSet cannot be used with the parameter maxResults")
		return
	}
	all, denied, err := h.instancesAsCaller(ctx, claims)
	if err != nil {
		h.readFailed(w, requestID, "instances", denied, err)
		return
	}
	want := setOf(ids)
	found := map[string]bool{}
	var sel []ec2Instance
	for _, in := range all {
		if in.id == "" || (len(ids) > 0 && !want[in.id]) {
			continue
		}
		found[in.id] = true
		if in.record(h.region(), h.account()).matches(fs) {
			sel = append(sel, in)
		}
	}
	var missing []string
	for _, id := range ids {
		if !found[id] {
			missing = append(missing, "'"+id+"'")
		}
	}
	if len(missing) == 1 {
		writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.NotFound", requestID, "The instance ID "+missing[0]+" does not exist")
		return
	} else if len(missing) > 1 {
		writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceID.NotFound", requestID, "The instance IDs "+strings.Join(missing, ", ")+" do not exist")
		return
	}
	start, end, next, msg, ok := ec2Page(r.Form, len(sel), 5, 1000)
	if !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	items := make([]string, 0, end-start)
	for _, in := range sel[start:end] {
		items = append(items, xtag("reservationId", in.reservationID())+xtag("ownerId", h.account())+"<groupSet/>"+
			xset("instancesSet", []string{h.instanceXML(in)}))
	}
	writeEC2(w, requestID, "DescribeInstances", xset("reservationSet", items)+xtag("nextToken", next))
}

func (h *ec2Handler) instanceXML(in ec2Instance) string {
	region := h.region()
	var b strings.Builder
	b.WriteString(xtag("instanceId", in.id) + xtag("imageId", in.imageID))
	b.WriteString("<instanceState><code>" + strconv.Itoa(in.code) + "</code><name>" + in.state + "</name></instanceState>")
	pdns := ""
	if in.privateIP != "" {
		pdns = awsidentity.PrivateDNSName(in.privateIP, region)
	}
	b.WriteString("<privateDnsName>" + xesc(pdns) + "</privateDnsName><dnsName>" + xesc(awsidentity.Current().PublicDNSName(in.publicIP)) + "</dnsName>")
	if in.stateReason != "" {
		b.WriteString("<stateReason><code>Server.InternalError</code><message>Server.InternalError: the VM reports " + xesc(in.stateReason) + "</message></stateReason>")
	}
	b.WriteString(xtag("keyName", in.keyName) + "<amiLaunchIndex>0</amiLaunchIndex><productCodes/>" + xtag("instanceType", in.instanceType))
	b.WriteString(xtag("launchTime", ec2Time(in.launch)))
	b.WriteString("<placement><availabilityZone>" + xesc(region+"a") + "</availabilityZone><groupName/><tenancy>default</tenancy></placement>")
	if in.windows {
		b.WriteString("<platform>windows</platform>")
	}
	b.WriteString("<monitoring><state>disabled</state></monitoring>")
	b.WriteString(xtag("subnetId", in.subnet) + xtag("vpcId", in.vpc) + xtag("privateIpAddress", in.privateIP) + xtag("ipAddress", in.publicIP))
	groups := make([]string, 0, len(in.groups))
	for _, g := range in.groups {
		groups = append(groups, xtag("groupId", g)+xtag("groupName", g))
	}
	b.WriteString(xset("groupSet", groups))
	b.WriteString(xtag("architecture", in.arch) + "<rootDeviceType>ebs</rootDeviceType><rootDeviceName>/dev/sda1</rootDeviceName>")
	bdm := make([]string, 0, len(in.disks))
	for _, d := range in.disks {
		bdm = append(bdm, xtag("deviceName", d.device)+"<ebs>"+xtag("volumeId", d.volumeID)+"<status>attached</status>"+
			xtag("attachTime", ec2Time(in.launch))+xbool("deleteOnTermination", d.deleteOnTermination)+"</ebs>")
	}
	b.WriteString(xset("blockDeviceMapping", bdm))
	b.WriteString("<virtualizationType>hvm</virtualizationType><clientToken/>" + xtags(in.tags) + "<hypervisor>xen</hypervisor>")
	if in.role != "" {
		b.WriteString("<iamInstanceProfile><arn>" + xesc("arn:aws:iam::"+h.account()+":instance-profile/"+in.role) + "</arn><id>" +
			xesc(strings.ToUpper(shortHashID("AIPA", in.role, 17))) + "</id></iamInstanceProfile>")
	}
	b.WriteString("<ebsOptimized>false</ebsOptimized><enaSupport>true</enaSupport><sourceDestCheck>true</sourceDestCheck>")
	b.WriteString("<metadataOptions><state>applied</state>" + xtag("httpTokens", in.httpTokens) + "<httpPutResponseHopLimit>" +
		strconv.FormatInt(in.hopLimit, 10) + "</httpPutResponseHopLimit>" + xtag("httpEndpoint", in.httpEndpoint) +
		"<httpProtocolIpv6>disabled</httpProtocolIpv6><instanceMetadataTags>disabled</instanceMetadataTags></metadataOptions>")
	if in.windows {
		b.WriteString("<platformDetails>Windows</platformDetails>")
	} else {
		b.WriteString("<platformDetails>Linux/UNIX</platformDetails>")
	}
	return b.String()
}

// --- volumes ---

// ec2Volume is a volume as EC2 describes it: a kind: Volume, or one of a VM's own disks.
type ec2Volume struct {
	id, state, volumeType, kmsKey, az, snapshot string
	sizeGiB                                     int64
	encrypted                                   bool
	created                                     time.Time
	tags                                        map[string]string
	attachments                                 []ec2Attachment
	own                                         bool // a VM's root or data disk: it goes with its VM
}

type ec2Attachment struct {
	instance, device    string
	deleteOnTermination bool
	attached            time.Time
}

// sizeGiB is a Kubernetes quantity in whole GiB, rounded up (EC2 sizes are GiB).
func sizeGiB(q string) int64 {
	if q == "" {
		return 0
	}
	v, err := resource.ParseQuantity(q)
	if err != nil {
		return 0
	}
	return int64(math.Ceil(float64(v.Value()) / (1 << 30)))
}

// volumesAsCaller describes the account's volumes the caller may read: each kind: Volume (in-use while a VM
// has it in spec.volumes), and each VM's root and data disks (in-use, deleted with the VM).
func (h *ec2Handler) volumesAsCaller(ctx context.Context, claims iam.Claims) ([]ec2Volume, bool, error) {
	vols, denied, err := h.listAsCaller(ctx, claims, volumeGVR)
	if err != nil {
		return nil, denied, err
	}
	insts, denied, err := h.instancesAsCaller(ctx, claims)
	if err != nil {
		return nil, denied, err
	}
	att := map[string][]ec2Attachment{}
	var out []ec2Volume
	for _, in := range insts {
		for _, d := range in.disks {
			a := ec2Attachment{instance: in.id, device: d.device, deleteOnTermination: d.deleteOnTermination, attached: in.launch}
			if d.kept {
				att[d.volumeID] = append(att[d.volumeID], a)
				continue
			}
			out = append(out, ec2Volume{id: d.volumeID, state: "in-use", volumeType: "gp3", az: h.zone(), sizeGiB: sizeGiB(d.size),
				encrypted: d.encrypted, created: in.launch, attachments: []ec2Attachment{a}, own: true})
		}
	}
	for i := range vols {
		u := &vols[i]
		spec, _, _ := unstructured.NestedMap(u.Object, "spec")
		phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
		size, _ := spec["size"].(string)
		enc, _ := spec["encrypted"].(bool)
		key, _ := spec["encryptionKey"].(string)
		view := cfn.ParseAWSView(u.GetAnnotations())
		v := ec2Volume{id: u.GetName(), volumeType: view.VolumeType, az: h.zone(), sizeGiB: sizeGiB(size), encrypted: enc,
			created: u.GetCreationTimestamp().Time, tags: view.Tags, attachments: att[u.GetName()]}
		if v.volumeType == "" {
			v.volumeType = "gp3"
		}
		if snap, _, _ := unstructured.NestedString(u.Object, "spec", "source", "snapshot"); snap != "" {
			v.snapshot = snap
		}
		if enc && key != "" {
			v.kmsKey = "arn:aws:kms:" + h.region() + ":" + h.account() + ":key/" + key
		}
		switch {
		case u.GetDeletionTimestamp() != nil:
			v.state = "deleting"
		case len(v.attachments) > 0:
			v.state = "in-use"
		case phase != "" && phase != "Bound":
			v.state = "creating"
		default:
			v.state = "available"
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, false, nil
}

func (v ec2Volume) record() ec2Record {
	f := map[string][]string{
		"volume-id": {v.id}, "status": {v.state}, "volume-type": {v.volumeType}, "availability-zone": {v.az},
		"encrypted": {strconv.FormatBool(v.encrypted)}, "size": {strconv.FormatInt(v.sizeGiB, 10)},
		"create-time": {ec2Time(v.created)}, "multi-attach-enabled": {"false"},
	}
	if v.snapshot != "" {
		f["snapshot-id"] = []string{v.snapshot}
	}
	for _, a := range v.attachments {
		f["attachment.instance-id"] = append(f["attachment.instance-id"], a.instance)
		f["attachment.device"] = append(f["attachment.device"], a.device)
		f["attachment.status"] = append(f["attachment.status"], "attached")
		f["attachment.delete-on-termination"] = append(f["attachment.delete-on-termination"], strconv.FormatBool(a.deleteOnTermination))
		f["attachment.attach-time"] = append(f["attachment.attach-time"], ec2Time(a.attached))
	}
	return ec2Record{fields: f, tags: v.tags}
}

var volumeFilters = []string{"volume-id", "status", "volume-type", "availability-zone", "encrypted", "size", "create-time",
	"multi-attach-enabled", "snapshot-id", "attachment.instance-id", "attachment.device", "attachment.status",
	"attachment.delete-on-termination", "attachment.attach-time"}

func (h *ec2Handler) describeVolumes(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, volumeFilters); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	all, denied, err := h.volumesAsCaller(ctx, claims)
	if err != nil {
		h.readFailed(w, requestID, "volumes", denied, err)
		return
	}
	ids := ec2List(r.Form, "VolumeId")
	want, found := setOf(ids), map[string]bool{}
	var sel []ec2Volume
	for _, v := range all {
		if len(ids) > 0 && !want[v.id] {
			continue
		}
		found[v.id] = true
		if v.record().matches(fs) {
			sel = append(sel, v)
		}
	}
	for _, id := range ids {
		if !found[id] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidVolume.NotFound", requestID, "The volume '"+id+"' does not exist.")
			return
		}
	}
	start, end, next, msg, ok := ec2Page(r.Form, len(sel), 5, 500)
	if !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	items := make([]string, 0, end-start)
	for _, v := range sel[start:end] {
		atts := make([]string, 0, len(v.attachments))
		for _, a := range v.attachments {
			atts = append(atts, xtag("volumeId", v.id)+xtag("instanceId", a.instance)+xtag("device", a.device)+"<status>attached</status>"+
				xtag("attachTime", ec2Time(a.attached))+xbool("deleteOnTermination", a.deleteOnTermination))
		}
		item := xtag("volumeId", v.id) + "<size>" + strconv.FormatInt(v.sizeGiB, 10) + "</size><snapshotId>" + xesc(v.snapshot) + "</snapshotId>" +
			xtag("availabilityZone", v.az) + xtag("status", v.state) + xtag("createTime", ec2Time(v.created)) + xset("attachmentSet", atts) +
			xtags(v.tags) + xtag("volumeType", v.volumeType) + xbool("encrypted", v.encrypted) + xtag("kmsKeyId", v.kmsKey) +
			"<multiAttachEnabled>false</multiAttachEnabled>"
		if v.volumeType == "gp3" {
			item += "<iops>3000</iops><throughput>125</throughput>"
		}
		items = append(items, item)
	}
	writeEC2(w, requestID, "DescribeVolumes", xset("volumeSet", items)+xtag("nextToken", next))
}

// deleteVolume deletes a kind: Volume (a volume an instance kept, DeleteOnTermination: false, or one a stack
// made), as the caller; refused with AWS's VolumeInUse while a VM has it, and for a VM's own disk.
func (h *ec2Handler) deleteVolume(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	id := r.Form.Get("VolumeId")
	if id == "" {
		writeEC2Error(w, http.StatusBadRequest, "MissingParameter", requestID, "The request must contain the parameter VolumeId")
		return
	}
	all, denied, err := h.volumesAsCaller(ctx, claims)
	if err != nil {
		h.readFailed(w, requestID, "volumes", denied, err)
		return
	}
	var v *ec2Volume
	for i := range all {
		if all[i].id == id {
			v = &all[i]
		}
	}
	if v == nil {
		writeEC2Error(w, http.StatusBadRequest, "InvalidVolume.NotFound", requestID, "The volume '"+id+"' does not exist.")
		return
	}
	if len(v.attachments) > 0 {
		insts := make([]string, 0, len(v.attachments))
		for _, a := range v.attachments {
			insts = append(insts, a.instance)
		}
		writeEC2Error(w, http.StatusBadRequest, "VolumeInUse", requestID, "Volume "+id+" is currently attached to "+strings.Join(insts, ", "))
		return
	}
	ap, err := h.door.applierFor(claims)
	if err != nil {
		h.readFailed(w, requestID, "volume", true, err)
		return
	}
	err = ap.caller.Resource(volumeGVR).Namespace(h.door.ns).Delete(ctx, id, metav1.DeleteOptions{})
	switch {
	case err == nil:
	case apierrors.IsForbidden(err):
		writeEC2Error(w, http.StatusForbidden, "UnauthorizedOperation", requestID, "You are not authorized to perform this operation. "+err.Error())
		return
	case apierrors.IsNotFound(err):
		writeEC2Error(w, http.StatusBadRequest, "InvalidVolume.NotFound", requestID, "The volume '"+id+"' does not exist.")
		return
	default:
		h.readFailed(w, requestID, "volume", false, err)
		return
	}
	writeEC2(w, requestID, "DeleteVolume", "<return>true</return>")
}

// --- security groups ---

var sgFilters = []string{"group-id", "group-name", "description", "vpc-id", "owner-id",
	"ip-permission.protocol", "ip-permission.from-port", "ip-permission.to-port", "ip-permission.cidr", "ip-permission.group-id",
	"egress.ip-permission.protocol", "egress.ip-permission.cidr"}

// sgPermissions renders a kind: SecurityGroup's rules (spec.ingress / spec.egress) as EC2 ip permissions,
// and the filter values they carry.
func sgPermissions(rules []any, peerKey string, f map[string][]string, prefix string) []string {
	var out []string
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		proto := strings.ToLower(strOf(rule["protocol"]))
		if proto == "" {
			proto = "tcp"
		}
		var ranges [][2]int64
		if ps, ok := rule["ports"].([]any); ok && len(ps) > 0 {
			for _, p := range ps {
				if n, ok := p.(int64); ok {
					ranges = append(ranges, [2]int64{n, n})
				}
			}
		}
		if fp, ok := rule["fromPort"].(int64); ok {
			tp, _ := rule["toPort"].(int64)
			if tp == 0 {
				tp = fp
			}
			ranges = append(ranges, [2]int64{fp, tp})
		}
		if len(ranges) == 0 {
			ranges = [][2]int64{{0, 65535}}
		}
		var cidrs, groups []string
		peers, _ := rule[peerKey].([]any)
		for _, pr := range peers {
			pm, _ := pr.(map[string]any)
			if c := strOf(pm["cidr"]); c != "" {
				cidrs = append(cidrs, "<cidrIp>"+xesc(c)+"</cidrIp>"+xtag("description", strOf(rule["description"])))
				f[prefix+"ip-permission.cidr"] = append(f[prefix+"ip-permission.cidr"], c)
			}
			if g := strOf(pm["securityGroup"]); g != "" {
				groups = append(groups, xtag("groupId", g)+xtag("groupName", g)+xtag("description", strOf(rule["description"])))
				f[prefix+"ip-permission.group-id"] = append(f[prefix+"ip-permission.group-id"], g)
			}
		}
		for _, rg := range ranges {
			f[prefix+"ip-permission.protocol"] = append(f[prefix+"ip-permission.protocol"], proto)
			f[prefix+"ip-permission.from-port"] = append(f[prefix+"ip-permission.from-port"], strconv.FormatInt(rg[0], 10))
			f[prefix+"ip-permission.to-port"] = append(f[prefix+"ip-permission.to-port"], strconv.FormatInt(rg[1], 10))
			out = append(out, xtag("ipProtocol", proto)+"<fromPort>"+strconv.FormatInt(rg[0], 10)+"</fromPort><toPort>"+
				strconv.FormatInt(rg[1], 10)+"</toPort>"+xset("groups", groups)+xset("ipRanges", cidrs)+"<ipv6Ranges/><prefixListIds/>")
		}
	}
	return out
}

func strOf(v any) string { s, _ := v.(string); return s }

func (h *ec2Handler) describeSecurityGroups(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, sgFilters); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	sgs, denied, err := h.listAsCaller(ctx, claims, securityGroupGVR)
	if err != nil {
		h.readFailed(w, requestID, "security groups", denied, err)
		return
	}
	ids, names := ec2List(r.Form, "GroupId"), ec2List(r.Form, "GroupName")
	wantID, wantName, found := setOf(ids), setOf(names), map[string]bool{}
	var items []string
	for i := range sgs {
		u := &sgs[i]
		view := cfn.ParseAWSView(u.GetAnnotations())
		name := view.GroupName
		if name == "" {
			name = u.GetName()
		}
		if (len(ids) > 0 || len(names) > 0) && !wantID[u.GetName()] && !wantName[name] {
			continue
		}
		found[u.GetName()], found[name] = true, true
		f := map[string][]string{"group-id": {u.GetName()}, "group-name": {name}, "description": {view.GroupDescription}, "owner-id": {h.account()}}
		ingress, _, _ := unstructured.NestedSlice(u.Object, "spec", "ingress")
		egress, _, _ := unstructured.NestedSlice(u.Object, "spec", "egress")
		in := sgPermissions(ingress, "from", f, "")
		out := sgPermissions(egress, "to", f, "egress.")
		if len(egress) == 0 {
			// No egress rules: the group restricts no outbound traffic, as AWS's default allow-all rule.
			out = []string{"<ipProtocol>-1</ipProtocol><groups/><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges><ipv6Ranges/><prefixListIds/>"}
			f["egress.ip-permission.protocol"], f["egress.ip-permission.cidr"] = []string{"-1"}, []string{"0.0.0.0/0"}
		}
		rec := ec2Record{fields: f, tags: view.Tags}
		if !rec.matches(fs) {
			continue
		}
		items = append(items, xtag("ownerId", h.account())+xtag("groupId", u.GetName())+xtag("groupName", name)+
			"<groupDescription>"+xesc(view.GroupDescription)+"</groupDescription>"+xset("ipPermissions", in)+
			xset("ipPermissionsEgress", out)+xtags(view.Tags)+xtag("securityGroupArn", "arn:aws:ec2:"+h.region()+":"+h.account()+":security-group/"+u.GetName()))
	}
	for _, id := range ids {
		if !found[id] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidGroup.NotFound", requestID, "The security group '"+id+"' does not exist")
			return
		}
	}
	for _, n := range names {
		if !found[n] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidGroup.NotFound", requestID, "The security group '"+n+"' does not exist")
			return
		}
	}
	writeEC2(w, requestID, "DescribeSecurityGroups", xset("securityGroupInfo", items))
}

// --- VPCs and subnets ---

func readyState(u *unstructured.Unstructured) string {
	if ok, _, _ := unstructured.NestedBool(u.Object, "status", "ready"); ok {
		return "available"
	}
	return "pending"
}

func (h *ec2Handler) describeVpcs(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"vpc-id", "cidr", "cidr-block-association.cidr-block", "state", "is-default", "owner-id", "dhcp-options-id"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	vpcs, denied, err := h.listAsCaller(ctx, claims, vpcGVR)
	if err != nil {
		h.readFailed(w, requestID, "VPCs", denied, err)
		return
	}
	ids := ec2List(r.Form, "VpcId")
	want, found := setOf(ids), map[string]bool{}
	var items []string
	for i := range vpcs {
		u := &vpcs[i]
		if len(ids) > 0 && !want[u.GetName()] {
			continue
		}
		found[u.GetName()] = true
		view := cfn.ParseAWSView(u.GetAnnotations())
		state := readyState(u)
		rec := ec2Record{fields: map[string][]string{"vpc-id": {u.GetName()}, "cidr": {view.CidrBlock}, "cidr-block-association.cidr-block": {view.CidrBlock},
			"state": {state}, "is-default": {"false"}, "owner-id": {h.account()}, "dhcp-options-id": {"default"}}, tags: view.Tags}
		if !rec.matches(fs) {
			continue
		}
		assoc := ""
		if view.CidrBlock != "" {
			assoc = xset("cidrBlockAssociationSet", []string{xtag("associationId", shortHashID("vpc-cidr-assoc-", u.GetName(), 17)) +
				xtag("cidrBlock", view.CidrBlock) + "<cidrBlockState><state>associated</state></cidrBlockState>"})
		}
		items = append(items, xtag("vpcId", u.GetName())+xtag("ownerId", h.account())+xtag("state", state)+xtag("cidrBlock", view.CidrBlock)+
			assoc+"<dhcpOptionsId>default</dhcpOptionsId>"+xtags(view.Tags)+"<instanceTenancy>default</instanceTenancy><isDefault>false</isDefault>")
	}
	for _, id := range ids {
		if !found[id] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidVpcID.NotFound", requestID, "The vpc ID '"+id+"' does not exist")
			return
		}
	}
	writeEC2(w, requestID, "DescribeVpcs", xset("vpcSet", items))
}

// usableAddresses is how many addresses of cidr an instance can take (AWS reserves 5 per subnet).
func usableAddresses(cidr string) int64 {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	ones, bits := n.Mask.Size()
	if bits-ones > 30 {
		return 0
	}
	if c := int64(1)<<(bits-ones) - 5; c > 0 {
		return c
	}
	return 0
}

func (h *ec2Handler) describeSubnets(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"subnet-id", "vpc-id", "cidr-block", "cidr", "cidrBlock", "availability-zone", "availabilityZone",
		"state", "default-for-az", "defaultForAz", "map-public-ip-on-launch", "owner-id", "subnet-arn"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	subs, denied, err := h.listAsCaller(ctx, claims, subnetGVR)
	if err != nil {
		h.readFailed(w, requestID, "subnets", denied, err)
		return
	}
	ids := ec2List(r.Form, "SubnetId")
	want, found := setOf(ids), map[string]bool{}
	var items []string
	for i := range subs {
		u := &subs[i]
		if len(ids) > 0 && !want[u.GetName()] {
			continue
		}
		found[u.GetName()] = true
		view := cfn.ParseAWSView(u.GetAnnotations())
		cidr, _, _ := unstructured.NestedString(u.Object, "spec", "cidr")
		vpc, _, _ := unstructured.NestedString(u.Object, "spec", "vpc")
		private := true
		if v, ok, _ := unstructured.NestedBool(u.Object, "spec", "private"); ok {
			private = v
		}
		state := readyState(u)
		arn := "arn:aws:ec2:" + h.region() + ":" + h.account() + ":subnet/" + u.GetName()
		rec := ec2Record{fields: map[string][]string{"subnet-id": {u.GetName()}, "vpc-id": {vpc}, "cidr-block": {cidr}, "cidr": {cidr}, "cidrBlock": {cidr},
			"availability-zone": {h.zone()}, "availabilityZone": {h.zone()}, "state": {state}, "default-for-az": {"false"}, "defaultForAz": {"false"},
			"map-public-ip-on-launch": {strconv.FormatBool(!private)}, "owner-id": {h.account()}, "subnet-arn": {arn}}, tags: view.Tags}
		if !rec.matches(fs) {
			continue
		}
		items = append(items, xtag("subnetId", u.GetName())+xtag("subnetArn", arn)+xtag("state", state)+xtag("ownerId", h.account())+
			xtag("vpcId", vpc)+xtag("cidrBlock", cidr)+"<availableIpAddressCount>"+strconv.FormatInt(usableAddresses(cidr), 10)+"</availableIpAddressCount>"+
			xtag("availabilityZone", h.zone())+xtag("availabilityZoneId", h.zoneID())+"<defaultForAz>false</defaultForAz>"+
			xbool("mapPublicIpOnLaunch", !private)+"<assignIpv6AddressOnCreation>false</assignIpv6AddressOnCreation>"+xtags(view.Tags))
	}
	for _, id := range ids {
		if !found[id] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidSubnetID.NotFound", requestID, "The subnet ID '"+id+"' does not exist")
			return
		}
	}
	writeEC2(w, requestID, "DescribeSubnets", xset("subnetSet", items))
}

// --- images, regions, zones ---

func (h *ec2Handler) describeImages(w http.ResponseWriter, r *http.Request, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"image-id", "name", "state", "architecture", "platform", "platform-details", "owner-alias",
		"owner-id", "is-public", "image-type", "root-device-type", "root-device-name", "virtualization-type", "hypervisor", "description"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	ids := ec2List(r.Form, "ImageId")
	for _, id := range ids {
		if !strings.HasPrefix(id, "ami-") {
			writeEC2Error(w, http.StatusBadRequest, "InvalidAMIID.Malformed", requestID, "Invalid id: \""+id+"\" (expecting \"ami-...\")")
			return
		}
	}
	owners := ec2List(r.Form, "Owner")
	want, found := setOf(ids), map[string]bool{}
	var items []string
	for _, os := range cfn.CatalogOSes() {
		id := imageIDForOS(os)
		if len(ids) > 0 && !want[id] {
			continue
		}
		found[id] = true
		if len(owners) > 0 && !setOf(owners)["openinfra"] {
			continue // the catalog's images are the platform's (owner alias openinfra), not self/amazon/an account's
		}
		platform, details := "", "Linux/UNIX"
		if strings.HasPrefix(os, "windows-") {
			platform, details = "windows", "Windows"
		}
		desc := "open-infra catalog image " + os
		rec := ec2Record{fields: map[string][]string{"image-id": {id}, "name": {os}, "state": {"available"}, "architecture": {"x86_64"},
			"platform": {platform}, "platform-details": {details}, "owner-alias": {"openinfra"}, "owner-id": {h.account()},
			"is-public": {"true"}, "image-type": {"machine"}, "root-device-type": {"ebs"}, "root-device-name": {"/dev/sda1"},
			"virtualization-type": {"hvm"}, "hypervisor": {"xen"}, "description": {desc}}}
		if !rec.matches(fs) {
			continue
		}
		item := xtag("imageId", id) + xtag("imageLocation", "openinfra/"+os) + "<imageState>available</imageState>" + xtag("imageOwnerId", h.account()) +
			"<isPublic>true</isPublic><architecture>x86_64</architecture><imageType>machine</imageType>"
		if platform != "" {
			item += xtag("platform", platform)
		}
		item += xtag("platformDetails", details) + xtag("imageOwnerAlias", "openinfra") + xtag("name", os) + xtag("description", desc) +
			"<rootDeviceType>ebs</rootDeviceType><rootDeviceName>/dev/sda1</rootDeviceName><blockDeviceMapping/><virtualizationType>hvm</virtualizationType>" +
			"<hypervisor>xen</hypervisor><enaSupport>true</enaSupport>"
		items = append(items, item)
	}
	for _, id := range ids {
		if !found[id] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidAMIID.NotFound", requestID, "The image id '["+id+"]' does not exist")
			return
		}
	}
	writeEC2(w, requestID, "DescribeImages", xset("imagesSet", items))
}

func (h *ec2Handler) describeRegions(w http.ResponseWriter, r *http.Request, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"region-name", "endpoint", "opt-in-status"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	reg := h.region()
	for _, n := range ec2List(r.Form, "RegionName") {
		if n != reg {
			writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "Invalid region names: "+n+" (this install is the one region "+reg+")")
			return
		}
	}
	endpoint := "ec2." + reg + ".amazonaws.com"
	var items []string
	if (ec2Record{fields: map[string][]string{"region-name": {reg}, "endpoint": {endpoint}, "opt-in-status": {"opt-in-not-required"}}}).matches(fs) {
		items = append(items, xtag("regionName", reg)+xtag("regionEndpoint", endpoint)+"<optInStatus>opt-in-not-required</optInStatus>")
	}
	writeEC2(w, requestID, "DescribeRegions", xset("regionInfo", items))
}

// zoneID is the install's one zone's id, in AWS's <region abbreviation>-az1 shape (us-east-1 -> use1-az1,
// ap-southeast-2 -> apse2-az1).
func (h *ec2Handler) zoneID() string {
	dir := map[string]string{"east": "e", "west": "w", "north": "n", "south": "s", "central": "c",
		"northeast": "ne", "northwest": "nw", "southeast": "se", "southwest": "sw"}
	parts := strings.Split(h.region(), "-")
	abbr := parts[0]
	for _, p := range parts[1:] {
		if d, ok := dir[p]; ok {
			abbr += d
		} else {
			abbr += p
		}
	}
	return abbr + "-az1"
}

func (h *ec2Handler) describeAvailabilityZones(w http.ResponseWriter, r *http.Request, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"zone-name", "zone-id", "state", "region-name", "zone-type", "group-name", "opt-in-status", "network-border-group"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	reg, zone, zid := h.region(), h.zone(), h.zoneID()
	for _, n := range ec2List(r.Form, "ZoneName") {
		if n != zone {
			writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "The zone '"+n+"' does not exist in this install (its one zone is "+zone+")")
			return
		}
	}
	for _, n := range ec2List(r.Form, "ZoneId") {
		if n != zid {
			writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, "The zone ID '"+n+"' does not exist in this install (its one zone is "+zid+")")
			return
		}
	}
	var items []string
	rec := ec2Record{fields: map[string][]string{"zone-name": {zone}, "zone-id": {zid}, "state": {"available"}, "region-name": {reg},
		"zone-type": {"availability-zone"}, "group-name": {reg}, "opt-in-status": {"opt-in-not-required"}, "network-border-group": {reg}}}
	if rec.matches(fs) {
		items = append(items, "<optInStatus>opt-in-not-required</optInStatus><zoneName>"+xesc(zone)+"</zoneName><zoneId>"+xesc(zid)+"</zoneId>"+
			"<zoneState>available</zoneState><regionName>"+xesc(reg)+"</regionName><groupName>"+xesc(reg)+"</groupName>"+
			"<networkBorderGroup>"+xesc(reg)+"</networkBorderGroup><zoneType>availability-zone</zoneType><messageSet/>")
	}
	writeEC2(w, requestID, "DescribeAvailabilityZones", xset("availabilityZoneInfo", items))
}

// --- addresses ---

// describeAddresses lists the account's Elastic IP allocations (a stack's addresses of their own, kept as
// holder Services, cfn_addresses.go) with the instance each is associated with.
func (h *ec2Handler) describeAddresses(ctx context.Context, w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, []string{"allocation-id", "association-id", "domain", "instance-id", "public-ip", "private-ip-address",
		"network-border-group", "public-ipv4-pool"}); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	if h.door.shimDyn == nil {
		writeEC2(w, requestID, "DescribeAddresses", "<addressesSet/>")
		return
	}
	svcs, err := h.door.shimDyn.Resource(serviceGVR).Namespace(h.door.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.readFailed(w, requestID, "addresses", false, err)
		return
	}
	// VM name -> instance, for the instance each allocation's address is on.
	byName := map[string]ec2Instance{}
	if insts, _, ierr := h.instancesAsCaller(ctx, claims); ierr == nil {
		for _, in := range insts {
			byName[in.name] = in
		}
	}
	allocs, ips := ec2List(r.Form, "AllocationId"), ec2List(r.Form, "PublicIp")
	wantA, wantIP, found := setOf(allocs), setOf(ips), map[string]bool{}
	var items []string
	for i := range svcs.Items {
		s := &svcs.Items[i]
		if s.GetLabels()[eipHolderLabel] != "true" {
			continue
		}
		alloc := s.GetName()
		ip := ""
		if ing, _, _ := unstructured.NestedSlice(s.Object, "status", "loadBalancer", "ingress"); len(ing) > 0 {
			m, _ := ing[0].(map[string]any)
			ip, _ = m["ip"].(string)
		}
		if (len(allocs) > 0 || len(ips) > 0) && !wantA[alloc] && !(ip != "" && wantIP[ip]) {
			continue
		}
		found[alloc] = true
		if ip != "" {
			found[ip] = true
		}
		var inst ec2Instance
		for j := range svcs.Items {
			o := &svcs.Items[j]
			if o.GetName() != alloc && o.GetAnnotations()[eipShareKey] == alloc && strings.HasSuffix(o.GetName(), "-lan") {
				inst = byName[strings.TrimSuffix(o.GetName(), "-lan")]
			}
		}
		tags := map[string]string{}
		if st := s.GetLabels()["cfn.openinfra.dev/stack"]; st != "" {
			tags["aws:cloudformation:stack-name"] = st
		}
		assoc := ""
		if inst.id != "" {
			assoc = shortHashID("eipassoc-", alloc+"/"+inst.id, 17)
		}
		rec := ec2Record{fields: map[string][]string{"allocation-id": {alloc}, "association-id": {assoc}, "domain": {"vpc"}, "instance-id": {inst.id},
			"public-ip": {ip}, "private-ip-address": {inst.privateIP}, "network-border-group": {h.region()}, "public-ipv4-pool": {"amazon"}}, tags: tags}
		if !rec.matches(fs) {
			continue
		}
		items = append(items, xtag("publicIp", ip)+xtag("allocationId", alloc)+"<domain>vpc</domain>"+xtag("instanceId", inst.id)+
			xtag("associationId", assoc)+xtag("privateIpAddress", inst.privateIP)+xtags(tags)+"<publicIpv4Pool>amazon</publicIpv4Pool>"+
			xtag("networkBorderGroup", h.region()))
	}
	for _, a := range allocs {
		if !found[a] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidAllocationID.NotFound", requestID, "The allocation ID '"+a+"' does not exist")
			return
		}
	}
	for _, ip := range ips {
		if !found[ip] {
			writeEC2Error(w, http.StatusBadRequest, "InvalidAddress.NotFound", requestID, "Address '"+ip+"' not found.")
			return
		}
	}
	writeEC2(w, requestID, "DescribeAddresses", xset("addressesSet", items))
}
