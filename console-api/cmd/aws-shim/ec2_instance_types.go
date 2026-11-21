package main

// DescribeInstanceTypes: the instance types an instance can be launched as here (an AWS::EC2::Instance's
// InstanceType; cfn's table), with the vCPUs and memory the instance gets, as EC2 reports them. Only what
// holds for the platform's instances is reported: every type is current-generation x86_64 on EBS-backed HVM,
// on demand; the t2 family is Xen with one thread per core and BIOS boot, the others Nitro with two threads per
// core and BIOS or UEFI boot. GPU, network and storage figures that the platform does not provide are left
// out rather than invented.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/cfn"
)

// ec2InstanceTypeFilters are the filters DescribeInstanceTypes accepts.
var ec2InstanceTypeFilters = []string{"instance-type", "current-generation", "free-tier-eligible", "burstable-performance-supported",
	"hypervisor", "bare-metal", "instance-storage-supported", "supported-usage-class", "supported-root-device-type",
	"supported-virtualization-type", "supported-boot-mode", "processor-info.supported-architecture", "vcpu-info.default-vcpus",
	"vcpu-info.default-cores", "vcpu-info.default-threads-per-core", "memory-info.size-in-mib"}

func (h *ec2Handler) describeInstanceTypes(w http.ResponseWriter, r *http.Request, requestID string) {
	fs := ec2Filters(r.Form)
	if msg, ok := checkFilters(fs, ec2InstanceTypeFilters); !ok {
		writeEC2Error(w, http.StatusBadRequest, "InvalidParameterValue", requestID, msg)
		return
	}
	types := cfn.InstanceTypes()
	known := make(map[string]bool, len(types))
	for _, t := range types {
		known[t.Name] = true
	}
	want := map[string]bool{}
	var missing []string
	for _, n := range ec2List(r.Form, "InstanceType") {
		if !known[n] {
			missing = append(missing, n)
		}
		want[n] = true
	}
	if len(missing) > 0 {
		writeEC2Error(w, http.StatusBadRequest, "InvalidInstanceType", requestID,
			"The following supplied instance types do not exist: ["+strings.Join(missing, ", ")+"]")
		return
	}
	var items []string
	for _, t := range types {
		if len(want) > 0 && !want[t.Name] {
			continue
		}
		it := instanceTypeOf(t)
		if it.record().matches(fs) {
			items = append(items, it.xml())
		}
	}
	writePage(w, r, requestID, "DescribeInstanceTypes", "instanceTypeSet", items, 5, 100)
}

// ec2InstanceType is one instance type as EC2 describes it.
type ec2InstanceType struct {
	name                  string
	vcpus, cores, threads int
	memoryMiB             int64
	hypervisor            string
	burstable, freeTier   bool
	bootModes             []string
	nvme, ebsOptimized    string
}

func instanceTypeOf(t cfn.InstanceTypeInfo) ec2InstanceType {
	family := t.Name
	if i := strings.IndexByte(family, '.'); i > 0 {
		family = family[:i]
	}
	it := ec2InstanceType{name: t.Name, vcpus: t.VCPUs, memoryMiB: t.MemoryMiB, burstable: strings.HasPrefix(family, "t"),
		freeTier: t.Name == "t2.micro" || t.Name == "t3.micro"}
	if family == "t2" {
		// Xen: one thread per core, BIOS boot, no NVMe or EBS optimization.
		it.hypervisor, it.cores, it.threads = "xen", t.VCPUs, 1
		it.bootModes, it.nvme, it.ebsOptimized = []string{"legacy-bios"}, "unsupported", "unsupported"
		return it
	}
	it.hypervisor, it.threads = "nitro", 2
	it.cores = t.VCPUs / 2
	if it.cores < 1 {
		it.cores, it.threads = 1, t.VCPUs
	}
	it.bootModes, it.nvme, it.ebsOptimized = []string{"legacy-bios", "uefi"}, "required", "default"
	return it
}

func (it ec2InstanceType) record() ec2Record {
	b := strconv.FormatBool
	return ec2Record{fields: map[string][]string{
		"instance-type": {it.name}, "current-generation": {"true"}, "free-tier-eligible": {b(it.freeTier)},
		"burstable-performance-supported": {b(it.burstable)}, "hypervisor": {it.hypervisor}, "bare-metal": {"false"},
		"instance-storage-supported": {"false"}, "supported-usage-class": {"on-demand"}, "supported-root-device-type": {"ebs"},
		"supported-virtualization-type": {"hvm"}, "supported-boot-mode": it.bootModes,
		"processor-info.supported-architecture": {"x86_64"}, "vcpu-info.default-vcpus": {strconv.Itoa(it.vcpus)},
		"vcpu-info.default-cores": {strconv.Itoa(it.cores)}, "vcpu-info.default-threads-per-core": {strconv.Itoa(it.threads)},
		"memory-info.size-in-mib": {strconv.FormatInt(it.memoryMiB, 10)},
	}}
}

func (it ec2InstanceType) xml() string {
	b := strconv.FormatBool
	var s strings.Builder
	s.WriteString(xtag("instanceType", it.name) + "<currentGeneration>true</currentGeneration>" +
		"<freeTierEligible>" + b(it.freeTier) + "</freeTierEligible>" +
		"<supportedUsageClasses><item>on-demand</item></supportedUsageClasses>" +
		"<supportedRootDeviceTypes><item>ebs</item></supportedRootDeviceTypes>" +
		"<supportedVirtualizationTypes><item>hvm</item></supportedVirtualizationTypes>" +
		"<bareMetal>false</bareMetal>" + xtag("hypervisor", it.hypervisor) +
		"<processorInfo><supportedArchitectures><item>x86_64</item></supportedArchitectures></processorInfo>" +
		"<vCpuInfo><defaultVCpus>" + strconv.Itoa(it.vcpus) + "</defaultVCpus><defaultCores>" + strconv.Itoa(it.cores) +
		"</defaultCores><defaultThreadsPerCore>" + strconv.Itoa(it.threads) + "</defaultThreadsPerCore></vCpuInfo>" +
		"<memoryInfo><sizeInMiB>" + strconv.FormatInt(it.memoryMiB, 10) + "</sizeInMiB></memoryInfo>" +
		"<instanceStorageSupported>false</instanceStorageSupported>" +
		"<ebsInfo><ebsOptimizedSupport>" + it.ebsOptimized + "</ebsOptimizedSupport><encryptionSupport>supported</encryptionSupport>" +
		"<nvmeSupport>" + it.nvme + "</nvmeSupport></ebsInfo>" +
		"<burstablePerformanceSupported>" + b(it.burstable) + "</burstablePerformanceSupported><supportedBootModes>")
	for _, m := range it.bootModes {
		s.WriteString("<item>" + m + "</item>")
	}
	s.WriteString("</supportedBootModes>")
	return s.String()
}
