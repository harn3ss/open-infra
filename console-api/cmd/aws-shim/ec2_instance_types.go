package main

// DescribeInstanceTypes: the instance types an instance can be launched as here (an AWS::EC2::Instance's
// InstanceType; cfn's table), with the vCPUs, memory and GPUs the instance gets, as EC2 reports them. Only
// what holds for the platform's instances is reported: every type is current-generation x86_64 on EBS-backed
// HVM, on demand; the t2 family is Xen with one thread per core and BIOS boot, the others Nitro with two
// threads per core and BIOS or UEFI boot. A GPU instance type's GPU is the installation's own card for the
// type's family (its instanceGPU; g4dn and g5 are each a pool of one card model), and a GPU type is listed
// only where the installation offers its family. Network and storage figures that the platform does not
// provide are left out rather than invented.

import (
	"net/http"
	"os"
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
	var types []cfn.InstanceTypeInfo
	for _, t := range cfn.InstanceTypes() {
		if t.GPUs > 0 && !h.gpus[t.GPUFamily].offered() {
			continue // no GPU instances of its family here: the type is not offered, as one outside a Region is not
		}
		types = append(types, t)
	}
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
		it := instanceTypeOf(t, h.gpus[t.GPUFamily])
		if it.record().matches(fs) {
			items = append(items, it.xml())
		}
	}
	writePage(w, r, requestID, "DescribeInstanceTypes", "instanceTypeSet", items, 5, 100)
}

// instanceGPU is the card a GPU instance type's instance is given here: the installation's card for the
// type's family, which its operator names (install.sh writes config.yaml's gpuInstances into the shim's
// optional openinfra-gpu-instances ConfigMap). Unnamed, the installation offers no instances of the family.
type instanceGPU struct {
	name, manufacturer string
	memoryMiB          int64
}

func (g instanceGPU) offered() bool { return g.name != "" }

// gpuFamilies are the GPU instance families an installation can offer, each a pool of its own cards.
var gpuFamilies = []string{"g4dn", "g5"}

// instanceGPUsFromEnv are the installation's GPU instance cards by family: g4dn's from GPU_INSTANCE_GPU_NAME
// (as EC2 names a GPU, e.g. "T4"), GPU_INSTANCE_GPU_MANUFACTURER and GPU_INSTANCE_GPU_MEMORY_MIB, as before
// families existed; every other family's from the same names with its family after GPU_INSTANCE_
// (GPU_INSTANCE_G5_GPU_NAME, ...).
func instanceGPUsFromEnv() map[string]instanceGPU {
	out := map[string]instanceGPU{}
	for _, fam := range gpuFamilies {
		prefix := "GPU_INSTANCE_"
		if fam != "g4dn" {
			prefix += strings.ToUpper(fam) + "_"
		}
		g := instanceGPU{name: strings.TrimSpace(os.Getenv(prefix + "GPU_NAME")),
			manufacturer: strings.TrimSpace(os.Getenv(prefix + "GPU_MANUFACTURER"))}
		g.memoryMiB, _ = strconv.ParseInt(strings.TrimSpace(os.Getenv(prefix+"GPU_MEMORY_MIB")), 10, 64)
		if g.offered() {
			out[fam] = g
		}
	}
	return out
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
	gpus                  int
	gpu                   instanceGPU
}

func instanceTypeOf(t cfn.InstanceTypeInfo, gpu instanceGPU) ec2InstanceType {
	family := t.Name
	if i := strings.IndexByte(family, '.'); i > 0 {
		family = family[:i]
	}
	it := ec2InstanceType{name: t.Name, vcpus: t.VCPUs, memoryMiB: t.MemoryMiB, burstable: strings.HasPrefix(family, "t"),
		freeTier: t.Name == "t2.micro" || t.Name == "t3.micro", gpus: t.GPUs}
	if t.GPUs > 0 {
		it.gpu = gpu
	}
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
		it.gpuInfoXML() +
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

// gpuInfoXML is a GPU instance type's GpuInfo: its GPUs, each the installation's card for its family ("" for a
// type with none).
func (it ec2InstanceType) gpuInfoXML() string {
	if it.gpus == 0 || !it.gpu.offered() {
		return ""
	}
	n := strconv.Itoa(it.gpus)
	gpu := xtag("name", it.gpu.name)
	if it.gpu.manufacturer != "" {
		gpu += xtag("manufacturer", it.gpu.manufacturer)
	}
	gpu += "<count>" + n + "</count>"
	total := ""
	if it.gpu.memoryMiB > 0 {
		gpu += "<memoryInfo><sizeInMiB>" + strconv.FormatInt(it.gpu.memoryMiB, 10) + "</sizeInMiB></memoryInfo>"
		total = "<totalGpuMemoryInMiB>" + strconv.FormatInt(it.gpu.memoryMiB*int64(it.gpus), 10) + "</totalGpuMemoryInMiB>"
	}
	return "<gpuInfo><gpus><item>" + gpu + "</item></gpus>" + total + "</gpuInfo>"
}
