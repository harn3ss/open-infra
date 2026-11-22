package cfn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// AWSViewAnnotation is where the engine records, on the kind an EC2 resource becomes, the AWS-side
// properties that kind does not model: the template's tags (and the aws:cloudformation:* tags AWS adds to
// a stack's resources), an instance's type and key pair, a security group's name and description, a VPC's
// CIDR block. The aws-shim's EC2 API reports them (DescribeInstances, DescribeSecurityGroups, …) and
// filters by them (tag:<key>). Nothing else reads it: no composition renders from it, so it changes no
// composed resource.
const AWSViewAnnotation = "openinfra.dev/aws-view"

// AWSView is the AWSViewAnnotation's JSON.
type AWSView struct {
	Tags             map[string]string `json:"tags,omitempty"`
	InstanceType     string            `json:"instanceType,omitempty"`
	KeyName          string            `json:"keyName,omitempty"`
	GroupName        string            `json:"groupName,omitempty"`
	GroupDescription string            `json:"groupDescription,omitempty"`
	CidrBlock        string            `json:"cidrBlock,omitempty"`
	VolumeType       string            `json:"volumeType,omitempty"`
	// DisableApiTermination is an instance's termination protection: the aws-shim's TerminateInstances
	// refuses the instance while it is set (OperationNotPermitted), as EC2 does.
	DisableApiTermination bool `json:"disableApiTermination,omitempty"`
	// InstanceInitiatedShutdownBehavior is what an instance does when it shuts itself down (stop, the only
	// behaviour offered, and EC2's default).
	InstanceInitiatedShutdownBehavior string `json:"instanceInitiatedShutdownBehavior,omitempty"`
}

// ParseAWSView reads an object's AWSViewAnnotation (the zero view when it has none or it does not parse).
func ParseAWSView(annotations map[string]string) AWSView {
	var v AWSView
	if s := annotations[AWSViewAnnotation]; s != "" {
		_ = json.Unmarshal([]byte(s), &v)
	}
	return v
}

// awsViewProps are, per EC2 type, the properties its view keeps (each under its AWSView field).
var awsViewProps = map[string][]string{
	"AWS::EC2::Instance":      {"InstanceType", "KeyName", "DisableApiTermination", "InstanceInitiatedShutdownBehavior"},
	"AWS::EC2::Volume":        {"VolumeType"},
	"AWS::EC2::SecurityGroup": {"GroupName", "GroupDescription"},
	"AWS::EC2::VPC":           {"CidrBlock"},
	"AWS::EC2::Subnet":        {},
}

func init() {
	for typ := range awsViewProps {
		inner := translators[typ]
		if inner == nil {
			continue
		}
		typ := typ
		translators[typ] = func(id string, props map[string]any, ctx *stackCtx) (*Manifest, []Finding) {
			m, f := inner(id, props, ctx)
			if m != nil {
				if s := awsViewJSON(typ, id, props, ctx); s != "" {
					if m.Annotations == nil {
						m.Annotations = map[string]string{}
					}
					m.Annotations[AWSViewAnnotation] = s
				}
			}
			return m, f
		}
	}
}

// awsViewJSON is resource id's view, as the annotation's value ("" when it has nothing to record).
func awsViewJSON(typ, id string, props map[string]any, ctx *stackCtx) string {
	v := AWSView{Tags: map[string]string{}}
	for k, val := range tagMap(props["Tags"]) {
		if s, ok := val.(string); ok && !strings.HasPrefix(k, "aws:") {
			v.Tags[k] = s
		}
	}
	// The tags AWS adds to every resource of a stack.
	if ctx != nil && ctx.resolver != nil {
		if s, _ := ctx.resolver.pseudo["AWS::StackName"].(string); s != "" {
			v.Tags["aws:cloudformation:stack-name"] = s
		}
		if s, _ := ctx.resolver.pseudo["AWS::StackId"].(string); s != "" {
			v.Tags["aws:cloudformation:stack-id"] = s
		}
		v.Tags["aws:cloudformation:logical-id"] = id
	}
	for _, p := range awsViewProps[typ] {
		s, ok := concrete(props[p])
		if !ok || s == "" {
			continue
		}
		switch p {
		case "InstanceType":
			v.InstanceType = strings.ToLower(s)
		case "KeyName":
			v.KeyName = s
		case "VolumeType":
			v.VolumeType = s
		case "GroupName":
			v.GroupName = s
		case "GroupDescription":
			v.GroupDescription = s
		case "CidrBlock":
			v.CidrBlock = s
		case "DisableApiTermination":
			v.DisableApiTermination = strings.EqualFold(s, "true")
		case "InstanceInitiatedShutdownBehavior":
			v.InstanceInitiatedShutdownBehavior = s
		}
	}
	if len(v.Tags) == 0 && v.InstanceType == "" && v.KeyName == "" && v.GroupName == "" &&
		v.GroupDescription == "" && v.CidrBlock == "" && v.VolumeType == "" && !v.DisableApiTermination &&
		v.InstanceInitiatedShutdownBehavior == "" {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// awsViewCaveats is the caveat for the properties among keys a resource sets that only its AWS view keeps:
// the EC2 API reports them (and filters and targets Run Command by tags), nothing else reads them.
func awsViewCaveats(props map[string]any, keys ...string) []string {
	var set []string
	for _, k := range keys {
		if _, ok := props[k]; ok {
			set = append(set, k)
		}
	}
	if len(set) == 0 {
		return nil
	}
	return []string{strings.Join(set, ", ") + " kept only as the resource's AWS view: the aws-shim's EC2 API reports them " +
		"(Describe*, tag: filters, Run Command targets); no open-infra kind, authorization or condition reads them"}
}

// ImageIDForOS is a catalog OS's image id: the ami-id a guest's instance metadata reports for it
// (vm-composition.yaml: ami- and the first 17 hex digits of sha256("<os>-image")), which the aws-shim's
// DescribeImages lists, and which an ImageId may name.
func ImageIDForOS(os string) string {
	sum := sha256.Sum256([]byte(os + "-image"))
	return "ami-" + hex.EncodeToString(sum[:])[:17]
}

// CatalogOSes lists the catalog OSes an ImageId names.
func CatalogOSes() []string { return append([]string(nil), ec2CatalogOSes...) }

// catalogOSForImageID is the catalog OS whose image id is id ("" for any other ami- id).
func catalogOSForImageID(id string) string {
	for _, c := range ec2CatalogOSes {
		if ImageIDForOS(c) == id {
			return c
		}
	}
	return ""
}

// InstanceTypeForShape is an instance type a VM of cpu vCPUs, memory and gpus GPUs is ("" for none in the
// mapping table): the t3 one when there is one, else the first by name. A VM a template made reports the
// template's own InstanceType (its AWS view) instead.
func InstanceTypeForShape(cpu int, memory string, gpus int) string {
	var match []string
	for t, s := range ec2InstanceTypes {
		if s.cpu == cpu && s.mem == memory && ec2InstanceGPUs[t] == gpus {
			match = append(match, t)
		}
	}
	sort.Strings(match)
	for _, t := range match {
		if strings.HasPrefix(t, "t3.") {
			return t
		}
	}
	if len(match) > 0 {
		return match[0]
	}
	return ""
}

// InstanceTypeShape is an instance type's vCPUs and memory as a kind: VirtualMachine sizes it (ok=false
// for a type the mapping table does not have).
func InstanceTypeShape(instanceType string) (cpu int, memory string, ok bool) {
	s, ok := ec2InstanceTypes[strings.ToLower(instanceType)]
	return s.cpu, s.mem, ok
}

// InstanceTypeInfo is an EC2 instance type an AWS::EC2::Instance may name: its vCPUs, memory and GPUs, as
// the VirtualMachine it launches is sized (EC2's DescribeInstanceTypes reports them).
type InstanceTypeInfo struct {
	Name      string
	VCPUs     int
	MemoryMiB int64
	GPUs      int
}

// InstanceTypes are the instance types an instance may be launched as, sorted by name.
func InstanceTypes() []InstanceTypeInfo {
	out := make([]InstanceTypeInfo, 0, len(ec2InstanceTypes))
	for name, s := range ec2InstanceTypes {
		out = append(out, InstanceTypeInfo{Name: name, VCPUs: s.cpu, MemoryMiB: memoryMiB(s.mem), GPUs: ec2InstanceGPUs[name]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// memoryMiB is a Kubernetes memory size in Mi or Gi, in MiB.
func memoryMiB(q string) int64 {
	switch {
	case strings.HasSuffix(q, "Gi"):
		n, _ := strconv.ParseInt(strings.TrimSuffix(q, "Gi"), 10, 64)
		return n * 1024
	case strings.HasSuffix(q, "Mi"):
		n, _ := strconv.ParseInt(strings.TrimSuffix(q, "Mi"), 10, 64)
		return n
	}
	return 0
}
