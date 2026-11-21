package main

import (
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// DescribeInstanceTypes reports the types an instance can be launched as, with the vCPUs and memory it gets,
// selected by name or filter and paged as EC2 pages them; a type that does not exist is EC2's error.
func TestEC2_DescribeInstanceTypes(t *testing.T) {
	h, _ := ec2Fixture(t)
	b := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstanceTypes"}}).Body.String()
	mustHave(t, "every type", b, []string{
		"<instanceType>c5.2xlarge</instanceType>", "<defaultVCpus>8</defaultVCpus><defaultCores>4</defaultCores><defaultThreadsPerCore>2</defaultThreadsPerCore>",
		"<sizeInMiB>16384</sizeInMiB>", "<hypervisor>nitro</hypervisor>", "<instanceType>t2.micro</instanceType>", "<hypervisor>xen</hypervisor>",
		"<supportedArchitectures><item>x86_64</item></supportedArchitectures>"}, []string{"<nextToken>"})

	b = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstanceTypes"}, "InstanceType.1": {"c5.2xlarge"}}).Body.String()
	if strings.Count(b, "<instanceType>") != 1 || !strings.Contains(b, "<sizeInMiB>16384</sizeInMiB>") {
		t.Errorf("one named type: %s", b)
	}
	b = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstanceTypes"}, "Filter.1.Name": {"instance-type"}, "Filter.1.Value.1": {"t3.*"},
		"Filter.2.Name": {"vcpu-info.default-vcpus"}, "Filter.2.Value.1": {"2"}, "Filter.3.Name": {"memory-info.size-in-mib"}, "Filter.3.Value.1": {"1024"}}).Body.String()
	mustHave(t, "filtered", b, []string{"<instanceType>t3.micro</instanceType>", "<burstablePerformanceSupported>true</burstablePerformanceSupported>"},
		[]string{"t3.small", "t2.micro", "c5."})

	w := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstanceTypes"}, "InstanceType.1": {"c5.2xlarge"}, "InstanceType.2": {"x9.huge"}})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>InvalidInstanceType</Code>") || !strings.Contains(w.Body.String(), "do not exist: [x9.huge]") {
		t.Errorf("a type that does not exist: %d %s", w.Code, w.Body.String())
	}
	if w = ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstanceTypes"}, "Filter.1.Name": {"gpu-info.count"}, "Filter.1.Value.1": {"1"}}); w.Code != 400 {
		t.Errorf("an unknown filter: %d %s", w.Code, w.Body.String())
	}

	page := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstanceTypes"}, "MaxResults": {"5"}}).Body.String()
	if strings.Count(page, "<instanceType>") != 5 || !strings.Contains(page, "<nextToken>") {
		t.Fatalf("a page of five: %s", page)
	}
	next := page[strings.Index(page, "<nextToken>")+len("<nextToken>"):]
	next = next[:strings.Index(next, "</nextToken>")]
	if p2 := ec2Call(h, ec2Alice, url.Values{"Action": {"DescribeInstanceTypes"}, "MaxResults": {"5"}, "NextToken": {next}}).Body.String(); strings.Count(p2, "<instanceType>") != 5 || p2 == page {
		t.Errorf("the next page: %s", p2)
	}
}

// A principal whose policy does not allow ec2:DescribeInstanceTypes is refused it, with EC2's error.
func TestEC2_DescribeInstanceTypes_Refused(t *testing.T) {
	h, _ := ec2Fixture(t)
	h.door.authz = checkerFor(policyengine.Statement{Effect: policyengine.Allow, Actions: []string{"ec2:DescribeInstances"}, Resources: []string{"*"}})
	role := iam.Claims{Sub: "assumed-role/r/s", AssumedRole: "r"}
	if w := ec2Call(h, role, url.Values{"Action": {"DescribeInstanceTypes"}}); w.Code != 403 || !strings.Contains(w.Body.String(), "UnauthorizedOperation") {
		t.Errorf("a role without ec2:DescribeInstanceTypes must be refused: %d %s", w.Code, w.Body.String())
	}
}
