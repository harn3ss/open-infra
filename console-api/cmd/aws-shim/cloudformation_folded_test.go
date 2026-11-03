package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
)

// #350 Y: a resource that provisions nothing of its own is a resource of the stack, as on AWS.
// (The VPC is a parameter here — the network's own stack — so the gateway, its attachment, the route
// table and its route have nothing in this stack to be part of: they follow the stack. The cfn package's
// tests cover them following an in-stack VPC.)
const foldedStackTmpl = `
Parameters:
  VpcId: { Type: String, Default: net-vpc }
Resources:
  G: { Type: AWS::EC2::SecurityGroup, Properties: { GroupDescription: web } }
  Http: { Type: AWS::EC2::SecurityGroupIngress, Properties: { GroupId: !Ref G, IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 10.0.0.0/8 } }
  Web: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref G ] } }
  Ip: { Type: AWS::EC2::EIP, Properties: { InstanceId: !Ref Web } }
  Igw: { Type: AWS::EC2::InternetGateway }
  Attach: { Type: AWS::EC2::VPCGatewayAttachment, Properties: { VpcId: !Ref VpcId, InternetGatewayId: !Ref Igw } }
  Rt: { Type: AWS::EC2::RouteTable, Properties: { VpcId: !Ref VpcId } }
  Default:
    Type: AWS::EC2::Route
    DependsOn: Attach
    Properties: { RouteTableId: !Ref Rt, DestinationCidrBlock: 0.0.0.0/0, GatewayId: !Ref Igw }
  Handle: { Type: AWS::CloudFormation::WaitConditionHandle }
`

type stackResourceMember struct {
	LogicalResourceID  string `xml:"LogicalResourceId"`
	PhysicalResourceID string `xml:"PhysicalResourceId"`
	ResourceType       string `xml:"ResourceType"`
	ResourceStatus     string `xml:"ResourceStatus"`
}

func TestCFNAPI_FoldedResourcesAreListed(t *testing.T) {
	h, ap := cfnTestDoorway(t, "192.0.2.10")
	h.signals = &signalStore{h: h}
	opts := h.optsFor("net", nil, stackExports{})
	opts.Wait = false
	if _, err := cfn.Deploy(context.Background(), []byte(foldedStackTmpl), opts, ap); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	rr := cfnPost(t, h, ap, url.Values{"StackName": {"net"}}, func(w http.ResponseWriter, r *http.Request) { h.listStackResources(w, r, ap, "req") })
	var got struct {
		Members []stackResourceMember `xml:"ListStackResourcesResult>StackResourceSummaries>member"`
	}
	if err := xml.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v\n%s", err, rr.Body.String())
	}
	by := map[string]stackResourceMember{}
	for _, m := range got.Members {
		by[m.LogicalResourceID] = m
	}
	// (The test doorway has no public base URL, so the handle's presigned URL is its path alone.)
	for id, prefix := range map[string]string{"Igw": "igw-", "Attach": "IGW|", "Rt": "rtb-", "Default": "rtb-", "Handle": "/cfn-signal/net/Handle?sig=",
		"Ip": "192.0.2.10", "Http": "sgr-"} {
		m, ok := by[id]
		if !ok {
			t.Errorf("ListStackResources must list %s (it provisions nothing of its own but is a resource of the stack):\n%s", id, rr.Body.String())
			continue
		}
		if !strings.HasPrefix(m.PhysicalResourceID, prefix) || m.ResourceStatus != "CREATE_COMPLETE" || !strings.HasPrefix(m.ResourceType, "AWS::") {
			t.Errorf("%s: %+v, want its Ref (%s…) and CREATE_COMPLETE", id, m, prefix)
		}
	}
	if d, rt := by["Default"].PhysicalResourceID, by["Rt"].PhysicalResourceID; d != rt+"|0.0.0.0/0" {
		t.Errorf("a route's physical id is its table's id and destination: %q (table %q)", d, rt)
	}

	// DescribeStackResource answers with the same physical id (it used to answer with the logical id).
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"net"}, "LogicalResourceId": {"Igw"}}, func(w http.ResponseWriter, r *http.Request) { h.describeStackResource(w, r, ap, "req") })
	var one struct {
		Phys string `xml:"DescribeStackResourceResult>StackResourceDetail>PhysicalResourceId"`
	}
	if err := xml.Unmarshal(rr.Body.Bytes(), &one); err != nil || one.Phys != by["Igw"].PhysicalResourceID {
		t.Errorf("DescribeStackResource Igw: %v %q, want %q\n%s", err, one.Phys, by["Igw"].PhysicalResourceID, rr.Body.String())
	}
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"net"}, "LogicalResourceId": {"Attach"}}, func(w http.ResponseWriter, r *http.Request) { h.describeStackResources(w, r, ap, "req") })
	if b := rr.Body.String(); strings.Count(b, "<member>") != 1 || !strings.Contains(b, "<PhysicalResourceId>IGW|") {
		t.Errorf("DescribeStackResources must list the attachment:\n%s", b)
	}

	// DescribeStackEvents has their create: the address and the rule following the instance and the
	// group they are part of, the rest the stack's own create.
	rr = cfnPost(t, h, ap, url.Values{"StackName": {"net"}}, func(w http.ResponseWriter, r *http.Request) { h.describeStackEvents(w, r, ap, "req") })
	b := rr.Body.String()
	for _, id := range []string{"Igw", "Attach", "Rt", "Default", "Handle", "Ip", "Http"} {
		for _, st := range []string{"CREATE_IN_PROGRESS", "CREATE_COMPLETE"} {
			if !strings.Contains(b, "<LogicalResourceId>"+id+"</LogicalResourceId><PhysicalResourceId>"+by[id].PhysicalResourceID+"</PhysicalResourceId><ResourceType>"+by[id].ResourceType+"</ResourceType>") || !strings.Contains(b, id+"-"+st+"-") {
				t.Errorf("DescribeStackEvents lacks %s %s:\n%s", id, st, b)
			}
		}
	}
}

// A folded resource's status follows its carriers: listed once one has started, created once all exist,
// deleted with them; a carrier's failure is its own.
func TestFoldedRows_FollowCarriers(t *testing.T) {
	folded := []cfn.FoldedResource{
		{LogicalID: "Attach", Type: "AWS::EC2::VPCGatewayAttachment", PhysicalID: "IGW|abc", Carriers: []string{"Vpc"}},
		{LogicalID: "Mount", Type: "AWS::EC2::VolumeAttachment", PhysicalID: "net-Mount-ABC", Carriers: []string{"Data", "Web"}},
		{LogicalID: "Handle", Type: "AWS::CloudFormation::WaitConditionHandle", PhysicalID: "https://h"},
	}
	rec := &cfn.StackRecord{Name: "net", Status: "CREATE_IN_PROGRESS", Events: []cfn.StackEvent{{EventID: "s1", LogicalID: "net", Type: cfn.StackTypeName, Status: "CREATE_IN_PROGRESS"}}}
	statusOf := func(rows []resourceRow) map[string]string {
		m := map[string]string{}
		for _, r := range foldedRows(rec, rows, folded) {
			m[r.logicalID] = r.status + "|" + r.reason
		}
		return m
	}
	// Nothing started: only the handle (it exists as soon as the create begins).
	got := statusOf(nil)
	if len(got) != 1 || got["Handle"] != "CREATE_COMPLETE|" {
		t.Fatalf("before any carrier starts: %v", got)
	}
	got = statusOf([]resourceRow{{logicalID: "Vpc", status: "CREATE_IN_PROGRESS"}, {logicalID: "Web", status: "CREATE_COMPLETE"}})
	if got["Attach"] != "CREATE_IN_PROGRESS|" || got["Mount"] != "CREATE_IN_PROGRESS|" {
		t.Fatalf("while carriers are created (one volume carrier not started): %v", got)
	}
	got = statusOf([]resourceRow{{logicalID: "Vpc", status: "CREATE_COMPLETE"}, {logicalID: "Web", status: "CREATE_FAILED", reason: "VM never ran"}, {logicalID: "Data", status: "CREATE_COMPLETE"}})
	if got["Attach"] != "CREATE_COMPLETE|" || got["Mount"] != "CREATE_FAILED|part of Web: VM never ran" {
		t.Fatalf("a carrier's failure: %v", got)
	}
	rec.Status = "DELETE_IN_PROGRESS"
	got = statusOf([]resourceRow{{logicalID: "Vpc", status: "DELETE_COMPLETE"}, {logicalID: "Web", status: "DELETE_IN_PROGRESS"}, {logicalID: "Data", status: "DELETE_COMPLETE"}})
	if got["Attach"] != "DELETE_COMPLETE|" || got["Mount"] != "DELETE_IN_PROGRESS|" || got["Handle"] != "DELETE_IN_PROGRESS|" {
		t.Fatalf("during a delete: %v", got)
	}
}

// Folded events follow the carrier events that move them, newest first like the rest.
func TestWithFoldedEvents(t *testing.T) {
	folded := []cfn.FoldedResource{
		{LogicalID: "Mount", Type: "AWS::EC2::VolumeAttachment", PhysicalID: "net-Mount-ABC", Carriers: []string{"Data", "Web"}},
		{LogicalID: "Handle", Type: "AWS::CloudFormation::WaitConditionHandle", PhysicalID: "https://h"},
	}
	chrono := []cfn.StackEvent{
		{EventID: "s1", LogicalID: "net", Type: cfn.StackTypeName, Status: "CREATE_IN_PROGRESS", Timestamp: "t1"},
		{EventID: "d1", LogicalID: "Data", Status: "CREATE_IN_PROGRESS", Timestamp: "t2"},
		{EventID: "w1", LogicalID: "Web", Status: "CREATE_IN_PROGRESS", Timestamp: "t3"},
		{EventID: "d2", LogicalID: "Data", Status: "CREATE_COMPLETE", Timestamp: "t4"},
		{EventID: "w2", LogicalID: "Web", Status: "CREATE_COMPLETE", Timestamp: "t5"},
		{EventID: "s2", LogicalID: "net", Type: cfn.StackTypeName, Status: "CREATE_COMPLETE", Timestamp: "t6"},
	}
	newest := make([]cfn.StackEvent, 0, len(chrono))
	for i := len(chrono) - 1; i >= 0; i-- {
		newest = append(newest, chrono[i])
	}
	out := withFoldedEvents(newest, folded, "net")
	var seq []string
	for i := len(out) - 1; i >= 0; i-- {
		seq = append(seq, out[i].LogicalID+":"+out[i].Status+"@"+out[i].Timestamp)
	}
	want := "net:CREATE_IN_PROGRESS@t1 Handle:CREATE_IN_PROGRESS@t1 Handle:CREATE_COMPLETE@t1 Data:CREATE_IN_PROGRESS@t2 Mount:CREATE_IN_PROGRESS@t2 " +
		"Web:CREATE_IN_PROGRESS@t3 Data:CREATE_COMPLETE@t4 Web:CREATE_COMPLETE@t5 Mount:CREATE_COMPLETE@t5 net:CREATE_COMPLETE@t6"
	if got := strings.Join(seq, " "); got != want {
		t.Fatalf("events (oldest first):\n got %s\nwant %s", got, want)
	}
	for _, e := range out {
		if e.LogicalID == "Mount" && (e.PhysicalID != "net-Mount-ABC" || e.Type != "AWS::EC2::VolumeAttachment") {
			t.Fatalf("a folded event carries its resource's physical id and type: %+v", e)
		}
	}
}
