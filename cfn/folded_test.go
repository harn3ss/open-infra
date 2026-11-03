package cfn

import (
	"context"
	"strings"
	"testing"
)

// foldedTmpl is an app tier with every kind of resource that provisions nothing of its own.
const foldedTmpl = `
Resources:
  Vpc: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  Subnet: { Type: AWS::EC2::Subnet, Properties: { VpcId: !Ref Vpc, CidrBlock: 10.0.1.0/24 } }
  Igw: { Type: AWS::EC2::InternetGateway }
  Attach: { Type: AWS::EC2::VPCGatewayAttachment, Properties: { VpcId: !Ref Vpc, InternetGatewayId: !Ref Igw } }
  Rt: { Type: AWS::EC2::RouteTable, Properties: { VpcId: !Ref Vpc } }
  Default:
    Type: AWS::EC2::Route
    DependsOn: Attach
    Properties: { RouteTableId: !Ref Rt, DestinationCidrBlock: 0.0.0.0/0, GatewayId: !Ref Igw }
  Assoc: { Type: AWS::EC2::SubnetRouteTableAssociation, Properties: { SubnetId: !Ref Subnet, RouteTableId: !Ref Rt } }
  G: { Type: AWS::EC2::SecurityGroup, Properties: { GroupDescription: web, VpcId: !Ref Vpc } }
  Web: { Type: AWS::EC2::Instance, Properties: { ImageId: ubuntu-24.04, SubnetId: !Ref Subnet, SecurityGroupIds: [ !Ref G ] } }
  Ip: { Type: AWS::EC2::EIP, Properties: { InstanceId: !Ref Web } }
  Data: { Type: AWS::EC2::Volume, Properties: { Size: 10, AvailabilityZone: us-east-1a } }
  Mount: { Type: AWS::EC2::VolumeAttachment, Properties: { InstanceId: !Ref Web, VolumeId: !Ref Data, Device: /dev/sdh } }
  Handle: { Type: AWS::CloudFormation::WaitConditionHandle }
  Wait: { Type: AWS::CloudFormation::WaitCondition, Properties: { Handle: !Ref Handle, Timeout: "300" } }
  Site: { Type: AWS::S3::Bucket, Properties: { BucketName: site } }
  SitePolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref Site
      PolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: "*", Action: "s3:GetObject", Resource: "arn:aws:s3:::site/*" } ] }
`

// translatedRecord is the record a deploy of tmpl as stack writes: each resource that translates to an
// object, as the engine records it (the deploy itself would wait on the VM and the wait condition).
func translatedRecord(t *testing.T, tmpl, stack string) *StackRecord {
	t.Helper()
	tm := mustParse(t, []byte(tmpl))
	r := newResolver(tm, resolveParams(tm, nil), nil, pseudoParams(stack))
	r.evalConditions()
	sctx := &stackCtx{template: tm, resolver: r, namer: newPhysNamer(stack, nil)}
	r.staticRef = func(id string) (string, bool) { return inStackRef(id, sctx) }
	r.staticAtt = func(id, attr string) (string, bool) { return serviceAtt(id, attr, sctx) }
	rec := &StackRecord{Name: stack, Namespace: "cfn-test", Status: "CREATE_COMPLETE", Template: tmpl}
	for _, id := range tm.rawOrder {
		res := tm.Resources[id]
		if !sctx.included(res) {
			continue
		}
		props, _ := sctx.resolveProps(id)
		m, fs := translatorFor(res.Type)(id, props, sctx)
		if len(fs) > 0 {
			t.Fatalf("%s is refused: %v", id, fs)
		}
		if m != nil {
			rec.Resources = append(rec.Resources, StackResource{LogicalID: id, APIVersion: m.APIVersion, Kind: m.Kind, Name: m.Name, Spec: m.Spec, Type: res.Type})
		}
	}
	return rec
}

// foldedRecord is foldedTmpl's record, with a status reader over its live objects.
func foldedRecord(t *testing.T) (*StackRecord, *fakeApplier) {
	t.Helper()
	rec := translatedRecord(t, foldedTmpl, "app")
	f := &fakeApplier{liveSpecs: map[string]map[string]any{}}
	for _, r := range rec.Resources {
		f.liveSpecs[r.Kind+"/"+r.Name] = r.Spec
	}
	return rec, f
}

func TestFoldedResources_ListsWhatProvisionsNothing(t *testing.T) {
	rec, f := foldedRecord(t)
	got := map[string]FoldedResource{}
	for _, fr := range FoldedResources(context.Background(), rec, DeployOptions{StackName: "app", Namespace: "cfn-test"}, f) {
		got[fr.LogicalID] = fr
	}
	for _, id := range []string{"Vpc", "Subnet", "G", "Web", "Wait", "Site"} {
		if _, isFolded := got[id]; isFolded {
			t.Errorf("%s provisions something of its own, so it is not folded", id)
		}
	}
	want := map[string]struct {
		prefix   string
		carriers string
	}{
		"Igw":        {"igw-", "Vpc"}, // names nothing; part of the VPC its attachment joins it to
		"Attach":     {"IGW|", "Vpc"}, // AWS's attachment id shape
		"Rt":         {"rtb-", "Vpc"}, // a route table is part of its VPC
		"Default":    {"rtb-", "Vpc"}, // a route: its table's id | its destination
		"Assoc":      {"rtbassoc-", "Subnet,Vpc"},
		"Mount":      {"app-Mount-", "Data,Web"}, // no Ref of its own: AWS's generated id; part of its volume and its instance
		"Handle":     {"", ""},                   // no carrier: it exists as soon as the create begins
		"SitePolicy": {"", "Site"},
	}
	for id, w := range want {
		fr, ok := got[id]
		if !ok {
			t.Errorf("%s provisions nothing of its own and must be listed as folded (got %v)", id, got)
			continue
		}
		if !strings.HasPrefix(fr.PhysicalID, w.prefix) || fr.PhysicalID == "" || fr.PhysicalID == id {
			t.Errorf("%s physical id %q, want its Ref (prefix %q)", id, fr.PhysicalID, w.prefix)
		}
		if c := strings.Join(fr.Carriers, ","); c != w.carriers {
			t.Errorf("%s carriers %q, want %q", id, c, w.carriers)
		}
	}
	if d := got["Default"].PhysicalID; !strings.HasSuffix(d, "|0.0.0.0/0") || !strings.HasPrefix(d, got["Rt"].PhysicalID) {
		t.Errorf("a route's physical id is <its table's id>|<destination>: %q (table %q)", d, got["Rt"].PhysicalID)
	}
	if ip, ok := got["Ip"]; !ok || strings.Join(ip.Carriers, ",") != "Web" {
		t.Errorf("an Elastic IP folded onto its instance follows it: %+v", ip)
	}
}

// An Elastic IP's physical id is its address (its Ref, as on AWS) once its instance's VM has one.
func TestFoldedResources_ElasticIPIsItsAddress(t *testing.T) {
	rec, f := foldedRecord(t)
	var vm string
	for _, r := range rec.Resources {
		if r.LogicalID == "Web" {
			vm = r.Kind + "/" + r.Name
		}
	}
	f.liveStatus = map[string]map[string]any{vm: {"lanIp": "192.0.2.10"}}
	for _, fr := range FoldedResources(context.Background(), rec, DeployOptions{StackName: "app", Namespace: "cfn-test"}, f) {
		if fr.LogicalID == "Ip" && fr.PhysicalID != "192.0.2.10" {
			t.Fatalf("the Elastic IP's physical id is its address: %+v (VM %s)", fr, vm)
		}
	}
}

// A resource gated off by its Condition is not a resource of the stack.
func TestFoldedResources_ConditionedOffIsNotListed(t *testing.T) {
	tmpl := `
Parameters:
  WithGw: { Type: String, Default: "no" }
Conditions:
  Gw: !Equals [ !Ref WithGw, "yes" ]
Resources:
  Vpc: { Type: AWS::EC2::VPC, Properties: { CidrBlock: 10.0.0.0/16 } }
  Igw: { Type: AWS::EC2::InternetGateway, Condition: Gw }
`
	rec := translatedRecord(t, tmpl, "c")
	if fr := FoldedResources(context.Background(), rec, DeployOptions{StackName: "c"}, nil); len(fr) != 0 {
		t.Fatalf("a conditioned-off resource is not listed: %+v", fr)
	}
}

func TestFoldedStatus(t *testing.T) {
	for _, c := range []struct {
		carriers []string
		want     string
		listed   bool
	}{
		{[]string{""}, "", false},
		{[]string{"CREATE_IN_PROGRESS"}, "CREATE_IN_PROGRESS", true},
		{[]string{"CREATE_COMPLETE", ""}, "CREATE_IN_PROGRESS", true}, // created once every carrier is
		{[]string{"CREATE_COMPLETE", "CREATE_COMPLETE"}, "CREATE_COMPLETE", true},
		{[]string{"CREATE_COMPLETE", "UPDATE_COMPLETE"}, "CREATE_COMPLETE", true}, // a carrier's update is not its own
		{[]string{"CREATE_FAILED", "CREATE_COMPLETE"}, "CREATE_FAILED", true},
		{[]string{"DELETE_IN_PROGRESS", "CREATE_COMPLETE"}, "DELETE_IN_PROGRESS", true},
		{[]string{"DELETE_COMPLETE", "CREATE_COMPLETE"}, "DELETE_IN_PROGRESS", true},
		{[]string{"DELETE_COMPLETE", "DELETE_SKIPPED"}, "DELETE_COMPLETE", true},
		{[]string{"DELETE_FAILED", "DELETE_COMPLETE"}, "DELETE_FAILED", true},
	} {
		if got, listed := FoldedStatus(c.carriers); got != c.want || listed != c.listed {
			t.Errorf("FoldedStatus(%v) = %s,%v want %s,%v", c.carriers, got, listed, c.want, c.listed)
		}
	}
	for stack, want := range map[string]string{"CREATE_IN_PROGRESS": "CREATE_COMPLETE", "UPDATE_COMPLETE": "CREATE_COMPLETE",
		"DELETE_IN_PROGRESS": "DELETE_IN_PROGRESS", "ROLLBACK_COMPLETE": "DELETE_COMPLETE", "DELETE_FAILED": "DELETE_COMPLETE"} {
		if got := FoldedStatusWithoutCarrier(stack); got != want {
			t.Errorf("FoldedStatusWithoutCarrier(%s) = %s, want %s", stack, got, want)
		}
	}
}
