package cfn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// #347: stack Outputs are evaluated against the deployed stack at *_COMPLETE and persisted on the record
// (DescribeStacks reads them there). Addresses are RFC 5737 documentation ranges.

func outputMap(rec *StackRecord) map[string]StackOutput {
	m := map[string]StackOutput{}
	for _, o := range rec.Outputs {
		m[o.OutputKey] = o
	}
	return m
}

func omissionMap(rec *StackRecord) map[string]string {
	m := map[string]string{}
	for _, o := range rec.OutputsOmitted {
		m[o.OutputKey] = o.Reason
	}
	return m
}

// fastOutputs shortens the post-deploy-attribute poll for a test.
func fastOutputs(t *testing.T) {
	t.Helper()
	prev := outputPollInterval
	outputPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { outputPollInterval = prev })
}

// Everything the template determines resolves directly — parameters, pseudo-parameters, mappings,
// Fn::Sub/Join, a conditioned-off Output is absent — and the Outputs persist on the stored record.
func TestOutputs_StaticValuesPersist(t *testing.T) {
	tmpl := `
Parameters:
  Env: { Type: String, Default: prod }
Mappings:
  Sizes: { prod: { Disk: "40" } }
Conditions:
  IsDev: !Equals [ !Ref Env, dev ]
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: k }
Outputs:
  EnvName:
    Description: the environment
    Value: !Ref Env
  Stack:
    Value: !Sub "${AWS::StackName}-${Env}"
    Export: { Name: !Sub "${AWS::StackName}-Env" }
  Disk:
    Value: !FindInMap [ Sizes, !Ref Env, Disk ]
  Joined:
    Value: !Join [ ",", [ a, b ] ]
  DevOnly:
    Condition: IsDev
    Value: dev-only
`
	f := &fakeApplier{}
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got := outputMap(rec)
	want := map[string]StackOutput{
		"EnvName": {OutputKey: "EnvName", OutputValue: "prod", Description: "the environment"},
		"Stack":   {OutputKey: "Stack", OutputValue: "s-prod", ExportName: "s-Env"},
		"Disk":    {OutputKey: "Disk", OutputValue: "40"},
		"Joined":  {OutputKey: "Joined", OutputValue: "a,b"},
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("Output %s = %+v, want %+v", k, got[k], w)
		}
	}
	if _, has := got["DevOnly"]; has || len(rec.OutputsOmitted) != 0 {
		t.Errorf("a conditioned-off Output is not an Output of the stack: outputs=%v omitted=%v", rec.Outputs, rec.OutputsOmitted)
	}
	// Persisted with the CREATE_COMPLETE record (what DescribeStacks reads).
	if f.stored == nil || f.stored.Status != "CREATE_COMPLETE" || len(f.stored.Outputs) != 4 {
		t.Fatalf("the Outputs must persist on the stored CREATE_COMPLETE record: %+v", f.stored)
	}
}

const outputsEIPTmpl = `
Resources:
  WebSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: web
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0 }
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref WebSG ] }
  WebEip:
    Type: AWS::EC2::EIP
    Properties: { Domain: vpc }
  Assoc:
    Type: AWS::EC2::EIPAssociation
    Properties: { AllocationId: !GetAtt WebEip.AllocationId, InstanceId: !Ref Web }
  Site:
    Type: AWS::S3::Bucket
    Properties: { BucketName: site-assets }
Outputs:
  Address:      { Value: !Ref WebEip }
  PublicIp:     { Value: !GetAtt WebEip.PublicIp }
  InstanceIp:   { Value: !GetAtt Web.PublicIp }
  Url:          { Value: !Sub "https://${WebEip}/" }
  AllocationId: { Value: !GetAtt WebEip.AllocationId }
  BucketName:   { Value: !Ref Site }
  PrivateIp:    { Value: !GetAtt Web.PrivateIp }
  GroupId:      { Value: !Ref WebSG }
`

// The post-deploy attributes resolve from the deployed claims' status: an Elastic IP (Ref / PublicIp)
// and the exposed instance's PublicIp -> the VM's status.lanIp, a bucket Ref -> status.bucket. An
// attribute open-infra does not surface (PrivateIp, an SG id) is OMITTED with its reason — never faked.
func TestOutputs_DeployedAttributes(t *testing.T) {
	f := &fakeApplier{liveStatus: map[string]map[string]any{
		"VirtualMachine/s-web": {"lanIp": "192.0.2.40"},
		"Bucket/s-site":        {"bucket": "site-assets", "ready": true},
	}}
	rec, err := Deploy(context.Background(), []byte(outputsEIPTmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got := outputMap(rec)
	for k, want := range map[string]string{
		"Address":      "192.0.2.40",
		"PublicIp":     "192.0.2.40",
		"InstanceIp":   "192.0.2.40",
		"Url":          "https://192.0.2.40/",
		"AllocationId": eipAllocationID("s", "WebEip"),
		"BucketName":   "site-assets",
	} {
		if got[k].OutputValue != want {
			t.Errorf("Output %s = %q, want %q", k, got[k].OutputValue, want)
		}
	}
	om := omissionMap(rec)
	if !strings.Contains(om["PrivateIp"], "Fn::GetAtt Web.PrivateIp (AWS::EC2::Instance) does not resolve") {
		t.Errorf("an unsupported attribute must be omitted with its reason, got %q", om["PrivateIp"])
	}
	if !strings.Contains(om["GroupId"], "Ref WebSG (AWS::EC2::SecurityGroup) does not resolve") {
		t.Errorf("an unsupported Ref must be omitted with its reason, got %q", om["GroupId"])
	}
	for _, k := range []string{"PrivateIp", "GroupId"} {
		if _, has := got[k]; has {
			t.Errorf("an unresolvable Output must never carry a value: %+v", got[k])
		}
	}
	js, _ := json.Marshal(f.stored)
	if strings.Contains(string(js), "<ref:") || strings.Contains(string(js), "<Web.") {
		t.Fatalf("no placeholder may be persisted as an Output value: %s", js)
	}
}

// A supported attribute that is not populated yet (MetalLB has not assigned the IP) is waited for —
// resolved once it appears — and if it never does within the bound, the Output is omitted saying so.
func TestOutputs_LanIPPendingWaitsThenResolvesOrOmits(t *testing.T) {
	fastOutputs(t)
	tmpl := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref TestSG ] }
  TestSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: test }
  WebEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Web }
Outputs:
  Address: { Value: !Ref WebEip }
`
	// Appears on the third read.
	reads := 0
	f := &fakeApplier{}
	f.statusFn = func(key string) (map[string]any, bool) {
		if key != "VirtualMachine/s-web" {
			return nil, false
		}
		reads++
		if reads < 3 {
			return map[string]any{"lanIp": ""}, true
		}
		return map[string]any{"lanIp": "192.0.2.50"}, true
	}
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got := outputMap(rec)["Address"].OutputValue; got != "192.0.2.50" || reads < 3 {
		t.Fatalf("a pending LAN IP must be waited for (reads=%d), got %q", reads, got)
	}

	// Never assigned within the bound: omitted, saying it was not assigned.
	never := &fakeApplier{statusFn: func(key string) (map[string]any, bool) { return map[string]any{}, true }}
	opts := deployOpts()
	opts.Timeout = 50 * time.Millisecond
	rec, err = Deploy(context.Background(), []byte(tmpl), opts, never)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, has := outputMap(rec)["Address"]; has {
		t.Fatalf("an unassigned LAN IP must not produce an Output value: %+v", rec.Outputs)
	}
	if r := omissionMap(rec)["Address"]; !strings.Contains(r, "LAN IP was not assigned before the stack completed") {
		t.Fatalf("the omission must say the LAN IP was not assigned, got %q", r)
	}
	if rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("an omitted Output does not fail the stack: %s", rec.Status)
	}
}

// An Output mixing a still-unassigned LAN IP with an attribute that never resolves is not waited for (it
// could never resolve), and its reason names both references.
func TestOutputs_MixedPendingAndUnsupportedNotWaited(t *testing.T) {
	tmpl := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref TestSG ] }
  TestSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: test }
  WebEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Web }
Outputs:
  Both: { Value: !Sub "${WebEip}/${Web.PrivateIp}" }
`
	f := &fakeApplier{statusFn: func(string) (map[string]any, bool) { return map[string]any{}, true }}
	start := time.Now()
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("an Output that can never resolve must not be polled for (took %s)", time.Since(start))
	}
	r := omissionMap(rec)["Both"]
	if !strings.Contains(r, "Fn::GetAtt Web.PrivateIp (AWS::EC2::Instance) does not resolve") || !strings.Contains(r, "LAN IP was not assigned") {
		t.Fatalf("the reason must name both references, got %q", r)
	}
}

// An instance that is NOT exposed has no LAN IP: GetAtt PublicIp is omitted (not waited for).
func TestOutputs_UnexposedInstancePublicIpOmitted(t *testing.T) {
	tmpl := `
Resources:
  Db:
    Type: AWS::EC2::Instance
    Properties: { ImageId: debian-12 }
Outputs:
  DbIp: { Value: !GetAtt Db.PublicIp }
`
	f := &fakeApplier{}
	start := time.Now()
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if r := omissionMap(rec)["DbIp"]; !strings.Contains(r, "not exposed") {
		t.Fatalf("an unexposed instance's PublicIp must be omitted as not exposed, got %q", r)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("a definitive miss must not be polled for (took %s)", time.Since(start))
	}
}

// Without a StatusReader (an Applier that can't read live status) a post-deploy attribute is omitted
// with that reason; template-determined Outputs still resolve.
func TestOutputs_NoStatusReader(t *testing.T) {
	type applierOnly struct{ Applier }
	tmpl := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref TestSG ] }
  TestSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: test }
  WebEip:
    Type: AWS::EC2::EIP
    Properties: { InstanceId: !Ref Web }
Outputs:
  Address: { Value: !Ref WebEip }
  Name:    { Value: !Ref AWS::StackName }
`
	rec, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), applierOnly{&fakeApplier{}})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if outputMap(rec)["Name"].OutputValue != "s" {
		t.Errorf("a template-determined Output resolves without status: %+v", rec.Outputs)
	}
	if r := omissionMap(rec)["Address"]; !strings.Contains(r, "cannot read") {
		t.Errorf("with no StatusReader the LAN IP Output is omitted saying so, got %q", r)
	}
}

// Fn::ImportValue resolves from the supplied exports, and the stack records which exports it imports.
func TestOutputs_ImportValueAndImports(t *testing.T) {
	tmpl := `
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: !ImportValue shared-KeyDescription }
Outputs:
  Upstream: { Value: !ImportValue net-Address }
`
	opts := deployOpts()
	opts.Exports = map[string]string{"net-Address": "192.0.2.60", "shared-KeyDescription": "k"}
	rec, err := Deploy(context.Background(), []byte(tmpl), opts, &fakeApplier{})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if outputMap(rec)["Upstream"].OutputValue != "192.0.2.60" {
		t.Errorf("an imported value must flow into the Output: %+v", rec.Outputs)
	}
	if strings.Join(rec.Imports, ",") != "net-Address,shared-KeyDescription" {
		t.Errorf("the stack must record the exports it imports, got %v", rec.Imports)
	}
}

// A custom resource's returned Data resolves an Output's Fn::GetAtt (interleaved deploy).
func TestOutputs_CustomResourceData(t *testing.T) {
	tmpl := `
Resources:
  Fn:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: ghcr.io/x/handler:latest } }
  Setup:
    Type: Custom::Setup
    Properties: { ServiceToken: !GetAtt Fn.Arn }
Outputs:
  Endpoint: { Value: !GetAtt Setup.Endpoint }
`
	opts := deployOpts()
	opts.Invoke = func(_ context.Context, _, _ string, _ []byte) (map[string]any, error) {
		return map[string]any{"Status": "SUCCESS", "Data": map[string]any{"Endpoint": "https://computed.example"}}, nil
	}
	rec, err := Deploy(context.Background(), []byte(tmpl), opts, &fakeApplier{})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if outputMap(rec)["Endpoint"].OutputValue != "https://computed.example" {
		t.Fatalf("custom-resource Data must resolve the Output: %+v / %+v", rec.Outputs, rec.OutputsOmitted)
	}
}

// Update: the new template's Outputs replace the old; an Outputs-only change is an update
// (UPDATE_COMPLETE); a true no-op writes nothing.
func TestOutputs_UpdateRefreshes(t *testing.T) {
	v1 := `
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: k }
Outputs:
  Version: { Value: one }
`
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), []byte(v1), deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	n := len(f.applied)
	if rec, err := Update(context.Background(), []byte(v1), deployOpts(), f); err != nil || rec.Status != "CREATE_COMPLETE" || len(f.applied) != n {
		t.Fatalf("a true no-op update writes nothing: status=%v err=%v writes=%d", rec.Status, err, len(f.applied)-n)
	}
	v2 := strings.Replace(v1, "Value: one", "Value: two", 1)
	rec, err := Update(context.Background(), []byte(v2), deployOpts(), f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if rec.Status != "UPDATE_COMPLETE" || outputMap(rec)["Version"].OutputValue != "two" || f.stored.Outputs[0].OutputValue != "two" {
		t.Fatalf("an Outputs-only change must update the stored Outputs: %+v", f.stored)
	}
	v3 := strings.Replace(v2, "Description: k", "Description: k2", 1)
	v3 = strings.Replace(v3, "Value: two", "Value: three", 1)
	if rec, err = Update(context.Background(), []byte(v3), deployOpts(), f); err != nil || outputMap(rec)["Version"].OutputValue != "three" {
		t.Fatalf("a resource update must re-evaluate Outputs: %+v err=%v", rec, err)
	}
}

// TemplateExportNames returns the statically-resolvable export names (what a front door checks for a
// collision before deploying); a conditioned-off Output's export is not one.
func TestTemplateExportNames(t *testing.T) {
	tmpl := `
Parameters:
  Env: { Type: String, Default: prod }
Conditions:
  Never: !Equals [ a, b ]
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties: { Description: k }
Outputs:
  A: { Value: x, Export: { Name: !Sub "${Env}-A" } }
  B: { Value: y }
  C: { Value: z, Condition: Never, Export: { Name: never-exported } }
`
	names, err := TemplateExportNames([]byte(tmpl), nil, nil, "s")
	if err != nil || strings.Join(names, ",") != "prod-A" {
		t.Fatalf("want [prod-A], got %v (%v)", names, err)
	}
}
