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
// and the exposed instance's PublicIp -> the VM's status.lanIp, its PrivateIp -> status.ip; a bucket's
// and a security group's Ref are their names (what another stack can pass back in).
func TestOutputs_DeployedAttributes(t *testing.T) {
	f := &fakeApplier{liveStatus: map[string]map[string]any{
		"VirtualMachine/s-web": {"lanIp": "192.0.2.40", "ip": "198.51.100.7"},
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
		"PrivateIp":    "198.51.100.7",
		"GroupId":      "s-websg",
	} {
		if got[k].OutputValue != want {
			t.Errorf("Output %s = %q, want %q", k, got[k].OutputValue, want)
		}
	}
	if len(rec.OutputsOmitted) != 0 {
		t.Errorf("every Output resolves: omitted %v", rec.OutputsOmitted)
	}
	js, _ := json.Marshal(f.stored)
	if strings.Contains(string(js), "<ref:") || strings.Contains(string(js), "<Web.") {
		t.Fatalf("no placeholder may be persisted as an Output value: %s", js)
	}
	// Each resource's physical id is its Ref.
	for _, r := range rec.Resources {
		if r.LogicalID == "Site" && r.PhysicalID != "site-assets" {
			t.Errorf("the bucket's physical id is its name, got %q", r.PhysicalID)
		}
		if r.LogicalID == "WebSG" && r.PhysicalID != "s-websg" {
			t.Errorf("the security group's physical id is its name, got %q", r.PhysicalID)
		}
	}
}

// An Output naming an attribute open-infra does not provide is refused at plan time — the stack is
// refused before anything is created, naming what the type does provide.
func TestOutputs_UnsupportedAttributeRefusedAtPlan(t *testing.T) {
	tmpl := `
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SecurityGroupIds: [ !Ref TestSG ] }
  TestSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: test }
Outputs:
  Dns: { Value: !Sub "${Web.PrivateDnsName}:443" }
  Ok:  { Value: !GetAtt Web.PrivateIp }
`
	plan, err := BuildPlan([]byte(tmpl), nil, "s")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan.Blockers, "\n")
	if plan.Verdict != Rejected || !strings.Contains(joined, "Output Dns: Fn::GetAtt Web.PrivateDnsName (AWS::EC2::Instance) does not resolve on open-infra") ||
		!strings.Contains(joined, "PrivateIp") {
		t.Fatalf("an unsupported attribute must refuse at plan, naming what is supported: %v", plan.Blockers)
	}
	if strings.Contains(joined, "Output Ok") {
		t.Fatalf("a supported attribute is not refused: %v", plan.Blockers)
	}
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f); err == nil || len(f.applied) != 0 {
		t.Fatalf("deploy must refuse before applying anything: err=%v applied=%v", err, f.applied)
	}
}

// A supported attribute that is not populated yet (MetalLB has not assigned the IP) is waited for —
// resolved once it appears — and if it never does within the bound, the create fails (rolled back),
// saying so: no stack completes with an Output missing.
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

	// Never assigned within the bound: the create fails and rolls back, saying the IP was not assigned.
	never := &fakeApplier{statusFn: func(key string) (map[string]any, bool) { return map[string]any{}, true }}
	opts := deployOpts()
	opts.Timeout = 50 * time.Millisecond
	rec, err = Deploy(context.Background(), []byte(tmpl), opts, never)
	if err == nil || !strings.Contains(err.Error(), "LAN IP was not assigned before the stack completed") {
		t.Fatalf("an Output that never resolves must fail the create, saying why: %v", err)
	}
	if rec.Status != "CREATE_FAILED" || len(never.deleted) == 0 {
		t.Fatalf("the failed create must be rolled back: status=%s deleted=%v", rec.Status, never.deleted)
	}
	if !hasEvent(rec, "s", "ROLLBACK_IN_PROGRESS") || !hasEvent(rec, "s", "CREATE_FAILED") {
		t.Fatalf("the stack's events must show the rollback: %+v", rec.Events)
	}
}

func hasEvent(rec *StackRecord, logicalID, status string) bool {
	for _, e := range rec.Events {
		if e.LogicalID == logicalID && e.Status == status {
			return true
		}
	}
	return false
}

// An Output whose value can never arrive (an unexposed instance's PublicIp) fails the create at once —
// a definitive miss is not polled for.
func TestOutputs_UnexposedInstancePublicIpFails(t *testing.T) {
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
	_, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "not exposed") {
		t.Fatalf("an unexposed instance's PublicIp must fail the create as not exposed, got %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("a definitive miss must not be polled for (took %s)", time.Since(start))
	}
}

// Without a StatusReader (an Applier that can't read live status) a post-deploy attribute cannot
// resolve, so the create fails saying so; a stack whose Outputs the template determines still completes.
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
	_, err := Deploy(context.Background(), []byte(tmpl), deployOpts(), applierOnly{&fakeApplier{}})
	if err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Errorf("with no StatusReader the LAN IP Output cannot resolve, and the create says so: %v", err)
	}
	static := strings.Replace(tmpl, "  Address: { Value: !Ref WebEip }\n", "", 1)
	rec, err := Deploy(context.Background(), []byte(static), deployOpts(), applierOnly{&fakeApplier{}})
	if err != nil || outputMap(rec)["Name"].OutputValue != "s" {
		t.Errorf("a template-determined Output resolves without status: %+v (%v)", rec, err)
	}
}

// A network stack's exports are what an app stack's translators accept back: the VPC and subnet ids are
// their names, so a SecurityGroup and an instance in the importing stack resolve them.
func TestOutputs_CrossStackNetworkExports(t *testing.T) {
	network := `
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.20.0.0/16 }
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Vpc, CidrBlock: 10.20.1.0/24 }
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties: { VpcId: !Ref Vpc, CidrBlock: 10.20.2.0/24 }
Outputs:
  VpcId:   { Value: !Ref Vpc, Export: { Name: !Sub "${AWS::StackName}-vpc" } }
  SubnetA: { Value: !Ref SubnetA, Export: { Name: !Sub "${AWS::StackName}-subnet-a" } }
  SubnetB: { Value: !GetAtt SubnetB.SubnetId, Export: { Name: !Sub "${AWS::StackName}-subnet-b" } }
  Cidr:    { Value: !GetAtt Vpc.CidrBlock }
`
	f := &fakeApplier{}
	opts := deployOpts()
	opts.StackName = "net"
	rec, err := Deploy(context.Background(), []byte(network), opts, f)
	if err != nil {
		t.Fatalf("network deploy: %v", err)
	}
	exports := map[string]string{}
	for _, o := range rec.Outputs {
		if o.ExportName != "" {
			exports[o.ExportName] = o.OutputValue
		}
	}
	if len(exports) != 3 || exports["net-vpc"] != "net-vpc" || exports["net-subnet-a"] != "net-subneta" || exports["net-subnet-b"] != "net-subnetb" {
		t.Fatalf("a network stack exports its VPC and both subnets (3 of 3): %v (omitted %v)", exports, rec.OutputsOmitted)
	}
	if outputMap(rec)["Cidr"].OutputValue != "10.20.0.0/16" {
		t.Errorf("a VPC's CidrBlock resolves: %+v", rec.Outputs)
	}

	app := `
Resources:
  AppSG:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: app, VpcId: !ImportValue net-vpc }
  App:
    Type: AWS::EC2::Instance
    Properties: { ImageId: ubuntu-24.04, SubnetId: !ImportValue net-subnet-a, SecurityGroupIds: [ !Ref AppSG ] }
`
	aopts := deployOpts()
	aopts.StackName = "app"
	aopts.Exports = exports
	if _, err := Deploy(context.Background(), []byte(app), aopts, &fakeApplier{}); err != nil {
		t.Fatalf("an app stack importing the network's exports must deploy: %v", err)
	}
}

// Every translated type's Ref and documented attributes resolve to a value: none is a placeholder, and an
// ARN is built from the stack's partition, region and account.
func TestResourceAttrs_EveryTypeResolves(t *testing.T) {
	tmpl := `
Resources:
  Bucket:   { Type: AWS::S3::Bucket, Properties: { BucketName: data-1 } }
  Queue:    { Type: AWS::SQS::Queue, Properties: { QueueName: jobs } }
  Fifo:     { Type: AWS::SQS::Queue, Properties: { FifoQueue: true } }
  Topic:    { Type: AWS::SNS::Topic, Properties: { TopicName: alerts } }
  Param:    { Type: AWS::SSM::Parameter, Properties: { Name: /app/flag, Type: String, Value: "on" } }
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: orders
      AttributeDefinitions: [ { AttributeName: id, AttributeType: S } ]
      KeySchema: [ { AttributeName: id, KeyType: HASH } ]
      BillingMode: PAY_PER_REQUEST
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [ { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole } ] }
Outputs:
  BucketArn:    { Value: !GetAtt Bucket.Arn }
  BucketRegion: { Value: !GetAtt Bucket.RegionalDomainName }
  QueueUrl:     { Value: !Ref Queue }
  QueueArn:     { Value: !GetAtt Queue.Arn }
  FifoName:     { Value: !GetAtt Fifo.QueueName }
  TopicArn:     { Value: !Ref Topic }
  ParamName:    { Value: !Ref Param }
  ParamValue:   { Value: !GetAtt Param.Value }
  TableArn:     { Value: !GetAtt Table.Arn }
  RoleArn:      { Value: !GetAtt Role.Arn }
`
	opts := deployOpts()
	opts.Caps.SQSURLBase = "https://shim.example:4566" // the queue URL base, even for a queue the SQS store does not serve
	rec, err := Deploy(context.Background(), []byte(tmpl), opts, &fakeApplier{})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	got := outputMap(rec)
	ps := pseudoParams("s")
	region, acct := ps["AWS::Region"].(string), ps["AWS::AccountId"].(string)
	for k, want := range map[string]string{
		"BucketArn":    "arn:aws:s3:::data-1",
		"BucketRegion": "data-1.s3." + region + ".amazonaws.com",
		"QueueUrl":     "https://shim.example:4566/" + acct + "/jobs",
		"QueueArn":     "arn:aws:sqs:" + region + ":" + acct + ":jobs",
		"FifoName":     "s-fifo", // the kind: Queue's name, as an imported policy's queue ARN names it
		"TopicArn":     "arn:aws:sns:" + region + ":" + acct + ":alerts",
		"ParamName":    "/app/flag",
		"ParamValue":   "on",
		"TableArn":     "arn:aws:dynamodb:" + region + ":" + acct + ":table/orders",
		"RoleArn":      "arn:aws:iam::" + acct + ":role/s-role",
	} {
		if got[k].OutputValue != want {
			t.Errorf("Output %s = %q, want %q", k, got[k].OutputValue, want)
		}
	}
	// Every registered type's every attribute is a function that never returns a placeholder.
	for typ, ta := range resourceAttrs {
		if ta.ref == nil && len(ta.attrs) == 0 {
			t.Errorf("%s is registered with nothing", typ)
		}
	}
}

// With the SQS, SNS, SSM and KMS stores serving a stack's resources, every Ref and attribute an Output
// names is the value that store holds (what the translator created the resource under), and each
// resource's physical id is its Ref.
func TestOutputs_ServiceBackedResources(t *testing.T) {
	withFixedKeyIDs(t)
	tmpl := `
Resources:
  Q: { Type: AWS::SQS::Queue }
  T: { Type: AWS::SNS::Topic }
  S: { Type: AWS::SNS::Subscription, Properties: { TopicArn: !Ref T, Protocol: sqs, Endpoint: !GetAtt Q.Arn } }
  P: { Type: AWS::SSM::Parameter, Properties: { Type: String, Value: hello } }
  K: { Type: AWS::KMS::Key }
  A: { Type: AWS::KMS::Alias, Properties: { AliasName: alias/app, TargetKeyId: !Ref K } }
Outputs:
  QueueUrl:  { Value: !Ref Q }
  QueueUrl2: { Value: !GetAtt Q.QueueUrl }
  QueueArn:  { Value: !GetAtt Q.Arn }
  QueueName: { Value: !GetAtt Q.QueueName }
  TopicArn:  { Value: !Ref T }
  TopicName: { Value: !GetAtt T.TopicName }
  SubArn:    { Value: !Ref S }
  ParamName: { Value: !Ref P }
  ParamType: { Value: !GetAtt P.Type }
  KeyId:     { Value: !Ref K }
  KeyId2:    { Value: !GetAtt K.KeyId }
  KeyArn:    { Value: !GetAtt K.Arn }
  Alias:     { Value: !Ref A }
`
	opts := DeployOptions{StackName: "st", Namespace: "open-infra-cfn", Caps: svcCaps}
	rec, err := Deploy(context.Background(), []byte(tmpl), opts, &fakeApplier{})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	byKind := map[string]StackResource{}
	byID := map[string]StackResource{}
	for _, r := range rec.Resources {
		byID[r.LogicalID] = r
		if r.APIVersion == ServiceAPIVersion {
			byKind[r.Kind] = r
		}
	}
	q, tp, s, p := byKind[KindSQSQueue], byKind[KindSNSTopic], byKind[KindSNSSubscription], byKind[KindSSMParameter]
	got := outputMap(rec)
	for k, want := range map[string]string{
		"QueueUrl": q.Spec["url"].(string), "QueueUrl2": q.Spec["url"].(string),
		"QueueArn": "arn:aws:sqs:us-east-1:000000000000:" + q.Name, "QueueName": q.Name,
		"TopicArn": tp.Spec["topicArn"].(string), "TopicName": tp.Name,
		"SubArn":    s.Spec["subscriptionArn"].(string),
		"ParamName": p.Name, "ParamType": "String",
		"KeyId": fixedKeyID, "KeyId2": fixedKeyID, "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/" + fixedKeyID,
		"Alias": "alias/app",
	} {
		if got[k].OutputValue != want {
			t.Errorf("Output %s = %q, want %q (the store's value)", k, got[k].OutputValue, want)
		}
	}
	if !strings.HasPrefix(q.Spec["url"].(string), svcCaps.SQSURLBase+"/") {
		t.Errorf("queue URL %v is not on SQS_QUEUE_URL_BASE", q.Spec["url"])
	}
	for id, want := range map[string]string{"Q": q.Spec["url"].(string), "T": tp.Spec["topicArn"].(string), "P": p.Name, "K": fixedKeyID} {
		if byID[id].PhysicalID != want {
			t.Errorf("%s physical id = %q, want %q", id, byID[id].PhysicalID, want)
		}
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
