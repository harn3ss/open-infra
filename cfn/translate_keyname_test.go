package cfn

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const keyNameTmpl = `
Parameters:
  Key: { Type: AWS::EC2::KeyPair::KeyName, Default: ops }
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      InstanceType: t3.small
      KeyName: !Ref Key
      Tags: [ { Key: Name, Value: web }, { Key: tier, Value: api } ]
`

const opsKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOqR0Jm8b2Y2c6JkqfQm0R0nq0nKc1pV0b9b1o0tK3Yv ops@example"

// #347 item 24: an instance's KeyName carries the named key pair's public key (an imported EC2 key pair the
// deploying environment holds) into the VM's spec.sshKey; a key pair it does not hold refuses, as AWS's
// InvalidKeyPair.NotFound; a deploy path that cannot read key pairs keeps it a caveat.
func TestTranslate_EC2Instance_KeyName(t *testing.T) {
	ctx := ctxWithParams(t, keyNameTmpl, nil)
	ctx.caps.KeyPairs = map[string]string{"ops": opsKey + "\n"}
	m, fs := translatorFor("AWS::EC2::Instance")("Web", ecsResolvedService(t, ctx, "Web"), ctx)
	if len(fs) != 0 || m.Spec["sshKey"] != opsKey {
		t.Fatalf("KeyName ops must become spec.sshKey %q: sshKey=%v findings=%v", opsKey, m.Spec["sshKey"], fs)
	}

	ctx = ctxWithParams(t, keyNameTmpl, map[string]string{"Key": "missing"})
	ctx.caps.KeyPairs = map[string]string{"ops": opsKey}
	_, fs = translatorFor("AWS::EC2::Instance")("Web", ecsResolvedService(t, ctx, "Web"), ctx)
	if len(fs) != 1 || !strings.Contains(fs[0].Reason, "InvalidKeyPair.NotFound") {
		t.Fatalf("a key pair that does not exist must refuse: %v", fs)
	}

	ctx = ctxWithParams(t, keyNameTmpl, nil) // no key-pair store (the CLI)
	m, fs = translatorFor("AWS::EC2::Instance")("Web", ecsResolvedService(t, ctx, "Web"), ctx)
	if len(fs) != 0 || m.Spec["sshKey"] != nil || !strings.Contains(strings.Join(m.Caveats, " "), "KeyName ops") {
		t.Fatalf("without the key-pair store KeyName is a caveat: sshKey=%v caveats=%v findings=%v", m.Spec["sshKey"], m.Caveats, fs)
	}
}

// The instance's AWS view (its tags, the tags a stack adds, its type and key pair) rides on the VM as an
// annotation for the aws-shim's EC2 API, and reaches the applied object.
func TestTranslate_EC2Instance_AWSView(t *testing.T) {
	ctx := ctxWithParams(t, keyNameTmpl, nil)
	ctx.caps.KeyPairs = map[string]string{"ops": opsKey}
	m, _ := translatorFor("AWS::EC2::Instance")("Web", ecsResolvedService(t, ctx, "Web"), ctx)
	v := ParseAWSView(m.Annotations)
	if v.InstanceType != "t3.small" || v.KeyName != "ops" || v.Tags["Name"] != "web" || v.Tags["tier"] != "api" ||
		v.Tags["aws:cloudformation:stack-name"] != "s" || v.Tags["aws:cloudformation:logical-id"] != "Web" ||
		!strings.HasPrefix(v.Tags["aws:cloudformation:stack-id"], "arn:aws:cloudformation:") {
		t.Fatalf("view = %+v", v)
	}
	y, err := renderManifest(m, deployOpts())
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	_ = yaml.Unmarshal(y, &obj)
	ann, _ := obj["metadata"].(map[string]any)["annotations"].(map[string]any)
	if s, _ := ann[AWSViewAnnotation].(string); s == "" || !strings.Contains(s, `"keyName":"ops"`) {
		t.Fatalf("the rendered VM must carry the view annotation: %v", obj["metadata"])
	}
	// A template tag cannot pose as one of AWS's own.
	ctx = ctxWithParams(t, strings.Replace(keyNameTmpl, "Key: tier", "Key: aws:cloudformation:stack-name", 1), nil)
	m, _ = translatorFor("AWS::EC2::Instance")("Web", ecsResolvedService(t, ctx, "Web"), ctx)
	if v := ParseAWSView(m.Annotations); v.Tags["aws:cloudformation:stack-name"] != "s" {
		t.Fatalf("an aws: tag in the template must not override the stack's: %+v", v)
	}
}

// A security group, VPC and volume record what their kinds do not model.
func TestTranslate_EC2_AWSViewOtherTypes(t *testing.T) {
	tmpl := `
Resources:
  Net:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: 10.20.0.0/16, Tags: [ { Key: Name, Value: main } ] }
  Web:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: web tier, GroupName: web-sg }
  Data:
    Type: AWS::EC2::Volume
    Properties: { Size: 10, VolumeType: gp3, AvailabilityZone: us-east-1a }
`
	ctx := ctxWithParams(t, tmpl, nil)
	for id, check := range map[string]func(AWSView) bool{
		"Net":  func(v AWSView) bool { return v.CidrBlock == "10.20.0.0/16" && v.Tags["Name"] == "main" },
		"Web":  func(v AWSView) bool { return v.GroupName == "web-sg" && v.GroupDescription == "web tier" },
		"Data": func(v AWSView) bool { return v.VolumeType == "gp3" },
	} {
		m, fs := translatorFor(ctx.template.Resources[id].Type)(id, ecsResolvedService(t, ctx, id), ctx)
		if m == nil || !check(ParseAWSView(m.Annotations)) {
			t.Errorf("%s: view = %+v (findings %v)", id, ParseAWSView(m.Annotations), fs)
		}
	}
}

// A catalog OS's own image id (what describe-images lists and the guest's ami-id reports) is an ImageId.
func TestTranslate_EC2Instance_CatalogImageID(t *testing.T) {
	for _, os := range CatalogOSes() {
		if got, reason := resolveEC2Image(ImageIDForOS(os)); got != os || reason != "" {
			t.Errorf("ImageId %s (%s) = %q %q", ImageIDForOS(os), os, got, reason)
		}
	}
	if _, reason := resolveEC2Image("ami-0123456789abcdef0"); reason != "ami" {
		t.Errorf("another ami- id must still refuse")
	}
}

// The view annotation reaches the object a deploy applies.
func TestDeploy_AWSViewAnnotationApplied(t *testing.T) {
	f := &fakeApplier{}
	opts := deployOpts()
	opts.Caps.KeyPairs = map[string]string{"ops": opsKey}
	if _, err := Deploy(context.Background(), []byte(keyNameTmpl), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if f.liveSpecs["VirtualMachine/s-web"]["sshKey"] != opsKey {
		t.Fatalf("the deployed VM's sshKey = %v", f.liveSpecs["VirtualMachine/s-web"]["sshKey"])
	}
}
