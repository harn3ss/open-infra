package cfn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// fakePackages is a PackageStore that records what it was asked to store.
type fakePackages struct {
	stored []*CodePackage
	err    error
}

func (p *fakePackages) Store(_ context.Context, ns string, pkg *CodePackage) (StoredPackage, error) {
	if p.err != nil {
		return StoredPackage{}, p.err
	}
	p.stored = append(p.stored, pkg)
	h := sha256.Sum256([]byte(ns + "|" + pkg.Origin() + "|" + fmt.Sprint(pkg.Inline)))
	return StoredPackage{SHA256: hex.EncodeToString(h[:]), Size: 321}, nil
}

const zipRoleYAML = `
  Exec:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement: [{Effect: Allow, Principal: {Service: lambda.amazonaws.com}, Action: sts:AssumeRole}]
`

func zipTemplate(fn string) []byte {
	return []byte("AWSTemplateFormatVersion: \"2010-09-09\"\nResources:" + zipRoleYAML + fn)
}

const inlineNodeFn = `
  Hello:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Role: !GetAtt Exec.Arn
      Code:
        ZipFile: |
          exports.handler = async (event) => ({ hello: event.name });
`

const s3PythonFn = `
  Hello:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: app.handler
      Role: !GetAtt Exec.Arn
      Code:
        S3Bucket: deploy-artifacts
        S3Key: hello/abc123.zip
        S3ObjectVersion: "3"
`

func appliedSpec(t *testing.T, f *fakeApplier, id string) map[string]any {
	t.Helper()
	y, ok := f.raw[id]
	if !ok {
		t.Fatalf("%s was not applied; applied: %v", id, f.applied)
	}
	var m map[string]any
	if err := yaml.Unmarshal(y, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func functionCode(t *testing.T, f *fakeApplier) (map[string]any, map[string]any) {
	t.Helper()
	m := appliedSpec(t, f, "Function/s-hello")
	spec, _ := m["spec"].(map[string]any)
	code, _ := spec["code"].(map[string]any)
	src, _ := code["source"].(map[string]any)
	return code, src
}

// Inline Node.js code (Code.ZipFile) plans PROVISIONABLE and deploys as a stored package: CloudFormation's
// index.js, handler index.handler, with the in-stack execution role.
func TestLambdaZip_InlineNodeIsAStoredPackage(t *testing.T) {
	tmpl := zipTemplate(inlineNodeFn)
	caps := Capabilities{LambdaPackageStore: true}
	plan, err := BuildPlanForStack(tmpl, nil, nil, "s", "", caps)
	if err != nil || plan.Verdict == Rejected {
		t.Fatalf("plan: %v %v", err, plan.Blockers)
	}
	store := &fakePackages{}
	opts := deployOpts()
	opts.Caps, opts.Packages = caps, store
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), tmpl, opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(store.stored) != 1 || store.stored[0].Inline["index.js"] != "exports.handler = async (event) => ({ hello: event.name });\n" {
		t.Fatalf("the inline code must be stored as index.js: %#v", store.stored)
	}
	code, src := functionCode(t, f)
	if code["runtime"] != "nodejs22" || code["handler"] != "index.handler" {
		t.Errorf("spec.code: %#v", code)
	}
	pkg, _ := src["package"].(map[string]any)
	if len(fmt.Sprint(pkg["sha256"])) != 64 || pkg["origin"] != "inline" || src["configMap"] != nil {
		t.Errorf("spec.code.source must be the stored package: %#v", src)
	}
	spec := appliedSpec(t, f, "Function/s-hello")["spec"].(map[string]any)
	if spec["role"] != "s-exec" {
		t.Errorf("the execution role must map: %#v", spec["role"])
	}
	for id := range f.raw {
		if strings.HasPrefix(id, "ConfigMap/") {
			t.Errorf("with a package store, no ConfigMap is applied (%s)", id)
		}
	}
}

// The CLI has no package store: inline code deploys as a ConfigMap of its source.
func TestLambdaZip_InlineOnTheCLIIsAConfigMap(t *testing.T) {
	tmpl := zipTemplate(inlineNodeFn)
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), tmpl, deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	_, src := functionCode(t, f)
	if src["configMap"] != "s-hello-code" {
		t.Fatalf("spec.code.source must name the ConfigMap: %#v", src)
	}
	cm := appliedSpec(t, f, "ConfigMap/s-hello-code")
	data, _ := cm["data"].(map[string]any)
	if !strings.Contains(fmt.Sprint(data["index.js"]), "exports.handler") || cm["spec"] != nil {
		t.Fatalf("the ConfigMap must hold index.js as data: %#v", cm)
	}
}

// Python inline code is CloudFormation's index.py.
func TestLambdaZip_InlinePythonIsIndexPy(t *testing.T) {
	fn := strings.NewReplacer("nodejs22.x", "python3.13", "exports.handler = async (event) => ({ hello: event.name });", "def handler(event, context):\n            return {'hello': event['name']}").Replace(inlineNodeFn)
	store := &fakePackages{}
	opts := deployOpts()
	opts.Caps, opts.Packages = Capabilities{LambdaPackageStore: true}, store
	if _, err := Deploy(context.Background(), zipTemplate(fn), opts, &fakeApplier{}); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(store.stored) != 1 || !strings.Contains(store.stored[0].Inline["index.py"], "def handler") {
		t.Fatalf("python inline code must be index.py: %#v", store.stored)
	}
}

// Inline code that loads CloudFormation's response module gets open-infra's beside it, as AWS provides its
// own for Code.ZipFile: cfn-response.js for Node.js, cfnresponse.py for Python. Code that does not load it
// is stored exactly as written, so its package does not change.
func TestLambdaZip_InlineCfnResponseGetsTheModule(t *testing.T) {
	cases := []struct{ runtime, src, file, mustHave string }{
		{"nodejs22.x", "const response = require('cfn-response'); exports.handler = (e, c) => response.send(e, c, response.SUCCESS, {});", "cfn-response.js", "exports.send = function (event, context, responseStatus"},
		{"python3.12", "import cfnresponse\n          def handler(e, c):\n              cfnresponse.send(e, c, cfnresponse.SUCCESS, {})", "cfnresponse.py", "def send(event, context, responseStatus"},
	}
	for _, c := range cases {
		fn := strings.NewReplacer("nodejs22.x", c.runtime, "exports.handler = async (event) => ({ hello: event.name });", c.src).Replace(inlineNodeFn)
		plan, err := BuildPlanForStack(zipTemplate(fn), nil, nil, "s", "", Capabilities{LambdaPackageStore: true})
		if err != nil || plan.Verdict == Rejected {
			t.Fatalf("%s: inline cfn-response code must plan: %v %v", c.runtime, err, plan.Blockers)
		}
		store := &fakePackages{}
		opts := deployOpts()
		opts.Caps, opts.Packages = Capabilities{LambdaPackageStore: true}, store
		if _, err := Deploy(context.Background(), zipTemplate(fn), opts, &fakeApplier{}); err != nil {
			t.Fatalf("%s: deploy: %v", c.runtime, err)
		}
		if len(store.stored) != 1 || !strings.Contains(store.stored[0].Inline[c.file], c.mustHave) {
			t.Fatalf("%s: the package must carry %s: %v", c.runtime, c.file, store.stored)
		}
	}
	store := &fakePackages{}
	opts := deployOpts()
	opts.Caps, opts.Packages = Capabilities{LambdaPackageStore: true}, store
	if _, err := Deploy(context.Background(), zipTemplate(inlineNodeFn), opts, &fakeApplier{}); err != nil {
		t.Fatal(err)
	}
	if len(store.stored[0].Inline) != 1 {
		t.Fatalf("code that does not load cfn-response is stored alone: %v", store.stored[0].Inline)
	}
}

// Code.S3Bucket/S3Key is read at deploy (the store reads it with the caller's authority) and recorded by
// its origin; an update with the same location keeps it without reading S3 again, as CloudFormation does,
// and a new key reads it.
func TestLambdaZip_S3PackageStoredOnceForItsLocation(t *testing.T) {
	tmpl := zipTemplate(s3PythonFn)
	store := &fakePackages{}
	opts := deployOpts()
	opts.Caps, opts.Packages = Capabilities{LambdaPackageStore: true}, store
	f := &fakeApplier{}
	if _, err := Deploy(context.Background(), tmpl, opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if len(store.stored) != 1 || store.stored[0].S3Bucket != "deploy-artifacts" || store.stored[0].S3Key != "hello/abc123.zip" || store.stored[0].S3Version != "3" {
		t.Fatalf("the S3 package must be stored by its location: %#v", store.stored)
	}
	code, src := functionCode(t, f)
	if code["runtime"] != "python3.12" || code["handler"] != "app.handler" {
		t.Errorf("spec.code: %#v", code)
	}
	if pkg, _ := src["package"].(map[string]any); pkg["origin"] != "s3://deploy-artifacts/hello/abc123.zip?versionId=3" {
		t.Errorf("origin: %#v", src)
	}
	tmpl2 := []byte(strings.Replace(string(tmpl), "Timeout", "Timeout", 1) + "      MemorySize: 256\n")
	if _, err := Update(context.Background(), tmpl2, opts, f); err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(store.stored) != 1 {
		t.Fatalf("an unchanged S3 location must not be read again: %d stores", len(store.stored))
	}
	tmpl3 := []byte(strings.Replace(string(tmpl2), "abc123", "def456", 1))
	if _, err := Update(context.Background(), tmpl3, opts, f); err != nil {
		t.Fatalf("update: %v", err)
	}
	if len(store.stored) != 2 || store.stored[1].S3Key != "hello/def456.zip" {
		t.Fatalf("a new key must be read: %#v", store.stored)
	}
}

// Without a package store (the CLI), an S3 package refuses at plan, naming the front door.
func TestLambdaZip_S3PackageNeedsTheFrontDoor(t *testing.T) {
	plan, err := BuildPlanForStack(zipTemplate(s3PythonFn), nil, nil, "s", "", Capabilities{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Verdict != Rejected || !strings.Contains(strings.Join(plan.Blockers, "\n"), "aws-shim CloudFormation front door") {
		t.Fatalf("an S3 package without a store must refuse at plan: %s %v", plan.Verdict, plan.Blockers)
	}
}

// What a zip Lambda refuses, with the reason AWS would give or the supported list.
func TestLambdaZip_Refusals(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"unsupported runtime", "nodejs22.x", "nodejs14.x", "the supported runtimes are nodejs16.x, nodejs18.x, nodejs20.x, nodejs22.x, nodejs24.x, python3.8, python3.9, python3.10, python3.11, python3.12, python3.13, python3.14 and dotnet8"},
		{"provided runtime", "nodejs22.x", "provided.al2023", "is not a runtime open-infra runs"},
		{"no runtime", "      Runtime: nodejs22.x\n", "", "Runtime is required"},
		{"handler not index", "Handler: index.handler", "Handler: app.handler", "must start with index."},
		{"zipfile for dotnet", "nodejs22.x", "dotnet8", "Code.ZipFile is for Node.js and Python functions"},
		{"zipfile and bucket", "      Code:\n", "      Code:\n        S3Bucket: b\n        S3Key: k\n", "both ZipFile and S3Bucket"},
		{"layers", "      Runtime: nodejs22.x\n", "      Runtime: nodejs22.x\n      Layers: [arn:aws:lambda:us-east-1:123456789012:layer:x:1]\n", "Layers are not supported"},
		{"image with runtime", "      Runtime: nodejs22.x\n", "      Runtime: nodejs22.x\n      PackageType: Image\n", "applies to a .zip deployment package"},
	}
	for _, c := range cases {
		fn := strings.Replace(inlineNodeFn, c.from, c.to, 1)
		plan, err := BuildPlanForStack(zipTemplate(fn), nil, nil, "s", "", Capabilities{LambdaPackageStore: true})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if plan.Verdict != Rejected || !strings.Contains(strings.Join(plan.Blockers, "\n"), c.want) {
			t.Errorf("%s: want a refusal naming %q, got %s %v", c.name, c.want, plan.Verdict, plan.Blockers)
		}
	}
}

// A PackageType: Image function is unchanged.
func TestLambdaZip_ImageUnchanged(t *testing.T) {
	fn := `
  Hello:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: Image
      Role: !GetAtt Exec.Arn
      Code: { ImageUri: "ghcr.io/me/hello:1" }
`
	f := &fakeApplier{}
	opts := deployOpts()
	opts.Caps, opts.Packages = Capabilities{LambdaPackageStore: true}, &fakePackages{}
	if _, err := Deploy(context.Background(), zipTemplate(fn), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	spec := appliedSpec(t, f, "Function/s-hello")["spec"].(map[string]any)
	if spec["image"] != "ghcr.io/me/hello:1" || spec["code"] != nil {
		t.Fatalf("an image function maps to spec.image alone: %#v", spec)
	}
}

// A store that fails stops the deploy before anything is applied.
func TestLambdaZip_StoreFailureAppliesNothing(t *testing.T) {
	opts := deployOpts()
	opts.Caps, opts.Packages = Capabilities{LambdaPackageStore: true}, &fakePackages{err: fmt.Errorf("access denied reading s3://deploy-artifacts/hello/abc123.zip")}
	f := &fakeApplier{}
	_, err := Deploy(context.Background(), zipTemplate(s3PythonFn), opts, f)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("a failed package read must fail the deploy: %v", err)
	}
	for _, a := range f.applied {
		if strings.HasPrefix(a, "Function/") {
			t.Fatalf("nothing may be applied: %v", f.applied)
		}
	}
}

// A ConfigMap reports no readiness: the CLI's inline-code ConfigMap is complete once applied, and the
// deploy does not wait on it (a live `cfn deploy` timed out on it before this).
func TestLambdaZip_TheCLIsConfigMapIsNotWaitedOn(t *testing.T) {
	f := &fakeApplier{notReady: "s-hello-code"}
	if _, err := Deploy(context.Background(), zipTemplate(inlineNodeFn), deployOpts(), f); err != nil {
		t.Fatalf("the inline-code ConfigMap must not be waited on: %v", err)
	}
}

// A stack with a custom resource is created resource by resource (deployInterleaved): its zip Lambdas'
// packages are stored there too, so a custom resource's inline handler (cfn-response) has its code.
func TestLambdaZip_InterleavedStackStoresThePackage(t *testing.T) {
	tmpl := zipTemplate(`
  Handler:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs22.x
      Handler: index.handler
      Role: !GetAtt Exec.Arn
      Code:
        ZipFile: |
          var response = require('cfn-response');
          exports.handler = function (e, c) { response.send(e, c, response.SUCCESS, { A: '1' }); };
  Setup:
    Type: Custom::Setup
    Properties: { ServiceToken: !GetAtt Handler.Arn }
`)
	store := &fakePackages{}
	opts := deployOpts()
	opts.Caps, opts.Packages = Capabilities{LambdaPackageStore: true}, store
	opts.Invoke = func(context.Context, string, string, []byte) (map[string]any, error) {
		return map[string]any{"Status": "SUCCESS", "Data": map[string]any{"A": "1"}}, nil
	}
	f := &fakeApplier{}
	rec, err := Deploy(context.Background(), tmpl, opts, f)
	if err != nil || rec.Status != "CREATE_COMPLETE" {
		t.Fatalf("deploy: %v %v", err, rec)
	}
	if len(store.stored) != 1 || store.stored[0].Inline["cfn-response.js"] == "" {
		t.Fatalf("the handler's package (with cfn-response) must be stored: %#v", store.stored)
	}
	m := appliedSpec(t, f, "Function/s-handler")
	spec, _ := m["spec"].(map[string]any)
	code, _ := spec["code"].(map[string]any)
	src, _ := code["source"].(map[string]any)
	if pkg, _ := src["package"].(map[string]any); len(fmt.Sprint(pkg["sha256"])) != 64 {
		t.Fatalf("the handler's spec.code.source must name its stored package: %#v", code)
	}
}
