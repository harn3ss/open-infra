package cfn

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

var s3BucketNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// One template deployed as two stacks in one namespace makes two sets of objects; neither stack
// touches the other's.
func TestNaming_TwoStacksFromOneTemplateDoNotCollide(t *testing.T) {
	f := &fakeApplier{}
	for _, stack := range []string{"dev", "prod"} {
		o := deployOpts()
		o.StackName = stack
		if _, err := Deploy(context.Background(), initialStack, o, f); err != nil {
			t.Fatalf("deploy %s: %v", stack, err)
		}
	}
	for _, want := range []string{"EncryptionKey/dev-keya", "EncryptionKey/dev-keyb", "EncryptionKey/prod-keya", "EncryptionKey/prod-keyb"} {
		if _, ok := f.liveSpecs[want]; !ok {
			t.Errorf("%s was not created; live: %v", want, keysOf(f.liveSpecs))
		}
	}
	if got := f.liveLabels["EncryptionKey/dev-keya"][labelStack]; got != "dev" {
		t.Errorf("dev's object was relabeled to %q", got)
	}
}

// An object of the same kind and name that another stack owns is never overwritten: the create fails,
// nothing of the other stack's is deleted, and its label is unchanged.
func TestNaming_AnotherStacksObjectIsRefused(t *testing.T) {
	f := &fakeApplier{liveLabels: map[string]map[string]string{"EncryptionKey/s-keyb": {labelStack: "other"}}}
	_, err := Deploy(context.Background(), initialStack, deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "belongs to stack other") {
		t.Fatalf("want a refusal naming the owning stack, got %v", err)
	}
	if contains(f.applied, "EncryptionKey/s-keyb") || contains(f.deleted, "EncryptionKey/s-keyb") {
		t.Fatalf("the other stack's object was touched: applied=%v deleted=%v", f.applied, f.deleted)
	}
	if f.liveLabels["EncryptionKey/s-keyb"][labelStack] != "other" {
		t.Fatal("the other stack's object was relabeled")
	}
}

// An existing object no stack created is refused the same way.
func TestNaming_UnmanagedObjectIsRefused(t *testing.T) {
	f := &fakeApplier{liveLabels: map[string]map[string]string{"EncryptionKey/s-keya": {}}}
	_, err := Deploy(context.Background(), initialStack, deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "no stack created it") {
		t.Fatalf("want a refusal, got %v", err)
	}
}

// A stack created before stack-qualified names keeps its resources' recorded names on update (renaming
// would orphan them); a resource the update adds is stack-qualified.
func TestNaming_ExistingStackKeepsRecordedNames(t *testing.T) {
	f := &fakeApplier{
		stored: &StackRecord{Name: "s", Namespace: "cfn-test", Status: "CREATE_COMPLETE", Resources: []StackResource{
			{LogicalID: "KeyA", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: "keya", Spec: map[string]any{"description": "a"}},
			{LogicalID: "KeyB", APIVersion: "openinfra.dev/v1", Kind: "EncryptionKey", Name: "keyb", Spec: map[string]any{"description": "b"}},
		}},
		liveLabels: map[string]map[string]string{
			"EncryptionKey/keya": {labelStack: "s"}, "EncryptionKey/keyb": {labelStack: "s"},
		},
		liveSpecs: map[string]map[string]any{
			"EncryptionKey/keya": {"description": "a"}, "EncryptionKey/keyb": {"description": "b"},
		},
	}
	rec, err := Update(context.Background(), updatedStack, deployOpts(), f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	names := map[string]string{}
	for _, r := range rec.Resources {
		names[r.LogicalID] = r.Name
	}
	if names["KeyA"] != "keya" {
		t.Errorf("KeyA was renamed to %q; an existing resource keeps its recorded name", names["KeyA"])
	}
	if names["KeyC"] != "s-keyc" {
		t.Errorf("the added KeyC is named %q, want s-keyc", names["KeyC"])
	}
	if !contains(f.applied, "EncryptionKey/keya") || contains(f.applied, "EncryptionKey/s-keya") {
		t.Errorf("KeyA must be modified in place: applied=%v", f.applied)
	}
}

// Generated names are deterministic, unique per (stack, logical id), at most maxPhysNameLen, valid
// Kubernetes names, and valid S3 bucket names (a bucket's default name is its kind's name).
func TestNaming_StackQualifiedNameShape(t *testing.T) {
	cases := [][2]string{
		{"s", "KeyA"}, {"lift-and-shift", "AppBucket"}, {"a-very-long-stack-name-for-production", "AnEvenLongerLogicalIdentifierHere"},
		{"x--y", "Z"}, {"xn--abc", "B"}, {"Prod", "Web"},
	}
	seen := map[string][2]string{}
	for _, c := range cases {
		n := stackQualifiedName(c[0], c[1])
		if n != stackQualifiedName(c[0], c[1]) {
			t.Errorf("%v: not deterministic", c)
		}
		if len(n) > maxPhysNameLen || !s3BucketNameRE.MatchString(n) || strings.Contains(n, "--") || strings.HasPrefix(n, "xn--") {
			t.Errorf("%v -> %q is not a valid short name", c, n)
		}
		if prev, dup := seen[n]; dup {
			t.Errorf("%v and %v both name %q", prev, c, n)
		}
		seen[n] = c
	}
	if got := stackQualifiedName("lift-and-shift", "AppBucket"); got != "lift-and-shift-appbucket" {
		t.Errorf("short names stay readable: got %q", got)
	}
	// A resource named for its own stack (the ECS front door's shape) is named after the stack.
	if got := stackQualifiedName("web", "web"); got != "web" {
		t.Errorf("same-name rule: got %q", got)
	}
	// Long names that share a prefix still differ.
	a := stackQualifiedName("a-very-long-stack-name-for-production", "LogicalOne")
	b := stackQualifiedName("a-very-long-stack-name-for-production", "LogicalTwo")
	if a == b {
		t.Errorf("truncated names collide: %q", a)
	}
}

// The probes' shell copy of the naming rule (phys_name) produces exactly the engine's names.
func TestNaming_ProbeHelperMatchesEngine(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	for _, probe := range []string{"../probe/aws-shim-cloudformation.sh", "../probe/aws-shim-cfn-cloudfront.sh"} {
		src, err := os.ReadFile(probe)
		if err != nil {
			t.Fatal(err)
		}
		fn := regexp.MustCompile(`(?s)phys_name\(\) \{.*?\n\}\n`).Find(src)
		if fn == nil {
			t.Fatalf("%s: phys_name not found", probe)
		}
		helper := string(fn)
		if strings.Contains(helper, "lc ") {
			helper = "lc() { printf '%s' \"$1\" | tr 'A-Z' 'a-z'; }\n" + helper
		}
		for _, c := range [][2]string{{"cfnprobe-ab12", "Orders"}, {"cfprobe-cdn-x9y8z7", "CdnX9y8z7"},
			{"a-very-long-stack-name-for-production", "AnEvenLongerLogicalIdentifierHere"}, {"web", "web"}} {
			out, err := exec.Command(bash, "-c", helper+`phys_name "$1" "$2"`, "_", c[0], c[1]).Output()
			if err != nil {
				t.Fatalf("%s: %v", probe, err)
			}
			if want := stackQualifiedName(c[0], c[1]); string(out) != want {
				t.Errorf("%s: phys_name %v = %q, engine says %q", probe, c, out, want)
			}
		}
	}
}

// A Lambda's kind: Function is named by its FunctionName (the name callers invoke), and Ref / Arn
// resolve to the Function's actual name. A FunctionName that is not a valid Function name falls back to
// the generated name, with a caveat, and Ref follows the Function.
func TestNaming_LambdaRefMatchesTheFunction(t *testing.T) {
	tmpl := []byte(`
Resources:
  Named:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, FunctionName: orders-handler }
  Upper:
    Type: AWS::Lambda::Function
    Properties: { PackageType: Image, Code: { ImageUri: "registry.example/fn:1" }, FunctionName: OrdersHandler }
  Caller:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: Image
      Code: { ImageUri: "registry.example/fn:1" }
      Environment: { Variables: { A: !Ref Named, B: !Ref Upper } }
`)
	built, err := buildManifests(tmpl, DeployOptions{StackName: "s", Namespace: "ns"})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]builtResource{}
	for _, b := range built {
		by[b.res.LogicalID] = b
	}
	if by["Named"].res.Name != "orders-handler" {
		t.Errorf("Named is %q, want its FunctionName", by["Named"].res.Name)
	}
	if by["Upper"].res.Name != "s-upper" || !cfHasCaveat(by["Upper"].cav, `FunctionName "OrdersHandler" is not a valid open-infra Function name`) {
		t.Errorf("Upper: name %q caveats %v", by["Upper"].res.Name, by["Upper"].cav)
	}
	env := map[string]string{}
	for _, e := range by["Caller"].res.Spec["env"].([]any) {
		m := e.(map[string]any)
		env[m["name"].(string)], _ = m["value"].(string)
	}
	if env["A"] != "orders-handler" || env["B"] != "s-upper" {
		t.Errorf("Ref does not name the Functions: %v", env)
	}
	tm := mustParse(t, tmpl)
	r := newResolver(tm, nil, nil, pseudoParams("s"))
	ctx := &stackCtx{template: tm, resolver: r, namer: newPhysNamer("s", nil)}
	if arn, _ := inStackARN("Upper", ctx); !strings.HasSuffix(arn, ":function:s-upper") {
		t.Errorf("Arn of Upper = %q, want the Function's name", arn)
	}
}

// The per-namespace default EncryptionKey is shared on purpose: a second stack's encrypted disk reuses
// it rather than being refused.
func TestNaming_SharedDefaultKeyIsNotRefused(t *testing.T) {
	tmpl := []byte(`
Resources:
  Data:
    Type: AWS::EC2::Volume
    Properties: { Size: 10, Encrypted: true, AvailabilityZone: us-east-1a }
`)
	f := &fakeApplier{}
	for _, stack := range []string{"one", "two"} {
		o := deployOpts()
		o.StackName = stack
		if _, err := Deploy(context.Background(), tmpl, o, f); err != nil {
			t.Fatalf("deploy %s: %v", stack, err)
		}
	}
	if _, ok := f.liveSpecs["Volume/one-data"]; !ok {
		t.Errorf("stack one's volume missing: %v", keysOf(f.liveSpecs))
	}
	if _, ok := f.liveSpecs["Volume/two-data"]; !ok {
		t.Errorf("stack two's volume missing: %v", keysOf(f.liveSpecs))
	}
}
