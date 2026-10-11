package cfn

import (
	"strings"
	"testing"
)

// memResolver resolves a TemplateURL to an in-memory child template (the test's stand-in for S3/MinIO).
type memResolver map[string]string

func (m memResolver) Resolve(url string) ([]byte, error) {
	b, ok := m[url]
	if !ok {
		return nil, errFake("no child template at " + url)
	}
	return []byte(b), nil
}

// A nested stack inlines its child: the child resource is prefixed, the parent-supplied Parameter is
// substituted, the parent's Fn::GetAtt <Stack>.Outputs.<Key> resolves to the child's Output expression,
// and the Stack resource itself is gone.
func TestFlattenNested_InlinesChildParamsAndOutputs(t *testing.T) {
	parent := `
Resources:
  Net:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: child-net
      Parameters: { Cidr: 10.0.0.0/16 }
  App:
    Type: AWS::Lambda::Function
    Properties:
      PackageType: Image
      Code: { ImageUri: ghcr.io/x/app:latest }
      Environment:
        Variables:
          VPC: !GetAtt Net.Outputs.VpcId
`
	child := `
Parameters:
  Cidr: { Type: String }
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties: { CidrBlock: !Ref Cidr }
Outputs:
  VpcId: { Value: !Ref Vpc }
`
	out, err := FlattenNested([]byte(parent), memResolver{"child-net": child})
	if err != nil {
		t.Fatalf("flatten failed: %v", err)
	}
	tmpl, err := Parse(out)
	if err != nil {
		t.Fatalf("flattened template does not parse: %v\n%s", err, out)
	}
	// The Stack resource is gone; the child resource is inlined with the stack-id prefix.
	if _, stillThere := tmpl.Resources["Net"]; stillThere {
		t.Errorf("the AWS::CloudFormation::Stack resource must be removed after inlining")
	}
	vpc, ok := tmpl.Resources["NetVpc"]
	if !ok || vpc.Type != "AWS::EC2::VPC" {
		t.Fatalf("child Vpc must inline as NetVpc (AWS::EC2::VPC); got %#v", tmpl.Resources)
	}
	// The parent-supplied Parameter was substituted into the child (Ref Cidr -> "10.0.0.0/16").
	if cb, _ := vpc.Properties["CidrBlock"].(string); cb != "10.0.0.0/16" {
		t.Errorf("child Parameter Cidr must be substituted to the parent value; got CidrBlock=%#v", vpc.Properties["CidrBlock"])
	}
	// The parent's Fn::GetAtt Net.Outputs.VpcId resolved to the child Output (Ref Vpc -> Ref NetVpc).
	js := string(out)
	if !strings.Contains(js, `"NetVpc"`) || !strings.Contains(js, `"Ref":"NetVpc"`) {
		t.Errorf("parent GetAtt Net.Outputs.VpcId must resolve to the child's Output expression (Ref NetVpc); got:\n%s", js)
	}
	if strings.Contains(js, "Outputs.VpcId") {
		t.Errorf("the parent's Outputs-GetAtt must be rewritten away, not left dangling:\n%s", js)
	}
}

// A template with NO nested stack is returned byte-for-byte unchanged (the common case is never touched).
func TestFlattenNested_NoStackUnchanged(t *testing.T) {
	in := []byte("Resources:\n  K:\n    Type: AWS::KMS::Key\n    Properties: { Description: k }\n")
	out, err := FlattenNested(in, nil) // nil resolver is fine when there are no nested stacks
	if err != nil {
		t.Fatalf("no-nested flatten must succeed with a nil resolver: %v", err)
	}
	if string(out) != string(in) {
		t.Errorf("a template with no nested stack must be returned unchanged")
	}
}

// FAIL-CLOSED: every construct the flattener can't rewrite CORRECTLY refuses (never a mis-wired flatten).
func TestFlattenNested_FailClosed(t *testing.T) {
	base := func(childKey, child string) ([]byte, memResolver) {
		parent := "Resources:\n  S:\n    Type: AWS::CloudFormation::Stack\n    Properties: { TemplateURL: " + childKey + " }\n"
		return []byte(parent), memResolver{childKey: child}
	}
	cases := map[string]struct {
		parent []byte
		res    TemplateResolver
		want   string
	}{
		"nil resolver": func() struct {
			parent []byte
			res    TemplateResolver
			want   string
		} {
			p, _ := base("c", "Resources: {}")
			return struct {
				parent []byte
				res    TemplateResolver
				want   string
			}{p, nil, "need a template resolver"}
		}(),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := FlattenNested(c.parent, c.res); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want refusal containing %q; got %v", c.want, err)
			}
		})
	}

	// The rest share a parent with an in-stack child; each child trips a distinct fail-closed guard.
	childCases := map[string]struct {
		child string
		want  string
	}{
		"fn::sub in child":  {"Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties: { BucketName: !Sub \"${AWS::StackName}-b\" }", "Fn::Sub"},
		"child conditions":  {"Conditions: { C: !Equals [a, a] }\nResources:\n  R: { Type: AWS::S3::Bucket, Properties: {} }", "Conditions"},
		"nested-nested":     {"Resources:\n  Inner: { Type: AWS::CloudFormation::Stack, Properties: { TemplateURL: x } }", "nested-nested"},
		"unknown ref":       {"Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties: { BucketName: !Ref Nope }", "can't be mapped"},
		"unbound parameter": {"Parameters: { P: { Type: String } }\nResources:\n  R: { Type: AWS::S3::Bucket, Properties: {} }", "no value from the parent and no Default"},
	}
	for name, c := range childCases {
		t.Run(name, func(t *testing.T) {
			parent := "Resources:\n  S:\n    Type: AWS::CloudFormation::Stack\n    Properties: { TemplateURL: child }\n"
			_, err := FlattenNested([]byte(parent), memResolver{"child": c.child})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want fail-closed refusal containing %q; got %v", c.want, err)
			}
		})
	}
}

// An intrinsic (non-literal) TemplateURL can't be resolved at flatten time — refuse.
func TestFlattenNested_IntrinsicTemplateURLRefused(t *testing.T) {
	parent := "Resources:\n  S:\n    Type: AWS::CloudFormation::Stack\n    Properties: { TemplateURL: !Ref SomeParam }\n"
	if _, err := FlattenNested([]byte(parent), memResolver{}); err == nil || !strings.Contains(err.Error(), "TemplateURL must be a literal string") {
		t.Fatalf("an intrinsic TemplateURL must refuse; got %v", err)
	}
}
