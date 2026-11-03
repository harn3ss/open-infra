package cfn

import (
	"context"
	"strings"
	"testing"
)

// #348: an unnamed bucket gets the name AWS gives it, <stack>-<logical id>-<suffix>: lowercase, at most 63
// characters, a valid S3 name, stable for one stack instance and different for another.
func TestBucketName_GeneratedAWSForm(t *testing.T) {
	cases := [][2]string{
		{"web", "AppBucket"},
		{"MyStack", "SiteBucket"},
		{"a-very-long-stack-name-for-the-production-environment-tier", "AnEvenLongerLogicalIdentifierForTheBucket"},
		{"x", "AVeryLongLogicalIdentifierThatAloneIsLongerThanTheRoomForItInABucketName"},
		{"xn--stack", "Data"},
		{"", "Data"},
	}
	for _, c := range cases {
		n := generatedBucketName(c[0], c[1], "2026-11-03T00:00:00Z")
		if !s3BucketNameRE.MatchString(n) || strings.Contains(n, "--") || strings.HasPrefix(n, "xn--") || strings.HasPrefix(n, "sthree-") {
			t.Errorf("%v -> %q is not a valid S3 bucket name", c, n)
		}
		if len(n) > maxBucketNameLen {
			t.Errorf("%v -> %q is %d characters, past S3's 63", c, n, len(n))
		}
		if n != generatedBucketName(c[0], c[1], "2026-11-03T00:00:00Z") {
			t.Errorf("%v: the name is not stable for one stack instance", c)
		}
		if n == generatedBucketName(c[0], c[1], "2026-11-04T00:00:00Z") {
			t.Errorf("%v: a later stack of the same name got the same bucket name %q", c, n)
		}
		if n == generatedBucketName(c[0], c[1]+"2", "2026-11-03T00:00:00Z") {
			t.Errorf("%v: two logical ids got one bucket name", c)
		}
	}
	if n := generatedBucketName("web", "AppBucket", "t"); !strings.HasPrefix(n, "web-appbucket-") || len(n) != len("web-appbucket-")+bucketSuffixLen {
		t.Errorf("web/AppBucket -> %q, want web-appbucket-<12-character suffix>", n)
	}
}

// Two stacks from one template in one namespace get two claims and two buckets; a stack created again
// under the same name gets a new bucket name; a bucket a stack recorded keeps its name on update.
func TestBucketName_StacksAndUpdates(t *testing.T) {
	tmpl := []byte(`
Resources:
  Data:
    Type: AWS::S3::Bucket
Outputs:
  Name: { Value: !Ref Data }
`)
	f := &fakeApplier{}
	names := map[string]string{}
	for _, stack := range []string{"dev", "prod"} {
		o := deployOpts()
		o.StackName = stack
		rec, err := Deploy(context.Background(), tmpl, o, f)
		if err != nil {
			t.Fatalf("deploy %s: %v", stack, err)
		}
		for _, r := range rec.Resources {
			if r.LogicalID == "Data" {
				names[stack] = bucketNameOf(r)
				if r.Name != stack+"-data" {
					t.Errorf("%s's claim is %q, want %s-data", stack, r.Name, stack)
				}
				if r.PhysicalID != names[stack] {
					t.Errorf("%s: Ref = %q, want the bucket's S3 name %q", stack, r.PhysicalID, names[stack])
				}
			}
		}
		if len(rec.Outputs) != 1 || rec.Outputs[0].OutputValue != names[stack] {
			t.Errorf("%s: the Output !Ref Data = %+v, want %q", stack, rec.Outputs, names[stack])
		}
	}
	if !strings.HasPrefix(names["dev"], "dev-data-") || !strings.HasPrefix(names["prod"], "prod-data-") || names["dev"] == names["prod"] {
		t.Fatalf("bucket names = %v, want dev-data-<suffix> and prod-data-<suffix>", names)
	}

	// An update keeps the recorded name, and a bucket it adds is named for the same stack instance.
	o := deployOpts()
	o.StackName = "dev"
	f.stored = nil
	if _, err := Deploy(context.Background(), tmpl, o, f); err != nil {
		t.Fatal(err)
	}
	created, _, _ := f.GetStack(context.Background(), "dev")
	first := ""
	for _, r := range created.Resources {
		if r.LogicalID == "Data" {
			first = bucketNameOf(r)
		}
	}
	rec, err := Update(context.Background(), []byte(`
Resources:
  Data:
    Type: AWS::S3::Bucket
  Logs:
    Type: AWS::S3::Bucket
`), o, f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, r := range rec.Resources {
		switch r.LogicalID {
		case "Data":
			if bucketNameOf(r) != first {
				t.Errorf("the update renamed bucket Data from %q to %q", first, bucketNameOf(r))
			}
		case "Logs":
			want := generatedBucketName("dev", "Logs", created.CreatedAt)
			if bucketNameOf(r) != want {
				t.Errorf("the added bucket is %q, want %q (named for the stack's instance)", bucketNameOf(r), want)
			}
		}
	}
}

// A bucket a stack created before generated names (no spec.bucketName: its claim's name is its bucket's)
// keeps that name on update — kind: Bucket's bucketName is immutable, so setting one would be refused, and
// renaming would orphan the data.
func TestBucketName_LegacyBucketKeepsItsName(t *testing.T) {
	f := &fakeApplier{
		stored: &StackRecord{Name: "s", Namespace: "cfn-test", Status: "CREATE_COMPLETE", CreatedAt: "2026-01-01T00:00:00Z", Resources: []StackResource{
			{LogicalID: "Data", APIVersion: "openinfra.dev/v1", Kind: "Bucket", Name: "data", Type: "AWS::S3::Bucket", Spec: map[string]any{"versioning": false}},
		}},
		liveLabels: map[string]map[string]string{"Bucket/data": {labelStack: "s"}},
		liveSpecs:  map[string]map[string]any{"Bucket/data": {"versioning": false}},
	}
	rec, err := Update(context.Background(), []byte(`
Resources:
  Data:
    Type: AWS::S3::Bucket
    Properties: { VersioningConfiguration: { Status: Enabled } }
Outputs:
  Name: { Value: !Ref Data }
`), deployOpts(), f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	for _, r := range rec.Resources {
		if r.LogicalID != "Data" {
			continue
		}
		if r.Name != "data" {
			t.Errorf("the legacy bucket's claim was renamed to %q", r.Name)
		}
		if _, set := r.Spec["bucketName"]; set {
			t.Errorf("the update set spec.bucketName on a bucket created without one: %v", r.Spec)
		}
		if r.Spec["versioning"] != true {
			t.Errorf("the update was not applied: %v", r.Spec)
		}
	}
	if len(rec.Outputs) != 1 || rec.Outputs[0].OutputValue != "data" {
		t.Errorf("Ref of the legacy bucket = %+v, want its claim name data", rec.Outputs)
	}
}
