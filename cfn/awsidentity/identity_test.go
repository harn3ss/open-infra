package awsidentity

import (
	"reflect"
	"strings"
	"testing"
)

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	id, warns := FromEnv(env(nil))
	if id != Default() || len(warns) != 0 {
		t.Fatalf("no env: got %+v %v, want the default and no warning", id, warns)
	}
	if id.AccountID != "000000000000" || id.Region != "us-east-1" {
		t.Fatalf("default identity is %+v", id)
	}

	id, warns = FromEnv(env(map[string]string{"ACCOUNT_ID": "123456789012", "AWS_DEFAULT_REGION": "eu-west-1", "CFN_NAMESPACE": "stacks"}))
	if id.AccountID != "123456789012" || id.Region != "eu-west-1" || id.StackNamespace != "stacks" || len(warns) != 0 {
		t.Fatalf("configured: got %+v %v", id, warns)
	}
	id, _ = FromEnv(env(map[string]string{"AWS_REGION": "us-west-2", "AWS_DEFAULT_REGION": "eu-west-1"}))
	if id.Region != "us-west-2" {
		t.Fatalf("AWS_REGION should win over AWS_DEFAULT_REGION, got %s", id.Region)
	}

	// The legacy value still works but is flagged: AWS account ids are 12 digits.
	id, warns = FromEnv(env(map[string]string{"ACCOUNT_ID": "open-infra"}))
	if id.AccountID != "open-infra" || len(warns) != 1 || !strings.Contains(warns[0], "12-digit") {
		t.Fatalf("legacy account: got %+v %v", id, warns)
	}
}

func TestARNs(t *testing.T) {
	id := Identity{AccountID: "123456789012", Region: "eu-west-1", StackNamespace: "open-infra-cfn"}
	cases := map[string]string{
		id.RegionalARN("sqs", "q"):         "arn:aws:sqs:eu-west-1:123456789012:q",
		id.IAMARN("role/app"):              "arn:aws:iam::123456789012:role/app",
		id.STSARN("assumed-role/app/s1"):   "arn:aws:sts::123456789012:assumed-role/app/s1",
		S3BucketARN("b"):                   "arn:aws:s3:::b",
		id.ARN("lambda", "", "function:f"): "arn:aws:lambda::123456789012:function:f",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

// The StackId keeps the formula the CloudFormation front door has always used for its unique part, so an
// existing stack's StackId changes only in its account (and region, if configured differently).
func TestStackID(t *testing.T) {
	id := Identity{AccountID: "000000000000", Region: "us-east-1", StackNamespace: "open-infra-cfn"}
	got := id.StackID("app")
	if !strings.HasPrefix(got, "arn:aws:cloudformation:us-east-1:000000000000:stack/app/") || len(got) != len("arn:aws:cloudformation:us-east-1:000000000000:stack/app/")+32 {
		t.Fatalf("StackID = %s", got)
	}
	if got != id.StackID("app") {
		t.Fatal("StackID is not stable")
	}
	other := id
	other.StackNamespace = "elsewhere"
	if other.StackID("app") == got {
		t.Fatal("StackID ignores the namespace")
	}
}

func TestCanonicalAndLegacy(t *testing.T) {
	id := Identity{AccountID: "000000000000", Region: "us-east-1"}
	cases := []struct{ in, canonical string }{
		{"arn:aws:sns:us-east-1:open-infra:orders", "arn:aws:sns:us-east-1:000000000000:orders"},
		{"arn:openinfra:iam::open-infra:assumed-role/app/s", "arn:aws:iam::000000000000:assumed-role/app/s"},
		{"arn:openinfra:iam::open-infra:user/alice", "arn:aws:iam::000000000000:user/alice"},
		{"https://s3.example/open-infra/orders", "https://s3.example/000000000000/orders"},
		{"http://aws-shim:4566/open-infra/orders.fifo", "http://aws-shim:4566/000000000000/orders.fifo"},
		// Already canonical, or not an account-bearing form: unchanged.
		{"arn:aws:sns:us-east-1:000000000000:orders", "arn:aws:sns:us-east-1:000000000000:orders"},
		{"arn:aws:s3:::open-infra", "arn:aws:s3:::open-infra"},
		{"arn:aws:sqs:us-east-1:123456789012:q", "arn:aws:sqs:us-east-1:123456789012:q"},
		{"https://s3.example/open-infra", "https://s3.example/open-infra"},
		{"orders", "orders"},
		{"", ""},
	}
	for _, c := range cases {
		if got := id.Canonical(c.in); got != c.canonical {
			t.Errorf("Canonical(%q) = %q, want %q", c.in, got, c.canonical)
		}
	}
	if got := id.Legacy("arn:aws:sns:us-east-1:000000000000:orders"); got != "arn:aws:sns:us-east-1:open-infra:orders" {
		t.Errorf("Legacy = %q", got)
	}
	if got := id.Legacy("https://h/000000000000/q"); got != "https://h/open-infra/q" {
		t.Errorf("Legacy URL = %q", got)
	}
	// Another account's ARN is never rewritten either way.
	if got := id.Legacy("arn:aws:sns:us-east-1:123456789012:orders"); got != "arn:aws:sns:us-east-1:123456789012:orders" {
		t.Errorf("Legacy rewrote another account: %q", got)
	}
}

func TestEquivalents(t *testing.T) {
	id := Identity{AccountID: "000000000000", Region: "us-east-1"}
	got := id.Equivalents("arn:aws:sns:us-east-1:000000000000:t")
	want := []string{"arn:aws:sns:us-east-1:000000000000:t", "arn:aws:sns:us-east-1:open-infra:t"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Equivalents(canonical) = %v, want %v", got, want)
	}
	got = id.Equivalents("arn:aws:sns:us-east-1:open-infra:t")
	want = []string{"arn:aws:sns:us-east-1:open-infra:t", "arn:aws:sns:us-east-1:000000000000:t"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Equivalents(legacy) = %v, want %v", got, want)
	}
	if got := id.Equivalents("orders"); !reflect.DeepEqual(got, []string{"orders"}) {
		t.Fatalf("Equivalents(name) = %v", got)
	}
	// An install that keeps the legacy account: still one form, and the legacy partition is fixed.
	legacy := Identity{AccountID: LegacyAccountID, Region: "us-east-1"}
	if got := legacy.Canonical("arn:openinfra:iam::open-infra:user/a"); got != "arn:aws:iam::open-infra:user/a" {
		t.Fatalf("legacy install Canonical = %q", got)
	}
}

func TestSetCurrent(t *testing.T) {
	defer Set(Current())
	Set(Identity{AccountID: "111111111111", Region: "ap-south-1", StackNamespace: "x"})
	if c := Current(); c.AccountID != "111111111111" || c.Region != "ap-south-1" {
		t.Fatalf("Current = %+v", c)
	}
}
