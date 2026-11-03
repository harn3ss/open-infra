package cfn

import (
	"context"
	"regexp"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// A stack instance has its own StackId, of AWS's form: a re-created stack of the same name gets another.
func TestNewStackID_PerInstanceAndAWSForm(t *testing.T) {
	id := awsidentity.Identity{AccountID: "123456789012", Region: "eu-west-1", StackNamespace: "open-infra-cfn"}
	a, b := id.NewStackID("app"), id.NewStackID("app")
	re := regexp.MustCompile(`^arn:aws:cloudformation:eu-west-1:123456789012:stack/app/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !re.MatchString(a) || !re.MatchString(b) {
		t.Fatalf("StackIds %q / %q are not AWS's form", a, b)
	}
	if a == b {
		t.Fatalf("two instances of stack app got the same StackId %s", a)
	}
	if n, ok := awsidentity.StackIDName(a); !ok || n != "app" {
		t.Fatalf("StackIDName(%s) = %q, %v", a, n, ok)
	}
	if awsidentity.SameStackID(a, b) {
		t.Fatal("two stack instances compare as one")
	}
	// The same instance in the legacy partition and account is still the same stack.
	legacy := "arn:openinfra:cloudformation:eu-west-1:open-infra:" + a[len("arn:aws:cloudformation:eu-west-1:123456789012:"):]
	if !awsidentity.SameStackID(a, legacy) {
		t.Fatalf("%s and %s should name one stack", a, legacy)
	}
	if awsidentity.SameStackID(a, id.StackID("app")) {
		t.Fatal("a per-instance StackId compares equal to the derived one")
	}
}

const stackIDTemplate = `
Resources:
  Key:
    Type: AWS::KMS::Key
    Properties:
      Description: !Select [2, !Split ["/", !Ref AWS::StackId]]
Outputs:
  Id: { Value: !Ref AWS::StackId }
`

func outputValue(rec *StackRecord, key string) string {
	for _, o := range rec.Outputs {
		if o.OutputKey == key {
			return o.OutputValue
		}
	}
	return ""
}

// A create records the stack instance's StackId, and AWS::StackId resolves to it in resources and Outputs;
// an update (whose options name none) keeps it.
func TestDeploy_StackInstanceIDIsRecordedAndResolved(t *testing.T) {
	id := awsidentity.Current().NewStackID("s")
	opts := deployOpts()
	opts.StackID = id
	f := &fakeApplier{}
	rec, err := Deploy(context.Background(), []byte(stackIDTemplate), opts, f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.StackID != id || f.stored.StackID != id {
		t.Fatalf("recorded StackId = %q (stored %q), want %s", rec.StackID, f.stored.StackID, id)
	}
	if got := outputValue(rec, "Id"); got != id {
		t.Fatalf("Output Id = %q, want %s", got, id)
	}
	unique := id[len(id)-36:]
	if got, _ := f.liveSpecs["EncryptionKey/s-key"]["description"].(string); got != unique {
		t.Fatalf("a property built from AWS::StackId = %q, want %s", got, unique)
	}

	// An update that changes resources (a fresh record is written at UPDATE_COMPLETE).
	upd := []byte(stackIDTemplate + `  Extra: { Value: x }
`)
	upd = []byte(string(upd[:len(`
Resources:
`)]) + `  Key2: { Type: AWS::KMS::Key, Properties: { Description: two } }
` + string(upd[len(`
Resources:
`):]))
	out, err := Update(context.Background(), upd, deployOpts(), f)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if out.StackID != id || f.stored.StackID != id {
		t.Fatalf("after an update the StackId is %q (stored %q), want %s kept", out.StackID, f.stored.StackID, id)
	}
	if got := outputValue(out, "Id"); got != id {
		t.Fatalf("after an update Output Id = %q, want %s", got, id)
	}
}

// A stack created with no StackId of its own (as every stack before per-instance ids) resolves
// AWS::StackId to the derived one, and its record names none — so it keeps that id.
func TestDeploy_NoStackIDKeepsTheDerivedOne(t *testing.T) {
	f := &fakeApplier{}
	rec, err := Deploy(context.Background(), []byte(stackIDTemplate), deployOpts(), f)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if rec.StackID != "" {
		t.Fatalf("a stack with no StackId of its own recorded %q", rec.StackID)
	}
	if got, want := outputValue(rec, "Id"), awsidentity.Current().StackID("s"); got != want {
		t.Fatalf("Output Id = %q, want the derived %s", got, want)
	}
}
