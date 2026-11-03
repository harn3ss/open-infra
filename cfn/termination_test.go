package cfn

import (
	"context"
	"errors"
	"testing"
)

// A stack created with termination protection refuses its delete (nothing is deleted), and keeps the
// protection across an update, as on AWS.
func TestTerminationProtection(t *testing.T) {
	f := &fakeApplier{}
	opts := deployOpts()
	opts.TerminationProtection = true
	if _, err := Deploy(context.Background(), []byte("Resources:\n  K: { Type: AWS::KMS::Key, Properties: { Description: a } }\n"), opts, f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	opts.TerminationProtection = false // an update does not take it from its options
	if _, err := Update(context.Background(), []byte("Resources:\n  K: { Type: AWS::KMS::Key, Properties: { Description: b } }\n"), opts, f); err != nil {
		t.Fatalf("update: %v", err)
	}
	if f.stored == nil || !f.stored.TerminationProtection {
		t.Fatalf("the update must keep termination protection: %+v", f.stored)
	}
	_, err := Destroy(context.Background(), opts, f)
	var tp *TerminationProtectedError
	if !errors.As(err, &tp) || len(f.deleted) != 0 {
		t.Fatalf("a protected stack's delete must be refused with nothing deleted: %v %v", err, f.deleted)
	}
}
