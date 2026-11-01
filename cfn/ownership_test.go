package cfn

import (
	"context"
	"strings"
	"testing"
)

// listingFake is a fakeApplier that can also list a kind (Lister) and create-if-absent (Creator), as
// the live appliers do. race, when set, is called on each Create: returning labels simulates another
// operation creating that object between this one's existence check and its create.
type listingFake struct {
	*fakeApplier
	race func(id string) map[string]string
}

func (l *listingFake) List(_ context.Context, _, kind string) ([]LiveObject, error) {
	var out []LiveObject
	for id, spec := range l.liveSpecs {
		k, name, _ := strings.Cut(id, "/")
		if k == kind {
			out = append(out, LiveObject{Name: name, Labels: l.liveLabels[id], Spec: spec})
		}
	}
	return out, nil
}

func (l *listingFake) Create(ctx context.Context, y []byte) (bool, error) {
	id := idOf(y)
	if l.race != nil {
		if labels := l.race(id); labels != nil {
			if l.liveLabels == nil {
				l.liveLabels, l.liveSpecs = map[string]map[string]string{}, map[string]map[string]any{}
			}
			l.liveLabels[id], l.liveSpecs[id] = labels, map[string]any{}
			return false, nil
		}
	}
	if _, exists := l.liveLabels[id]; exists {
		return false, nil
	}
	return true, l.fakeApplier.Apply(ctx, y)
}

// A resource a deleted stack retained keeps the stack's label but is no longer the stack's. A new stack
// of the same name is refused rather than adopting it — adopting would let this stack's rollback (or
// delete) remove the data the template asked to keep.
func TestOwnership_RetainedObjectIsNotReadopted(t *testing.T) {
	keep := []byte(`
Resources:
  Data:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
`)
	f := &listingFake{fakeApplier: &fakeApplier{}}
	if _, err := Deploy(context.Background(), keep, deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, err := Destroy(context.Background(), deployOpts(), f); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, ok := f.liveSpecs["Bucket/s-data"]; !ok {
		t.Fatal("test premise: the retained bucket is kept")
	}
	// With another resource applied first, the refusal rolls the new stack back.
	again := append(append([]byte{}, keep...), []byte(`  Another:
    Type: AWS::KMS::Key
`)...)
	_, err := Deploy(context.Background(), again, deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "an earlier stack named s left it") {
		t.Fatalf("a re-created stack must refuse the retained object, got %v", err)
	}
	if contains(f.deleted, "Bucket/s-data") {
		t.Fatalf("the retained bucket was deleted by the new stack's rollback: %v", f.deleted)
	}
}

// The same holds within one stack: a Retain resource removed by an update is unmanaged, and a later
// update that adds it again is refused instead of quietly adopting it.
func TestOwnership_RemovedRetainedObjectIsNotReadoptedByUpdate(t *testing.T) {
	with := []byte(`
Resources:
  Data:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
  K:
    Type: AWS::KMS::Key
`)
	without := []byte("Resources:\n  K:\n    Type: AWS::KMS::Key\n")
	f := &listingFake{fakeApplier: &fakeApplier{}}
	if _, err := Deploy(context.Background(), with, deployOpts(), f); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, err := Update(context.Background(), without, deployOpts(), f); err != nil {
		t.Fatalf("update removing the bucket: %v", err)
	}
	if _, err := Update(context.Background(), with, deployOpts(), f); err == nil || !strings.Contains(err.Error(), "an earlier stack named s left it") {
		t.Fatalf("re-adding the retained bucket must refuse, got %v", err)
	}
	// An object the stack's record does name is updated in place as before.
	if _, err := Update(context.Background(), []byte("Resources:\n  K:\n    Type: AWS::KMS::Key\n    Properties: { Description: changed }\n"), deployOpts(), f); err != nil {
		t.Fatalf("an in-place update of the stack's own object: %v", err)
	}
}

// An explicit physical name (BucketName, QueueName, TopicName, TableName, an SSM Name) is what the
// platform creates, whatever the object is called. Two stacks naming the same one would share it, so the
// second is refused — as AWS refuses a create whose name is taken. A stack with generated names is not.
func TestOwnership_ExplicitPhysicalNameIsNotShared(t *testing.T) {
	for name, res := range map[string]string{
		"bucket":    `{ Type: AWS::S3::Bucket, Properties: { BucketName: shared-assets } }`,
		"queue":     `{ Type: AWS::SQS::Queue, Properties: { QueueName: shared-jobs } }`,
		"topic":     `{ Type: AWS::SNS::Topic, Properties: { TopicName: shared-events } }`,
		"table":     `{ Type: AWS::DynamoDB::Table, Properties: { TableName: shared-items, BillingMode: PAY_PER_REQUEST, KeySchema: [ { AttributeName: id, KeyType: HASH } ], AttributeDefinitions: [ { AttributeName: id, AttributeType: S } ] } }`,
		"parameter": `{ Type: AWS::SSM::Parameter, Properties: { Name: /shared/url, Type: String, Value: v } }`,
	} {
		tmpl := []byte("Resources:\n  R: " + res + "\n")
		f := &listingFake{fakeApplier: &fakeApplier{}}
		dev, prod := deployOpts(), deployOpts()
		dev.StackName, prod.StackName = "dev", "prod"
		if _, err := Deploy(context.Background(), tmpl, dev, f); err != nil {
			t.Fatalf("%s: deploy dev: %v", name, err)
		}
		f.stored = nil // each stack has its own record
		_, err := Deploy(context.Background(), tmpl, prod, f)
		if err == nil || !strings.Contains(err.Error(), "is already") || !strings.Contains(err.Error(), "owned by stack dev") {
			t.Errorf("%s: a second stack naming the same physical resource must refuse, got %v", name, err)
		}
	}
	// Generated names never collide, and an update of the stack that owns the name is not refused.
	gen := []byte("Resources:\n  R: { Type: AWS::S3::Bucket }\n")
	f := &listingFake{fakeApplier: &fakeApplier{}}
	for _, st := range []string{"dev", "prod"} {
		o := deployOpts()
		o.StackName = st
		f.stored = nil
		if _, err := Deploy(context.Background(), gen, o, f); err != nil {
			t.Fatalf("generated names: deploy %s: %v", st, err)
		}
	}
	named := []byte("Resources:\n  R: { Type: AWS::S3::Bucket, Properties: { BucketName: mine, VersioningConfiguration: { Status: Enabled } } }\n")
	f = &listingFake{fakeApplier: &fakeApplier{}}
	if _, err := Deploy(context.Background(), []byte("Resources:\n  R: { Type: AWS::S3::Bucket, Properties: { BucketName: mine } }\n"), deployOpts(), f); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(context.Background(), named, deployOpts(), f); err != nil {
		t.Fatalf("updating the stack that owns the name: %v", err)
	}
}

// Two operations racing to create one name cannot both take it: the create is create-only, so the one
// that loses finds the other's object and refuses rather than overwriting it.
func TestOwnership_ConcurrentCreateIsRefused(t *testing.T) {
	f := &listingFake{fakeApplier: &fakeApplier{}, race: func(id string) map[string]string {
		if id == "EncryptionKey/s-keya" {
			return map[string]string{labelStack: "other"}
		}
		return nil
	}}
	_, err := Deploy(context.Background(), initialStack, deployOpts(), f)
	if err == nil || !strings.Contains(err.Error(), "belongs to stack other") || !strings.Contains(err.Error(), "created while this stack was creating it") {
		t.Fatalf("the losing create must refuse, got %v", err)
	}
	if f.liveLabels["EncryptionKey/s-keya"][labelStack] != "other" {
		t.Fatal("the other operation's object was overwritten")
	}
	if contains(f.deleted, "EncryptionKey/s-keya") {
		t.Fatal("the other operation's object was deleted by this one's rollback")
	}
}
