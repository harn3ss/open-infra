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

// recordedName is the object name stack record rec gives logical id.
func recordedName(rec *StackRecord, id string) string {
	for _, r := range rec.Resources {
		if r.LogicalID == id {
			return r.Name
		}
	}
	return ""
}

// A resource a deleted stack retained keeps the stack's label but is no longer the stack's. A new stack
// of the same name neither adopts it (its rollback or delete would remove the data the template asked to
// keep) nor is blocked by it: as on AWS, the new stack's resource is a new one — named around the
// retained object, which stays exactly as it was.
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
	retainedLabels := f.liveLabels["Bucket/s-data"]
	applied := len(f.applied)
	again := append(append([]byte{}, keep...), []byte(`  Another:
    Type: AWS::KMS::Key
`)...)
	rec, err := Deploy(context.Background(), again, deployOpts(), f)
	if err != nil {
		t.Fatalf("a re-created stack must create its own bucket beside the retained one: %v", err)
	}
	name := recordedName(rec, "Data")
	if name == "" || name == "s-data" || !strings.HasPrefix(name, "s-data-") {
		t.Fatalf("the re-created stack's bucket must be a new object named around the retained s-data, got %q", name)
	}
	for _, a := range f.applied[applied:] {
		if a == "Bucket/s-data" {
			t.Fatalf("the retained bucket was written by the new stack: %v", f.applied[applied:])
		}
	}
	if f.liveLabels["Bucket/s-data"]["cfn.openinfra.dev/stack"] != retainedLabels["cfn.openinfra.dev/stack"] {
		t.Fatal("the retained bucket's labels changed")
	}
	// Its Ref (the bucket name) is the new bucket's, and deleting the new stack leaves the retained one.
	for _, r := range rec.Resources {
		if r.LogicalID == "Data" && r.PhysicalID != name {
			t.Fatalf("the re-created bucket's physical id = %q, want %q", r.PhysicalID, name)
		}
	}
	f.deleted = nil
	f.stored.Resources[0].DeletionPolicy = "Delete" // the new stack's own bucket goes with it
	if _, err := Destroy(context.Background(), deployOpts(), f); err != nil {
		t.Fatalf("destroy of the re-created stack: %v", err)
	}
	if contains(f.deleted, "Bucket/s-data") {
		t.Fatalf("deleting the re-created stack deleted the retained bucket: %v", f.deleted)
	}
}

// A create that fails and rolls back keeps its Retain bucket; re-creating the stack with a
// new BucketName succeeds (the retained bucket's claim name no longer blocks it), and the retained bucket
// is untouched. The same BucketName is still refused, as AWS refuses a bucket name that is taken.
func TestOwnership_RetainedFromAFailedCreate_RecreateWithNewBucketName(t *testing.T) {
	tmpl := func(bucket string) []byte {
		return []byte(`
Resources:
  ConfigBucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Properties: { BucketName: ` + bucket + ` }
  Key:
    Type: AWS::KMS::Key
    DependsOn: ConfigBucket
`)
	}
	f := &listingFake{fakeApplier: &fakeApplier{failOn: "EncryptionKey/s-key"}}
	if _, err := Deploy(context.Background(), tmpl("cfg-one"), deployOpts(), f); err == nil {
		t.Fatal("test premise: the first create fails")
	}
	if _, ok := f.liveSpecs["Bucket/s-configbucket"]; !ok || contains(f.deleted, "Bucket/s-configbucket") {
		t.Fatal("test premise: the rollback keeps the Retain bucket")
	}
	f.stored = nil // as after DeleteStack of the rolled-back stack
	f.failOn = ""

	// The same BucketName: still the retained bucket's, so refused.
	if _, err := Deploy(context.Background(), tmpl("cfg-one"), deployOpts(), f); err == nil || !strings.Contains(err.Error(), "an earlier stack named s left behind") {
		t.Fatalf("re-creating with the retained bucket's BucketName must be refused, got %v", err)
	}
	f.stored = nil

	// A new BucketName: created.
	rec, err := Deploy(context.Background(), tmpl("cfg-two"), deployOpts(), f)
	if err != nil {
		t.Fatalf("re-creating with a new BucketName must succeed: %v", err)
	}
	name := recordedName(rec, "ConfigBucket")
	if name == "s-configbucket" {
		t.Fatal("the new bucket's claim must not be the retained one")
	}
	if got := f.liveSpecs["Bucket/"+name]["bucketName"]; got != "cfg-two" {
		t.Fatalf("the new claim's bucketName = %v, want cfg-two", got)
	}
	if got := f.liveSpecs["Bucket/s-configbucket"]["bucketName"]; got != "cfg-one" {
		t.Fatalf("the retained bucket changed: bucketName = %v", got)
	}
	// An update of the re-created stack keeps the name it recorded (no rename, no second object).
	upd, err := Update(context.Background(), tmpl("cfg-two"), deployOpts(), f)
	if err != nil {
		t.Fatalf("no-op update: %v", err)
	}
	if recordedName(upd, "ConfigBucket") != name {
		t.Fatalf("an update renamed the bucket: %q -> %q", name, recordedName(upd, "ConfigBucket"))
	}
}

// A resource a stack retained more than once (each re-created stack failing again) never blocks the next:
// each generation is named around every earlier one.
func TestOwnership_RetainedTwice(t *testing.T) {
	tmpl := []byte(`
Resources:
  Data:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
  Key:
    Type: AWS::KMS::Key
    DependsOn: Data
`)
	f := &listingFake{fakeApplier: &fakeApplier{failOn: "EncryptionKey/s-key"}}
	names := map[string]bool{}
	for i := 0; i < 3; i++ {
		rec, err := Deploy(context.Background(), tmpl, deployOpts(), f)
		if err == nil {
			t.Fatalf("attempt %d: test premise: the create fails", i)
		}
		if strings.Contains(err.Error(), "left it") {
			t.Fatalf("attempt %d: blocked by an earlier attempt's retained bucket: %v", i, err)
		}
		n := recordedName(rec, "Data")
		if names[n] {
			t.Fatalf("attempt %d reused %q", i, n)
		}
		names[n] = true
		f.stored = nil
	}
}

// The same holds within one stack: a Retain resource removed by an update is unmanaged, and a later
// update that adds it again creates a new object rather than quietly adopting the retained one.
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
	applied := len(f.applied)
	rec, err := Update(context.Background(), with, deployOpts(), f)
	if err != nil {
		t.Fatalf("re-adding the bucket must create a new one: %v", err)
	}
	if n := recordedName(rec, "Data"); n == "s-data" || !strings.HasPrefix(n, "s-data-") {
		t.Fatalf("the re-added bucket must be named around the retained s-data, got %q", n)
	}
	for _, a := range f.applied[applied:] {
		if a == "Bucket/s-data" {
			t.Fatalf("the retained bucket was written by the update: %v", f.applied[applied:])
		}
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
