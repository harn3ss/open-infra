package cfn

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// fakeBuckets is the S3 side of a bucket teardown: which buckets exist and hold data, and which were
// removed.
type fakeBuckets struct {
	data    map[string]bool // bucket -> holds data (absent = no such bucket)
	removed []string
}

func (b *fakeBuckets) opts(o DeployOptions) DeployOptions {
	o.BucketData = func(_ context.Context, name string) (bool, bool, error) {
		full, ok := b.data[name]
		return ok, !full, nil
	}
	o.RemoveBucket = func(_ context.Context, name string) error {
		if b.data[name] {
			return ErrBucketNotEmpty
		}
		delete(b.data, name)
		b.removed = append(b.removed, name)
		return nil
	}
	return o
}

const bucketStack = `
Resources:
  Data:
    Type: AWS::S3::Bucket
  Named:
    Type: AWS::S3::Bucket
    Properties: { BucketName: my-named-bucket }
`

// stackBucketName is the S3 name the stack recorded for bucket id (bucketNameOf: its spec.bucketName — for
// an unnamed bucket the generated <stack>-<logical id>-<suffix>).
func stackBucketName(t *testing.T, f *fakeApplier, id string) string {
	t.Helper()
	rec, _, _ := f.GetStack(context.Background(), "s")
	if rec != nil {
		for _, r := range rec.Resources {
			if r.LogicalID == id {
				return bucketNameOf(r)
			}
		}
	}
	t.Fatalf("no recorded bucket %s", id)
	return ""
}

func TestDestroy_EmptyBucketsAreRemoved(t *testing.T) {
	f := deployTemplate(t, []byte(bucketStack))
	gen := stackBucketName(t, f, "Data")
	if !strings.HasPrefix(gen, "s-data-") || len(gen) != len("s-data-")+bucketSuffixLen {
		t.Fatalf("an unnamed bucket's S3 name = %q, want AWS's form s-data-<12-character suffix>", gen)
	}
	b := &fakeBuckets{data: map[string]bool{gen: false, "my-named-bucket": false}}
	rec, err := Destroy(context.Background(), b.opts(deployOpts()), f)
	if err != nil || rec.Status != "DELETE_COMPLETE" {
		t.Fatalf("destroy = %v, %v; want DELETE_COMPLETE", rec, err)
	}
	if !contains(f.deleted, "Bucket/s-data") || !contains(f.deleted, "Bucket/s-named") {
		t.Errorf("bucket claims not deleted: %v", f.deleted)
	}
	sort.Strings(b.removed) // no dependency between them: either may go first
	if strings.Join(b.removed, ",") != "my-named-bucket,"+gen {
		t.Errorf("removed buckets = %v, want the explicit name and the generated one", b.removed)
	}
}

// AWS: DeleteStack fails with BucketNotEmpty and keeps the bucket and its data.
func TestDestroy_NonEmptyBucketFailsTheDelete(t *testing.T) {
	f := deployTemplate(t, []byte(bucketStack))
	b := &fakeBuckets{data: map[string]bool{stackBucketName(t, f, "Data"): false, "my-named-bucket": true}}
	rec, err := Destroy(context.Background(), b.opts(deployOpts()), f)
	if err == nil || !IsBucketNotEmpty(err) {
		t.Fatalf("destroy err = %v, want BucketNotEmpty", err)
	}
	if rec.Status != "DELETE_FAILED" || !strings.Contains(rec.Message, "BucketNotEmpty") || !strings.Contains(rec.Message, "my-named-bucket") {
		t.Errorf("record = %s %q, want DELETE_FAILED naming the bucket", rec.Status, rec.Message)
	}
	if contains(f.deleted, "Bucket/s-named") {
		t.Error("the non-empty bucket's claim was deleted")
	}
	if len(b.removed) != 0 && contains(b.removed, "my-named-bucket") {
		t.Errorf("the non-empty bucket was removed: %v", b.removed)
	}
	found := false
	for _, r := range rec.Resources {
		found = found || r.LogicalID == "Named"
	}
	if !found {
		t.Errorf("the kept bucket is not reported as remaining: %v", rec.Resources)
	}
}

func TestDestroy_RetainedNonEmptyBucketIsKept(t *testing.T) {
	f := deployTemplate(t, []byte(`
Resources:
  Data:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
`))
	b := &fakeBuckets{data: map[string]bool{stackBucketName(t, f, "Data"): true}}
	rec, err := Destroy(context.Background(), b.opts(deployOpts()), f)
	if err != nil || rec.Status != "DELETE_COMPLETE" {
		t.Fatalf("destroy = %v, %v", rec, err)
	}
	if contains(f.deleted, "Bucket/s-data") || len(b.removed) != 0 {
		t.Errorf("a retained bucket was deleted: claims %v, buckets %v", f.deleted, b.removed)
	}
}

// Without the hooks (the CLI) the claim is deleted and the bucket reaper decides.
func TestDestroy_BucketWithoutHooks(t *testing.T) {
	f := deployTemplate(t, []byte(bucketStack))
	rec, err := Destroy(context.Background(), deployOpts(), f)
	if err != nil || rec.Status != "DELETE_COMPLETE" || !contains(f.deleted, "Bucket/s-data") {
		t.Fatalf("destroy = %v, %v, deleted %v", rec, err, f.deleted)
	}
}

func TestUpdate_DroppedBucket(t *testing.T) {
	for _, full := range []bool{false, true} {
		f := &fakeApplier{}
		if _, err := Deploy(context.Background(), []byte(bucketStack), deployOpts(), f); err != nil {
			t.Fatal(err)
		}
		f.deleted = nil
		gen := stackBucketName(t, f, "Data")
		b := &fakeBuckets{data: map[string]bool{gen: full, "my-named-bucket": false}}
		rec, err := Update(context.Background(), []byte(`
Resources:
  Named:
    Type: AWS::S3::Bucket
    Properties: { BucketName: my-named-bucket }
`), b.opts(deployOpts()), f)
		if err != nil || rec.Status != "UPDATE_COMPLETE" {
			t.Fatalf("full=%v: update = %v, %v", full, rec, err)
		}
		for _, r := range rec.Resources {
			if r.LogicalID == "Data" {
				t.Errorf("full=%v: the dropped bucket is still in the stack", full)
			}
		}
		// AWS's cleanup deletes an empty dropped bucket, and leaves one that holds data.
		if full == contains(f.deleted, "Bucket/s-data") {
			t.Errorf("full=%v: claim deleted = %v", full, contains(f.deleted, "Bucket/s-data"))
		}
		if full == contains(b.removed, gen) {
			t.Errorf("full=%v: bucket removed = %v", full, b.removed)
		}
		// The dropped bucket's cleanup event: DELETE_COMPLETE, or (kept with its data) DELETE_FAILED
		// with BucketNotEmpty — the update itself still completes, as on AWS.
		want := "DELETE_COMPLETE"
		if full {
			want = "DELETE_FAILED"
		}
		last := ""
		for _, e := range rec.Events {
			if e.LogicalID == "Data" {
				last = e.Status
				if full && e.Status == "DELETE_FAILED" && !strings.Contains(e.Reason, "BucketNotEmpty") {
					t.Errorf("full=%v: DELETE_FAILED reason %q does not name BucketNotEmpty", full, e.Reason)
				}
			}
		}
		if last != want {
			t.Errorf("full=%v: the dropped bucket's last event is %q, want %q", full, last, want)
		}
		if n := len(rec.Events); n == 0 || rec.Events[n-1].Status != "UPDATE_COMPLETE" {
			t.Errorf("full=%v: the stack's last event is not UPDATE_COMPLETE: %+v", full, rec.Events)
		}
	}
}

// A stack delete a non-empty bucket refuses ends with the stack's DELETE_FAILED event naming it.
func TestDestroy_NonEmptyBucketEvent(t *testing.T) {
	f := deployTemplate(t, []byte(bucketStack))
	b := &fakeBuckets{data: map[string]bool{stackBucketName(t, f, "Data"): false, "my-named-bucket": true}}
	rec, _ := Destroy(context.Background(), b.opts(deployOpts()), f)
	n := len(rec.Events)
	if n == 0 || rec.Events[n-1].Status != "DELETE_FAILED" || !strings.Contains(rec.Events[n-1].Reason, "BucketNotEmpty") {
		t.Errorf("last event = %+v, want the stack's DELETE_FAILED naming BucketNotEmpty", rec.Events)
	}
}
