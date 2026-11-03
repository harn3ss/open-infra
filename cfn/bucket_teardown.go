package cfn

import (
	"context"
	"errors"
	"fmt"
)

// BucketNotEmptyError is a stack delete refused because one of its S3 buckets still holds data. AWS
// CloudFormation fails the same delete (DELETE_FAILED, the bucket and its data kept) unless the bucket
// has DeletionPolicy: Retain; empty the bucket, or retain it, and delete the stack again.
type BucketNotEmptyError struct {
	LogicalID string
	Bucket    string
}

func (e *BucketNotEmptyError) Error() string {
	return fmt.Sprintf("%s: The bucket you tried to delete is not empty (Bucket: %s; Error Code: BucketNotEmpty)", e.LogicalID, e.Bucket)
}

// ErrBucketNotEmpty is what a RemoveBucket hook returns (wrapped or as is) for a bucket that still holds
// data.
var ErrBucketNotEmpty = errors.New("BucketNotEmpty")

// IsBucketNotEmpty reports whether err is a bucket that still holds data.
func IsBucketNotEmpty(err error) bool {
	var bne *BucketNotEmptyError
	return errors.As(err, &bne) || errors.Is(err, ErrBucketNotEmpty)
}

// deleteStackObject deletes one recorded object (waiting for it to go when opts.Wait), deleting a kind:
// Bucket as AWS deletes a bucket. A bucket that still holds data is never deleted: with refuseNotEmpty (a
// stack delete) that fails the operation with BucketNotEmpty; without it (an update that drops the
// bucket, where AWS's cleanup fails to delete it and leaves it) the bucket and its claim are kept,
// unmanaged, and kept=true. An empty bucket is removed with its claim.
func deleteStackObject(ctx context.Context, opts DeployOptions, ap Applier, r StackResource, refuseNotEmpty bool) (kept bool, err error) {
	bucket := ""
	if r.APIVersion == "openinfra.dev/v1" && r.Kind == "Bucket" {
		bucket = bucketNameOf(r)
		if opts.BucketData != nil {
			exists, empty, err := opts.BucketData(ctx, bucket)
			if err != nil {
				return false, fmt.Errorf("checking bucket %s of %s: %w", bucket, r.LogicalID, err)
			}
			if exists && !empty {
				if refuseNotEmpty {
					return false, &BucketNotEmptyError{LogicalID: r.LogicalID, Bucket: bucket}
				}
				return true, nil
			}
		}
	}
	if err := ap.Delete(ctx, r.APIVersion, r.Kind, r.Name); err != nil {
		return false, fmt.Errorf("deleting %s/%s: %w", r.Kind, r.Name, err)
	}
	if opts.Wait {
		if err := ap.WaitGone(ctx, r.APIVersion, r.Kind, r.Name, opts.Timeout); err != nil {
			return false, err
		}
	}
	if bucket != "" && opts.RemoveBucket != nil {
		if err := opts.RemoveBucket(ctx, bucket); err != nil {
			if IsBucketNotEmpty(err) { // data arrived after the check: the bucket stays, as on AWS
				return false, &BucketNotEmptyError{LogicalID: r.LogicalID, Bucket: bucket}
			}
			return false, fmt.Errorf("removing bucket %s of %s: %w", bucket, r.LogicalID, err)
		}
	}
	// A DynamoDB table goes with its data, as AWS deletes a table (table_teardown.go).
	if err := removeTableData(ctx, opts, r); err != nil {
		return false, err
	}
	return false, nil
}

// bucketNameOf is the S3 name of a recorded kind: Bucket — its explicit bucketName, else the claim's name
// (which the composition uses as the bucket name).
func bucketNameOf(r StackResource) string {
	if n, _ := r.Spec["bucketName"].(string); n != "" {
		return n
	}
	return r.Name
}
