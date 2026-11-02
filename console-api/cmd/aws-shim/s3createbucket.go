package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// ---- CreateBucket ----
//
// A bucket made through the S3 API is a kind: Bucket claim, exactly like one a stack makes: the claim is
// the resource AWS's bucket is, so the platform's bucket setup creates it in MinIO (with the platform's
// default encryption), mints its scoped credentials, and the reaper and owner records treat it like any
// other claim; DeleteBucket deletes it the same way. The claim lives in one account-wide namespace
// (S3_BUCKET_NAMESPACE, default open-infra-s3), as buckets on AWS belong to the account, not to a stack,
// and it is created with the CALLER's authority (impersonated), so RBAC decides whether they may make one.
// CreateBucket is synchronous on AWS — an immediate PutObject works — so the call answers once the
// bucket's setup has finished, and otherwise a 503 the SDK retries (the retry finds the caller's bucket
// and waits again).

// defaultBucketNamespace is where an S3-API-created bucket's kind: Bucket claim lives.
const defaultBucketNamespace = "open-infra-s3"

// maxBucketClaimName keeps the claim's derived names valid: its setup Job is <claim>-bucket-<10 hex>,
// and a Job name is also a label value (at most 63 characters).
const maxBucketClaimName = 40

// s3BucketNameRE is S3's general-purpose bucket name shape: 3-63 lowercase letters, digits, dots and
// hyphens, starting and ending with a letter or digit.
var s3BucketNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// validS3BucketName applies S3's bucket naming rules (general purpose buckets).
func validS3BucketName(n string) bool {
	if !s3BucketNameRE.MatchString(n) || strings.Contains(n, "..") || net.ParseIP(n) != nil {
		return false
	}
	for _, p := range []string{"xn--", "sthree-", "amzn-s3-demo-"} {
		if strings.HasPrefix(n, p) {
			return false
		}
	}
	for _, s := range []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"} {
		if strings.HasSuffix(n, s) {
			return false
		}
	}
	return true
}

// bucketClaimName is the kind: Bucket claim name of an S3-API-created bucket: the bucket name itself when
// it fits (no dots, at most maxBucketClaimName characters), else a shortened form with a hash of the
// bucket name appended, so it is unique per bucket. The bucket name is the claim's spec.bucketName.
func bucketClaimName(bucket string) string {
	n := strings.ReplaceAll(bucket, ".", "-")
	if n == bucket && len(n) <= maxBucketClaimName {
		return n
	}
	sum := sha256.Sum256([]byte(bucket))
	head := n
	if len(head) > maxBucketClaimName-9 {
		head = head[:maxBucketClaimName-9]
	}
	head = strings.Trim(head, "-")
	if head == "" {
		head = "b"
	}
	return head + "-" + hex.EncodeToString(sum[:])[:8]
}

// createBucketConfiguration is CreateBucket's optional request body.
type createBucketConfiguration struct {
	XMLName            xml.Name  `xml:"CreateBucketConfiguration"`
	LocationConstraint string    `xml:"LocationConstraint"`
	Location           *struct{} `xml:"Location"`
	Bucket             *struct{} `xml:"Bucket"`
}

// createBucketRequestError checks CreateBucket's headers and body as AWS does for a bucket with ACLs
// disabled (Object Ownership BucketOwnerEnforced, AWS's default since 2023). It returns the S3 error code,
// status and message to answer, or "" when the request is acceptable.
//
// LocationConstraint is checked against the region the request was signed for, which is the region of the
// endpoint the client believes it called (the shim accepts every region's signature): a client configured
// for eu-west-1 (`aws s3 mb` sends its own region as the constraint) is accepted; a constraint naming a
// region other than the signing region is IllegalLocationConstraintException, as a regional endpoint
// answers; an explicit us-east-1 is InvalidLocationConstraint (that region is given by omitting it). No
// constraint is accepted from any region, as before.
func createBucketRequestError(r *http.Request, signingRegion string) (code string, status int, msg string) {
	h := r.Header
	if acl := strings.TrimSpace(h.Get("x-amz-acl")); acl != "" && acl != "private" {
		return "InvalidBucketAclWithObjectOwnership", http.StatusBadRequest, "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting"
	}
	for _, g := range []string{"x-amz-grant-full-control", "x-amz-grant-read", "x-amz-grant-read-acp", "x-amz-grant-write", "x-amz-grant-write-acp"} {
		if h.Get(g) != "" {
			return "InvalidBucketAclWithObjectOwnership", http.StatusBadRequest, "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting"
		}
	}
	switch strings.TrimSpace(h.Get("x-amz-object-ownership")) {
	case "", "BucketOwnerEnforced":
	case "BucketOwnerPreferred", "ObjectWriter":
		return "InvalidArgument", http.StatusBadRequest, "Object Ownership " + h.Get("x-amz-object-ownership") + " is not supported here: buckets are BucketOwnerEnforced (ACLs disabled)."
	default:
		return "InvalidArgument", http.StatusBadRequest, "Invalid x-amz-object-ownership header: " + h.Get("x-amz-object-ownership")
	}
	if strings.EqualFold(strings.TrimSpace(h.Get("x-amz-bucket-object-lock-enabled")), "true") {
		return "NotImplemented", http.StatusNotImplemented, "Object Lock cannot be enabled through CreateBucket here; create the bucket as a kind: Bucket (spec.objectLock) or in a stack with ObjectLockConfiguration."
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return "MalformedXML", http.StatusBadRequest, s3Errors["MalformedXML"].Message
	}
	if strings.TrimSpace(string(body)) == "" {
		return "", 0, ""
	}
	var cfg createBucketConfiguration
	if err := xml.Unmarshal(body, &cfg); err != nil {
		return "MalformedXML", http.StatusBadRequest, s3Errors["MalformedXML"].Message
	}
	if cfg.Location != nil || cfg.Bucket != nil {
		return "NotImplemented", http.StatusNotImplemented, "Directory buckets (CreateBucketConfiguration Location/Bucket) are not supported."
	}
	if signingRegion == "" {
		signingRegion = "us-east-1"
	}
	lc := strings.TrimSpace(cfg.LocationConstraint)
	switch {
	case lc == "":
	case lc == "us-east-1" && signingRegion == "us-east-1":
		// AWS refuses an explicit us-east-1: the region is the default and is given by omitting it.
		return "InvalidLocationConstraint", http.StatusBadRequest, "The specified location-constraint is not valid"
	case lc == signingRegion, lc == "EU" && signingRegion == "eu-west-1": // "EU" is eu-west-1's legacy name
	default:
		return "IllegalLocationConstraintException", http.StatusBadRequest,
			"The " + lc + " location constraint is incompatible for the region specific endpoint this request was sent to."
	}
	return "", 0, ""
}

// createBucket is S3 CreateBucket.
func (h *s3Handler) createBucket(w http.ResponseWriter, r *http.Request, claims iam.Claims, op s3op, requestID string) {
	ctx := r.Context()
	if !validS3BucketName(op.bucket) {
		writeS3Error(w, "InvalidBucketName", requestID, r.URL.Path)
		return
	}
	if code, status, msg := createBucketRequestError(r, requestSigningRegion(r)); code != "" {
		writeS3ErrorFull(w, code, status, requestID, msg, r.URL.Path)
		return
	}
	if h.dyn == nil || h.callerDyn == nil || h.bucketNS == "" {
		writeS3Error(w, "NotImplemented", requestID, r.URL.Path)
		return
	}
	// A platform bucket's name is taken, whether or not it exists right now.
	if isPlatformBucket(op.bucket) {
		writeS3Error(w, "BucketAlreadyExists", requestID, r.URL.Path)
		return
	}
	user, groups, ok := iam.Identity(claims)
	if !ok {
		writeS3Error(w, "AccessDenied", requestID, r.URL.Path)
		return
	}
	cdyn, err := h.callerDyn(user, groups)
	if err != nil {
		writeS3Error(w, "InternalError", requestID, r.URL.Path)
		return
	}
	// A bucket that is already a claim's: the caller's own (one they may read) is answered as AWS answers
	// re-creating your own bucket in us-east-1 — 200 — once it is ready; anyone else's name is taken.
	if claim, found, err := bucketClaimFor(ctx, h.dyn, op.bucket); err != nil {
		h.logger.Error("s3 CreateBucket: listing buckets", "bucket", op.bucket, "err", err)
		writeS3Error(w, "InternalError", requestID, r.URL.Path)
		return
	} else if found {
		h.createdOrExisting(w, r, cdyn, claim, op, requestID)
		return
	}
	claim := bucketClaim{namespace: h.bucketNS, name: bucketClaimName(op.bucket)}
	// An S3-API claim whose composite Crossplane has not made yet is found at its own name.
	if cur, err := cdyn.Resource(bucketGVR).Namespace(claim.namespace).Get(ctx, claim.name, metav1.GetOptions{}); err == nil {
		if b, _, _ := unstructuredString(cur.Object, "spec", "bucketName"); b == op.bucket {
			h.createdOrExisting(w, r, cdyn, claim, op, requestID)
			return
		}
	}
	// A bucket with no claim behind it (another resource's own bucket, or one nothing manages) is taken.
	if exists, err := h.mc.BucketExists(ctx, op.bucket); err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	} else if exists {
		writeS3Error(w, "BucketAlreadyExists", requestID, r.URL.Path)
		return
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "Bucket",
		"metadata": map[string]any{
			"name": claim.name, "namespace": claim.namespace,
			"labels": map[string]any{"app.kubernetes.io/managed-by": "aws-shim", "openinfra.dev/s3-api": "true"},
			"annotations": map[string]any{
				"openinfra.dev/created-by": claims.PrincipalType() + "/" + claims.PrincipalID(),
				"openinfra.dev/bucket":     op.bucket,
			},
		},
		"spec": map[string]any{"bucketName": op.bucket},
	}}
	if _, err := cdyn.Resource(bucketGVR).Namespace(claim.namespace).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		switch {
		case apierrors.IsAlreadyExists(err): // a concurrent CreateBucket of the same name
			h.createdOrExisting(w, r, cdyn, claim, op, requestID)
		case apierrors.IsForbidden(err):
			h.logger.Warn("s3 CreateBucket: creating the claim", "bucket", op.bucket, "user", claims.Sub, "err", err)
			writeS3ErrorFull(w, "AccessDenied", http.StatusForbidden, requestID,
				"Access Denied: may not create kind: Bucket "+claim.namespace+"/"+claim.name+", which this bucket would be.", r.URL.Path)
		default:
			h.logger.Error("s3 CreateBucket: creating the claim", "bucket", op.bucket, "err", err)
			writeS3Error(w, "InternalError", requestID, r.URL.Path)
		}
		return
	}
	h.logger.Info("s3 CreateBucket", "bucket", op.bucket, "claim", claim.namespace+"/"+claim.name, "user", claims.Sub)
	h.answerWhenReady(w, r, cdyn, claim, op, requestID)
}

// createdOrExisting answers CreateBucket for a bucket that already has a claim: the caller's own (they
// may read the claim, and it names this bucket) is 200 once ready, as AWS answers re-creating your own
// bucket in us-east-1; one being deleted is OperationAborted; anyone else's is BucketAlreadyExists.
func (h *s3Handler) createdOrExisting(w http.ResponseWriter, r *http.Request, cdyn dynamic.Interface, claim bucketClaim, op s3op, requestID string) {
	cur, err := cdyn.Resource(bucketGVR).Namespace(claim.namespace).Get(r.Context(), claim.name, metav1.GetOptions{})
	if err != nil {
		// Not readable by the caller (another tenant's) or gone: the name is taken either way, as on AWS.
		writeS3Error(w, "BucketAlreadyExists", requestID, r.URL.Path)
		return
	}
	if b, _, _ := unstructuredString(cur.Object, "spec", "bucketName"); b != "" && b != op.bucket {
		writeS3Error(w, "OperationAborted", requestID, r.URL.Path)
		return
	}
	if cur.GetDeletionTimestamp() != nil {
		writeS3Error(w, "OperationAborted", requestID, r.URL.Path)
		return
	}
	h.answerWhenReady(w, r, cdyn, claim, op, requestID)
}

// answerWhenReady waits (bounded) until the bucket is usable (bucketUsable), then answers 200. Past the
// wait it answers 503, which SDKs retry.
func (h *s3Handler) answerWhenReady(w http.ResponseWriter, r *http.Request, cdyn dynamic.Interface, claim bucketClaim, op s3op, requestID string) {
	wait, poll := h.createWait, h.createPoll
	if wait <= 0 {
		wait = 50 * time.Second
	}
	if poll <= 0 {
		poll = time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), wait)
	defer cancel()
	for {
		cur, err := cdyn.Resource(bucketGVR).Namespace(claim.namespace).Get(ctx, claim.name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			writeS3Error(w, "OperationAborted", requestID, r.URL.Path) // deleted while being created
			return
		case err == nil && cur.GetDeletionTimestamp() != nil:
			writeS3Error(w, "OperationAborted", requestID, r.URL.Path)
			return
		case err == nil && h.bucketUsable(ctx, cur, op.bucket):
			w.Header().Set("Location", "/"+op.bucket)
			w.Header().Set("x-amz-request-id", requestID)
			w.WriteHeader(http.StatusOK)
			return
		}
		select {
		case <-ctx.Done():
			if r.Context().Err() != nil {
				return // the client went away
			}
			writeS3ErrorFull(w, "ServiceUnavailable", http.StatusServiceUnavailable, requestID,
				"The bucket "+op.bucket+" is still being created. Please retry.", r.URL.Path)
			return
		case <-time.After(poll):
		}
	}
}

// bucketUsable reports whether a CreateBucket caller can use the bucket: MinIO has it, and either the
// claim's setup has finished (claimReady) or the setup has done what this caller depends on — created the
// bucket and, while the platform encrypts new buckets, set its default encryption. The rest of the setup
// delivers the claim's own credentials, which only the claim's apps use; waiting for that hand-off
// (Crossplane observing two Secrets in turn) made `aws s3 mb` take a minute or more for a bucket that was
// ready in seconds. The caller reaches the bucket through the shim, never with those credentials.
func (h *s3Handler) bucketUsable(ctx context.Context, cur *unstructured.Unstructured, bucket string) bool {
	if exists, err := h.mc.BucketExists(ctx, bucket); err != nil || !exists {
		return false
	}
	if claimReady(cur) || h.encryptsNewBuckets == nil || !h.encryptsNewBuckets() {
		return true
	}
	cfg, err := h.mc.GetBucketEncryption(ctx, bucket)
	return err == nil && cfg != nil && len(cfg.Rules) > 0
}

// claimReady reports whether a kind: Bucket claim's setup has finished: status.ready, which the
// composition sets once the bucket's credentials are delivered (the setup's last step).
func claimReady(u *unstructured.Unstructured) bool {
	ready, ok, _ := unstructured.NestedBool(u.Object, "status", "ready")
	return ok && ready
}
