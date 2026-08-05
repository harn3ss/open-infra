package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/minio/minio-go/v7"
	"k8s.io/client-go/kubernetes"
)

// s3Handler fronts MinIO with an S3-faithful, SigV4-enforcing surface. The request path is the
// design's four parts (handoff §2): authenticate (SigV4 → open-infra principal), authorize (the
// SAME impersonated SubjectAccessReview the console uses), dispatch to MinIO, and re-encode the
// response in S3's exact byte-shape.
//
// Identity bridge — v1 and its graduation path (be explicit, per the design's own discipline):
//   - Authentication is per-principal and real: the caller's open-infra access key is verified and
//     resolved to their kind: User identity. This is the shared "one policy world" identity.
//   - Authorization in v1 is a COARSE, real RBAC gate: read vs. write is decided by the SAME
//     impersonated SubjectAccessReview everything else uses (see authorizeS3). It is bucket-
//     agnostic because open-infra has no per-bucket RBAC resource yet — the platform already flags
//     per-tenant object-storage isolation as an open gap. Per-bucket authorization (a kind: Bucket
//     or a boundary addition, minting a per-principal scoped MinIO user) is the flagged next
//     graduation step; until then the shim acts to MinIO as a single scoped, NON-root service
//     account, and this coarse gate is honest about what it does and does not enforce.
type s3Handler struct {
	cs      kubernetes.Interface // for the impersonated SubjectAccessReview (iam.CanDo)
	mc      *minio.Client        // MinIO bridge — a scoped, non-root service account (v1 identity bridge)
	authzNS string               // namespace the coarse object-storage RBAC gate is evaluated in
	logger  *slog.Logger
}

// s3op describes a decoded S3 request: the operation kind and the target bucket/key.
type s3op struct {
	kind   string // "list-buckets" | "head-bucket" | "list-objects" | "get" | "head" | "put" | "delete"
	bucket string
	key    string
	write  bool // put/delete mutate; drives the read-vs-write authorization verb
}

// authFailure writes S3's dialect of an authentication rejection (design's indistinguishable 403).
func (h *s3Handler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	writeS3Error(w, "SignatureDoesNotMatch", requestID, r.URL.Path)
}

// serve handles an already-authenticated S3 request: decode intent → authorize via the shared
// impersonated SubjectAccessReview (one policy world) → dispatch to MinIO → re-encode byte-faithful.
func (h *s3Handler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	// 1. Decode the S3 intent from path-style addressing (/{bucket}/{key}).
	op, ok := decodeS3(r)
	if !ok {
		writeS3Error(w, "NotImplemented", requestID, r.URL.Path)
		return
	}

	// 2. Authorize via the shared impersonated SubjectAccessReview — one policy world.
	if allowed, reason := h.authorizeS3(r.Context(), claims, op); !allowed {
		h.logger.Warn("s3 denied", "user", claims.Sub, "op", op.kind,
			"bucket", op.bucket, "key", op.key, "reason", reason)
		writeS3Error(w, "AccessDenied", requestID, r.URL.Path)
		return
	}

	// 3. Dispatch to MinIO and re-encode.
	switch op.kind {
	case "list-buckets":
		h.listBuckets(w, r, requestID)
	case "head-bucket":
		h.headBucket(w, r, op, requestID)
	case "list-objects":
		h.listObjects(w, r, op, requestID)
	case "get":
		h.getObject(w, r, op, requestID)
	case "head":
		h.headObject(w, r, op, requestID)
	case "put":
		h.putObject(w, r, op, requestID)
	case "delete":
		h.deleteObject(w, r, op, requestID)
	default:
		writeS3Error(w, "NotImplemented", requestID, r.URL.Path)
	}
}

// decodeS3 maps HTTP method + path-style URL onto an s3op. Virtual-host addressing (bucket in the
// Host header) is intentionally unsupported in v1 — clients must use path-style (documented), the
// same one-line client setting LocalStack/MinIO expect.
func decodeS3(r *http.Request) (s3op, bool) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(p, "/")

	switch {
	case bucket == "": // "/"
		if r.Method == http.MethodGet {
			return s3op{kind: "list-buckets"}, true
		}
	case key == "": // "/{bucket}"
		switch r.Method {
		case http.MethodGet:
			return s3op{kind: "list-objects", bucket: bucket}, true
		case http.MethodHead:
			return s3op{kind: "head-bucket", bucket: bucket}, true
		}
	default: // "/{bucket}/{key}"
		switch r.Method {
		case http.MethodGet:
			return s3op{kind: "get", bucket: bucket, key: key}, true
		case http.MethodHead:
			return s3op{kind: "head", bucket: bucket, key: key}, true
		case http.MethodPut:
			return s3op{kind: "put", bucket: bucket, key: key, write: true}, true
		case http.MethodDelete:
			return s3op{kind: "delete", bucket: bucket, key: key, write: true}, true
		}
	}
	return s3op{}, false
}

// authorizeS3 is the v1 authorization gate: a real, impersonated SubjectAccessReview in the one
// policy world, mapping read/write onto verbs the platform roles already grant differentially
// (readers can get but not create/delete; powerusers/admins can do both). It is deliberately
// coarse — bucket-agnostic — and that limitation is documented on s3Handler. It is NOT theater:
// the decision is made by the API server's RBAC against the impersonated identity, and it fails
// closed. verb "get" reads / "create" writes / "delete" deletes, checked on the primary product
// resource that owns object storage (applications) in the configured namespace.
func (h *s3Handler) authorizeS3(ctx context.Context, claims iam.Claims, op s3op) (bool, string) {
	verb := "get"
	switch op.kind {
	case "put":
		verb = "create"
	case "delete":
		verb = "delete"
	}
	return iam.CanDo(ctx, h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, "")
}

func (h *s3Handler) listBuckets(w http.ResponseWriter, r *http.Request, requestID string) {
	buckets, err := h.mc.ListBuckets(r.Context())
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	res := listAllMyBucketsResult{Owner: canonicalUser{ID: "open-infra"}}
	for _, b := range buckets {
		res.Buckets.Bucket = append(res.Buckets.Bucket, s3Bucket{
			Name:         b.Name,
			CreationDate: b.CreationDate.UTC().Format(iso8601Millis),
		})
	}
	writeXML(w, http.StatusOK, requestID, res)
}

func (h *s3Handler) headBucket(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	exists, err := h.mc.BucketExists(r.Context(), op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	if !exists {
		// HEAD carries no body; S3 signals a missing bucket with a bare 404.
		w.Header().Set("x-amz-request-id", requestID)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
}

func (h *s3Handler) listObjects(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	prefix := r.URL.Query().Get("prefix")
	res := listBucketResult{Name: op.bucket, Prefix: prefix, MaxKeys: 1000}
	for obj := range h.mc.ListObjects(r.Context(), op.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			writeS3Error(w, minioErrToS3(obj.Err), requestID, r.URL.Path)
			return
		}
		res.Contents = append(res.Contents, listObjectV2{
			Key:          obj.Key,
			LastModified: obj.LastModified.UTC().Format(iso8601Millis),
			ETag:         quoteETag(obj.ETag),
			Size:         obj.Size,
			StorageClass: "STANDARD",
		})
	}
	res.KeyCount = len(res.Contents)
	writeXML(w, http.StatusOK, requestID, res)
}

func (h *s3Handler) getObject(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	obj, err := h.mc.GetObject(r.Context(), op.bucket, op.key, minio.GetObjectOptions{})
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	defer obj.Close()
	stat, err := obj.Stat()
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	setObjectHeaders(w, stat)
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, obj)
}

func (h *s3Handler) headObject(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	stat, err := h.mc.StatObject(r.Context(), op.bucket, op.key, minio.StatObjectOptions{})
	if err != nil {
		// HEAD has no body: signal with status alone (SDKs map 404 → NoSuchKey on HEAD).
		w.Header().Set("x-amz-request-id", requestID)
		w.WriteHeader(statusForMinioErr(err))
		return
	}
	setObjectHeaders(w, stat)
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
}

func (h *s3Handler) putObject(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	info, err := h.mc.PutObject(r.Context(), op.bucket, op.key, r.Body, r.ContentLength,
		minio.PutObjectOptions{ContentType: r.Header.Get("Content-Type")})
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	// S3 acks a successful PutObject with the object's ETag header and an empty 200 body.
	w.Header().Set("ETag", quoteETag(info.ETag))
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
}

func (h *s3Handler) deleteObject(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	if err := h.mc.RemoveObject(r.Context(), op.bucket, op.key, minio.RemoveObjectOptions{}); err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	// S3 returns 204 No Content for a successful delete (idempotent — missing key is still 204).
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusNoContent)
}

const iso8601Millis = "2006-01-02T15:04:05.000Z"

// setObjectHeaders writes the S3 response headers a GET/HEAD carries, so an SDK sees the same
// bytes it would from AWS: quoted ETag, Content-Length, Content-Type, Last-Modified, Accept-Ranges.
func setObjectHeaders(w http.ResponseWriter, stat minio.ObjectInfo) {
	w.Header().Set("ETag", quoteETag(stat.ETag))
	w.Header().Set("Content-Length", strconv.FormatInt(stat.Size, 10))
	if stat.ContentType != "" {
		w.Header().Set("Content-Type", stat.ContentType)
	}
	w.Header().Set("Last-Modified", stat.LastModified.UTC().Format(http.TimeFormat))
	w.Header().Set("Accept-Ranges", "bytes")
}

// quoteETag returns an S3-style quoted ETag. MinIO/minio-go hand back the hex without quotes; the
// S3 wire form is quoted, and SDKs compare the quoted value.
func quoteETag(etag string) string {
	etag = strings.Trim(etag, `"`)
	return `"` + etag + `"`
}

// minioErrToS3 maps a minio-go error to the S3 error code the SDK expects. An unrecognised error
// degrades to InternalError (500) rather than leaking a MinIO-specific shape.
func minioErrToS3(err error) string {
	code := minio.ToErrorResponse(err).Code
	if code == "" {
		return "InternalError"
	}
	if _, known := s3Errors[code]; !known {
		// A real S3 code we don't have a row for — pass it through if plausible, else InternalError.
		switch code {
		case "NoSuchKey", "NoSuchBucket", "AccessDenied", "SignatureDoesNotMatch", "InvalidAccessKeyId":
			return code
		}
		return "InternalError"
	}
	return code
}

func statusForMinioErr(err error) int {
	if info, ok := s3Errors[minioErrToS3(err)]; ok {
		return info.Status
	}
	return http.StatusInternalServerError
}
