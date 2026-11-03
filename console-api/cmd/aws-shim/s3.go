package main

import (
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
	"github.com/minio/minio-go/v7"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// s3Handler fronts MinIO with an S3-faithful, SigV4-enforcing surface. The request path is the
// design's four parts: authenticate (SigV4 → open-infra principal), authorize, dispatch to MinIO, and
// re-encode the response in S3's exact byte-shape.
//
// Identity bridge:
// - Authentication is per-principal and real: the caller's open-infra access key is verified and
// resolved to their kind: User identity (or an assumed role's session).
// - Authorization is s3authz.Gate, the one object-storage check the console's bucket browser runs too:
// platform buckets are admin-only; a User needs the coarse impersonated SubjectAccessReview (read,
// write or delete) and no data-plane Deny; an assumed role needs a data-plane Allow. Each operation is
// checked on what it acts on — an object operation on Bucket::<bucket>/<key>, a bucket operation on
// Bucket::<bucket> — so an object-prefix grant reaches only its keys.
// - To MinIO the shim acts as one scoped, NON-root service account; the gate above is what keeps a
// caller to their grants.
type s3Handler struct {
	cs      kubernetes.Interface    // for the impersonated SubjectAccessReview (iam.CanDo)
	mc      *minio.Client           // MinIO bridge — a scoped, non-root service account (v1 identity bridge)
	authzNS string                  // namespace the coarse object-storage RBAC gate is evaluated in
	authz   *dataplaneauthz.Checker // fine-grained kind: Policy data-plane check (additive; may be nil)
	logger  *slog.Logger
	// vhostSuffixes are the host suffixes under which a leading label is the BUCKET (virtual-hosted
	// addressing): the shim's own in-cluster names (S3_INTERNAL_VHOST_SUFFIXES, so a default SDK client
	// pointed at AWS_ENDPOINT_URL=https://aws-shim.<ns>.svc.cluster.local:4567 works) and the site's
	// external S3 hostname (S3_VHOST_SUFFIXES). An unmodified AWS SDK (no forcePathStyle) addresses
	// "<bucket>.<suffix>", so without this a default client — and every presigned URL it generates —
	// fails. AWS's own S3 names are recognized without configuration (decode). Empty = path-style only.
	vhostSuffixes []string
	// dyn (the shim's own client) finds the kind: Bucket a bucket is; callerDyn impersonates a caller, so
	// DeleteBucket deletes that claim with the caller's authority. Either nil: DeleteBucket is not served.
	dyn       dynamic.Interface
	callerDyn func(user string, groups []string) (dynamic.Interface, error)
	// bucketNS is where a bucket made through CreateBucket gets its kind: Bucket claim (S3_BUCKET_NAMESPACE).
	// createWait/createPoll bound how long CreateBucket waits for the bucket's setup (0 = the defaults).
	bucketNS               string
	createWait, createPoll time.Duration
	// encryptsNewBuckets reports whether the platform gives new buckets default encryption (the same
	// switch CloudFormation's BucketEncryption reads, live). nil = no.
	encryptsNewBuckets func() bool
}

// s3op describes a decoded S3 request: the operation kind and the target bucket/key.
type s3op struct {
	// kind: "list-buckets" | "head-bucket" | "list-objects" | "get" | "head" | "put" | "delete",
	// "delete-objects" (DeleteObjects, s3deleteobjects.go), or a bucket
	// operation: "create-bucket", "delete-bucket", "get-/put-bucket-versioning", "list-object-versions",
	// "get-/put-/delete-bucket-tagging", "get-bucket-location", "get-bucket-encryption", "get-bucket-policy"
	// (s3bucket.go).
	kind      string
	bucket    string
	key       string
	versionID string // an object version the request names (?versionId=)
	write     bool   // mutates; drives the read-vs-write authorization verb
	// A multipart upload's id (?uploadId=) and an UploadPart's raw ?partNumber= (validated by the handler,
	// which answers S3's own InvalidArgument for a bad one).
	uploadID   string
	partNumber string
}

// authFailure writes S3's dialect of an authentication rejection (design's indistinguishable 403).
func (h *s3Handler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	writeS3Error(w, "SignatureDoesNotMatch", requestID, r.URL.Path)
}

// serve handles an already-authenticated S3 request: decode intent → authorize via the shared
// impersonated SubjectAccessReview (one policy world) → dispatch to MinIO → re-encode byte-faithful.
func (h *s3Handler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	// 1. Decode the S3 intent — virtual-hosted (bucket in the Host) if the host matches a configured
	// suffix, else path-style (/{bucket}/{key}).
	op, ok := h.decode(r)
	if !ok {
		writeS3Error(w, "NotImplemented", requestID, r.URL.Path)
		return
	}

	// 2. Authorize. DeleteObjects is the exception: as on AWS the batch is not authorized as a whole, each
	// key is (in the handler), and a key the caller may not delete is that key's AccessDenied.
	if op.kind != "delete-objects" && !h.allowed(r, claims, op) {
		writeS3Error(w, "AccessDenied", requestID, r.URL.Path)
		return
	}
	// A copy reads its source as well: the source object is authorized as a read of it (s3:GetObject, or
	// s3:GetObjectVersion for a version), exactly as AWS evaluates CopyObject and UploadPartCopy.
	var src copySource
	if op.kind == "copy-object" || op.kind == "upload-part-copy" {
		var ok bool
		if src, ok = parseCopySource(r.Header.Get("x-amz-copy-source")); !ok {
			writeS3ErrorFull(w, "InvalidArgument", http.StatusBadRequest, requestID,
				"Copy Source must mention the source bucket and key: sourcebucket/sourcekey", r.URL.Path)
			return
		}
		if !h.allowed(r, claims, s3op{kind: "get", bucket: src.bucket, key: src.key, versionID: src.versionID}) {
			writeS3Error(w, "AccessDenied", requestID, r.URL.Path)
			return
		}
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
	case "delete-objects":
		h.deleteObjects(w, r, claims, op, requestID)
	case "create-bucket":
		h.createBucket(w, r, claims, op, requestID)
	case "delete-bucket":
		h.deleteBucket(w, r, claims, op, requestID)
	case "get-bucket-versioning":
		h.getBucketVersioning(w, r, op, requestID)
	case "put-bucket-versioning":
		h.putBucketVersioning(w, r, op, requestID)
	case "list-object-versions":
		h.listObjectVersions(w, r, op, requestID)
	case "get-bucket-tagging":
		h.getBucketTagging(w, r, op, requestID)
	case "put-bucket-tagging":
		h.putBucketTagging(w, r, op, requestID)
	case "delete-bucket-tagging":
		h.deleteBucketTagging(w, r, op, requestID)
	case "get-bucket-location":
		h.getBucketLocation(w, r, op, requestID)
	case "get-bucket-encryption":
		h.getBucketEncryption(w, r, op, requestID)
	case "get-bucket-ownership-controls":
		h.getBucketOwnershipControls(w, r, op, requestID)
	case "get-bucket-policy":
		h.getBucketPolicy(w, r, op, requestID)
	case "get-object-tagging":
		h.getObjectTagging(w, r, op, requestID)
	case "put-object-tagging":
		h.putObjectTagging(w, r, op, requestID)
	case "delete-object-tagging":
		h.deleteObjectTagging(w, r, op, requestID)
	case "create-multipart-upload":
		h.createMultipartUpload(w, r, op, requestID)
	case "upload-part":
		h.uploadPart(w, r, op, requestID)
	case "upload-part-copy":
		h.uploadPartCopy(w, r, op, src, requestID)
	case "complete-multipart-upload":
		h.completeMultipartUpload(w, r, op, requestID)
	case "abort-multipart-upload":
		h.abortMultipartUpload(w, r, op, requestID)
	case "list-parts":
		h.listParts(w, r, op, requestID)
	case "list-multipart-uploads":
		h.listMultipartUploads(w, r, op, requestID)
	case "copy-object":
		h.copyObject(w, r, op, src, requestID)
	default:
		writeS3Error(w, "NotImplemented", requestID, r.URL.Path)
	}
}

// allowed runs the S3 authorization for op (s3authz.Gate, the same check the console's bucket browser
// runs): the platform-bucket fence; then for an assumed role its data-plane policies alone (default deny),
// for a User the coarse SubjectAccessReview and then the data-plane policies, which can only tighten it —
// each on the resource the operation acts on, the object for an object operation (Bucket::<bucket>/<key>)
// and the bucket for a bucket operation. A denial is logged with its reason.
func (h *s3Handler) allowed(r *http.Request, claims iam.Claims, op s3op) bool {
	return h.allowedIn(nil, r, claims, op)
}

// allowedIn is allowed within a batch (DeleteObjects' keys), which shares the coarse review; nil = none.
func (h *s3Handler) allowedIn(b *s3authz.Batch, r *http.Request, claims iam.Claims, op s3op) bool {
	var ok bool
	var reason string
	if b != nil {
		ok, reason = b.Allow(r.Context(), claims, op.authzRequest(), requestContext(claims, r))
	} else {
		ok, reason = h.gate().Allow(r.Context(), claims, op.authzRequest(), requestContext(claims, r))
	}
	if !ok {
		h.logger.Warn("s3 denied", "user", claims.Sub, "principal", claims.PrincipalType(), "op", op.kind,
			"bucket", op.bucket, "key", op.key, "reason", reason)
	}
	return ok
}

// gate is the shared object-storage authorization (internal/s3authz) over this handler's clients.
func (h *s3Handler) gate() s3authz.Gate {
	return s3authz.Gate{CS: h.cs, Authz: h.authz, NS: h.authzNS}
}

// authzRequest is op as an authorization question: its AWS action, the coarse RBAC verb it needs, and the
// resource it acts on (the object for an object operation).
func (op s3op) authzRequest() s3authz.Request {
	return s3authz.Request{Action: op.action(), Verb: op.verb(), Bucket: op.bucket, Key: op.key, Object: op.onObject()}
}

// onObject reports whether op acts on an object (authorized on Bucket::<bucket>/<key>, as AWS authorizes
// it on arn:aws:s3:::<bucket>/<key>) rather than on its bucket. Listing a bucket's objects, versions or
// multipart uploads is a bucket operation (s3:ListBucket …), as on AWS.
func (op s3op) onObject() bool {
	switch op.kind {
	case "get", "head", "put", "delete", "copy-object",
		"get-object-tagging", "put-object-tagging", "delete-object-tagging",
		"create-multipart-upload", "upload-part", "upload-part-copy", "complete-multipart-upload",
		"abort-multipart-upload", "list-parts":
		return true
	}
	return false
}

// verb is the coarse RBAC verb op needs: "delete" to delete an object or bucket, "create" for any other
// change (an upload, a copy, tagging, versioning), else "get".
func (op s3op) verb() string {
	switch op.kind {
	case "delete", "delete-bucket":
		return "delete"
	case "put", "create-bucket", "put-bucket-versioning", "put-bucket-tagging", "delete-bucket-tagging",
		"create-multipart-upload", "upload-part", "upload-part-copy", "complete-multipart-upload",
		"abort-multipart-upload", "copy-object":
		return "create"
	}
	if op.write { // object tagging and anything else that changes state
		return "create"
	}
	return "get"
}

// decode maps a request onto an s3op, choosing virtual-hosted addressing (bucket in the Host header)
// when the host matches a configured vhostSuffix or is one of AWS's own virtual-hosted S3 names
// (<bucket>.s3[.<region>].amazonaws.com, which a VM guest's resolver sends here), else path-style.
// Virtual-hosted is what an unmodified AWS SDK (no forcePathStyle) and the presigned URLs it mints use
// when AWS_ENDPOINT_URL names a hostname; path-style stays the explicit LocalStack/MinIO-style client
// option.
func (h *s3Handler) decode(r *http.Request) (s3op, bool) {
	var op s3op
	var ok bool
	host := hostNoPort(r.Host)
	if b := vhostBucket(host, h.vhostSuffixes); b != "" {
		op, ok = decodeVHost(r, b)
	} else if m := awsS3VhostRe.FindStringSubmatch(host); m != nil {
		op, ok = decodeVHost(r, m[1])
	} else {
		op, ok = decodeS3(r)
	}
	return asCopy(op, r), ok
}

// hostNoPort lowercases a Host header and strips any :port (leaving a bracketed IPv6 literal intact).
func hostNoPort(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return h
}

// vhostBucket returns the bucket label when host is "<bucket>.<suffix>" for one of the suffixes, or
// "" for a bare suffix (path-style endpoint) or no match. Only a single-label bucket is accepted: a
// dotted bucket name cannot be virtual-hosted over TLS anyway, so such a request is treated as
// path-style rather than mis-split.
func vhostBucket(host string, suffixes []string) string {
	for _, suf := range suffixes {
		suf = strings.ToLower(strings.Trim(strings.TrimSpace(suf), "."))
		if suf == "" {
			continue
		}
		if prefix, ok := strings.CutSuffix(host, "."+suf); ok && prefix != "" && !strings.Contains(prefix, ".") {
			return prefix
		}
	}
	return ""
}

// decodeVHost maps a virtual-hosted request (bucket already known from the Host) onto an s3op, where
// the whole URL path is the object key.
func decodeVHost(r *http.Request, bucket string) (s3op, bool) {
	return decodeTarget(r.Method, bucket, strings.TrimPrefix(r.URL.Path, "/"), r.URL.Query())
}

// decodeS3 maps HTTP method + path-style URL onto an s3op (/{bucket}/{key}). Virtual-hosted
// addressing is handled by h.decode before this is reached; this remains the path-style decoder.
func decodeS3(r *http.Request) (s3op, bool) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(p, "/")
	if bucket == "" { // "/"
		if r.Method == http.MethodGet && s3Subresource(r.URL.Query()) == "" {
			return s3op{kind: "list-buckets"}, true
		}
		return s3op{}, false
	}
	return decodeTarget(r.Method, bucket, key, r.URL.Query())
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
			CreationDate: bucketCreationDate(b.CreationDate),
		})
	}
	writeXML(w, http.StatusOK, requestID, res)
}

// bucketCreationDate is a ListBuckets CreationDate. A bucket MinIO has no creation time for (one made
// before it recorded them) reports the Unix epoch: S3 never sends the zero time, and SDKs and the
// AWS CLI fail the whole listing on year 0001 ("date value out of range").
func bucketCreationDate(t time.Time) string {
	if t.IsZero() || t.Year() < 1970 {
		t = time.Unix(0, 0)
	}
	return t.UTC().Format(iso8601Millis)
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
	opts := minio.GetObjectOptions{VersionID: op.versionID}
	// A Range request (the AWS CLI downloads a file over 8 MiB as parallel ranged GETs) is answered 206 with
	// just that range, as S3 does; answering each part with the whole object would corrupt the download.
	var full *minio.ObjectInfo
	var start, end int64
	if hdr := r.Header.Get("Range"); hdr != "" {
		st, err := h.mc.StatObject(r.Context(), op.bucket, op.key, minio.StatObjectOptions{VersionID: op.versionID})
		if err != nil {
			writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
			return
		}
		s, e, ranged, satisfiable := parseByteRange(hdr, st.Size)
		if ranged && !satisfiable {
			w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(st.Size, 10))
			writeS3Error(w, "InvalidRange", requestID, r.URL.Path)
			return
		}
		if ranged {
			if err := opts.SetRange(s, e); err != nil {
				writeS3Error(w, "InvalidRange", requestID, r.URL.Path)
				return
			}
			full, start, end = &st, s, e
		}
	}
	obj, err := h.mc.GetObject(r.Context(), op.bucket, op.key, opts)
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
	if full == nil {
		setObjectHeaders(w, stat)
		w.Header().Set("x-amz-request-id", requestID)
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, obj)
		return
	}
	n := end - start + 1
	setObjectHeaders(w, *full)
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10)+"/"+strconv.FormatInt(full.Size, 10))
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusPartialContent)
	_, _ = io.CopyN(w, obj, n)
}

// parseByteRange reads a Range header against an object of size bytes. ranged=false means the header is
// not a single byte range S3 honours (malformed, or several ranges): the whole object is served, as S3
// does. satisfiable=false is S3's InvalidRange (416): a range starting at or past the end, or an empty
// suffix. start and end are inclusive offsets, end clamped to the object's last byte.
func parseByteRange(h string, size int64) (start, end int64, ranged, satisfiable bool) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(h), "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return 0, 0, false, false
	}
	a, b, ok := strings.Cut(strings.TrimSpace(spec), "-")
	if !ok {
		return 0, 0, false, false
	}
	if a == "" { // bytes=-N: the last N bytes
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n < 0 {
			return 0, 0, false, false
		}
		if n == 0 || size == 0 {
			return 0, 0, true, false
		}
		if n > size {
			n = size
		}
		return size - n, size - 1, true, true
	}
	s, err := strconv.ParseInt(a, 10, 64)
	if err != nil || s < 0 {
		return 0, 0, false, false
	}
	e := size - 1
	if b != "" {
		if e2, err := strconv.ParseInt(b, 10, 64); err != nil || e2 < s {
			return 0, 0, false, false
		} else if e2 < e {
			e = e2
		}
	}
	if s >= size {
		return 0, 0, true, false
	}
	return s, e, true, true
}

func (h *s3Handler) headObject(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	stat, err := h.mc.StatObject(r.Context(), op.bucket, op.key, minio.StatObjectOptions{VersionID: op.versionID})
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
	// If the client used aws-chunked framing (a trailing checksum, the AWS CLI v2 default in many
	// paths), strip the framing so we store the real object bytes, not the chunk headers — otherwise
	// the framing would be persisted verbatim, silently corrupting the object.
	var body io.Reader = r.Body
	size := r.ContentLength
	if isAwsChunked(r) {
		body = newAwsChunkedReader(r.Body)
		size = decodedContentLength(r)
	}
	info, err := h.mc.PutObject(r.Context(), op.bucket, op.key, body, size,
		minio.PutObjectOptions{ContentType: r.Header.Get("Content-Type")})
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	// S3 acks a successful PutObject with the object's ETag header and an empty 200 body.
	w.Header().Set("ETag", quoteETag(info.ETag))
	if info.VersionID != "" { // a versioned bucket: the version this put created, as S3 reports it
		w.Header().Set("x-amz-version-id", info.VersionID)
	}
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
}

func (h *s3Handler) deleteObject(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	if err := h.mc.RemoveObject(r.Context(), op.bucket, op.key, minio.RemoveObjectOptions{VersionID: op.versionID}); err != nil {
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
	if stat.VersionID != "" {
		w.Header().Set("x-amz-version-id", stat.VersionID)
	}
	// An object stored encrypted (a bucket with default encryption) says so, as S3 does.
	if sse := stat.Metadata.Get("X-Amz-Server-Side-Encryption"); sse != "" {
		w.Header().Set("x-amz-server-side-encryption", sse)
	}
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
