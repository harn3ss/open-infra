package main

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/s3utils"

	"github.com/harn3ss/open-infra/console-api/internal/awssig"
)

// ---- Multipart upload, CopyObject and UploadPartCopy ----
//
// The AWS CLI and SDKs switch to a multipart upload above their threshold (8 MiB for the CLI), and to
// UploadPartCopy for a large server-side copy, so these are what `aws s3 cp`/`sync` of an ordinary build
// artifact sends. Each is passed through to MinIO's own multipart API (minio-go Core), streaming the part
// body: nothing is buffered beyond the client library's chunk, so a large part costs no more memory than a
// small one. MinIO applies the bucket's default encryption to the completed object, as it does to a
// PutObject. Client checksums (x-amz-checksum-*) are not passed on, as for PutObject; a Content-MD5 or a
// signed payload hash is, so MinIO verifies the part's bytes.

// maxCompleteBody bounds a CompleteMultipartUpload document (10,000 parts of about 150 bytes each).
const maxCompleteBody = 4 << 20

// decodeMultipart decodes the object-level multipart operations. multipart=false means the request is
// not one (decodeTarget carries on); ok=false with multipart=true is a multipart request the shim does not
// serve (NotImplemented).
func decodeMultipart(method, bucket, key string, q url.Values) (op s3op, ok, multipart bool) {
	_, uploads := q["uploads"]
	_, hasUploadID := q["uploadId"]
	_, hasPart := q["partNumber"]
	if !uploads && !hasUploadID {
		return s3op{}, false, false
	}
	base := s3op{bucket: bucket, key: key, uploadID: q.Get("uploadId"), partNumber: q.Get("partNumber")}
	switch {
	case uploads && !hasUploadID && method == http.MethodPost:
		base.kind, base.write = "create-multipart-upload", true
	case hasUploadID && hasPart && method == http.MethodPut:
		base.kind, base.write = "upload-part", true
	case hasUploadID && !hasPart && method == http.MethodPost:
		base.kind, base.write = "complete-multipart-upload", true
	case hasUploadID && !hasPart && method == http.MethodDelete:
		base.kind, base.write = "abort-multipart-upload", true
	case hasUploadID && !hasPart && method == http.MethodGet:
		base.kind = "list-parts"
	default:
		return s3op{}, false, true
	}
	return base, true, true
}

// asCopy turns a PUT that names a copy source into the copy it is: PutObject → CopyObject, UploadPart →
// UploadPartCopy. A PUT with x-amz-copy-source is never stored as an (empty) object.
func asCopy(op s3op, r *http.Request) s3op {
	if r.Header.Get("x-amz-copy-source") == "" {
		return op
	}
	switch op.kind {
	case "put":
		op.kind = "copy-object"
	case "upload-part":
		op.kind = "upload-part-copy"
	}
	return op
}

// copySource is a parsed x-amz-copy-source.
type copySource struct{ bucket, key, versionID string }

// parseCopySource parses x-amz-copy-source: "[/]<bucket>/<key>[?versionId=<id>]", URL-encoded. An access
// point or Outposts ARN is not a source the shim serves (ok=false).
func parseCopySource(v string) (copySource, bool) {
	v = strings.TrimSpace(v)
	var version string
	if i := strings.Index(v, "?"); i >= 0 {
		q, err := url.ParseQuery(v[i+1:])
		if err != nil {
			return copySource{}, false
		}
		version, v = q.Get("versionId"), v[:i]
	}
	p, err := url.PathUnescape(v)
	if err != nil || strings.HasPrefix(p, "arn:") {
		return copySource{}, false
	}
	b, k, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	if b == "" || k == "" {
		return copySource{}, false
	}
	return copySource{bucket: b, key: k, versionID: version}, true
}

// partNumberOf validates an UploadPart's part number: an integer from 1 to 10,000, as S3 requires.
func partNumberOf(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 1 && n <= 10000
}

func writeInvalidPartNumber(w http.ResponseWriter, r *http.Request, requestID string) {
	writeS3ErrorFull(w, "InvalidArgument", http.StatusBadRequest, requestID,
		"Part number must be an integer between 1 and 10000, inclusive", r.URL.Path)
}

// ---- wire shapes ----

type initiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

type completeMultipartUploadRequest struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber int    `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	} `xml:"Part"`
}

type completeMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

type listPartsResult struct {
	XMLName              xml.Name     `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult"`
	Bucket               string       `xml:"Bucket"`
	Key                  string       `xml:"Key"`
	UploadID             string       `xml:"UploadId"`
	PartNumberMarker     int          `xml:"PartNumberMarker"`
	NextPartNumberMarker int          `xml:"NextPartNumberMarker"`
	MaxParts             int          `xml:"MaxParts"`
	IsTruncated          bool         `xml:"IsTruncated"`
	Parts                []listedPart `xml:"Part"`
	StorageClass         string       `xml:"StorageClass"`
}

type listedPart struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

type listMultipartUploadsResult struct {
	XMLName            xml.Name         `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListMultipartUploadsResult"`
	Bucket             string           `xml:"Bucket"`
	KeyMarker          string           `xml:"KeyMarker"`
	UploadIDMarker     string           `xml:"UploadIdMarker"`
	NextKeyMarker      string           `xml:"NextKeyMarker"`
	NextUploadIDMarker string           `xml:"NextUploadIdMarker"`
	Prefix             string           `xml:"Prefix"`
	Delimiter          string           `xml:"Delimiter,omitempty"`
	MaxUploads         int              `xml:"MaxUploads"`
	IsTruncated        bool             `xml:"IsTruncated"`
	Uploads            []listedUpload   `xml:"Upload"`
	CommonPrefixes     []commonPrefixEl `xml:"CommonPrefixes,omitempty"`
}

type listedUpload struct {
	Key          string `xml:"Key"`
	UploadID     string `xml:"UploadId"`
	Initiated    string `xml:"Initiated"`
	StorageClass string `xml:"StorageClass"`
}

type commonPrefixEl struct {
	Prefix string `xml:"Prefix"`
}

type copyObjectResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

type copyPartResult struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyPartResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// ---- handlers ----

func (h *s3Handler) core() minio.Core { return minio.Core{Client: h.mc} }

func (h *s3Handler) createMultipartUpload(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	opts := minio.PutObjectOptions{ContentType: r.Header.Get("Content-Type")}
	// x-amz-tagging: the AWS CLI carries a copied object's tags here (read with GetObjectTagging).
	if tg := r.Header.Get("x-amz-tagging"); tg != "" {
		q, err := url.ParseQuery(tg)
		if err != nil {
			writeS3ErrorFull(w, "InvalidArgument", http.StatusBadRequest, requestID, "The x-amz-tagging header is not a valid query string.", r.URL.Path)
			return
		}
		opts.UserTags = map[string]string{}
		for k, v := range q {
			if len(v) > 0 {
				opts.UserTags[k] = v[0]
			}
		}
	}
	id, err := h.core().NewMultipartUpload(r.Context(), op.bucket, op.key, opts)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	writeXML(w, http.StatusOK, requestID, initiateMultipartUploadResult{Bucket: op.bucket, Key: op.key, UploadID: id})
}

// hexSHA256RE matches a signed payload hash (as opposed to UNSIGNED-PAYLOAD or a STREAMING-* sentinel).
var hexSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (h *s3Handler) uploadPart(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	part, ok := partNumberOf(op.partNumber)
	if !ok {
		writeInvalidPartNumber(w, r, requestID)
		return
	}
	// The part streams through: the aws-chunked framing (a trailing checksum) is stripped on the fly, and
	// the declared length lets minio-go send it on without buffering.
	var body io.Reader = r.Body
	size := r.ContentLength
	opts := minio.PutObjectPartOptions{Md5Base64: r.Header.Get("Content-MD5")}
	if isAwsChunked(r) {
		body, size = newAwsChunkedReader(r.Body), decodedContentLength(r)
	} else if sum := strings.ToLower(r.Header.Get("X-Amz-Content-Sha256")); hexSHA256RE.MatchString(sum) {
		opts.Sha256Hex = sum // MinIO checks the bytes against the hash the client signed
	}
	if size < 0 {
		writeS3ErrorFull(w, "MissingContentLength", http.StatusLengthRequired, requestID,
			"You must provide the Content-Length HTTP header.", r.URL.Path)
		return
	}
	p, err := h.core().PutObjectPart(r.Context(), op.bucket, op.key, op.uploadID, part, body, size, opts)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	w.Header().Set("ETag", quoteETag(p.ETag))
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
}

func (h *s3Handler) completeMultipartUpload(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	var in completeMultipartUploadRequest
	if err := xml.NewDecoder(io.LimitReader(r.Body, maxCompleteBody)).Decode(&in); err != nil || len(in.Parts) == 0 {
		writeS3Error(w, "MalformedXML", requestID, r.URL.Path)
		return
	}
	parts := make([]minio.CompletePart, 0, len(in.Parts))
	for _, p := range in.Parts {
		parts = append(parts, minio.CompletePart{PartNumber: p.PartNumber, ETag: strings.Trim(p.ETag, `"`)})
	}
	info, err := h.core().CompleteMultipartUpload(r.Context(), op.bucket, op.key, op.uploadID, parts, minio.PutObjectOptions{})
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	if info.VersionID != "" {
		w.Header().Set("x-amz-version-id", info.VersionID)
	}
	writeXML(w, http.StatusOK, requestID, completeMultipartUploadResult{
		Location: objectLocation(r, op), Bucket: op.bucket, Key: op.key, ETag: quoteETag(info.ETag)})
}

// objectLocation is CompleteMultipartUpload's Location: the object's path-style URL on this endpoint.
func objectLocation(r *http.Request, op s3op) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/" + op.bucket + "/" + s3utils.EncodePath(op.key)
}

func (h *s3Handler) abortMultipartUpload(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	if err := h.core().AbortMultipartUpload(r.Context(), op.bucket, op.key, op.uploadID); err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusNoContent)
}

// queryInt reads a non-negative integer query parameter, def when absent; ok=false for a malformed one.
func queryInt(q url.Values, name string, def int) (int, bool) {
	v := q.Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 0
}

func (h *s3Handler) listParts(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	q := r.URL.Query()
	maxParts, ok1 := queryInt(q, "max-parts", 1000)
	marker, ok2 := queryInt(q, "part-number-marker", 0)
	if !ok1 || !ok2 {
		writeS3Error(w, "InvalidArgument", requestID, r.URL.Path)
		return
	}
	if maxParts > 1000 || maxParts == 0 {
		maxParts = 1000
	}
	res, err := h.core().ListObjectParts(r.Context(), op.bucket, op.key, op.uploadID, marker, maxParts)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	out := listPartsResult{Bucket: op.bucket, Key: op.key, UploadID: op.uploadID, PartNumberMarker: marker,
		NextPartNumberMarker: res.NextPartNumberMarker, MaxParts: maxParts, IsTruncated: res.IsTruncated, StorageClass: "STANDARD"}
	for _, p := range res.ObjectParts {
		out.Parts = append(out.Parts, listedPart{PartNumber: p.PartNumber, LastModified: p.LastModified.UTC().Format(iso8601Millis),
			ETag: quoteETag(p.ETag), Size: p.Size})
	}
	writeXML(w, http.StatusOK, requestID, out)
}

func (h *s3Handler) listMultipartUploads(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	q := r.URL.Query()
	maxUploads, ok := queryInt(q, "max-uploads", 1000)
	if !ok {
		writeS3Error(w, "InvalidArgument", requestID, r.URL.Path)
		return
	}
	if maxUploads > 1000 || maxUploads == 0 {
		maxUploads = 1000
	}
	res, err := h.core().ListMultipartUploads(r.Context(), op.bucket, q.Get("prefix"), q.Get("key-marker"),
		q.Get("upload-id-marker"), q.Get("delimiter"), maxUploads)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	out := listMultipartUploadsResult{Bucket: op.bucket, KeyMarker: q.Get("key-marker"), UploadIDMarker: q.Get("upload-id-marker"),
		NextKeyMarker: res.NextKeyMarker, NextUploadIDMarker: res.NextUploadIDMarker, Prefix: q.Get("prefix"),
		Delimiter: q.Get("delimiter"), MaxUploads: maxUploads, IsTruncated: res.IsTruncated}
	for _, u := range res.Uploads {
		out.Uploads = append(out.Uploads, listedUpload{Key: u.Key, UploadID: u.UploadID,
			Initiated: u.Initiated.UTC().Format(iso8601Millis), StorageClass: "STANDARD"})
	}
	for _, p := range res.CommonPrefixes {
		out.CommonPrefixes = append(out.CommonPrefixes, commonPrefixEl{Prefix: p.Prefix})
	}
	writeXML(w, http.StatusOK, requestID, out)
}

// copyConditionHeaders are the copy preconditions passed on to MinIO, which evaluates them as S3 does.
var copyConditionHeaders = []string{"x-amz-copy-source-if-match", "x-amz-copy-source-if-none-match",
	"x-amz-copy-source-if-modified-since", "x-amz-copy-source-if-unmodified-since"}

func (h *s3Handler) copyObject(w http.ResponseWriter, r *http.Request, op s3op, src copySource, requestID string) {
	md := map[string]string{}
	for _, k := range copyConditionHeaders {
		if v := r.Header.Get(k); v != "" {
			md[k] = v
		}
	}
	// COPY (the default) keeps the source's metadata; REPLACE takes the request's Content-Type.
	switch d := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-metadata-directive"))); d {
	case "", "COPY":
	case "REPLACE":
		md["x-amz-metadata-directive"] = "REPLACE"
		if ct := r.Header.Get("Content-Type"); ct != "" {
			md["Content-Type"] = ct
		}
	default:
		writeS3ErrorFull(w, "InvalidArgument", http.StatusBadRequest, requestID, "Unknown metadata directive.", r.URL.Path)
		return
	}
	info, err := h.core().CopyObject(r.Context(), src.bucket, src.key, op.bucket, op.key, md,
		minio.CopySrcOptions{Bucket: src.bucket, Object: src.key, VersionID: src.versionID}, minio.PutObjectOptions{})
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	if info.VersionID != "" {
		w.Header().Set("x-amz-version-id", info.VersionID)
	}
	if src.versionID != "" {
		w.Header().Set("x-amz-copy-source-version-id", src.versionID)
	}
	writeXML(w, http.StatusOK, requestID, copyObjectResult{ETag: quoteETag(info.ETag), LastModified: lastModified(info.LastModified)})
}

// copyRangeRE is x-amz-copy-source-range: bytes=<first>-<last>.
var copyRangeRE = regexp.MustCompile(`^bytes=(\d+)-(\d+)$`)

func (h *s3Handler) uploadPartCopy(w http.ResponseWriter, r *http.Request, op s3op, src copySource, requestID string) {
	part, ok := partNumberOf(op.partNumber)
	if !ok {
		writeInvalidPartNumber(w, r, requestID)
		return
	}
	start, length := int64(0), int64(-1) // the whole source
	if rg := strings.TrimSpace(r.Header.Get("x-amz-copy-source-range")); rg != "" {
		m := copyRangeRE.FindStringSubmatch(rg)
		var first, last int64
		if m != nil {
			first, _ = strconv.ParseInt(m[1], 10, 64)
			last, _ = strconv.ParseInt(m[2], 10, 64)
		}
		if m == nil || last < first {
			writeS3ErrorFull(w, "InvalidArgument", http.StatusBadRequest, requestID,
				"The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy", r.URL.Path)
			return
		}
		start, length = first, last-first+1
	}
	md := map[string]string{}
	for _, k := range copyConditionHeaders {
		if v := r.Header.Get(k); v != "" {
			md[k] = v
		}
	}
	if src.versionID != "" { // minio-go's part copy names no version; the header is set whole instead
		md["x-amz-copy-source"] = s3utils.EncodePath(src.bucket+"/"+src.key) + "?versionId=" + url.QueryEscape(src.versionID)
	}
	p, err := h.core().CopyObjectPart(r.Context(), src.bucket, src.key, op.bucket, op.key, op.uploadID, part, start, length, md)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	if src.versionID != "" {
		w.Header().Set("x-amz-copy-source-version-id", src.versionID)
	}
	writeXML(w, http.StatusOK, requestID, copyPartResult{ETag: quoteETag(p.ETag), LastModified: lastModified(time.Now())})
}

func lastModified(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Format(iso8601Millis)
}

// getObjectTagging is GetObjectTagging: the object's tags, an empty TagSet when it has none (as S3).
func (h *s3Handler) getObjectTagging(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	t, err := h.mc.GetObjectTagging(r.Context(), op.bucket, op.key, minio.GetObjectTaggingOptions{VersionID: op.versionID})
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	var out s3Tagging
	if t != nil {
		m := t.ToMap()
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out.TagSet.Tag = append(out.TagSet.Tag, s3Tag{Key: k, Value: m[k]})
		}
	}
	if op.versionID != "" {
		w.Header().Set("x-amz-version-id", op.versionID)
	}
	writeXML(w, http.StatusOK, requestID, out)
}

// ---- GetBucketOwnershipControls ----

type ownershipControls struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ OwnershipControls"`
	Rule    struct {
		ObjectOwnership string `xml:"ObjectOwnership"`
	} `xml:"Rule"`
}

// getBucketOwnershipControls answers BucketOwnerEnforced (ACLs disabled), the only object ownership a
// bucket here has: CreateBucket refuses the others, as AWS's default since 2023.
func (h *s3Handler) getBucketOwnershipControls(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	exists, err := h.mc.BucketExists(r.Context(), op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	if !exists {
		writeS3Error(w, "NoSuchBucket", requestID, r.URL.Path)
		return
	}
	var out ownershipControls
	out.Rule.ObjectOwnership = "BucketOwnerEnforced"
	writeXML(w, http.StatusOK, requestID, out)
}

// requestSigningRegion is the region the request was signed for (its SigV4 credential scope, from the
// Authorization header or a pre-signed URL's X-Amz-Credential), or "" when it carries neither.
func requestSigningRegion(r *http.Request) string {
	if c, err := awssig.ParseAuthorization(r.Header.Get("Authorization")); err == nil {
		return c.Region
	}
	if p, err := awssig.ParsePresigned(r); err == nil {
		return p.Region
	}
	return ""
}
