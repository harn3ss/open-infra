package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/tags"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/s3authz"
)

// newS3Handler builds the S3 front door. dyn and cfg may be nil (no Kubernetes dynamic client): the
// handler then serves everything but CreateBucket and DeleteBucket.
func newS3Handler(cs kubernetes.Interface, mc *minio.Client, dyn dynamic.Interface, cfg *rest.Config, authzNS string,
	authz *dataplaneauthz.Checker, logger *slog.Logger, vhostSuffixes []string) *s3Handler {
	encEnv := os.Getenv("OBJECT_ENCRYPTION") == "true"
	encFile := getenv("OBJECT_ENCRYPTION_FILE", "/etc/openinfra/object-encryption/enabled")
	h := &s3Handler{cs: cs, mc: mc, authzNS: authzNS, authz: authz, logger: logger, vhostSuffixes: vhostSuffixes,
		bucketNS:           getenv("S3_BUCKET_NAMESPACE", defaultBucketNamespace),
		encryptsNewBuckets: func() bool { return encEnv || fileSaysTrue(encFile) }}
	if dyn != nil && cfg != nil {
		h.dyn = dyn
		h.callerDyn = func(user string, groups []string) (dynamic.Interface, error) {
			icfg := rest.CopyConfig(cfg)
			icfg.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
			return dynamic.NewForConfig(icfg)
		}
	}
	return h
}

// Bucket sub-resources and DeleteBucket. S3 addresses a bucket's configuration by a query-string
// sub-resource on the bucket URL (GET /bucket?versioning). Each one the shim serves is decoded to its
// own operation; any other sub-resource is refused as NotImplemented rather than being mistaken for a
// listing (GET /bucket?versioning used to come back as a ListBucketResult, which an SDK reads as
// "versioning never enabled").

// s3Subresources are the S3 sub-resource query keys. A request that carries one addresses that
// sub-resource, not the bucket or object itself. (Ordinary parameters such as prefix, list-type,
// versionId or a pre-signed URL's X-Amz-* and x-id are not sub-resources.)
var s3Subresources = []string{
	"versioning", "versions", "tagging", "location",
	"acl", "accelerate", "analytics", "attributes", "cors", "delete", "encryption", "intelligent-tiering",
	"inventory", "legal-hold", "lifecycle", "logging", "metrics", "notification", "object-lock",
	"ownershipControls", "partNumber", "policy", "policyStatus", "publicAccessBlock", "replication",
	"requestPayment", "restore", "retention", "select", "torrent", "uploadId", "uploads", "website",
}

// s3Subresource returns the sub-resource a request addresses, or "" for none.
func s3Subresource(q url.Values) string {
	for _, k := range s3Subresources {
		if _, ok := q[k]; ok {
			return k
		}
	}
	return ""
}

// decodeTarget maps a method on a bucket (key == "") or object onto an s3op, honouring the
// sub-resource the query names. ok=false means an operation the shim does not serve (NotImplemented).
func decodeTarget(method, bucket, key string, q url.Values) (s3op, bool) {
	sub := s3Subresource(q)
	if key == "" {
		switch {
		case sub == "" && method == http.MethodGet:
			return s3op{kind: "list-objects", bucket: bucket}, true
		case sub == "" && method == http.MethodHead:
			return s3op{kind: "head-bucket", bucket: bucket}, true
		case sub == "" && method == http.MethodPut:
			return s3op{kind: "create-bucket", bucket: bucket, write: true}, true
		case sub == "" && method == http.MethodDelete:
			return s3op{kind: "delete-bucket", bucket: bucket, write: true}, true
		case sub == "versioning" && method == http.MethodGet:
			return s3op{kind: "get-bucket-versioning", bucket: bucket}, true
		case sub == "versioning" && method == http.MethodPut:
			return s3op{kind: "put-bucket-versioning", bucket: bucket, write: true}, true
		case sub == "versions" && method == http.MethodGet:
			return s3op{kind: "list-object-versions", bucket: bucket}, true
		case sub == "tagging" && method == http.MethodGet:
			return s3op{kind: "get-bucket-tagging", bucket: bucket}, true
		case sub == "tagging" && method == http.MethodPut:
			return s3op{kind: "put-bucket-tagging", bucket: bucket, write: true}, true
		case sub == "tagging" && method == http.MethodDelete:
			return s3op{kind: "delete-bucket-tagging", bucket: bucket, write: true}, true
		case sub == "location" && method == http.MethodGet:
			return s3op{kind: "get-bucket-location", bucket: bucket}, true
		case sub == "encryption" && method == http.MethodGet:
			return s3op{kind: "get-bucket-encryption", bucket: bucket}, true
		case sub == "ownershipControls" && method == http.MethodGet:
			return s3op{kind: "get-bucket-ownership-controls", bucket: bucket}, true
		case sub == "ownershipControls" && method == http.MethodPut:
			return s3op{kind: "put-bucket-ownership-controls", bucket: bucket, write: true}, true
		case sub == "ownershipControls" && method == http.MethodDelete:
			return s3op{kind: "delete-bucket-ownership-controls", bucket: bucket, write: true}, true
		case sub == "policy" && method == http.MethodGet:
			return s3op{kind: "get-bucket-policy", bucket: bucket}, true
		case sub == "uploads" && method == http.MethodGet:
			return s3op{kind: "list-multipart-uploads", bucket: bucket}, true
		case sub == "delete" && method == http.MethodPost: // DeleteObjects: the keys are in the body
			return s3op{kind: "delete-objects", bucket: bucket, write: true}, true
		}
		return s3op{}, false
	}
	if op, ok, multipart := decodeMultipart(method, bucket, key, q); multipart {
		return op, ok
	}
	// GetObjectTagging: the AWS CLI reads a source object's tags before a large (multipart) copy.
	if sub == "tagging" && method == http.MethodGet {
		return s3op{kind: "get-object-tagging", bucket: bucket, key: key, versionID: q.Get("versionId")}, true
	}
	// PutObjectTagging / DeleteObjectTagging (#350 S).
	if sub == "tagging" && method == http.MethodPut {
		return s3op{kind: "put-object-tagging", bucket: bucket, key: key, versionID: q.Get("versionId"), write: true}, true
	}
	if sub == "tagging" && method == http.MethodDelete {
		return s3op{kind: "delete-object-tagging", bucket: bucket, key: key, versionID: q.Get("versionId"), write: true}, true
	}
	if sub != "" { // object tagging, ACLs, retention… are not served
		return s3op{}, false
	}
	v := q.Get("versionId")
	switch method {
	case http.MethodGet:
		return s3op{kind: "get", bucket: bucket, key: key, versionID: v}, true
	case http.MethodHead:
		return s3op{kind: "head", bucket: bucket, key: key, versionID: v}, true
	case http.MethodPut:
		return s3op{kind: "put", bucket: bucket, key: key, write: true}, true
	case http.MethodDelete:
		return s3op{kind: "delete", bucket: bucket, key: key, versionID: v, write: true}, true
	}
	return s3op{}, false
}

// action is the IAM action an operation is authorized as — AWS's action names, so a policy written
// for AWS (s3:GetBucketVersioning, s3:DeleteBucket, s3:GetObjectVersion …) governs it the same way.
func (op s3op) action() string {
	switch op.kind {
	case "get", "head":
		if op.versionID != "" {
			return "s3:GetObjectVersion"
		}
	case "delete":
		if op.versionID != "" {
			return "s3:DeleteObjectVersion"
		}
	case "delete-objects":
		// AWS has no s3:DeleteObjects: DeleteObjects is authorized key by key, each as s3:DeleteObject (or
		// s3:DeleteObjectVersion), by the handler (s3deleteobjects.go). This is only the action it is known by.
		return "s3:DeleteObject"
	case "get-bucket-versioning":
		return "s3:GetBucketVersioning"
	case "put-bucket-versioning":
		return "s3:PutBucketVersioning"
	case "list-object-versions":
		return "s3:ListBucketVersions"
	case "get-bucket-tagging":
		return "s3:GetBucketTagging"
	case "put-bucket-tagging", "delete-bucket-tagging": // AWS authorizes DeleteBucketTagging as PutBucketTagging
		return "s3:PutBucketTagging"
	case "get-bucket-location":
		return "s3:GetBucketLocation"
	case "get-bucket-encryption":
		return "s3:GetEncryptionConfiguration"
	case "get-bucket-ownership-controls":
		return "s3:GetBucketOwnershipControls"
	case "put-bucket-ownership-controls", "delete-bucket-ownership-controls": // AWS authorizes the delete as the put
		return "s3:PutBucketOwnershipControls"
	case "get-bucket-policy":
		return "s3:GetBucketPolicy"
	case "get-object-tagging":
		if op.versionID != "" {
			return "s3:GetObjectVersionTagging"
		}
		return "s3:GetObjectTagging"
	case "put-object-tagging":
		if op.versionID != "" {
			return "s3:PutObjectVersionTagging"
		}
		return "s3:PutObjectTagging"
	case "delete-object-tagging":
		if op.versionID != "" {
			return "s3:DeleteObjectVersionTagging"
		}
		return "s3:DeleteObjectTagging"
	// Multipart upload and copy, as AWS authorizes them: every step of an upload is s3:PutObject on the
	// object (the copy's source is checked separately, as s3:GetObject), aborting and listing have their
	// own actions.
	case "create-multipart-upload", "upload-part", "upload-part-copy", "complete-multipart-upload", "copy-object":
		return "s3:PutObject"
	case "abort-multipart-upload":
		return "s3:AbortMultipartUpload"
	case "list-parts":
		return "s3:ListMultipartUploadParts"
	case "list-multipart-uploads":
		return "s3:ListBucketMultipartUploads"
	case "create-bucket":
		return "s3:CreateBucket"
	case "delete-bucket":
		return "s3:DeleteBucket"
	}
	return s3Action(op.kind)
}

// ---- wire shapes ----

type versioningConfiguration struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ VersioningConfiguration"`
	Status  string   `xml:"Status,omitempty"`
}

type listVersionsResult struct {
	XMLName       xml.Name           `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListVersionsResult"`
	Name          string             `xml:"Name"`
	Prefix        string             `xml:"Prefix"`
	KeyMarker     string             `xml:"KeyMarker"`
	MaxKeys       int                `xml:"MaxKeys"`
	IsTruncated   bool               `xml:"IsTruncated"`
	Versions      []objectVersion    `xml:"Version"`
	DeleteMarkers []deleteMarkerItem `xml:"DeleteMarker"`
}

type objectVersion struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type deleteMarkerItem struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
}

type s3Tagging struct {
	XMLName xml.Name `xml:"Tagging"`
	TagSet  struct {
		Tag []s3Tag `xml:"Tag"`
	} `xml:"TagSet"`
}

type s3Tag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type locationConstraint struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint"`
	Region  string   `xml:",chardata"`
}

// ---- handlers ----

func (h *s3Handler) getBucketVersioning(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	cfg, err := h.mc.GetBucketVersioning(r.Context(), op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	// A bucket whose versioning was never set has no Status at all (AWS returns an empty document).
	writeXML(w, http.StatusOK, requestID, versioningConfiguration{Status: cfg.Status})
}

func (h *s3Handler) putBucketVersioning(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	var in versioningConfiguration
	if err := xml.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
		writeS3Error(w, "MalformedXML", requestID, r.URL.Path)
		return
	}
	if in.Status != "Enabled" && in.Status != "Suspended" {
		writeS3Error(w, "MalformedXML", requestID, r.URL.Path)
		return
	}
	if err := h.mc.SetBucketVersioning(r.Context(), op.bucket, minio.BucketVersioningConfiguration{Status: in.Status}); err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
}

func (h *s3Handler) listObjectVersions(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	prefix := r.URL.Query().Get("prefix")
	res := listVersionsResult{Name: op.bucket, Prefix: prefix, MaxKeys: 1000}
	for obj := range h.mc.ListObjects(r.Context(), op.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true, WithVersions: true}) {
		if obj.Err != nil {
			writeS3Error(w, minioErrToS3(obj.Err), requestID, r.URL.Path)
			return
		}
		vid := obj.VersionID
		if vid == "" {
			vid = "null" // an object written before versioning was enabled
		}
		mod := obj.LastModified.UTC().Format(iso8601Millis)
		if obj.IsDeleteMarker {
			res.DeleteMarkers = append(res.DeleteMarkers, deleteMarkerItem{Key: obj.Key, VersionID: vid, IsLatest: obj.IsLatest, LastModified: mod})
			continue
		}
		res.Versions = append(res.Versions, objectVersion{Key: obj.Key, VersionID: vid, IsLatest: obj.IsLatest,
			LastModified: mod, ETag: quoteETag(obj.ETag), Size: obj.Size, StorageClass: "STANDARD"})
	}
	writeXML(w, http.StatusOK, requestID, res)
}

// getBucketPolicy answers the bucket's policy document as MinIO holds it — a kind: Bucket's spec.policy is
// applied there verbatim (put-bucket-policy) — as the JSON body S3 returns; a bucket with none is
// NoSuchBucketPolicy, as on S3.
func (h *s3Handler) getBucketPolicy(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	p, err := h.mc.GetBucketPolicy(r.Context(), op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	if strings.TrimSpace(p) == "" {
		writeS3Error(w, "NoSuchBucketPolicy", requestID, r.URL.Path)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, p)
}

func (h *s3Handler) getBucketTagging(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	t, err := h.mc.GetBucketTagging(r.Context(), op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	m := t.ToMap()
	if len(m) == 0 {
		writeS3Error(w, "NoSuchTagSet", requestID, r.URL.Path)
		return
	}
	var out s3Tagging
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.TagSet.Tag = append(out.TagSet.Tag, s3Tag{Key: k, Value: m[k]})
	}
	writeXML(w, http.StatusOK, requestID, out)
}

func (h *s3Handler) putBucketTagging(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	var in s3Tagging
	if err := xml.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in); err != nil {
		writeS3Error(w, "MalformedXML", requestID, r.URL.Path)
		return
	}
	m := map[string]string{}
	for _, t := range in.TagSet.Tag {
		m[t.Key] = t.Value
	}
	bt, err := tags.NewTags(m, false)
	if err != nil { // more than 50 tags, or a key/value S3 does not allow
		writeS3Error(w, "InvalidTag", requestID, r.URL.Path)
		return
	}
	if err := h.mc.SetBucketTagging(r.Context(), op.bucket, bt); err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *s3Handler) deleteBucketTagging(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	if err := h.mc.RemoveBucketTagging(r.Context(), op.bucket); err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusNoContent)
}

func (h *s3Handler) getBucketLocation(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	if _, err := h.mc.GetBucketLocation(r.Context(), op.bucket); err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	// AWS returns an empty LocationConstraint for us-east-1, the region the shim reports.
	writeXML(w, http.StatusOK, requestID, locationConstraint{})
}

// serverSideEncryptionConfiguration is GetBucketEncryption's document.
type serverSideEncryptionConfiguration struct {
	XMLName xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ServerSideEncryptionConfiguration"`
	Rules   []sseRule `xml:"Rule"`
}

type sseRule struct {
	Default struct {
		SSEAlgorithm   string `xml:"SSEAlgorithm"`
		KMSMasterKeyID string `xml:"KMSMasterKeyID,omitempty"`
	} `xml:"ApplyServerSideEncryptionByDefault"`
	BucketKeyEnabled bool `xml:"BucketKeyEnabled"`
}

// getBucketEncryption returns the bucket's default encryption: AES256 on a bucket created while the
// platform's object encryption is on (storage/minio-kms.yaml). A bucket with none answers
// ServerSideEncryptionConfigurationNotFoundError, as S3 did before default encryption.
func (h *s3Handler) getBucketEncryption(w http.ResponseWriter, r *http.Request, op s3op, requestID string) {
	cfg, err := h.mc.GetBucketEncryption(r.Context(), op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	var out serverSideEncryptionConfiguration
	for _, rule := range cfg.Rules {
		var x sseRule
		x.Default.SSEAlgorithm = rule.Apply.SSEAlgorithm
		x.Default.KMSMasterKeyID = rule.Apply.KmsMasterKeyID
		out.Rules = append(out.Rules, x)
	}
	if len(out.Rules) == 0 {
		writeS3Error(w, "ServerSideEncryptionConfigurationNotFoundError", requestID, r.URL.Path)
		return
	}
	writeXML(w, http.StatusOK, requestID, out)
}

// ---- DeleteBucket ----

// platformBuckets are owned by the platform: never deleted through the S3 API, and reachable by admins
// only (s3authz.Gate). Kept in step with PLATFORM_BUCKETS in platform/abstraction/provider-setup.yaml
// (TestPlatformBucketsMatchOwnership).
var platformBuckets = s3authz.PlatformBuckets

var (
	xbucketGVR = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "xbuckets"}
	bucketGVR  = schema.GroupVersionResource{Group: "openinfra.dev", Version: "v1", Resource: "buckets"}
)

// bucketClaim is the kind: Bucket claim that is a bucket's AWS-visible resource.
type bucketClaim struct{ namespace, name string }

// bucketClaimFor finds the kind: Bucket claim whose bucket is name (its composite reports the bucket in
// status.bucket). ok=false: no kind: Bucket is this bucket — it belongs to another kind (a StaticSite's
// own bucket, an Application's storage) or to nothing the platform manages.
func bucketClaimFor(ctx context.Context, dyn dynamic.Interface, name string) (bucketClaim, bool, error) {
	l, err := dyn.Resource(xbucketGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return bucketClaim{}, false, err
	}
	for _, x := range l.Items {
		b, _, _ := unstructuredString(x.Object, "status", "bucket")
		if b == "" {
			b, _, _ = unstructuredString(x.Object, "spec", "bucketName")
		}
		if b != name {
			continue
		}
		lbl := x.GetLabels()
		ns, cn := lbl["crossplane.io/claim-namespace"], lbl["crossplane.io/claim-name"]
		if ns == "" || cn == "" {
			continue
		}
		return bucketClaim{namespace: ns, name: cn}, true, nil
	}
	return bucketClaim{}, false, nil
}

func unstructuredString(obj map[string]any, path ...string) (string, bool, error) {
	cur := any(obj)
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false, nil
		}
		cur = m[p]
	}
	s, ok := cur.(string)
	return s, ok, nil
}

// bucketEmpty reports whether a bucket holds no objects, no prior versions and no delete markers — the
// condition AWS requires before it deletes a bucket.
func bucketEmpty(ctx context.Context, mc *minio.Client, name string) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for obj := range mc.ListObjects(ctx, name, minio.ListObjectsOptions{Recursive: true, WithVersions: true, MaxKeys: 1}) {
		if obj.Err != nil {
			return false, obj.Err
		}
		return false, nil
	}
	return true, nil
}

// errBucketNotEmpty is returned when a bucket still holds data.
var errBucketNotEmpty = errors.New("BucketNotEmpty")

// deleteBucket is S3 DeleteBucket. A bucket here is the bucket of a kind: Bucket claim — the claim is the
// resource AWS's bucket is, so deleting the bucket deletes the claim (with the caller's own authority,
// so RBAC decides whether they may) and then the now-empty MinIO bucket; the bucket reaper removes the
// claim's MinIO user and credentials. A bucket that is not a kind: Bucket's — a platform bucket, a
// StaticSite's or an Application's own, or one the platform does not manage — is refused: deleting it
// would break the resource that uses it, and that resource is what to delete.
func (h *s3Handler) deleteBucket(w http.ResponseWriter, r *http.Request, claims iam.Claims, op s3op, requestID string) {
	ctx := r.Context()
	if isPlatformBucket(op.bucket) {
		writeS3ErrorFull(w, "AccessDenied", http.StatusForbidden, requestID, "Bucket "+op.bucket+" is a platform bucket and cannot be deleted.", r.URL.Path)
		return
	}
	exists, err := h.mc.BucketExists(ctx, op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	if !exists {
		writeS3Error(w, "NoSuchBucket", requestID, r.URL.Path)
		return
	}
	if h.dyn == nil || h.callerDyn == nil {
		writeS3Error(w, "NotImplemented", requestID, r.URL.Path)
		return
	}
	claim, ok, err := bucketClaimFor(ctx, h.dyn, op.bucket)
	if err != nil {
		h.logger.Error("s3 DeleteBucket: listing buckets", "bucket", op.bucket, "err", err)
		writeS3Error(w, "InternalError", requestID, r.URL.Path)
		return
	}
	if !ok {
		writeS3ErrorFull(w, "AccessDenied", http.StatusForbidden, requestID,
			"Bucket "+op.bucket+" is not a kind: Bucket's bucket (it belongs to another resource, or to nothing the platform manages); delete the resource that owns it.", r.URL.Path)
		return
	}
	if empty, err := bucketEmpty(ctx, h.mc, op.bucket); err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	} else if !empty {
		writeS3Error(w, "BucketNotEmpty", requestID, r.URL.Path)
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
	if err := cdyn.Resource(bucketGVR).Namespace(claim.namespace).Delete(ctx, claim.name, metav1.DeleteOptions{}); err != nil {
		h.logger.Warn("s3 DeleteBucket: deleting the claim", "bucket", op.bucket, "claim", claim.namespace+"/"+claim.name, "user", claims.Sub, "err", err)
		writeS3ErrorFull(w, "AccessDenied", http.StatusForbidden, requestID,
			fmt.Sprintf("Access Denied: may not delete kind: Bucket %s/%s, which this bucket is.", claim.namespace, claim.name), r.URL.Path)
		return
	}
	if err := removeEmptyBucket(ctx, h.mc, op.bucket); err != nil {
		if errors.Is(err, errBucketNotEmpty) {
			writeS3Error(w, "BucketNotEmpty", requestID, r.URL.Path)
			return
		}
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	h.logger.Info("s3 DeleteBucket", "bucket", op.bucket, "claim", claim.namespace+"/"+claim.name, "user", claims.Sub)
	w.Header().Set("x-amz-request-id", requestID)
	w.WriteHeader(http.StatusNoContent)
}

// removeEmptyBucket removes a bucket that holds nothing. The claim's setup Job may still be running
// against it for a moment after the claim is deleted, so a transient failure is retried briefly; a
// bucket that is (or has become) non-empty is errBucketNotEmpty, and one already gone is success.
func removeEmptyBucket(ctx context.Context, mc *minio.Client, name string) error {
	var last error
	for i := 0; i < 5; i++ {
		err := mc.RemoveBucket(ctx, name)
		if err == nil {
			return nil
		}
		switch minio.ToErrorResponse(err).Code {
		case "NoSuchBucket":
			return nil
		case "BucketNotEmpty":
			return errBucketNotEmpty
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return last
}

// isPlatformBucket reports whether name is a platform bucket.
func isPlatformBucket(name string) bool {
	for _, p := range platformBuckets {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}
