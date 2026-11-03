package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/minio/minio-go/v7"
)

// DeleteObjects (POST /<bucket>?delete): S3's batch delete of up to 1000 keys in one request. As on AWS
// there is no s3:DeleteObjects action: the request as a whole is not authorized, each key is — as
// s3:DeleteObject, or s3:DeleteObjectVersion when the entry names a VersionId — and a key the caller may
// not delete comes back as that key's AccessDenied error while the others are deleted (a 200 either way).
// Quiet mode leaves the deleted keys out of the answer; errors are always listed.

// maxDeleteObjects is S3's limit on the keys one DeleteObjects request may name.
const maxDeleteObjects = 1000

// maxDeleteBody bounds the request document: 1000 keys of S3's 1024-byte maximum, escaped, fit well
// within it.
const maxDeleteBody = 2 << 20

// deleteRequest is the DeleteObjects request document (<Delete xmlns="…">; any namespace is accepted).
type deleteRequest struct {
	XMLName xml.Name `xml:"Delete"`
	Quiet   bool     `xml:"Quiet"`
	Objects []struct {
		Key       *string `xml:"Key"`
		VersionID string  `xml:"VersionId"`
	} `xml:"Object"`
}

// deleteResult is the DeleteObjects answer.
type deleteResult struct {
	XMLName xml.Name        `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
	Deleted []deletedObject `xml:"Deleted"`
	Errors  []deleteError   `xml:"Error"`
}

type deletedObject struct {
	Key                   string `xml:"Key"`
	VersionID             string `xml:"VersionId,omitempty"`
	DeleteMarker          bool   `xml:"DeleteMarker,omitempty"`
	DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId,omitempty"`
}

type deleteError struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId,omitempty"`
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
}

// deleteEntry is one key of the request, in request order.
type deleteEntry struct{ key, versionID string }

func (e deleteEntry) id() string { return e.key + "\x00" + e.versionID }

// deleteObjects serves DeleteObjects. op.bucket is the bucket; the keys are in the body.
func (h *s3Handler) deleteObjects(w http.ResponseWriter, r *http.Request, claims iam.Claims, op s3op, requestID string) {
	var body io.Reader = r.Body
	chunked := isAwsChunked(r)
	if chunked {
		body = newAwsChunkedReader(r.Body)
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxDeleteBody+1))
	if err != nil || len(raw) > maxDeleteBody {
		writeS3Error(w, "MalformedXML", requestID, r.URL.Path)
		return
	}
	// The document's integrity: Content-MD5 (the CLI and older SDKs) or a flexible checksum header (the
	// newer SDKs' default). A checksum carried in an aws-chunked trailer is not checked here.
	if code, msg := checkDeleteDigest(r.Header, raw, chunked); code != "" {
		status := http.StatusBadRequest
		if info, ok := s3Errors[code]; ok {
			status = info.Status
		}
		writeS3ErrorFull(w, code, status, requestID, msg, r.URL.Path)
		return
	}
	var in deleteRequest
	if err := xml.Unmarshal(raw, &in); err != nil || len(in.Objects) == 0 || len(in.Objects) > maxDeleteObjects {
		writeS3Error(w, "MalformedXML", requestID, r.URL.Path)
		return
	}
	entries := make([]deleteEntry, 0, len(in.Objects))
	for _, o := range in.Objects {
		if o.Key == nil || *o.Key == "" {
			writeS3Error(w, "MalformedXML", requestID, r.URL.Path)
			return
		}
		entries = append(entries, deleteEntry{key: *o.Key, versionID: strings.TrimSpace(o.VersionID)})
	}

	exists, err := h.mc.BucketExists(r.Context(), op.bucket)
	if err != nil {
		writeS3Error(w, minioErrToS3(err), requestID, r.URL.Path)
		return
	}
	if !exists {
		writeS3Error(w, "NoSuchBucket", requestID, r.URL.Path)
		return
	}

	// Authorize each key on its own object (Bucket::<bucket>/<key>), as AWS does: a grant on a prefix
	// deletes the keys under it and no others. The coarse review depends only on the verb, so the batch
	// makes it once.
	batch := h.gate().Batch()
	var res deleteResult
	var allowed []deleteEntry
	for _, e := range entries {
		keyOp := s3op{kind: "delete", bucket: op.bucket, key: e.key, versionID: e.versionID, write: true}
		if !h.allowedIn(batch, r, claims, keyOp) {
			res.Errors = append(res.Errors, perKeyError(e, "AccessDenied"))
			continue
		}
		allowed = append(allowed, e)
	}

	if len(allowed) > 0 {
		results, batchErr := h.removeBatch(r, op.bucket, allowed)
		for _, e := range allowed {
			rr, found := results[e.id()]
			switch {
			case found && rr.Err != nil:
				res.Errors = append(res.Errors, perKeyError(e, minioErrToS3(rr.Err)))
			case !found && batchErr != nil:
				res.Errors = append(res.Errors, perKeyError(e, minioErrToS3(batchErr)))
			default:
				// MinIO lists no result for a version that does not exist; S3 reports a key or version
				// that is not there as deleted.
				if !in.Quiet {
					d := deletedObject{Key: e.key, VersionID: e.versionID}
					if found {
						d.DeleteMarker, d.DeleteMarkerVersionID = rr.DeleteMarker, rr.DeleteMarkerVersionID
					}
					res.Deleted = append(res.Deleted, d)
				}
			}
		}
	}
	h.logger.Info("s3 DeleteObjects", "user", claims.Sub, "bucket", op.bucket, "keys", len(entries),
		"denied", len(entries)-len(allowed), "errors", len(res.Errors))
	writeXML(w, http.StatusOK, requestID, res)
}

// removeBatch deletes the entries through MinIO's own multi-object delete, returning each key's result by
// entry id. batchErr is an error MinIO gave for the batch as a whole (no key named): the keys it left
// without a result share it.
func (h *s3Handler) removeBatch(r *http.Request, bucket string, entries []deleteEntry) (map[string]minio.RemoveObjectResult, error) {
	asked := make(map[string]bool, len(entries))
	ch := make(chan minio.ObjectInfo, len(entries))
	for _, e := range entries {
		asked[e.id()] = true
		ch <- minio.ObjectInfo{Key: e.key, VersionID: e.versionID}
	}
	close(ch)
	out := map[string]minio.RemoveObjectResult{}
	var batchErr error
	for rr := range h.mc.RemoveObjectsWithResult(r.Context(), bucket, ch, minio.RemoveObjectsOptions{}) {
		if rr.ObjectName == "" {
			if rr.Err != nil {
				batchErr = rr.Err
			}
			continue
		}
		e := deleteEntry{key: rr.ObjectName, versionID: rr.ObjectVersionID}
		if !asked[e.id()] {
			// A delete that named no version may be answered with the version it removed: it is the
			// key's result as asked for.
			e.versionID = ""
		}
		out[e.id()] = rr
	}
	if err := r.Context().Err(); err != nil && batchErr == nil {
		batchErr = err
	}
	return out, batchErr
}

func perKeyError(e deleteEntry, code string) deleteError {
	msg := "We encountered an internal error. Please try again."
	if info, ok := s3Errors[code]; ok {
		msg = info.Message
	} else {
		code = "InternalError"
	}
	if code == "AccessDenied" {
		msg = "Access Denied"
	}
	return deleteError{Key: e.key, VersionID: e.versionID, Code: code, Message: msg}
}

// checkDeleteDigest verifies the request document against the digests it carries: Content-MD5, and an
// x-amz-checksum-{crc32,crc32c,sha1,sha256} header. It returns S3's error code and message for a
// malformed or mismatched one, or "" when they hold (or none is sent: the shim does not insist on one).
func checkDeleteDigest(hd http.Header, body []byte, chunked bool) (code, message string) {
	if v := hd.Get("Content-MD5"); v != "" {
		want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
		if err != nil || len(want) != md5.Size {
			return "InvalidDigest", s3Errors["InvalidDigest"].Message
		}
		if got := md5.Sum(body); !bytes.Equal(got[:], want) {
			return "BadDigest", s3Errors["BadDigest"].Message
		}
	}
	if chunked {
		return "", ""
	}
	for _, c := range []struct {
		header, name string
		h            func() hash.Hash
	}{
		{"x-amz-checksum-crc32", "CRC32", func() hash.Hash { return crc32.NewIEEE() }},
		{"x-amz-checksum-crc32c", "CRC32C", func() hash.Hash { return crc32.New(crc32.MakeTable(crc32.Castagnoli)) }},
		{"x-amz-checksum-sha1", "SHA1", sha1.New},
		{"x-amz-checksum-sha256", "SHA256", sha256.New},
	} {
		v := hd.Get(c.header)
		if v == "" {
			continue
		}
		want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
		hh := c.h()
		if err != nil || len(want) != hh.Size() {
			return "InvalidRequest", "Value for " + c.header + " header is invalid."
		}
		hh.Write(body)
		if !bytes.Equal(hh.Sum(nil), want) {
			return "BadDigest", "The " + c.name + " you specified did not match the calculated checksum."
		}
	}
	return "", ""
}
