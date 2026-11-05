package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// fakeMPS3 is a minimal S3 server for minio-go's multipart and copy calls: objects with bytes (and
// versions), multipart uploads and their parts.
type fakeMPS3 struct {
	mu         sync.Mutex
	objects    map[string][]byte // "bucket/key" -> bytes (the latest)
	versions   map[string][]byte // "bucket/key?versionId" -> bytes
	tags       map[string]string // "bucket/key" -> <Tag> elements
	uploads    map[string]*fakeUpload
	nextID     int
	firstByte  chan struct{} // closed when a part's first bytes arrive (streaming check)
	gotFirst   bool
	createTags []string // x-amz-tagging of each CreateMultipartUpload
	rangedGets int      // GETs with a Range header
}

type fakeUpload struct {
	bucket, key string
	parts       map[int][]byte
	initiated   time.Time
}

func newFakeMPS3() *fakeMPS3 {
	return &fakeMPS3{objects: map[string][]byte{}, versions: map[string][]byte{}, tags: map[string]string{},
		uploads: map[string]*fakeUpload{}, firstByte: make(chan struct{})}
}

func md5hex(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }

func (f *fakeMPS3) xml(w http.ResponseWriter, v string) {
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` + v))
}

func (f *fakeMPS3) fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<Error><Code>` + code + `</Code><Message>` + code + `</Message></Error>`))
}

// source returns the bytes x-amz-copy-source names.
func (f *fakeMPS3) source(h string) ([]byte, bool) {
	ver := ""
	if i := strings.Index(h, "?versionId="); i >= 0 {
		ver, h = h[i+len("?versionId="):], h[:i]
	}
	p, _ := url.PathUnescape(strings.TrimPrefix(h, "/"))
	if ver != "" {
		b, ok := f.versions[p+"?"+ver]
		return b, ok
	}
	b, ok := f.objects[p]
	return b, ok
}

func (f *fakeMPS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(p, "/")
	q := r.URL.Query()
	_, uploads := q["uploads"]
	uploadID := q.Get("uploadId")
	switch {
	case key == "" && r.Method == http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case key == "" && uploads && r.Method == http.MethodGet:
		f.mu.Lock()
		var sb strings.Builder
		sb.WriteString(`<ListMultipartUploadsResult><Bucket>` + bucket + `</Bucket><IsTruncated>false</IsTruncated>`)
		ids := make([]string, 0, len(f.uploads))
		for id := range f.uploads {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			u := f.uploads[id]
			if u.bucket == bucket && strings.HasPrefix(u.key, q.Get("prefix")) {
				sb.WriteString(`<Upload><Key>` + u.key + `</Key><UploadId>` + id + `</UploadId><Initiated>` + u.initiated.Format(iso8601Millis) + `</Initiated></Upload>`)
			}
		}
		sb.WriteString(`</ListMultipartUploadsResult>`)
		f.mu.Unlock()
		f.xml(w, sb.String())
	case uploads && r.Method == http.MethodPost:
		f.mu.Lock()
		f.nextID++
		id := fmt.Sprintf("upload-%d", f.nextID)
		f.uploads[id] = &fakeUpload{bucket: bucket, key: key, parts: map[int][]byte{}, initiated: time.Now()}
		f.createTags = append(f.createTags, r.Header.Get("X-Amz-Tagging"))
		f.mu.Unlock()
		f.xml(w, `<InitiateMultipartUploadResult><Bucket>`+bucket+`</Bucket><Key>`+key+`</Key><UploadId>`+id+`</UploadId></InitiateMultipartUploadResult>`)
	case uploadID != "" && r.Method == http.MethodPut:
		n, _ := strconv.Atoi(q.Get("partNumber"))
		f.mu.Lock()
		u := f.uploads[uploadID]
		f.mu.Unlock()
		if u == nil {
			f.fail(w, 404, "NoSuchUpload")
			return
		}
		var data []byte
		if cs := r.Header.Get("x-amz-copy-source"); cs != "" {
			f.mu.Lock()
			src, ok := f.source(cs)
			f.mu.Unlock()
			if !ok {
				f.fail(w, 404, "NoSuchKey")
				return
			}
			if rg := r.Header.Get("x-amz-copy-source-range"); rg != "" {
				var a, b int
				_, _ = fmt.Sscanf(rg, "bytes=%d-%d", &a, &b)
				src = src[a : b+1]
			}
			data = append([]byte(nil), src...)
			f.mu.Lock()
			u.parts[n] = data
			f.mu.Unlock()
			f.xml(w, `<CopyPartResult><ETag>"`+md5hex(data)+`"</ETag><LastModified>2026-11-02T00:00:00.000Z</LastModified></CopyPartResult>`)
			return
		}
		var body io.Reader = r.Body
		if isAwsChunked(r) {
			body = newAwsChunkedReader(r.Body)
		}
		buf := make([]byte, 32<<10)
		for {
			k, err := body.Read(buf)
			if k > 0 {
				data = append(data, buf[:k]...)
				f.mu.Lock()
				if !f.gotFirst {
					f.gotFirst = true
					close(f.firstByte)
				}
				f.mu.Unlock()
			}
			if err != nil {
				break
			}
		}
		if m := r.Header.Get("Content-Md5"); m != "" {
			sum := md5.Sum(data)
			if base64.StdEncoding.EncodeToString(sum[:]) != m {
				f.fail(w, 400, "BadDigest")
				return
			}
		}
		f.mu.Lock()
		u.parts[n] = data
		f.mu.Unlock()
		w.Header().Set("ETag", `"`+md5hex(data)+`"`)
	case uploadID != "" && r.Method == http.MethodPost:
		var in struct {
			Parts []struct {
				PartNumber int
				ETag       string
			} `xml:"Part"`
		}
		_ = xml.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		u := f.uploads[uploadID]
		if u == nil {
			f.fail(w, 404, "NoSuchUpload")
			return
		}
		var all, sums []byte
		for i, cp := range in.Parts {
			if i > 0 && cp.PartNumber <= in.Parts[i-1].PartNumber {
				f.fail(w, 400, "InvalidPartOrder")
				return
			}
			d, ok := u.parts[cp.PartNumber]
			if !ok || strings.Trim(cp.ETag, `"`) != md5hex(d) {
				f.fail(w, 400, "InvalidPart")
				return
			}
			all = append(all, d...)
			s := md5.Sum(d)
			sums = append(sums, s[:]...)
		}
		etag := fmt.Sprintf("%s-%d", md5hex(sums), len(in.Parts))
		f.objects[bucket+"/"+key] = all
		delete(f.uploads, uploadID)
		f.xml(w, `<CompleteMultipartUploadResult><Bucket>`+bucket+`</Bucket><Key>`+key+`</Key><ETag>"`+etag+`"</ETag></CompleteMultipartUploadResult>`)
	case uploadID != "" && r.Method == http.MethodDelete:
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.uploads[uploadID] == nil {
			f.fail(w, 404, "NoSuchUpload")
			return
		}
		delete(f.uploads, uploadID)
		w.WriteHeader(http.StatusNoContent)
	case uploadID != "" && r.Method == http.MethodGet:
		f.mu.Lock()
		defer f.mu.Unlock()
		u := f.uploads[uploadID]
		if u == nil {
			f.fail(w, 404, "NoSuchUpload")
			return
		}
		var sb strings.Builder
		sb.WriteString(`<ListPartsResult><Bucket>` + bucket + `</Bucket><Key>` + key + `</Key><UploadId>` + uploadID + `</UploadId><IsTruncated>false</IsTruncated>`)
		nums := make([]int, 0, len(u.parts))
		for n := range u.parts {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		for _, n := range nums {
			sb.WriteString(fmt.Sprintf(`<Part><PartNumber>%d</PartNumber><LastModified>2026-11-02T00:00:00.000Z</LastModified><ETag>"%s"</ETag><Size>%d</Size></Part>`, n, md5hex(u.parts[n]), len(u.parts[n])))
		}
		sb.WriteString(`</ListPartsResult>`)
		f.xml(w, sb.String())
	case key != "" && r.Method == http.MethodPut && r.Header.Get("x-amz-copy-source") != "":
		f.mu.Lock()
		defer f.mu.Unlock()
		src, ok := f.source(r.Header.Get("x-amz-copy-source"))
		if !ok {
			f.fail(w, 404, "NoSuchKey")
			return
		}
		f.objects[bucket+"/"+key] = append([]byte(nil), src...)
		f.xml(w, `<CopyObjectResult><ETag>"`+md5hex(src)+`"</ETag><LastModified>2026-11-02T00:00:00.000Z</LastModified></CopyObjectResult>`)
	case key != "" && (r.Method == http.MethodPut || r.Method == http.MethodDelete) && q.Has("tagging"):
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		_, ok := f.objects[bucket+"/"+key]
		if ok {
			s := string(body)
			if i, j := strings.Index(s, "<TagSet>"), strings.Index(s, "</TagSet>"); r.Method == http.MethodPut && i >= 0 && j > i {
				f.tags[bucket+"/"+key] = s[i+len("<TagSet>") : j]
			} else {
				delete(f.tags, bucket+"/"+key)
			}
		}
		f.mu.Unlock()
		if !ok {
			f.fail(w, 404, "NoSuchKey")
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	case key != "" && r.Method == http.MethodGet && q.Has("tagging"):
		f.mu.Lock()
		_, ok := f.objects[bucket+"/"+key]
		tags := f.tags[bucket+"/"+key]
		f.mu.Unlock()
		if !ok {
			f.fail(w, 404, "NoSuchKey")
			return
		}
		f.xml(w, `<Tagging><TagSet>`+tags+`</TagSet></Tagging>`)
	case key != "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		f.mu.Lock()
		b, ok := f.objects[bucket+"/"+key]
		f.mu.Unlock()
		if !ok {
			if r.Method == http.MethodHead {
				w.WriteHeader(404)
				return
			}
			f.fail(w, 404, "NoSuchKey")
			return
		}
		w.Header().Set("ETag", `"`+md5hex(b)+`"`)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/octet-stream")
		if rg := r.Header.Get("Range"); rg != "" && r.Method == http.MethodGet {
			f.mu.Lock()
			f.rangedGets++
			f.mu.Unlock()
			var a, e int
			if _, err := fmt.Sscanf(rg, "bytes=%d-%d", &a, &e); err != nil || a > e || a >= len(b) {
				f.fail(w, 416, "InvalidRange")
				return
			}
			if e >= len(b) {
				e = len(b) - 1
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", a, e, len(b)))
			w.Header().Set("Content-Length", strconv.Itoa(e-a+1))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(b[a : e+1])
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	case key != "" && r.Method == http.MethodPut:
		var body io.Reader = r.Body
		if isAwsChunked(r) {
			body = newAwsChunkedReader(r.Body)
		}
		data, _ := io.ReadAll(body)
		f.mu.Lock()
		f.objects[bucket+"/"+key] = data
		f.mu.Unlock()
		w.Header().Set("ETag", `"`+md5hex(data)+`"`)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func fakeMPMinio(t *testing.T, f *fakeMPS3) *minio.Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	mc, err := minio.New(u.Host, &minio.Options{Creds: credentials.NewStaticV4("a", "b", ""), Region: "us-east-1", BucketLookup: minio.BucketLookupPath})
	if err != nil {
		t.Fatal(err)
	}
	return mc
}

// awsChunked frames body as the CLI does with a trailing checksum (aws-chunked, STREAMING-…-TRAILER).
func awsChunked(body []byte, chunk int) []byte {
	var b bytes.Buffer
	for i := 0; i < len(body); i += chunk {
		end := i + chunk
		if end > len(body) {
			end = len(body)
		}
		fmt.Fprintf(&b, "%x\r\n", end-i)
		b.Write(body[i:end])
		b.WriteString("\r\n")
	}
	b.WriteString("0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n")
	return b.Bytes()
}

func TestS3Decode_MultipartAndCopy(t *testing.T) {
	cases := []struct {
		method, url, copySrc string
		ok                   bool
		kind                 string
		write                bool
	}{
		{"POST", "/b/k?uploads", "", true, "create-multipart-upload", true},
		{"PUT", "/b/k?partNumber=3&uploadId=u1", "", true, "upload-part", true},
		{"PUT", "/b/k?partNumber=3&uploadId=u1", "/src/obj", true, "upload-part-copy", true},
		{"POST", "/b/k?uploadId=u1", "", true, "complete-multipart-upload", true},
		{"DELETE", "/b/k?uploadId=u1", "", true, "abort-multipart-upload", true},
		{"GET", "/b/k?uploadId=u1", "", true, "list-parts", false},
		{"GET", "/b?uploads", "", true, "list-multipart-uploads", false},
		{"GET", "/b?uploads&prefix=k", "", true, "list-multipart-uploads", false},
		{"PUT", "/b/k", "/src/obj", true, "copy-object", true},
		{"GET", "/b?ownershipControls", "", true, "get-bucket-ownership-controls", false},
		{"PUT", "/b?ownershipControls", "", true, "put-bucket-ownership-controls", true},
		{"DELETE", "/b?ownershipControls", "", true, "delete-bucket-ownership-controls", true},
		// a pre-signed UploadPart URL is still an UploadPart
		{"PUT", "/b/k?partNumber=1&uploadId=u1&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc", "", true, "upload-part", true},
		// not served: a part GET (GetObject ?partNumber) and a POST ?uploads on a bucket
		{"GET", "/b/k?partNumber=1", "", false, "", false},
		{"PUT", "/b/k?uploads", "", false, "", false},
		{"POST", "/b?uploads", "", false, "", false},
	}
	h := &s3Handler{}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "https://s3.example.com"+c.url, nil)
		if c.copySrc != "" {
			r.Header.Set("x-amz-copy-source", c.copySrc)
		}
		op, ok := h.decode(r)
		if ok != c.ok || (ok && (op.kind != c.kind || op.write != c.write || op.bucket != "b")) {
			t.Errorf("%s %s (copy %q): decode = %+v ok=%v; want kind=%q write=%v ok=%v", c.method, c.url, c.copySrc, op, ok, c.kind, c.write, c.ok)
		}
		if ok && strings.Contains(c.url, "uploadId=u1") && op.uploadID != "u1" {
			t.Errorf("%s %s: uploadID = %q", c.method, c.url, op.uploadID)
		}
	}
}

func TestS3OpAction_MultipartAndCopy(t *testing.T) {
	cases := map[string]string{
		"create-multipart-upload":          "s3:PutObject",
		"upload-part":                      "s3:PutObject",
		"upload-part-copy":                 "s3:PutObject",
		"complete-multipart-upload":        "s3:PutObject",
		"copy-object":                      "s3:PutObject",
		"abort-multipart-upload":           "s3:AbortMultipartUpload",
		"list-parts":                       "s3:ListMultipartUploadParts",
		"list-multipart-uploads":           "s3:ListBucketMultipartUploads",
		"get-bucket-ownership-controls":    "s3:GetBucketOwnershipControls",
		"put-bucket-ownership-controls":    "s3:PutBucketOwnershipControls",
		"delete-bucket-ownership-controls": "s3:PutBucketOwnershipControls",
	}
	for kind, want := range cases {
		if got := (s3op{kind: kind}).action(); got != want {
			t.Errorf("%s action = %q, want %q", kind, got, want)
		}
	}
}

func TestParseCopySource(t *testing.T) {
	cases := []struct {
		in   string
		want copySource
		ok   bool
	}{
		{"src/dir/obj.txt", copySource{"src", "dir/obj.txt", ""}, true},
		{"/src/obj", copySource{"src", "obj", ""}, true},
		{"src/a%20b%2Bc.txt", copySource{"src", "a b+c.txt", ""}, true},
		{"/src/obj?versionId=v%2B1", copySource{"src", "obj", "v+1"}, true},
		{"src", copySource{}, false},
		{"/src/", copySource{}, false},
		{"arn:aws:s3:us-east-1:111122223333:accesspoint/ap/object/obj", copySource{}, false},
	}
	for _, c := range cases {
		got, ok := parseCopySource(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parseCopySource(%q) = %+v %v, want %+v %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// A multipart upload round-trips byte-identical: an aws-chunked part (the CLI's trailing checksum) is
// stored without its framing, a Content-MD5 part is passed on (and checked), and the completed object is
// the parts in order with an S3 multipart ETag.
func TestS3Multipart_RoundTrip(t *testing.T) {
	f := newFakeMPS3()
	h := &s3Handler{mc: fakeMPMinio(t, f), logger: discardLogger()}
	op := s3op{bucket: "data", key: "dir/big.bin"}

	w := httptest.NewRecorder()
	h.createMultipartUpload(w, httptest.NewRequest("POST", "/data/dir/big.bin?uploads", nil), op, "r")
	var init initiateMultipartUploadResult
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &init) != nil || init.UploadID == "" || init.Key != "dir/big.bin" {
		t.Fatalf("CreateMultipartUpload = %d %s", w.Code, w.Body)
	}
	op.uploadID = init.UploadID

	part1 := bytes.Repeat([]byte("a"), 300<<10)
	part2 := []byte("the last, short part")
	// Part 1: aws-chunked framing (a trailing checksum), as the CLI v2 sends by default.
	r := httptest.NewRequest("PUT", "/data/dir/big.bin?partNumber=1&uploadId="+op.uploadID, bytes.NewReader(awsChunked(part1, 64<<10)))
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len(part1)))
	w = httptest.NewRecorder()
	op.partNumber = "1"
	h.uploadPart(w, r, op, "r")
	etag1 := w.Header().Get("ETag")
	if w.Code != 200 || etag1 != `"`+md5hex(part1)+`"` {
		t.Fatalf("UploadPart 1 = %d %s ETag %q", w.Code, w.Body, etag1)
	}
	// Part 2: a plain body with Content-MD5.
	sum := md5.Sum(part2)
	r = httptest.NewRequest("PUT", "/data/dir/big.bin?partNumber=2&uploadId="+op.uploadID, bytes.NewReader(part2))
	r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	w = httptest.NewRecorder()
	op.partNumber = "2"
	h.uploadPart(w, r, op, "r")
	etag2 := w.Header().Get("ETag")
	if w.Code != 200 || etag2 != `"`+md5hex(part2)+`"` {
		t.Fatalf("UploadPart 2 = %d %s ETag %q", w.Code, w.Body, etag2)
	}
	// A wrong Content-MD5 is S3's BadDigest, passed through.
	r = httptest.NewRequest("PUT", "/data/dir/big.bin?partNumber=3&uploadId="+op.uploadID, bytes.NewReader(part2))
	r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	w = httptest.NewRecorder()
	op.partNumber = "3"
	h.uploadPart(w, r, op, "r")
	if w.Code != 400 || !strings.Contains(w.Body.String(), "BadDigest") {
		t.Errorf("UploadPart with a wrong Content-MD5 = %d %s, want 400 BadDigest", w.Code, w.Body)
	}
	// A bad part number is S3's InvalidArgument.
	for _, pn := range []string{"0", "10001", "x"} {
		w = httptest.NewRecorder()
		op.partNumber = pn
		h.uploadPart(w, httptest.NewRequest("PUT", "/data/k?partNumber="+pn, strings.NewReader("x")), op, "r")
		if w.Code != 400 || !strings.Contains(w.Body.String(), "InvalidArgument") {
			t.Errorf("partNumber %s = %d %s, want 400 InvalidArgument", pn, w.Code, w.Body)
		}
	}

	// ListParts shows both.
	w = httptest.NewRecorder()
	h.listParts(w, httptest.NewRequest("GET", "/data/dir/big.bin?uploadId="+op.uploadID, nil), op, "r")
	var lp listPartsResult
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &lp) != nil || len(lp.Parts) != 2 || lp.Parts[0].Size != int64(len(part1)) || lp.Parts[1].ETag != etag2 {
		t.Fatalf("ListParts = %d %s", w.Code, w.Body)
	}

	// Complete: the body as the CLI sends it (namespaced, quoted ETags, a checksum it computed).
	body := `<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Part><ETag>` + etag1 + `</ETag><PartNumber>1</PartNumber><ChecksumCRC32>AAAAAA==</ChecksumCRC32></Part><Part><ETag>` + etag2 + `</ETag><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>`
	w = httptest.NewRecorder()
	h.completeMultipartUpload(w, httptest.NewRequest("POST", "http://shim.example/data/dir/big.bin?uploadId="+op.uploadID, strings.NewReader(body)), op, "r")
	var done completeMultipartUploadResult
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &done) != nil || !strings.HasSuffix(done.ETag, `-2"`) || done.Key != "dir/big.bin" {
		t.Fatalf("CompleteMultipartUpload = %d %s", w.Code, w.Body)
	}
	if got := f.objects["data/dir/big.bin"]; !bytes.Equal(got, append(append([]byte(nil), part1...), part2...)) {
		t.Fatalf("the completed object is not the parts in order (%d bytes)", len(got))
	}
	// Completing again: the upload is gone (NoSuchUpload, 404).
	w = httptest.NewRecorder()
	h.completeMultipartUpload(w, httptest.NewRequest("POST", "/data/dir/big.bin?uploadId="+op.uploadID, strings.NewReader(body)), op, "r")
	if w.Code != 404 || !strings.Contains(w.Body.String(), "NoSuchUpload") {
		t.Errorf("completing a completed upload = %d %s, want 404 NoSuchUpload", w.Code, w.Body)
	}
	// An empty part list is MalformedXML.
	w = httptest.NewRecorder()
	h.completeMultipartUpload(w, httptest.NewRequest("POST", "/data/k?uploadId=x", strings.NewReader(`<CompleteMultipartUpload/>`)), op, "r")
	if w.Code != 400 || !strings.Contains(w.Body.String(), "MalformedXML") {
		t.Errorf("an empty CompleteMultipartUpload = %d %s, want MalformedXML", w.Code, w.Body)
	}
}

// An upload can be listed and aborted; after the abort it is gone.
func TestS3Multipart_ListAndAbort(t *testing.T) {
	f := newFakeMPS3()
	h := &s3Handler{mc: fakeMPMinio(t, f), logger: discardLogger()}
	op := s3op{bucket: "data", key: "half.bin"}
	w := httptest.NewRecorder()
	h.createMultipartUpload(w, httptest.NewRequest("POST", "/data/half.bin?uploads", nil), op, "r")
	var init initiateMultipartUploadResult
	_ = xml.Unmarshal(w.Body.Bytes(), &init)
	op.uploadID = init.UploadID

	w = httptest.NewRecorder()
	h.listMultipartUploads(w, httptest.NewRequest("GET", "/data?uploads&prefix=half.bin", nil), s3op{bucket: "data"}, "r")
	var lu listMultipartUploadsResult
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &lu) != nil || len(lu.Uploads) != 1 || lu.Uploads[0].UploadID != op.uploadID || lu.Uploads[0].Key != "half.bin" {
		t.Fatalf("ListMultipartUploads = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.abortMultipartUpload(w, httptest.NewRequest("DELETE", "/data/half.bin?uploadId="+op.uploadID, nil), op, "r")
	if w.Code != 204 {
		t.Fatalf("AbortMultipartUpload = %d %s, want 204", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.listParts(w, httptest.NewRequest("GET", "/data/half.bin?uploadId="+op.uploadID, nil), op, "r")
	if w.Code != 404 || !strings.Contains(w.Body.String(), "NoSuchUpload") {
		t.Errorf("ListParts after the abort = %d %s, want 404 NoSuchUpload", w.Code, w.Body)
	}
}

// CopyObject copies the bytes (a version too), and UploadPartCopy copies a byte range into a part.
func TestS3Copy_ObjectAndPart(t *testing.T) {
	f := newFakeMPS3()
	f.objects["src/obj"] = []byte("0123456789abcdef")
	f.versions["src/obj?v1"] = []byte("the first version")
	h := &s3Handler{mc: fakeMPMinio(t, f), logger: discardLogger()}

	w := httptest.NewRecorder()
	h.copyObject(w, httptest.NewRequest("PUT", "/dst/copy", nil), s3op{bucket: "dst", key: "copy"}, copySource{"src", "obj", ""}, "r")
	var cr copyObjectResult
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &cr) != nil || cr.ETag != `"`+md5hex([]byte("0123456789abcdef"))+`"` {
		t.Fatalf("CopyObject = %d %s", w.Code, w.Body)
	}
	if string(f.objects["dst/copy"]) != "0123456789abcdef" {
		t.Fatalf("CopyObject stored %q", f.objects["dst/copy"])
	}
	w = httptest.NewRecorder()
	h.copyObject(w, httptest.NewRequest("PUT", "/dst/old", nil), s3op{bucket: "dst", key: "old"}, copySource{"src", "obj", "v1"}, "r")
	if w.Code != 200 || string(f.objects["dst/old"]) != "the first version" || w.Header().Get("x-amz-copy-source-version-id") != "v1" {
		t.Fatalf("CopyObject of a version = %d %s, stored %q", w.Code, w.Body, f.objects["dst/old"])
	}
	w = httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/dst/x", nil)
	r.Header.Set("x-amz-metadata-directive", "SOMETIMES")
	h.copyObject(w, r, s3op{bucket: "dst", key: "x"}, copySource{"src", "obj", ""}, "r")
	if w.Code != 400 {
		t.Errorf("an unknown metadata directive = %d, want 400", w.Code)
	}

	// UploadPartCopy with a range, then complete.
	op := s3op{bucket: "dst", key: "ranged"}
	w = httptest.NewRecorder()
	h.createMultipartUpload(w, httptest.NewRequest("POST", "/dst/ranged?uploads", nil), op, "r")
	var init initiateMultipartUploadResult
	_ = xml.Unmarshal(w.Body.Bytes(), &init)
	op.uploadID, op.partNumber = init.UploadID, "1"
	r = httptest.NewRequest("PUT", "/dst/ranged?partNumber=1&uploadId="+op.uploadID, nil)
	r.Header.Set("x-amz-copy-source-range", "bytes=2-5")
	w = httptest.NewRecorder()
	h.uploadPartCopy(w, r, op, copySource{"src", "obj", ""}, "r")
	var pr copyPartResult
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &pr) != nil || pr.ETag != `"`+md5hex([]byte("2345"))+`"` {
		t.Fatalf("UploadPartCopy = %d %s", w.Code, w.Body)
	}
	r = httptest.NewRequest("PUT", "/dst/ranged?partNumber=1&uploadId="+op.uploadID, nil)
	r.Header.Set("x-amz-copy-source-range", "bytes=5-2")
	w = httptest.NewRecorder()
	h.uploadPartCopy(w, r, op, copySource{"src", "obj", ""}, "r")
	if w.Code != 400 || !strings.Contains(w.Body.String(), "InvalidArgument") {
		t.Errorf("a backwards copy range = %d %s, want 400 InvalidArgument", w.Code, w.Body)
	}
	body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + pr.ETag + `</ETag></Part></CompleteMultipartUpload>`
	w = httptest.NewRecorder()
	h.completeMultipartUpload(w, httptest.NewRequest("POST", "/dst/ranged?uploadId="+op.uploadID, strings.NewReader(body)), op, "r")
	if w.Code != 200 || string(f.objects["dst/ranged"]) != "2345" {
		t.Fatalf("complete after UploadPartCopy = %d %s, stored %q", w.Code, w.Body, f.objects["dst/ranged"])
	}
}

// Through the front door, as an assumed role: each multipart step is authorized as AWS does, and a copy
// also needs a read of its source; a PUT naming a copy source is never stored as an empty object.
func TestS3Multipart_AuthorizedAsAWS(t *testing.T) {
	f := newFakeMPS3()
	f.objects["private/secret.txt"] = []byte("not yours")
	f.objects["shared/ok.txt"] = []byte("readable")
	authz := roleChecker(
		dpAllow([]string{"s3:PutObject"}, "Bucket::dst"),
		dpAllow([]string{"s3:GetObject"}, "Bucket::shared"),
	)
	h := &s3Handler{mc: fakeMPMinio(t, f), logger: discardLogger(), authz: authz}
	serve := func(method, target, copySrc string, body io.Reader) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, body)
		if copySrc != "" {
			r.Header.Set("x-amz-copy-source", copySrc)
		}
		w := httptest.NewRecorder()
		h.serve(w, r, ecrRoleClaims(), "r")
		return w
	}

	w := serve("POST", "/dst/obj?uploads", "", nil)
	var init initiateMultipartUploadResult
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &init) != nil {
		t.Fatalf("CreateMultipartUpload with s3:PutObject = %d %s", w.Code, w.Body)
	}
	if w = serve("PUT", "/dst/obj?partNumber=1&uploadId="+init.UploadID, "", strings.NewReader("part")); w.Code != 200 {
		t.Fatalf("UploadPart with s3:PutObject = %d %s", w.Code, w.Body)
	}
	// Abort needs s3:AbortMultipartUpload, which this role does not have; listing parts needs its own too.
	if w = serve("DELETE", "/dst/obj?uploadId="+init.UploadID, "", nil); w.Code != 403 {
		t.Errorf("AbortMultipartUpload without s3:AbortMultipartUpload = %d, want 403", w.Code)
	}
	if w = serve("GET", "/dst/obj?uploadId="+init.UploadID, "", nil); w.Code != 403 {
		t.Errorf("ListParts without s3:ListMultipartUploadParts = %d, want 403", w.Code)
	}
	if w = serve("POST", "/other/obj?uploads", "", nil); w.Code != 403 {
		t.Errorf("CreateMultipartUpload on a bucket outside the policy = %d, want 403", w.Code)
	}

	// Copy: the source must be readable too.
	if w = serve("PUT", "/dst/stolen", "/private/secret.txt", nil); w.Code != 403 {
		t.Fatalf("CopyObject from an unreadable source = %d %s, want 403", w.Code, w.Body)
	}
	if _, stored := f.objects["dst/stolen"]; stored {
		t.Fatal("a denied copy stored an object")
	}
	if w = serve("PUT", "/dst/copied", "/shared/ok.txt", nil); w.Code != 200 || string(f.objects["dst/copied"]) != "readable" {
		t.Fatalf("CopyObject from a readable source = %d %s, stored %q", w.Code, w.Body, f.objects["dst/copied"])
	}
	if w = serve("PUT", "/dst/obj?partNumber=2&uploadId="+init.UploadID, "/private/secret.txt", nil); w.Code != 403 {
		t.Errorf("UploadPartCopy from an unreadable source = %d, want 403", w.Code)
	}
	if w = serve("PUT", "/dst/bad", "nobucket", nil); w.Code != 400 {
		t.Errorf("a malformed copy source = %d, want 400", w.Code)
	}
}

// A part streams through to MinIO: its first bytes arrive before the client has finished sending, so a
// part costs the shim a chunk of memory, not the part's size.
func TestS3Multipart_PartStreams(t *testing.T) {
	f := newFakeMPS3()
	h := &s3Handler{mc: fakeMPMinio(t, f), logger: discardLogger()}
	op := s3op{bucket: "data", key: "stream.bin"}
	w := httptest.NewRecorder()
	h.createMultipartUpload(w, httptest.NewRequest("POST", "/data/stream.bin?uploads", nil), op, "r")
	var init initiateMultipartUploadResult
	_ = xml.Unmarshal(w.Body.Bytes(), &init)
	op.uploadID, op.partNumber = init.UploadID, "1"

	const size = 8 << 20
	pr, pw := io.Pipe()
	r := httptest.NewRequest("PUT", "/data/stream.bin?partNumber=1&uploadId="+op.uploadID, pr)
	r.ContentLength = size
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		rec := httptest.NewRecorder()
		h.uploadPart(rec, r, op, "r")
		done <- rec
	}()
	chunk := bytes.Repeat([]byte("z"), 1<<20)
	if _, err := pw.Write(chunk); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.firstByte:
	case <-time.After(5 * time.Second):
		_ = pw.CloseWithError(io.ErrUnexpectedEOF)
		t.Fatal("MinIO saw none of the part before the client finished sending it: the part is buffered, not streamed")
	}
	for i := 1; i < size/len(chunk); i++ {
		if _, err := pw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	_ = pw.Close()
	rec := <-done
	if rec.Code != 200 {
		t.Fatalf("UploadPart = %d %s", rec.Code, rec.Body)
	}
	f.mu.Lock()
	got := len(f.uploads[op.uploadID].parts[1])
	f.mu.Unlock()
	if got != size {
		t.Fatalf("stored %d bytes, want %d", got, size)
	}
}

func TestS3GetBucketOwnershipControls(t *testing.T) {
	f := newFakeS3()
	f.buckets["data"] = true
	h := &s3Handler{mc: fakeMinio(t, f), logger: discardLogger()}
	w := httptest.NewRecorder()
	h.getBucketOwnershipControls(w, httptest.NewRequest("GET", "/data?ownershipControls", nil), s3op{bucket: "data"}, "r")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `<OwnershipControls xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>`) {
		t.Fatalf("GetBucketOwnershipControls = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.getBucketOwnershipControls(w, httptest.NewRequest("GET", "/nope?ownershipControls", nil), s3op{bucket: "nope"}, "r")
	if w.Code != 404 || !strings.Contains(w.Body.String(), "NoSuchBucket") {
		t.Fatalf("GetBucketOwnershipControls of a missing bucket = %d %s", w.Code, w.Body)
	}
}

// PutBucketOwnershipControls accepts BucketOwnerEnforced (already in force) and refuses the modes that
// enable ACLs, with the reason; DeleteBucketOwnershipControls (re-enabling ACLs on AWS) is refused. Both
// are authorized as s3:PutBucketOwnershipControls on the bucket, a write.
func TestS3PutDeleteBucketOwnershipControls(t *testing.T) {
	f := newFakeS3()
	f.buckets["data"] = true
	h := &s3Handler{mc: fakeMinio(t, f), logger: discardLogger()}
	body := func(own string) io.Reader {
		return strings.NewReader(`<OwnershipControls xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ObjectOwnership>` + own + `</ObjectOwnership></Rule></OwnershipControls>`)
	}
	put := func(bucket, own string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.putBucketOwnershipControls(w, httptest.NewRequest("PUT", "/"+bucket+"?ownershipControls", body(own)), s3op{bucket: bucket}, "r")
		return w
	}
	if w := put("data", "BucketOwnerEnforced"); w.Code != 200 {
		t.Fatalf("Put BucketOwnerEnforced = %d %s", w.Code, w.Body)
	}
	for _, own := range []string{"BucketOwnerPreferred", "ObjectWriter"} {
		if w := put("data", own); w.Code != 501 || !strings.Contains(w.Body.String(), "ACLs") {
			t.Fatalf("Put %s = %d %s, want 501 naming ACLs", own, w.Code, w.Body)
		}
	}
	if w := put("data", "Bogus"); w.Code != 400 || !strings.Contains(w.Body.String(), "MalformedXML") {
		t.Fatalf("Put of an unknown ownership = %d %s", w.Code, w.Body)
	}
	if w := put("nope", "BucketOwnerEnforced"); w.Code != 404 {
		t.Fatalf("Put on a missing bucket = %d %s", w.Code, w.Body)
	}
	w := httptest.NewRecorder()
	h.deleteBucketOwnershipControls(w, httptest.NewRequest("DELETE", "/data?ownershipControls", nil), s3op{bucket: "data"}, "r")
	if w.Code != 501 || !strings.Contains(w.Body.String(), "ACLs") {
		t.Fatalf("DeleteBucketOwnershipControls = %d %s", w.Code, w.Body)
	}
	for method, kind := range map[string]string{"PUT": "put-bucket-ownership-controls", "DELETE": "delete-bucket-ownership-controls"} {
		op, ok := (&s3Handler{}).decode(httptest.NewRequest(method, "/data?ownershipControls", nil))
		if !ok || op.kind != kind || !op.write {
			t.Fatalf("%s ?ownershipControls decoded as %+v (ok=%v), want %s (a write)", method, op, ok, kind)
		}
		if op.action() != "s3:PutBucketOwnershipControls" || op.onObject() {
			t.Fatalf("%s is authorized as %s (onObject=%v), want s3:PutBucketOwnershipControls on the bucket", kind, op.action(), op.onObject())
		}
	}
}
