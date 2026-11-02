package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseByteRange(t *testing.T) {
	cases := []struct {
		h                   string
		size                int64
		start, end          int64
		ranged, satisfiable bool
	}{
		{"bytes=0-8388607", 20 << 20, 0, 8388607, true, true},
		{"bytes=16777216-20971519", 20 << 20, 16777216, 20971519, true, true},
		{"bytes=10-", 100, 10, 99, true, true},
		{"bytes=-10", 100, 90, 99, true, true},
		{"bytes=-1000", 100, 0, 99, true, true},
		{"bytes=90-1000", 100, 90, 99, true, true}, // the end is clamped
		{"bytes=0-0", 100, 0, 0, true, true},
		{"bytes=100-", 100, 0, 0, true, false}, // starts past the end: InvalidRange
		{"bytes=-0", 100, 0, 0, true, false},
		{"bytes=0-1", 0, 0, 0, true, false},    // any range of an empty object
		{"bytes=5-3", 100, 0, 0, false, false}, // malformed: the whole object
		{"bytes=0-1,5-6", 100, 0, 0, false, false},
		{"items=0-1", 100, 0, 0, false, false},
		{"bytes=x-1", 100, 0, 0, false, false},
	}
	for _, c := range cases {
		s, e, r, ok := parseByteRange(c.h, c.size)
		if r != c.ranged || ok != c.satisfiable || (ok && (s != c.start || e != c.end)) {
			t.Errorf("parseByteRange(%q, %d) = %d-%d ranged=%v satisfiable=%v; want %d-%d %v %v", c.h, c.size, s, e, r, ok, c.start, c.end, c.ranged, c.satisfiable)
		}
	}
}

// A ranged GetObject answers 206 with just the range and its Content-Range; an unsatisfiable one 416;
// none, the whole object.
func TestS3GetObject_Range(t *testing.T) {
	f := newFakeMPS3()
	f.objects["data/obj"] = []byte("0123456789")
	h := &s3Handler{mc: fakeMPMinio(t, f), logger: discardLogger()}
	get := func(rng string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/data/obj", nil)
		if rng != "" {
			r.Header.Set("Range", rng)
		}
		w := httptest.NewRecorder()
		h.getObject(w, r, s3op{kind: "get", bucket: "data", key: "obj"}, "r")
		return w
	}
	w := get("bytes=2-5")
	if w.Code != 206 || w.Body.String() != "2345" || w.Header().Get("Content-Range") != "bytes 2-5/10" || w.Header().Get("Content-Length") != "4" {
		t.Fatalf("ranged GET = %d %q Content-Range %q Content-Length %q", w.Code, w.Body, w.Header().Get("Content-Range"), w.Header().Get("Content-Length"))
	}
	if w = get("bytes=-3"); w.Code != 206 || w.Body.String() != "789" {
		t.Fatalf("suffix GET = %d %q", w.Code, w.Body)
	}
	if w = get("bytes=10-"); w.Code != 416 || !strings.Contains(w.Body.String(), "InvalidRange") || w.Header().Get("Content-Range") != "bytes */10" {
		t.Fatalf("unsatisfiable GET = %d %s", w.Code, w.Body)
	}
	if w = get(""); w.Code != 200 || w.Body.String() != "0123456789" {
		t.Fatalf("plain GET = %d %q", w.Code, w.Body)
	}
	if w = get("bytes=0-1,4-5"); w.Code != 200 || w.Body.String() != "0123456789" {
		t.Fatalf("multi-range GET (served whole, as S3) = %d %q", w.Code, w.Body)
	}
}

// GetObjectTagging answers the object's tags (an empty TagSet when none), and a copy's tags travel on
// CreateMultipartUpload's x-amz-tagging, as the AWS CLI sends them.
func TestS3ObjectTagging_ReadAndCarriedOnCreate(t *testing.T) {
	f := newFakeMPS3()
	f.objects["data/tagged"] = []byte("x")
	f.objects["data/plain"] = []byte("y")
	f.tags["data/tagged"] = `<Tag><Key>team</Key><Value>a</Value></Tag>`
	h := &s3Handler{mc: fakeMPMinio(t, f), logger: discardLogger()}
	if op, ok := decodeTarget(http.MethodGet, "data", "tagged", url.Values{"tagging": {""}}); !ok || op.kind != "get-object-tagging" || op.action() != "s3:GetObjectTagging" {
		t.Fatalf("GET /data/tagged?tagging decodes to %+v %v", op, ok)
	}
	if op, _ := decodeTarget(http.MethodGet, "data", "tagged", url.Values{"tagging": {""}, "versionId": {"v1"}}); op.action() != "s3:GetObjectVersionTagging" {
		t.Errorf("a version's tagging action = %q", op.action())
	}
	w := httptest.NewRecorder()
	h.getObjectTagging(w, httptest.NewRequest("GET", "/data/tagged?tagging", nil), s3op{bucket: "data", key: "tagged"}, "r")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<Tag><Key>team</Key><Value>a</Value></Tag>") {
		t.Fatalf("GetObjectTagging = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	h.getObjectTagging(w, httptest.NewRequest("GET", "/data/plain?tagging", nil), s3op{bucket: "data", key: "plain"}, "r")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<TagSet></TagSet>") {
		t.Fatalf("GetObjectTagging (none) = %d %s", w.Code, w.Body)
	}
	r := httptest.NewRequest("POST", "/data/copy?uploads", nil)
	r.Header.Set("x-amz-tagging", "team=a&env=dev")
	w = httptest.NewRecorder()
	h.createMultipartUpload(w, r, s3op{bucket: "data", key: "copy"}, "r")
	if w.Code != 200 || len(f.createTags) != 1 || !strings.Contains(f.createTags[0], "team=a") || !strings.Contains(f.createTags[0], "env=dev") {
		t.Fatalf("CreateMultipartUpload with x-amz-tagging = %d %s; MinIO got %q", w.Code, w.Body, f.createTags)
	}
}

// withoutEnv drops the named variables from env.
func withoutEnv(env []string, names ...string) []string {
	out := env[:0:0]
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, n := range names {
			drop = drop || k == n
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}

// The real AWS CLI against the front door (authorization: a role allowed s3:* on the bucket; a fake MinIO
// behind): a 20 MiB `aws s3 cp` up (multipart) and down (parallel ranged GETs) is byte-identical, and so
// are server-side copies above the threshold (GetObjectTagging + UploadPartCopy) and below it
// (CopyObject). Skipped without the aws CLI.
func TestS3_AWSCLIMultipartRoundTrip(t *testing.T) {
	cli, err := exec.LookPath("aws")
	if err != nil {
		t.Skip("the aws CLI is not installed")
	}
	f := newFakeMPS3()
	h := &s3Handler{mc: fakeMPMinio(t, f), logger: discardLogger(), authz: roleChecker(dpAllow([]string{"s3:*"}, "Bucket::data"))}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.serve(w, r, ecrRoleClaims(), "r")
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(cli, append([]string{"--endpoint-url", srv.URL, "--no-cli-pager", "--only-show-errors"}, args...)...)
		cmd.Env = append(os.Environ(), "AWS_ACCESS_KEY_ID=AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY=secret", "AWS_REGION=us-east-1",
			"AWS_CONFIG_FILE=/dev/null", "AWS_SHARED_CREDENTIALS_FILE=/dev/null", "HOME="+dir)
		cmd.Env = withoutEnv(cmd.Env, "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("aws %v: %v\n%s", args, err, out)
		}
	}
	big := make([]byte, 20<<20)
	for i := range big {
		big[i] = byte(i*7 + i/4096)
	}
	in := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(in, big, 0o600); err != nil {
		t.Fatal(err)
	}
	run("s3", "cp", in, "s3://data/big.bin")
	f.mu.Lock()
	up := f.objects["data/big.bin"]
	f.mu.Unlock()
	if !bytes.Equal(up, big) {
		t.Fatalf("the uploaded object (%d bytes) is not the file", len(up))
	}
	out := filepath.Join(dir, "big-out.bin")
	run("s3", "cp", "s3://data/big.bin", out)
	if got, _ := os.ReadFile(out); !bytes.Equal(got, big) {
		t.Fatalf("the downloaded file (%d bytes) is not the object (ranged GETs must answer just their range)", len(got))
	}
	run("s3", "cp", "s3://data/big.bin", "s3://data/big-copy.bin")
	f.mu.Lock()
	cp := f.objects["data/big-copy.bin"]
	f.objects["data/small.txt"] = []byte("small")
	f.mu.Unlock()
	if !bytes.Equal(cp, big) {
		t.Fatalf("the multipart server-side copy (%d bytes) is not the source", len(cp))
	}
	run("s3", "cp", "s3://data/small.txt", "s3://data/small-copy.txt")
	f.mu.Lock()
	small := string(f.objects["data/small-copy.txt"])
	uploads, ranged := f.nextID, f.rangedGets
	f.mu.Unlock()
	if small != "small" {
		t.Fatalf("the small copy stored %q", small)
	}
	// The paths under test were the ones taken: two multipart uploads (the upload, the large copy) and a
	// download in ranges.
	if uploads != 2 || ranged < 2 {
		t.Fatalf("multipart uploads = %d (want 2), ranged GETs = %d (want several)", uploads, ranged)
	}
}
