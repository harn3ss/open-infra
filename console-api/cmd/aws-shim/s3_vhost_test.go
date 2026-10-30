package main

import (
	"net/http/httptest"
	"testing"
)

func TestVhostBucket(t *testing.T) {
	suf := []string{"s3.example.com", "s3.us-east-1.amazonaws.com"}
	cases := []struct {
		host, want string
	}{
		{"pics.s3.example.com", "pics"},
		{"s3.example.com", ""},          // bare endpoint → path-style
		{"up.loads.s3.example.com", ""}, // dotted bucket → treated as path-style, not mis-split
		{"bucket.s3.us-east-1.amazonaws.com", "bucket"},
		{"example.com", ""},  // unrelated host
		{"s3.other.com", ""}, // suffix not configured
		{"", ""},
	}
	for _, c := range cases {
		if got := vhostBucket(c.host, suf); got != c.want {
			t.Errorf("vhostBucket(%q) = %q, want %q", c.host, got, c.want)
		}
	}
	// hostNoPort strips the port (and lowercases) before vhostBucket sees it.
	if got := vhostBucket(hostNoPort("PICS.s3.example.com:8443"), suf); got != "pics" {
		t.Errorf("vhostBucket(hostNoPort(...:8443)) = %q, want pics", got)
	}
}

func TestS3Decode_VhostAndPathStyle(t *testing.T) {
	h := &s3Handler{vhostSuffixes: []string{"s3.example.com"}}

	// Virtual-hosted: bucket in the host, whole path is the key.
	vreq := httptest.NewRequest("GET", "https://pics.s3.example.com/a/b/photo.jpg", nil)
	vreq.Host = "pics.s3.example.com"
	op, ok := h.decode(vreq)
	if !ok || op.kind != "get" || op.bucket != "pics" || op.key != "a/b/photo.jpg" {
		t.Errorf("vhost decode = %+v ok=%v; want get pics a/b/photo.jpg", op, ok)
	}

	// Path-style on the bare endpoint still works.
	preq := httptest.NewRequest("GET", "https://s3.example.com/pics/photo.jpg", nil)
	preq.Host = "s3.example.com"
	op, ok = h.decode(preq)
	if !ok || op.kind != "get" || op.bucket != "pics" || op.key != "photo.jpg" {
		t.Errorf("path-style decode = %+v ok=%v; want get pics photo.jpg", op, ok)
	}

	// Virtual-hosted PUT is a write.
	wreq := httptest.NewRequest("PUT", "https://uploads.s3.example.com/key", nil)
	wreq.Host = "uploads.s3.example.com"
	op, ok = h.decode(wreq)
	if !ok || op.kind != "put" || op.bucket != "uploads" || op.key != "key" || !op.write {
		t.Errorf("vhost PUT decode = %+v ok=%v; want put uploads key write", op, ok)
	}

	// With no suffixes configured, the same request is decoded path-style (host ignored): the first
	// path segment becomes the bucket.
	h0 := &s3Handler{}
	op, ok = h0.decode(vreq)
	if !ok || op.kind != "get" || op.bucket != "a" || op.key != "b/photo.jpg" {
		t.Errorf("no-suffix decode = %+v ok=%v; want get a b/photo.jpg (path-style)", op, ok)
	}
}
