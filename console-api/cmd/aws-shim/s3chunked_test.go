package main

import (
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// chunkFrame wraps data as one aws-chunked chunk with a (fake) chunk-signature, as the signed
// STREAMING-AWS4-HMAC-SHA256-PAYLOAD variant sends it.
func chunkFrame(data string) string {
	return fmt.Sprintf("%x;chunk-signature=%064d\r\n%s\r\n", len(data), 0, data)
}

func TestAwsChunkedReader_Signed(t *testing.T) {
	payload := "the-quick-brown-fox-jumps-over-the-lazy-dog"
	// Two data chunks + the terminating zero chunk — the shape a real signed chunked PUT sends.
	body := chunkFrame(payload[:20]) + chunkFrame(payload[20:]) +
		fmt.Sprintf("0;chunk-signature=%064d\r\n\r\n", 0)

	got, err := io.ReadAll(newAwsChunkedReader(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("dechunked payload mismatch:\n got %q\nwant %q", got, payload)
	}
}

func TestAwsChunkedReader_UnsignedTrailer(t *testing.T) {
	payload := "checksum-trailer-variant-payload-0123456789"
	// UNSIGNED-PAYLOAD-TRAILER: chunk headers carry no signature, and a trailer follows the final
	// zero chunk (e.g. an x-amz-checksum-*). The decoder must return only the object bytes.
	body := fmt.Sprintf("%x\r\n%s\r\n", len(payload), payload) +
		"0\r\n" +
		"x-amz-checksum-crc32:abcd1234\r\n\r\n"

	got, err := io.ReadAll(newAwsChunkedReader(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("dechunked payload mismatch:\n got %q\nwant %q", got, payload)
	}
}

// TestAwsChunkedReader_SmallReads proves the reader is correct across buffer boundaries (a caller
// reading a few bytes at a time must still get exactly the object, framing stripped).
func TestAwsChunkedReader_SmallReads(t *testing.T) {
	payload := strings.Repeat("abcdefghij", 50) // 500 bytes across one chunk
	body := chunkFrame(payload) + "0\r\n\r\n"
	r := newAwsChunkedReader(strings.NewReader(body))

	var out []byte
	buf := make([]byte, 7) // deliberately awkward size
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if string(out) != payload {
		t.Fatalf("small-read dechunk mismatch (len got %d want %d)", len(out), len(payload))
	}
}

func TestIsAwsChunked(t *testing.T) {
	cases := []struct {
		contentSHA, contentEnc string
		want                   bool
	}{
		{"STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "", true},
		{"STREAMING-UNSIGNED-PAYLOAD-TRAILER", "", true},
		{"", "aws-chunked", true},
		{"", "gzip, aws-chunked", true},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("PUT", "http://s3/b/k", nil)
		if c.contentSHA != "" {
			r.Header.Set("X-Amz-Content-Sha256", c.contentSHA)
		}
		if c.contentEnc != "" {
			r.Header.Set("Content-Encoding", c.contentEnc)
		}
		if got := isAwsChunked(r); got != c.want {
			t.Errorf("isAwsChunked(sha=%q enc=%q)=%v want %v", c.contentSHA, c.contentEnc, got, c.want)
		}
	}
}

func TestDecodedContentLength(t *testing.T) {
	r := httptest.NewRequest("PUT", "http://s3/b/k", nil)
	if got := decodedContentLength(r); got != -1 {
		t.Fatalf("absent header should be -1, got %d", got)
	}
	r.Header.Set("X-Amz-Decoded-Content-Length", "12345")
	if got := decodedContentLength(r); got != 12345 {
		t.Fatalf("got %d want 12345", got)
	}
}
