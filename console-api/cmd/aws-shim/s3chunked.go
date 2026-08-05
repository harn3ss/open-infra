package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// aws-chunked decoding.
//
// When an AWS SDK/CLI adds a trailing integrity checksum (the v2 default for many uploads, or an
// explicit --checksum-algorithm), it switches PutObject to the `aws-chunked` content-encoding: the
// wire body is NOT the raw object, it is the object wrapped in per-chunk framing —
//
//	<hex chunk size>[;chunk-signature=<sig>]\r\n<chunk data>\r\n … 0[;…]\r\n<trailer>\r\n
//
// and the real object length travels in x-amz-decoded-content-length while x-amz-content-sha256 is
// a STREAMING-* sentinel. If those framing bytes reach the object store undecoded they are stored
// verbatim — a silent corruption that breaks byte-identity. This decoder strips the framing so the
// object stored is exactly what the client uploaded. (SigV4 verification is unaffected: it already
// ran against the STREAMING-* sentinel as the literal payload hash, which is what the client signed,
// and it does not consume the body — so the body is intact here to decode.)

// isAwsChunked reports whether the request body is aws-chunked framed.
func isAwsChunked(r *http.Request) bool {
	if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "aws-chunked")
}

// decodedContentLength returns the real object length from x-amz-decoded-content-length, or -1 when
// absent (MinIO's PutObject streams an unknown-length body via multipart when given -1).
func decodedContentLength(r *http.Request) int64 {
	if v := r.Header.Get("X-Amz-Decoded-Content-Length"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return -1
}

// awsChunkedReader unwraps aws-chunked framing, yielding only the object bytes.
type awsChunkedReader struct {
	br        *bufio.Reader
	remaining int64 // unread bytes in the current chunk
	done      bool  // saw the terminating 0-size chunk
}

func newAwsChunkedReader(r io.Reader) *awsChunkedReader {
	return &awsChunkedReader{br: bufio.NewReader(r)}
}

func (c *awsChunkedReader) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	if c.remaining == 0 {
		size, err := c.nextChunkSize()
		if err != nil {
			return 0, err
		}
		if size == 0 {
			c.done = true
			return 0, io.EOF
		}
		c.remaining = size
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.br.Read(p)
	c.remaining -= int64(n)
	if c.remaining == 0 && err == nil {
		// Consume the CRLF that terminates the chunk data.
		if derr := c.discardCRLF(); derr != nil {
			return n, derr
		}
	}
	return n, err
}

// nextChunkSize reads a "<hexsize>[;chunk-signature=…]\r\n" header line and returns the size.
func (c *awsChunkedReader) nextChunkSize() (int64, error) {
	line, err := c.br.ReadString('\n')
	if err != nil {
		return 0, err
	}
	line = strings.TrimRight(line, "\r\n")
	if i := strings.IndexByte(line, ';'); i >= 0 { // strip the chunk-signature extension
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	size, err := strconv.ParseInt(line, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("aws-chunked: bad chunk size %q: %w", line, err)
	}
	return size, nil
}

// discardCRLF consumes the exactly-two bytes ("\r\n") that follow a chunk's data.
func (c *awsChunkedReader) discardCRLF() error {
	for i := 0; i < 2; i++ {
		if _, err := c.br.ReadByte(); err != nil {
			return err
		}
	}
	return nil
}
