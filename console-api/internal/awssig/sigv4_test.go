package awssig

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The AWS documentation example secret, shared by every published SigV4 vector.
const exampleSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

// newReq is a tiny helper: build a request and set headers, failing the test on a bad URL.
func newReq(t *testing.T, method, url string, hdr map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

// TestVerify_GroundTruth_GetVanilla anchors the GENERIC SigV4 path against the canonical
// "get-vanilla" vector from AWS's published SigV4 test suite. Verify returning nil for the
// published signature proves our recomputation is byte-identical to AWS's own — if a single
// byte of the canonical request / string-to-sign / signing-key math were wrong, the signatures
// would diverge and Verify would reject.
func TestVerify_GroundTruth_GetVanilla(t *testing.T) {
	req := newReq(t, "GET", "https://example.amazonaws.com/", map[string]string{
		"X-Amz-Date": "20150830T123600Z",
	})
	req.Host = "example.amazonaws.com"
	cred := Credential{
		AccessKeyID:   "AKIDEXAMPLE",
		Date:          "20150830",
		Region:        "us-east-1",
		Service:       "service",
		SignedHeaders: []string{"host", "x-amz-date"},
		// The signature AWS publishes for get-vanilla.
		Signature: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
	}
	if err := Verify(req, cred, exampleSecret); err != nil {
		t.Fatalf("get-vanilla vector should verify against AWS's published signature, got: %v", err)
	}
}

// TestVerify_GroundTruth_S3GetObject anchors the S3-SPECIFIC path (single path encoding,
// x-amz-content-sha256 payload declaration, a signed Range header) against AWS's own worked
// example from "Signature Calculations for the Authorization Header: Transferring Payload in a
// Single Chunk" (GET Object). AWS publishes the canonical-request hash for this example as
// 7344ae5b…; asserting our canonical request hashes to that same value is a real ground-truth
// check of the S3 canonicalization (which get-vanilla, a non-S3 service, does not exercise). The
// final-HMAC step is already ground-truth-anchored end-to-end by get-vanilla, so we then derive
// the true signature and confirm Verify accepts it (and rejects a wrong secret) over an S3-shaped
// request — exercising Verify's x-amz-content-sha256 payload handling and the s3 path encoding.
func TestVerify_GroundTruth_S3GetObject(t *testing.T) {
	// AWS-documented canonical-request hash for the GET Object single-chunk example.
	const awsCanonicalReqHash = "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"

	req := newReq(t, "GET", "https://examplebucket.s3.amazonaws.com/test.txt", map[string]string{
		"Range":                "bytes=0-9",
		"X-Amz-Content-Sha256": emptyStringSHA256,
		"X-Amz-Date":           "20130524T000000Z",
	})
	req.Host = "examplebucket.s3.amazonaws.com"
	cred := Credential{
		AccessKeyID:   "AKIAIOSFODNN7EXAMPLE",
		Date:          "20130524",
		Region:        "us-east-1",
		Service:       "s3",
		SignedHeaders: []string{"host", "range", "x-amz-content-sha256", "x-amz-date"},
	}

	ph, err := payloadHash(req)
	if err != nil {
		t.Fatalf("payload hash: %v", err)
	}
	if got := sha256Hex([]byte(canonicalRequest(req, cred, ph))); got != awsCanonicalReqHash {
		t.Fatalf("S3 canonical-request hash mismatch vs AWS-documented value:\n got %s\nwant %s", got, awsCanonicalReqHash)
	}

	// Derive the true signature via the (get-vanilla-proven) signing path and confirm Verify's
	// S3-shaped happy path accepts it, and that a wrong secret over the same request is rejected.
	cred.Signature = signForTest(req, cred, exampleSecret)
	if err := Verify(req, cred, exampleSecret); err != nil {
		t.Fatalf("Verify should accept the correctly-signed S3 request, got: %v", err)
	}
	if err := Verify(req, cred, "wrong-secret"); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("Verify should reject a wrong secret on the S3 request, got: %v", err)
	}
}

// signForTest computes the SigV4 signature the way a correct client would, so tests can produce a
// valid signature to feed back through Verify. It reuses the package's own (vector-anchored) math.
func signForTest(req *http.Request, cred Credential, secret string) string {
	sig, err := Sign(req, cred, secret)
	if err != nil {
		panic(err)
	}
	return sig
}

// TestVerify_WrongSecret is the "prove the no" test for authentication: a caller who NAMES a
// valid access key but does not hold its secret must be rejected. This is the exact failure the
// "verify, don't just parse" rule exists to catch — and it is silent-green if you skip it.
func TestVerify_WrongSecret(t *testing.T) {
	req := newReq(t, "GET", "https://example.amazonaws.com/", map[string]string{
		"X-Amz-Date": "20150830T123600Z",
	})
	req.Host = "example.amazonaws.com"
	cred := Credential{
		AccessKeyID:   "AKIDEXAMPLE",
		Date:          "20150830",
		Region:        "us-east-1",
		Service:       "service",
		SignedHeaders: []string{"host", "x-amz-date"},
		Signature:     "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
	}
	if err := Verify(req, cred, "an-attacker-guessed-secret"); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("wrong secret must be a signature mismatch, got: %v", err)
	}
}

// TestVerify_EmptySecret: an unknown access key (no secret on file) must be indistinguishable
// from a bad signature — never a distinct error a probing attacker could use to enumerate keys.
func TestVerify_EmptySecret(t *testing.T) {
	req := newReq(t, "GET", "https://example.amazonaws.com/", map[string]string{
		"X-Amz-Date": "20150830T123600Z",
	})
	req.Host = "example.amazonaws.com"
	cred := Credential{AccessKeyID: "AKIDEXAMPLE", Date: "20150830", Region: "us-east-1",
		Service: "service", SignedHeaders: []string{"host", "x-amz-date"}, Signature: "deadbeef"}
	if err := Verify(req, cred, ""); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("empty secret must be a signature mismatch, got: %v", err)
	}
}

// TestVerify_Tampered: because SigV4 signs the method/path/headers, mutating any signed part of
// the request after signing must break verification (tamper-detection for free). We take a known-
// good vector and flip the method; the signature must no longer match.
func TestVerify_Tampered(t *testing.T) {
	req := newReq(t, "GET", "https://example.amazonaws.com/", map[string]string{
		"X-Amz-Date": "20150830T123600Z",
	})
	req.Host = "example.amazonaws.com"
	cred := Credential{
		AccessKeyID:   "AKIDEXAMPLE",
		Date:          "20150830",
		Region:        "us-east-1",
		Service:       "service",
		SignedHeaders: []string{"host", "x-amz-date"},
		Signature:     "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
	}
	req.Method = "POST" // an attacker rewrites the verb after the client signed a GET
	if err := Verify(req, cred, exampleSecret); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("tampered method must fail verification, got: %v", err)
	}
}

func TestParseAuthorization(t *testing.T) {
	t.Run("well-formed", func(t *testing.T) {
		hdr := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, " +
			"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc123"
		cred, err := ParseAuthorization(hdr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cred.AccessKeyID != "AKIDEXAMPLE" || cred.Region != "us-east-1" || cred.Service != "s3" {
			t.Fatalf("bad scope parse: %+v", cred)
		}
		if cred.Signature != "abc123" {
			t.Fatalf("bad signature parse: %q", cred.Signature)
		}
		if got := strings.Join(cred.SignedHeaders, ";"); got != "host;x-amz-content-sha256;x-amz-date" {
			t.Fatalf("bad signed headers parse: %q", got)
		}
		if got := cred.CredentialScope(); got != "20150830/us-east-1/s3/aws4_request" {
			t.Fatalf("bad credential scope: %q", got)
		}
	})

	t.Run("no header", func(t *testing.T) {
		if _, err := ParseAuthorization(""); !errors.Is(err, ErrNoAuthorization) {
			t.Fatalf("want ErrNoAuthorization, got %v", err)
		}
	})

	t.Run("wrong scheme (e.g. SigV2/Basic) is treated as absent", func(t *testing.T) {
		if _, err := ParseAuthorization("Basic dXNlcjpwYXNz"); !errors.Is(err, ErrNoAuthorization) {
			t.Fatalf("want ErrNoAuthorization, got %v", err)
		}
	})

	t.Run("malformed scope", func(t *testing.T) {
		hdr := "AWS4-HMAC-SHA256 Credential=AKID/only/two, SignedHeaders=host, Signature=x"
		if _, err := ParseAuthorization(hdr); !errors.Is(err, ErrMalformedAuthorization) {
			t.Fatalf("want ErrMalformedAuthorization, got %v", err)
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		hdr := "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/s3/aws4_request, SignedHeaders=host"
		if _, err := ParseAuthorization(hdr); !errors.Is(err, ErrMalformedAuthorization) {
			t.Fatalf("want ErrMalformedAuthorization, got %v", err)
		}
	})
}
