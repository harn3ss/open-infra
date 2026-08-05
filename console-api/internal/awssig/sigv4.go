// Package awssig verifies AWS Signature Version 4 (SigV4) signatures on incoming
// requests, so the AWS-shim can authenticate an unmodified AWS SDK client WITHOUT
// the client ever transmitting its secret key.
//
// This is the security heart of the shim's "verify, don't just parse" rule (design
// handoff §4). In a SigV4 request the access key ID travels in the clear — it only
// NAMES the caller — while the signature rides along, computed from the secret. The
// secret itself is never on the wire. Verify recomputes that signature from the
// looked-up secret and constant-time compares it: a caller who merely names a valid
// key but cannot reproduce its signature is rejected, exactly as real AWS returns
// SignatureDoesNotMatch. Because SigV4 signs the method, path, query, the signed
// headers, and a hash of the payload, a passing signature also proves the request was
// not tampered with in flight — tamper-detection for free.
//
// The two-call shape is deliberate and mirrors the protocol's own chicken-and-egg:
// you must read the header to learn WHICH key is claimed (ParseAuthorization) before
// you can look up that key's secret and check the signature (Verify).
//
//	cred, err := awssig.ParseAuthorization(r.Header.Get("Authorization"))
//	secret    := store.SecretFor(cred.AccessKeyID)   // caller owns the key store
//	err        = awssig.Verify(r, cred, secret)      // ErrSignatureMismatch on a bad sig
//
// The algorithm is AWS's documented SigV4 procedure (canonical request → string to
// sign → derived signing key → HMAC-SHA256). It is validated against AWS's published
// SigV4 test-suite vectors in sigv4_test.go. The S3-specific single-encoding of the
// path (S3 is the one service that encodes path segments once, not twice, and does
// not normalize dot-segments) is exercised here and gets its ultimate ground-truth
// validation from the real-SDK compatibility probe: the models get you ~90%, the
// probe gets you faithful.
package awssig

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

const (
	algorithm         = "AWS4-HMAC-SHA256"
	terminator        = "aws4_request"
	unsignedPayload   = "UNSIGNED-PAYLOAD"
	emptyStringSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Errors are deliberately coarse: a client (and an attacker) must not be able to tell
// "unknown key" from "bad signature" from "malformed header" — every failure looks like
// the same authentication failure. The caller maps them all to S3's SignatureDoesNotMatch.
var (
	// ErrNoAuthorization means the request carried no SigV4 Authorization header at all.
	ErrNoAuthorization = errors.New("awssig: no AWS4-HMAC-SHA256 Authorization header")
	// ErrMalformedAuthorization means the header was present but not parseable as SigV4.
	ErrMalformedAuthorization = errors.New("awssig: malformed SigV4 Authorization header")
	// ErrSignatureMismatch means the recomputed signature did not match the presented one —
	// the caller does not hold the secret for the named access key, or the request was altered.
	ErrSignatureMismatch = errors.New("awssig: signature mismatch")
)

// Credential is the parsed content of a request's Authorization header: the claimed
// identity (AccessKeyID), the credential scope (Date/Region/Service), the set of headers
// that were signed, and the signature the client presented. It carries no secret.
type Credential struct {
	AccessKeyID   string   // the claimed identity — travels in the clear
	Date          string   // credential-scope date, yyyymmdd
	Region        string   // e.g. "us-east-1"
	Service       string   // e.g. "s3"
	SignedHeaders []string // lowercased header names, in signing order
	Signature     string   // hex, exactly as the client presented it
}

// CredentialScope is the "yyyymmdd/region/service/aws4_request" string the signing key is
// derived over. It is what a key's secret is (implicitly) scoped to.
func (c Credential) CredentialScope() string {
	return strings.Join([]string{c.Date, c.Region, c.Service, terminator}, "/")
}

// ParseAuthorization extracts the SigV4 credential from an Authorization header value.
// It performs NO verification — it only reports which access key is being CLAIMED, so the
// caller can look up that key's secret before Verify recomputes and checks the signature.
// A well-formed header looks like:
//
//	AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123...
func ParseAuthorization(authz string) (Credential, error) {
	authz = strings.TrimSpace(authz)
	if authz == "" {
		return Credential{}, ErrNoAuthorization
	}
	rest, ok := strings.CutPrefix(authz, algorithm+" ")
	if !ok {
		return Credential{}, ErrNoAuthorization
	}
	var cred Credential
	// The three components are comma-separated; whitespace after commas is optional per RFC.
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "Credential="):
			scope := strings.SplitN(strings.TrimPrefix(part, "Credential="), "/", 5)
			if len(scope) != 5 || scope[4] != terminator {
				return Credential{}, fmt.Errorf("%w: bad credential scope", ErrMalformedAuthorization)
			}
			cred.AccessKeyID, cred.Date, cred.Region, cred.Service = scope[0], scope[1], scope[2], scope[3]
		case strings.HasPrefix(part, "SignedHeaders="):
			cred.SignedHeaders = strings.Split(strings.TrimPrefix(part, "SignedHeaders="), ";")
		case strings.HasPrefix(part, "Signature="):
			cred.Signature = strings.TrimPrefix(part, "Signature=")
		}
	}
	if cred.AccessKeyID == "" || cred.Signature == "" || len(cred.SignedHeaders) == 0 {
		return Credential{}, fmt.Errorf("%w: missing component", ErrMalformedAuthorization)
	}
	return cred, nil
}

// Verify recomputes the SigV4 signature over req using secretKey and constant-time compares
// it against the signature the client presented (cred.Signature). A nil return proves the
// client holds the secret for cred.AccessKeyID — without the secret ever crossing the wire —
// and that the signed portions of the request were not altered in flight.
//
// Verify may read and restore req.Body to compute the payload hash when the client did not
// send x-amz-content-sha256 (S3 clients always send it; a generic SDK request may not).
func Verify(req *http.Request, cred Credential, secretKey string) error {
	if secretKey == "" {
		// No secret on file for this key. Fail as a signature mismatch, NOT a distinct
		// "unknown key" — the two must be indistinguishable to the caller.
		return ErrSignatureMismatch
	}
	amzDate := req.Header.Get("X-Amz-Date")
	if amzDate == "" {
		amzDate = req.Header.Get("Date")
	}
	if amzDate == "" {
		return fmt.Errorf("%w: no X-Amz-Date", ErrMalformedAuthorization)
	}

	want, err := signature(req, cred, amzDate, secretKey)
	if err != nil {
		return err
	}
	// Constant-time comparison — never leak, via timing, how many leading hex digits matched.
	if subtle.ConstantTimeCompare([]byte(want), []byte(cred.Signature)) != 1 {
		return ErrSignatureMismatch
	}
	return nil
}

// Sign computes the SigV4 signature a correct client would present for req under cred, using
// secretKey. It is the exact inverse of Verify (Verify recomputes this and compares), and exists
// so an internal signer — or a test that must produce a genuinely-valid request — can reuse the
// same vector-anchored math rather than reimplementing it. It reads X-Amz-Date/Date from req.
func Sign(req *http.Request, cred Credential, secretKey string) (string, error) {
	amzDate := req.Header.Get("X-Amz-Date")
	if amzDate == "" {
		amzDate = req.Header.Get("Date")
	}
	if amzDate == "" {
		return "", fmt.Errorf("%w: no X-Amz-Date", ErrMalformedAuthorization)
	}
	return signature(req, cred, amzDate, secretKey)
}

// signature is the shared core of Verify and Sign: canonical request → string to sign → HMAC.
func signature(req *http.Request, cred Credential, amzDate, secretKey string) (string, error) {
	ph, err := payloadHash(req)
	if err != nil {
		return "", err
	}
	sts := stringToSign(amzDate, cred.CredentialScope(), canonicalRequest(req, cred, ph))
	return hex.EncodeToString(hmacSHA256(deriveSigningKey(secretKey, cred), sts)), nil
}

// canonicalRequest builds AWS's canonical request string (SigV4 step 1).
func canonicalRequest(req *http.Request, cred Credential, payloadHash string) string {
	signed := append([]string(nil), cred.SignedHeaders...)
	sort.Strings(signed)

	var hdrs strings.Builder
	for _, name := range signed {
		hdrs.WriteString(name)
		hdrs.WriteByte(':')
		hdrs.WriteString(canonicalHeaderValue(req, name))
		hdrs.WriteByte('\n')
	}

	return strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.EscapedPath(), cred.Service),
		canonicalQuery(req.URL.RawQuery),
		hdrs.String(),
		strings.Join(signed, ";"),
		payloadHash,
	}, "\n")
}

// canonicalHeaderValue returns the value of a signed header, canonicalized: leading/trailing
// whitespace trimmed and internal runs of whitespace collapsed to a single space. The Host
// header is taken from req.Host (net/http keeps it out of req.Header).
func canonicalHeaderValue(req *http.Request, name string) string {
	var raw string
	if name == "host" {
		raw = req.Host
	} else {
		raw = strings.Join(req.Header.Values(name), ",")
	}
	return strings.Join(strings.Fields(raw), " ")
}

// canonicalURI encodes the request path per SigV4. S3 is the documented exception: it encodes
// each segment exactly once and does NOT collapse dot-segments; every other service encodes
// twice. (Our target is S3, but the double-encode path keeps the generic test vectors honest.)
func canonicalURI(escapedPath, service string) string {
	if escapedPath == "" {
		return "/"
	}
	// req.URL.EscapedPath() is already single-encoded. For S3 that is exactly what is signed.
	if service == "s3" {
		return escapedPath
	}
	// Non-S3: the already-once-encoded path is encoded a second time, segment by segment.
	segs := strings.Split(escapedPath, "/")
	for i, s := range segs {
		segs[i] = uriEncode(s, false)
	}
	return strings.Join(segs, "/")
}

// canonicalQuery re-encodes and sorts the query string per SigV4 (sorted by encoded key, then
// encoded value; keys without a value become "key="). Empty query → empty string.
func canonicalQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	type kv struct{ k, v string }
	var pairs []kv
	for _, p := range strings.Split(rawQuery, "&") {
		if p == "" {
			continue
		}
		k, v, _ := strings.Cut(p, "=")
		// The incoming query is percent-encoded; decode then re-encode canonically so our
		// encoding is byte-identical to the client's regardless of its encoding choices.
		pairs = append(pairs, kv{uriEncode(decode(k), false), uriEncode(decode(v), false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}
	return b.String()
}

// stringToSign is SigV4 step 2.
func stringToSign(amzDate, scope, canonReq string) string {
	return strings.Join([]string{
		algorithm,
		amzDate,
		scope,
		sha256Hex([]byte(canonReq)),
	}, "\n")
}

// deriveSigningKey is SigV4 step 3: the secret is stretched through the credential scope so the
// signing key is bound to date+region+service and never reused across them.
func deriveSigningKey(secret string, cred Credential) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), cred.Date)
	kRegion := hmacSHA256(kDate, cred.Region)
	kService := hmacSHA256(kRegion, cred.Service)
	return hmacSHA256(kService, terminator)
}

// payloadHash returns the hash of the request body that the client signed. S3 clients declare it
// in x-amz-content-sha256 (a hex digest, or the sentinel UNSIGNED-PAYLOAD); when absent we hash
// the body ourselves and restore it so downstream handlers still see it.
func payloadHash(req *http.Request) (string, error) {
	if v := req.Header.Get("X-Amz-Content-Sha256"); v != "" {
		return v, nil
	}
	if req.Body == nil {
		return emptyStringSHA256, nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", fmt.Errorf("awssig: read body for payload hash: %w", err)
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		return emptyStringSHA256, nil
	}
	return sha256Hex(body), nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// decode reverses percent-encoding for a query token, tolerating malformed input by returning it
// unchanged (canonicalization then re-encodes it consistently either way).
func decode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '%' && i+2 < len(s):
			hi, lo := unhex(s[i+1]), unhex(s[i+2])
			if hi < 0 || lo < 0 {
				b.WriteByte(s[i])
				continue
			}
			b.WriteByte(byte(hi<<4 | lo))
			i += 2
		case s[i] == '+':
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	case 'A' <= c && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// uriEncode percent-encodes per RFC 3986, leaving the unreserved set (A-Za-z0-9-_.~) intact.
// When encodeSlash is false, '/' is also left intact (used for path segments joined by '/').
func uriEncode(s string, encodeSlash bool) string {
	const upperhex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperhex[c>>4])
			b.WriteByte(upperhex[c&0x0f])
		}
	}
	return b.String()
}
