package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAWSSQSHost(t *testing.T) {
	for host, want := range map[string]bool{
		"sqs.us-east-1.amazonaws.com":       true,
		"sqs.us-gov-west-1.amazonaws.com":   true,
		"us-east-1.queue.amazonaws.com":     true,
		"queue.amazonaws.com":               true,
		"SQS.US-EAST-1.AMAZONAWS.COM:443":   true,
		"aws-shim.open-infra-aws-shim.svc":  false,
		"sqs.us-east-1.amazonaws.com.evil":  false,
		"sns.us-east-1.amazonaws.com":       false,
		"shim.local:4566":                   false,
		"notsqs.us-east-1.amazonaws.com":    false,
		"sqs.us-east-1.amazonaws.com.cn":    false,
		"evil.sqs.us-east-1.amazonaws.com":  false,
		"s3.lan.example:443":                false,
		"x.aws-shim.open-infra-aws-shim.sv": false,
	} {
		r := httptest.NewRequest(http.MethodPost, "http://x/", nil)
		r.Host = host
		if got := awsSQSHost(r); got != want {
			t.Errorf("awsSQSHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestSplitSuffixes(t *testing.T) {
	got := splitSuffixes("aws-shim.ns.svc.cluster.local, aws-shim.ns.svc", "", " S3.LAN.Example. ,aws-shim.ns.svc")
	want := []string{"aws-shim.ns.svc.cluster.local", "aws-shim.ns.svc", "s3.lan.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitSuffixes = %v, want %v", got, want)
	}
}

// A default SDK client (virtual-hosted addressing) reaches the bucket by the shim's own in-cluster name
// and by AWS's own S3 names (a guest's resolver sends those here); path-style keeps working on both.
func TestS3Decode_ShimNameAndAWSNamesVirtualHosted(t *testing.T) {
	h := &s3Handler{vhostSuffixes: splitSuffixes("aws-shim.open-infra-aws-shim.svc.cluster.local,aws-shim.open-infra-aws-shim.svc")}
	cases := []struct {
		host, path, kind, bucket, key string
	}{
		{"photos.aws-shim.open-infra-aws-shim.svc.cluster.local:4567", "/a/b.jpg", "get", "photos", "a/b.jpg"},
		{"photos.aws-shim.open-infra-aws-shim.svc:4567", "/b.jpg", "get", "photos", "b.jpg"},
		{"aws-shim.open-infra-aws-shim.svc.cluster.local:4567", "/photos/b.jpg", "get", "photos", "b.jpg"}, // path-style
		{"photos.s3.us-west-2.amazonaws.com", "/a/b.jpg", "get", "photos", "a/b.jpg"},
		{"photos.s3.amazonaws.com", "/b.jpg", "get", "photos", "b.jpg"},
		{"s3.us-west-2.amazonaws.com", "/photos/b.jpg", "get", "photos", "b.jpg"}, // AWS's path-style
		{"s3.amazonaws.com", "/photos/b.jpg", "get", "photos", "b.jpg"},
		{"photos.s3.us-west-2.amazonaws.com", "/", "list-objects", "photos", ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "https://x"+c.path, nil)
		r.Host = c.host
		op, ok := h.decode(r)
		if !ok || op.kind != c.kind || op.bucket != c.bucket || op.key != c.key {
			t.Errorf("%s%s: decoded %+v (ok %v), want %s %s/%s", c.host, c.path, op, ok, c.kind, c.bucket, c.key)
		}
	}
}

// A caller that came by an AWS SQS name gets AWS-shaped queue URLs, but the queue is recorded under the
// shim's own URL: no other caller is ever handed an amazonaws.com URL (an SDK that sends to the QueueUrl's
// host would send its credentials and messages to AWS). Every other caller sees exactly what it did.
func TestSQS_QueueURLsFollowTheCallersAWSName(t *testing.T) {
	h := &sqsHandler{account: "000000000000"}
	req := func(host string, tlsOn bool) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://x/", nil)
		r.Host = host
		if tlsOn {
			r.TLS = &tls.ConnectionState{}
		}
		return r
	}

	aws := req("sqs.us-east-1.amazonaws.com", true)
	stored, answer := h.queueURLs(aws, "jobs")
	if stored != defaultQueueURLBase+"/000000000000/jobs" {
		t.Errorf("a queue created by an AWS name must be recorded under the shim's URL, got %q", stored)
	}
	if answer != "https://sqs.us-east-1.amazonaws.com/000000000000/jobs" {
		t.Errorf("its creator is answered in AWS's shape, got %q", answer)
	}
	h.urlBase = "http://shim.example:4566/"
	if stored, _ := h.queueURLs(aws, "jobs"); stored != "http://shim.example:4566/000000000000/jobs" {
		t.Errorf("SQS_QUEUE_URL_BASE names the recorded URL's base, got %q", stored)
	}
	if got := h.answerURL(aws, "http://aws-shim.open-infra-aws-shim.svc.cluster.local:4566/000000000000/jobs"); got != "https://sqs.us-east-1.amazonaws.com/000000000000/jobs" {
		t.Errorf("GetQueueUrl/ListQueues by an AWS name answer at that name, got %q", got)
	}

	for _, r := range []*http.Request{req("aws-shim.open-infra-aws-shim.svc.cluster.local:4567", true), req("shim.local:4566", false)} {
		stored, answer := h.queueURLs(r, "jobs")
		if stored != answer || !strings.HasPrefix(stored, "http") || !strings.Contains(stored, r.Host+"/000000000000/jobs") {
			t.Errorf("%s: recorded %q answered %q, want both the caller's own endpoint", r.Host, stored, answer)
		}
		const rec = "https://sqs.us-east-1.amazonaws.com/000000000000/legacy"
		if got := h.answerURL(r, rec); got != rec {
			t.Errorf("%s: a recorded URL is reported unchanged to a caller that did not come by an AWS name, got %q", r.Host, got)
		}
	}
}

// constrainedCA is a CA name-constrained to amazonaws.com, like openinfra-aws-endpoints-ca.
func constrainedCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test AWS endpoints CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"amazonaws.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return ca, key
}

func writeLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, certFile, keyFile string, names ...string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The AWS-names listener: off without TLS_CERT_FILE/TLS_KEY_FILE; with them it starts before the
// certificate exists (the Secret is optional) and fails handshakes until it does; then a client that
// trusts the name-constrained CA reaches it by an AWS name (wildcard SANs under the constraint verify),
// and a certificate that CA signed for any other name is refused.
func TestAWSNamesTLSServer(t *testing.T) {
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	if s := newAWSNamesTLSServer(http.NotFoundHandler(), nil); s != nil {
		t.Fatal("unset cert/key: no AWS-names listener")
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	t.Setenv("TLS_CERT_FILE", certFile)
	t.Setenv("TLS_KEY_FILE", keyFile)
	t.Setenv("TLS_LISTEN_ADDR", "")
	srv := newAWSNamesTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(hostNoPort(r.Host)))
	}), nil)
	if srv == nil || srv.Addr != ":8443" || srv.TLSConfig == nil || srv.TLSConfig.GetCertificate == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("want a :8443 listener serving a reloaded certificate with TLS >= 1.2, got %+v", srv)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()

	ca, caKey := constrainedCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	get := func(name string) (string, error) {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: name}, DisableKeepAlives: true}
		resp, err := (&http.Client{Transport: tr}).Get("https://" + ln.Addr().String() + "/")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b := make([]byte, 256)
		n, _ := resp.Body.Read(b)
		return string(b[:n]), nil
	}

	if _, err := get("sqs.us-east-1.amazonaws.com"); err == nil {
		t.Fatal("before the certificate exists, handshakes must fail")
	}
	// Until it has a certificate the reloader looks for one on every handshake.
	writeLeaf(t, ca, caKey, certFile, keyFile, "*.us-east-1.amazonaws.com", "*.s3.us-east-1.amazonaws.com", "*.amazonaws.com")
	for _, name := range []string{"sqs.us-east-1.amazonaws.com", "photos.s3.us-east-1.amazonaws.com", "sts.amazonaws.com"} {
		if _, err := get(name); err != nil {
			t.Errorf("%s: a guest that trusts the AWS endpoints CA must reach the shim: %v", name, err)
		}
	}
	if _, err := get("sqs.us-west-2.amazonaws.com"); err == nil {
		t.Error("a name the certificate does not cover must fail verification")
	}

	// The CA cannot vouch for anything but AWS's names, even when it signs one.
	other := filepath.Join(dir, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	oc, okey := filepath.Join(other, "tls.crt"), filepath.Join(other, "tls.key")
	writeLeaf(t, ca, caKey, oc, okey, "platform.example.com")
	pemBytes, _ := os.ReadFile(oc)
	blk, _ := pem.Decode(pemBytes)
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "platform.example.com"}); err == nil {
		t.Error("the name constraint must refuse a certificate for a name outside amazonaws.com")
	}
}
