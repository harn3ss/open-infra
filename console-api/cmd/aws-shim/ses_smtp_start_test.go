package main

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func authPlain(user, pass string) string {
	return "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00"+user+"\x00"+pass))
}

// startSESSMTP serves from its environment: off is off; with the in-cluster certificate it offers STARTTLS
// and serves TLS Wrapper; without one it offers no STARTTLS, so it never takes a credential.
func TestStartSESSMTP_FromItsEnvironment(t *testing.T) {
	h := newSESHandler(csWithSAR(true), "default", "127.0.0.1:1", smtpChecker(t), discardLogger())
	auth := &authenticator{keys: smtpKeys(), resolve: func(_ context.Context, owner string) ([]string, bool) { return nil, true }}
	errs := make(chan error, 1)

	t.Setenv("SES_SMTP_LISTEN_ADDR", "off")
	if s := startSESSMTP(h, auth, discardLogger(), errs); s != nil {
		t.Fatal("SES_SMTP_LISTEN_ADDR=off still served")
	}

	dir := t.TempDir()
	certPEM, keyPEM := testCert(t, "aws-shim.open-infra-aws-shim.svc", false)
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	plain, wrapped := freePort(t), freePort(t)
	t.Setenv("SES_SMTP_LISTEN_ADDR", plain)
	t.Setenv("SES_SMTPS_LISTEN_ADDR", wrapped)
	t.Setenv("INTERNAL_TLS_CERT_FILE", certFile)
	t.Setenv("INTERNAL_TLS_KEY_FILE", keyFile)
	s := startSESSMTP(h, auth, discardLogger(), errs)
	if s == nil {
		t.Fatal("not served")
	}
	t.Cleanup(func() { _ = s.Close() })
	c := dialSMTP(t, plain, false)
	if code, ehlo := c.cmd("EHLO client.test"); code != 250 || !strings.Contains(ehlo, "STARTTLS") {
		t.Fatalf("EHLO = %d %q, want STARTTLS offered", code, ehlo)
	}
	c.startTLS()
	if code, msg := c.cmd(authPlain(smtpKeyID, smtpPassword(smtpSecret))); code != 235 {
		t.Fatalf("AUTH after STARTTLS = %d %q", code, msg)
	}
	w := dialSMTP(t, wrapped, true)
	if code, msg := w.cmd("EHLO client.test"); code != 250 {
		t.Fatalf("TLS Wrapper EHLO = %d %q", code, msg)
	}

	// Without a certificate: no STARTTLS, no TLS Wrapper listener, and AUTH is refused.
	plain2, wrapped2 := freePort(t), freePort(t)
	t.Setenv("SES_SMTP_LISTEN_ADDR", plain2)
	t.Setenv("SES_SMTPS_LISTEN_ADDR", wrapped2)
	t.Setenv("INTERNAL_TLS_CERT_FILE", "")
	s2 := startSESSMTP(h, auth, discardLogger(), errs)
	if s2 == nil {
		t.Fatal("not served without a certificate")
	}
	t.Cleanup(func() { _ = s2.Close() })
	c2 := dialSMTP(t, plain2, false)
	if code, ehlo := c2.cmd("EHLO client.test"); code != 250 || strings.Contains(ehlo, "STARTTLS") {
		t.Fatalf("EHLO without a certificate = %d %q, want no STARTTLS", code, ehlo)
	}
	if code, msg := c2.cmd(authPlain(smtpKeyID, smtpPassword(smtpSecret))); code != 530 {
		t.Fatalf("AUTH without a certificate = %d %q, want 530", code, msg)
	}
	if conn, err := net.Dial("tcp", wrapped2); err == nil {
		_ = conn.Close()
		t.Fatal("a TLS Wrapper listener was served without a certificate")
	}
	select {
	case err := <-errs:
		t.Fatalf("a listener failed: %v", err)
	default:
	}
}
