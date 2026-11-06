package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// probeSMTPClient is the SMTP client of probe/aws-shim-ses-smtp.sh (Python's smtplib, as an app's SMTP
// library speaks), extracted from the probe.
func probeSMTPClient(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../../probe/aws-shim-ses-smtp.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	start := strings.Index(s, "<<'PY'\n")
	end := strings.Index(s, "\nPY\n")
	if start < 0 || end < start {
		t.Fatal("no smtplib client in the probe")
	}
	p := filepath.Join(t.TempDir(), "smtp.py")
	if err := os.WriteFile(p, []byte(s[start+len("<<'PY'\n"):end+1]), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A real SMTP client — Python's smtplib, driven by the probe's own client — speaks to the interface: STARTTLS,
// AUTH PLAIN and LOGIN, the derived password (the probe derives it in Python, as AWS's script does), a
// delivered message and SES's refusals.
func TestSESSMTP_PythonSmtplibInterop(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	client := probeSMTPClient(t)
	f := newSMTPFixture(t, nil)
	host, port, _ := net.SplitHostPort(f.addr)
	run := func(mode string, env ...string) string {
		t.Helper()
		cmd := exec.Command(py, "-I", client, mode)
		cmd.Env = append([]string{"SMTP_HOST=" + host, "SMTP_PORT=" + port, "RCPT=ops@example.test"}, env...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	pw := run("password", "SMTP_SECRET="+smtpSecret, "SMTP_REGION=us-east-1")
	if pw != smtpPassword(smtpSecret) {
		t.Fatalf("the probe derives %q, the shim %q", pw, smtpPassword(smtpSecret))
	}
	for _, tc := range []struct {
		name string
		mode string
		env  []string
		want string
	}{
		{"AUTH in clear", "auth-in-clear", []string{"SMTP_USER=" + smtpKeyID, "SMTP_PASS=" + pw}, "530 Must issue a STARTTLS command first"},
		{"LOGIN, wrong password", "login", []string{"SMTP_USER=" + smtpKeyID, "SMTP_PASS=wrong"}, "535 Authentication Credentials Invalid"},
		{"LOGIN", "login", []string{"SMTP_USER=" + smtpKeyID, "SMTP_PASS=" + pw}, "235 "},
		{"granted", "send", []string{"SMTP_USER=" + smtpKeyID, "SMTP_PASS=" + pw, "MAIL_FROM=" + sesSender,
			"HEADER_FROM=Probe <" + sesSender + ">", "SUBJECT=granted"}, "250 Ok "},
		{"From header outside the grant", "send", []string{"SMTP_USER=" + smtpKeyID, "SMTP_PASS=" + pw, "MAIL_FROM=" + sesSender,
			"HEADER_FROM=ceo@example.test", "SUBJECT=denied"}, "554 Access denied: "},
		{"no policy", "send", []string{"SMTP_USER=" + smtpNoPolicy, "SMTP_PASS=" + pw, "MAIL_FROM=" + sesSender,
			"HEADER_FROM=" + sesSender, "SUBJECT=nopolicy"}, "554 Access denied: "},
		{"PLAIN, wrong password", "send", []string{"SMTP_USER=" + smtpKeyID, "SMTP_PASS=wrong", "MAIL_FROM=" + sesSender,
			"HEADER_FROM=" + sesSender, "SUBJECT=x"}, "535 Authentication Credentials Invalid"},
	} {
		if got := run(tc.mode, tc.env...); !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s: %q, want %q…", tc.name, got, tc.want)
		}
	}
	if got := f.relay.got(); len(got) != 1 || !strings.Contains(got[0].data, "Subject: granted") {
		t.Fatalf("the relay got %d messages, want only the granted one", len(got))
	}
}
