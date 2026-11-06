package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/policyengine"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

// The SMTP password is AWS's version-4 derivation. The expected values are the output of AWS's own
// published script (SES Developer Guide, "Obtaining Amazon SES SMTP credentials", smtp_credentials_generate.py)
// for AWS's documentation example secret access key.
func TestSESSMTPPassword_AWSPublishedAlgorithm(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	for region, want := range map[string]string{
		"us-east-1": "BLBM/9hSUELfq8Gw+rU1YcBjkOxGbhT2XG763xVLGWL9",
		"us-west-2": "BF2PynzbSCAjX08zhZZnP/kW+T9P5zs/1Er0pi5vTEmd",
		"eu-west-1": "BMW5RDrXmmVs0lV7GpI4oLkHXpZ4stDsk6q91z1g38Pk",
	} {
		if got := sesSMTPPassword(secret, region); got != want {
			t.Errorf("%s: SMTP password %q, want AWS's %q", region, got, want)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(sesSMTPPassword(secret, "us-east-1"))
	if err != nil || len(raw) != 33 || raw[0] != 0x04 {
		t.Fatalf("a password is base64 of the version byte 0x04 and a 32-byte HMAC-SHA256: %x %v", raw, err)
	}
}

const (
	smtpKeyID     = "OIAKSMTPTEST0000001"
	smtpSecret    = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlYw=="
	smtpMemberKey = "OIAKSMTPMEMBER00001"
	smtpNoPolicy  = "OIAKSMTPNOPOLICY001"
	smtpGoneKey   = "OIAKSMTPGONE0000001"
)

func smtpPassword(secret string) string { return sesSMTPPassword(secret, "us-east-1") }

// smtpKeys are the fixture's access keys: a management-account user allowed ses:SendRawEmail as
// app@example.test, a member account's user, a user with no policy, and a key whose owner is gone.
func smtpKeys() fakeKeys {
	return fakeKeys{
		smtpKeyID:     {AccessKeyID: smtpKeyID, SecretKey: smtpSecret, Owner: "smtp-user"},
		smtpMemberKey: {AccessKeyID: smtpMemberKey, SecretKey: smtpSecret, Owner: "bob", Account: testMember},
		smtpNoPolicy:  {AccessKeyID: smtpNoPolicy, SecretKey: smtpSecret, Owner: "nobody"},
		smtpGoneKey:   {AccessKeyID: smtpGoneKey, SecretKey: smtpSecret, Owner: "gone"},
	}
}

func smtpChecker(t *testing.T) *dataplaneauthz.Checker {
	return checkerInMode(t, "enforce",
		dataplaneauthz.PolicyDoc{Name: "AmazonSesSendingAccess", AppliesTo: []string{"User::smtp-user"},
			Statements: []policyengine.Statement{dpAllow([]string{"ses:SendRawEmail"}, "Identity::"+sesSender)}},
		dataplaneauthz.PolicyDoc{Name: "member-ses", AppliesTo: []string{"User::" + memberHome + "/bob"},
			Statements: []policyengine.Statement{dpAllow([]string{"ses:SendRawEmail"}, "*")}})
}

type smtpFixture struct {
	addr, tlsAddr string
	relay         *fakeSMTP
	backend       *sesSMTPBackend
}

// newSMTPFixture serves the SMTP interface (STARTTLS and TLS Wrapper) over a capturing relay, with a test
// certificate; dyn holds the kind: Accounts a member account's identities are read from (nil: none).
func newSMTPFixture(t *testing.T, dyn dynamic.Interface) *smtpFixture {
	t.Helper()
	relay := newFakeSMTP(t)
	h := newSESHandler(csWithSAR(true), "default", relay.ln.Addr().String(), smtpChecker(t), discardLogger())
	h.dyn = dyn
	auth := &authenticator{
		keys: smtpKeys(),
		resolve: func(_ context.Context, owner string) ([]string, bool) {
			return []string{"openinfra:users"}, owner != "gone"
		},
		resolveIn: func(_ context.Context, _, owner string) ([]string, bool) {
			return []string{"openinfra:users"}, owner != "gone"
		},
		dir: testDirectory(),
	}
	b := newSESSMTPBackend(h, auth, discardLogger())
	b.failDelay = 0
	certPEM, keyPEM := testCert(t, "aws-shim.open-infra-aws-shim.svc", false)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	srv := newSESSMTPServer(b, cfg)
	t.Cleanup(func() { _ = srv.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	go func() { _ = srv.Serve(tls.NewListener(tln, cfg)) }()
	return &smtpFixture{addr: ln.Addr().String(), tlsAddr: tln.Addr().String(), relay: relay, backend: b}
}

// smtpClient speaks raw SMTP, so each reply is asserted exactly as the server wrote it.
type smtpClient struct {
	t    *testing.T
	conn net.Conn
	tp   *textproto.Conn
}

func dialSMTP(t *testing.T, addr string, implicitTLS bool) *smtpClient {
	t.Helper()
	var conn net.Conn
	var err error
	if implicitTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test certificate
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	c := &smtpClient{t: t, conn: conn, tp: textproto.NewConn(conn)}
	t.Cleanup(func() { _ = conn.Close() })
	if code, msg := c.read(); code != 220 || !strings.HasPrefix(msg, sesSMTPDomain+" ESMTP") {
		t.Fatalf("greeting %d %q, want 220 %s ESMTP", code, msg, sesSMTPDomain)
	}
	return c
}

func (c *smtpClient) read() (int, string) {
	c.t.Helper()
	code, msg, err := c.tp.ReadResponse(0)
	if err != nil && code == 0 {
		c.t.Fatalf("reading a reply: %v", err)
	}
	return code, msg
}

func (c *smtpClient) cmd(line string) (int, string) {
	c.t.Helper()
	if err := c.tp.PrintfLine("%s", line); err != nil {
		c.t.Fatal(err)
	}
	return c.read()
}

func (c *smtpClient) startTLS() {
	c.t.Helper()
	if code, msg := c.cmd("STARTTLS"); code != 220 {
		c.t.Fatalf("STARTTLS = %d %s", code, msg)
	}
	tc := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test certificate
	if err := tc.Handshake(); err != nil {
		c.t.Fatal(err)
	}
	c.conn, c.tp = tc, textproto.NewConn(tc)
	if code, msg := c.cmd("EHLO client.test"); code != 250 {
		c.t.Fatalf("EHLO after STARTTLS = %d %s", code, msg)
	}
}

// login opens an encrypted session (STARTTLS) and signs in with AUTH PLAIN.
func (c *smtpClient) login(user, pass string) (int, string) {
	c.t.Helper()
	c.cmd("EHLO client.test")
	c.startTLS()
	return c.cmd("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00"+user+"\x00"+pass)))
}

// send submits one message and returns the reply to its end of DATA (or the first refusal before it).
func (c *smtpClient) send(from string, rcpts []string, msg string) (int, string) {
	c.t.Helper()
	if code, text := c.cmd("MAIL FROM:<" + from + ">"); code != 250 {
		return code, text
	}
	for _, r := range rcpts {
		if code, text := c.cmd("RCPT TO:<" + r + ">"); code != 250 {
			return code, text
		}
	}
	if code, text := c.cmd("DATA"); code != 354 {
		return code, text
	}
	if err := c.tp.PrintfLine("%s\r\n.", strings.ReplaceAll(msg, "\n", "\r\n")); err != nil {
		c.t.Fatal(err)
	}
	return c.read()
}

func smtpMessage(from, subject string) string {
	return "From: " + from + "\nTo: ops@example.test\nSubject: " + subject + "\n\nsent through the SMTP interface"
}

// The endpoint behaves as SES's does before a credential crosses: it advertises STARTTLS and AUTH PLAIN
// LOGIN, refuses AUTH until the connection is encrypted, and mail until a user has signed in.
func TestSESSMTP_EncryptionThenAuthentication(t *testing.T) {
	f := newSMTPFixture(t, nil)
	c := dialSMTP(t, f.addr, false)
	code, ehlo := c.cmd("EHLO client.test")
	if code != 250 || !strings.Contains(ehlo, "STARTTLS") || !strings.Contains(ehlo, "AUTH PLAIN LOGIN") ||
		!strings.Contains(ehlo, "SIZE 10485760") {
		t.Fatalf("EHLO = %d %q, want STARTTLS, AUTH PLAIN LOGIN and SES's SIZE", code, ehlo)
	}
	for _, auth := range []string{"AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00"+smtpKeyID+"\x00"+smtpPassword(smtpSecret))), "AUTH LOGIN"} {
		if code, msg := c.cmd(auth); code != 530 || msg != "Must issue a STARTTLS command first" {
			t.Errorf("%s before STARTTLS = %d %q, want SES's 530 Must issue a STARTTLS command first", strings.Fields(auth)[1], code, msg)
		}
	}
	if code, msg := c.cmd("MAIL FROM:<" + sesSender + ">"); code != 530 || msg != "Authentication required" {
		t.Errorf("MAIL before AUTH = %d %q, want 530 Authentication required", code, msg)
	}
	c.startTLS()
	if code, msg := c.cmd("MAIL FROM:<" + sesSender + ">"); code != 530 || msg != "Authentication required" {
		t.Errorf("MAIL after STARTTLS but before AUTH = %d %q, want 530 Authentication required", code, msg)
	}
	if n := len(f.relay.got()); n != 0 {
		t.Fatalf("the relay received %d messages", n)
	}
}

// SES SMTP credentials are an access key id and the SMTP password derived from its secret: the right ones
// sign in (PLAIN and LOGIN), and every wrong one — a wrong password, the secret itself, a password for
// another region, an unknown or inactive key, a key whose owner is gone — is the same 535.
func TestSESSMTP_Credentials(t *testing.T) {
	f := newSMTPFixture(t, nil)
	if code, msg := dialSMTP(t, f.addr, false).login(smtpKeyID, smtpPassword(smtpSecret)); code != 235 {
		t.Fatalf("AUTH PLAIN with the derived password = %d %q", code, msg)
	}
	c := dialSMTP(t, f.addr, false)
	c.cmd("EHLO client.test")
	c.startTLS()
	if code, _ := c.cmd("AUTH LOGIN"); code != 334 {
		t.Fatalf("AUTH LOGIN should ask for the user name, got %d", code)
	}
	if code, _ := c.cmd(base64.StdEncoding.EncodeToString([]byte(smtpKeyID))); code != 334 {
		t.Fatalf("AUTH LOGIN should ask for the password, got %d", code)
	}
	if code, msg := c.cmd(base64.StdEncoding.EncodeToString([]byte(smtpPassword(smtpSecret)))); code != 235 {
		t.Fatalf("AUTH LOGIN with the derived password = %d %q", code, msg)
	}
	for name, cred := range map[string][2]string{
		"wrong password":        {smtpKeyID, smtpPassword("another-secret")},
		"the secret itself":     {smtpKeyID, smtpSecret},
		"another region":        {smtpKeyID, sesSMTPPassword(smtpSecret, "eu-west-1")},
		"unknown key":           {"OIAKNOSUCHKEY000001", smtpPassword(smtpSecret)},
		"owner no longer exist": {smtpGoneKey, smtpPassword(smtpSecret)},
		"empty":                 {"", ""},
	} {
		if code, msg := dialSMTP(t, f.addr, false).login(cred[0], cred[1]); code != 535 || msg != "Authentication Credentials Invalid" {
			t.Errorf("%s: AUTH = %d %q, want 535 Authentication Credentials Invalid", name, code, msg)
		}
	}
	// TLS Wrapper: encrypted from the first byte, so AUTH is taken at once.
	c = dialSMTP(t, f.tlsAddr, true)
	if code, ehlo := c.cmd("EHLO client.test"); code != 250 || strings.Contains(ehlo, "STARTTLS") {
		t.Fatalf("EHLO over TLS Wrapper = %d %q, want no STARTTLS", code, ehlo)
	}
	if code, msg := c.cmd("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00"+smtpKeyID+"\x00"+smtpPassword(smtpSecret)))); code != 235 {
		t.Fatalf("AUTH over TLS Wrapper = %d %q", code, msg)
	}
}

// A signed-in user's message is SendRawEmail as that user: sent as the identity its policy grants it is
// delivered to the relay with its envelope (250 Ok <MessageId>); a From header naming another identity, or
// a user with no ses:SendRawEmail, is SES's 554 Access denied, and nothing reaches the relay.
func TestSESSMTP_SendsAsSendRawEmail(t *testing.T) {
	f := newSMTPFixture(t, nil)
	c := dialSMTP(t, f.addr, false)
	if code, _ := c.login(smtpKeyID, smtpPassword(smtpSecret)); code != 235 {
		t.Fatal("sign in")
	}
	code, msg := c.send(sesSender, []string{"ops@example.test", "audit@example.test"}, smtpMessage("App <"+sesSender+">", "granted"))
	if code != 250 || !strings.HasPrefix(msg, "Ok ") || !strings.HasSuffix(msg, "@open-infra-ses") {
		t.Fatalf("a granted send = %d %q, want 250 Ok <MessageId>", code, msg)
	}
	got := f.relay.got()
	if len(got) != 1 || got[0].from != sesSender || strings.Join(got[0].to, ",") != "ops@example.test,audit@example.test" ||
		!strings.Contains(got[0].data, "Subject: granted") {
		t.Fatalf("the relay got %+v, want the message with its envelope", got)
	}
	// The From header is sent as too: the envelope alone cannot launder another identity.
	if code, msg := c.send(sesSender, []string{"ops@example.test"}, smtpMessage("ceo@example.test", "header")); code != 554 ||
		!strings.HasPrefix(msg, "Access denied: ") || !strings.Contains(msg, "ses:SendRawEmail") {
		t.Errorf("a From header outside the grant = %d %q, want 554 Access denied", code, msg)
	}
	if code, msg := c.send("ceo@example.test", []string{"ops@example.test"}, smtpMessage(sesSender, "envelope")); code != 554 ||
		!strings.HasPrefix(msg, "Access denied: ") {
		t.Errorf("MAIL FROM outside the grant = %d %q, want 554 Access denied", code, msg)
	}
	n := dialSMTP(t, f.addr, false)
	if code, _ := n.login(smtpNoPolicy, smtpPassword(smtpSecret)); code != 235 {
		t.Fatal("a user with no policy still signs in (authentication is not authorization)")
	}
	if code, msg := n.send(sesSender, []string{"ops@example.test"}, smtpMessage(sesSender, "nopolicy")); code != 554 ||
		!strings.HasPrefix(msg, "Access denied: User: arn:aws:iam::") {
		t.Errorf("a user without ses:SendRawEmail = %d %q, want 554 Access denied", code, msg)
	}
	if got := f.relay.got(); len(got) != 1 {
		t.Fatalf("the relay received %d messages, want only the granted one", len(got))
	}
	if code, msg := c.cmd("MAIL FROM:<not an address>"); code == 250 {
		t.Errorf("an invalid MAIL FROM was accepted: %q", msg)
	}
}

func sesAccountObj(id string, ses map[string]any) *unstructured.Unstructured {
	spec := map[string]any{"accountId": id, "namespaces": []any{memberHome}}
	if ses != nil {
		spec["ses"] = ses
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "organizations.openinfra.dev/v1", "kind": "Account", "metadata": map[string]any{"name": id}, "spec": spec}}
}

func accountsDyn(objs ...runtime.Object) dynamic.Interface {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrAccounts: "AccountList"}, objs...)
}

// A member account's user sends only as the identities verified for its account — and, while the account
// is in the sandbox, only to them: anything else is SES's 554 Message rejected: Email address is not
// verified, naming every identity that failed.
func TestSESSMTP_MemberAccountVerifiedIdentities(t *testing.T) {
	cases := []struct {
		name    string
		account map[string]any // the Account's spec.ses (nil: none)
		from    string
		rcpts   []string
		failed  string // "" = delivered
	}{
		{"nothing verified", nil, sesSender, []string{"ops@example.test"}, sesSender + ", ops@example.test"},
		{"verified domain, sandbox, unverified recipient",
			map[string]any{"verifiedIdentities": []any{"example.test"}}, sesSender, []string{"ops@elsewhere.test"}, "ops@elsewhere.test"},
		{"verified domain, sandbox, verified recipient",
			map[string]any{"verifiedIdentities": []any{"Example.Test"}}, sesSender, []string{"ops@example.test"}, ""},
		{"production access, any recipient",
			map[string]any{"verifiedIdentities": []any{"example.test"}, "productionAccessEnabled": true}, sesSender, []string{"ops@elsewhere.test"}, ""},
		{"verified address, another address of its domain",
			map[string]any{"verifiedIdentities": []any{"noreply@example.test"}, "productionAccessEnabled": true}, sesSender, []string{"ops@elsewhere.test"}, sesSender},
		{"a subdomain is its own identity",
			map[string]any{"verifiedIdentities": []any{"example.test"}, "productionAccessEnabled": true}, "app@mail.example.test", []string{"ops@elsewhere.test"}, "app@mail.example.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dyn dynamic.Interface = accountsDyn()
			if tc.account != nil {
				dyn = accountsDyn(sesAccountObj(testMember, tc.account))
			}
			f := newSMTPFixture(t, dyn)
			c := dialSMTP(t, f.addr, false)
			if code, msg := c.login(smtpMemberKey, smtpPassword(smtpSecret)); code != 235 {
				t.Fatalf("member sign in = %d %q", code, msg)
			}
			code, msg := c.send(tc.from, tc.rcpts, smtpMessage(tc.from, tc.name))
			if tc.failed == "" {
				if code != 250 || len(f.relay.got()) != 1 {
					t.Fatalf("send = %d %q (relay %d), want delivered", code, msg, len(f.relay.got()))
				}
				return
			}
			want := "Message rejected: Email address is not verified. The following identities failed the check in region US-EAST-1: " + tc.failed
			if code != 554 || msg != want {
				t.Fatalf("send = %d %q, want 554 %q", code, msg, want)
			}
			if n := len(f.relay.got()); n != 0 {
				t.Fatalf("the relay received %d messages", n)
			}
		})
	}
}

// AUTH failures are limited per client address and per access key id: past the limit even the right
// credentials are 454 Temporary authentication failure, with no key lookup, until the window passes.
func TestSESSMTP_AuthFailuresAreRateLimited(t *testing.T) {
	f := newSMTPFixture(t, nil)
	now := time.Unix(1_800_000_000, 0)
	f.backend.limiter = newAuthFailureLimiter(3, time.Minute)
	f.backend.limiter.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if code, _ := dialSMTP(t, f.addr, false).login(smtpKeyID, "wrong"); code != 535 {
			t.Fatalf("failure %d = %d, want 535", i+1, code)
		}
	}
	if code, msg := dialSMTP(t, f.addr, false).login(smtpKeyID, smtpPassword(smtpSecret)); code != 454 || msg != "Temporary authentication failure" {
		t.Fatalf("past the limit = %d %q, want 454 Temporary authentication failure", code, msg)
	}
	now = now.Add(time.Minute)
	if code, msg := dialSMTP(t, f.addr, false).login(smtpKeyID, smtpPassword(smtpSecret)); code != 235 {
		t.Fatalf("after the window = %d %q, want 235", code, msg)
	}
}

func TestAuthFailureLimiter_KeysAndMemory(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newAuthFailureLimiter(2, time.Minute)
	l.now = func() time.Time { return now }
	l.fail("ip:a", "key:K")
	l.fail("ip:b", "key:K")
	if !l.blocked("ip:c", "key:K") {
		t.Fatal("a key failed from two addresses is blocked from a third")
	}
	if l.blocked("ip:a", "key:other") {
		t.Fatal("one failure from an address does not block it")
	}
	for i := 0; i < authFailureLimiterMaxKeys+10; i++ {
		l.fail("ip:" + strings.Repeat("x", i%7) + time.Duration(i).String())
	}
	if len(l.fails) > authFailureLimiterMaxKeys {
		t.Fatalf("the limiter holds %d keys, more than its bound %d", len(l.fails), authFailureLimiterMaxKeys)
	}
}

// A message over SES's 10 MB SMTP limit is SES's 552 Message is too long.
func TestSESSMTP_MessageTooLong(t *testing.T) {
	f := newSMTPFixture(t, nil)
	c := dialSMTP(t, f.addr, false)
	if code, _ := c.login(smtpKeyID, smtpPassword(smtpSecret)); code != 235 {
		t.Fatal("sign in")
	}
	big := smtpMessage(sesSender, "big") + "\n" + strings.Repeat(strings.Repeat("x", 998)+"\n", sesSMTPMaxMessageBytes/999+2)
	if code, msg := c.send(sesSender, []string{"ops@example.test"}, big); code != 552 || msg != "Message is too long." {
		t.Fatalf("an oversized message = %d %q, want 552 Message is too long.", code, msg)
	}
	if n := len(f.relay.got()); n != 0 {
		t.Fatalf("the relay received %d messages", n)
	}
}

// Every SES front-door answer maps to SES's SMTP reply.
func TestSESSMTPAnswer(t *testing.T) {
	q := func(code, msg string) []byte {
		return []byte(`<?xml version="1.0"?><ErrorResponse><Error><Type>Sender</Type><Code>` + code + `</Code><Message>` + msg + `</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
	}
	for _, tc := range []struct {
		status int
		body   []byte
		code   int
		text   string
	}{
		{200, []byte(`<SendRawEmailResponse><SendRawEmailResult><MessageId>abc@open-infra-ses</MessageId></SendRawEmailResult></SendRawEmailResponse>`), 250, "Ok abc@open-infra-ses"},
		{400, q("MessageRejected", "Email address is not verified."), 554, "Message rejected: Email address is not verified."},
		{403, q("AccessDenied", "User: x is not\nauthorized"), 554, "Access denied: User: x is not authorized"},
		{400, q("InvalidParameterValue", "bad"), 554, "Transaction failed: bad"},
		{500, q("InternalFailure", "the relay could not accept the message"), 451, "Temporary service failure"},
		{501, q("NotImplemented", "not fronted"), 451, "Temporary service failure"},
		{200, []byte("garbage"), 451, "Temporary service failure"},
	} {
		got := sesSMTPAnswer(tc.status, tc.body)
		if got.Code != tc.code || got.Message != tc.text {
			t.Errorf("%d %s → %d %q, want %d %q", tc.status, tc.body, got.Code, got.Message, tc.code, tc.text)
		}
	}
}

// Nothing the interface logs carries a password: a user name that is not an access key id is never shown.
func TestLoggableKeyID(t *testing.T) {
	if got := loggableKeyID(smtpKeyID); got != smtpKeyID {
		t.Errorf("an access key id is loggable, got %q", got)
	}
	if got := loggableKeyID(smtpPassword(smtpSecret)); strings.Contains(got, smtpPassword(smtpSecret)) {
		t.Errorf("a password typed as the user name was logged: %q", got)
	}
}
