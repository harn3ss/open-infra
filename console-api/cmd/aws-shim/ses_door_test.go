package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeSMTP is the least SMTP net/smtp needs (no STARTTLS, no AUTH): it records each message's envelope
// and data, as a capturing relay would.
type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []fakeMail
}

type fakeMail struct {
	from string
	to   []string
	data string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.session(c)
		}
	}()
	return f
}

func (f *fakeSMTP) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	rd := bufio.NewReader(c)
	say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	say("220 capture ESMTP")
	var m fakeMail
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250-capture")
			say("250 8BITMIME")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			m = fakeMail{from: smtpPath(line[len("MAIL FROM:"):])}
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			m.to = append(m.to, smtpPath(line[len("RCPT TO:"):]))
			say("250 ok")
		case cmd == "DATA":
			say("354 go ahead")
			var b strings.Builder
			for {
				l, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			m.data = b.String()
			f.mu.Lock()
			f.msgs = append(f.msgs, m)
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

// smtpPath is the address in "<a@b> PARAM=…" (an SMTP MAIL/RCPT argument).
func smtpPath(arg string) string {
	arg = strings.TrimSpace(arg)
	if i := strings.IndexByte(arg, ' '); i >= 0 {
		arg = arg[:i]
	}
	return strings.Trim(arg, "<>")
}

func (f *fakeSMTP) got() []fakeMail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeMail(nil), f.msgs...)
}

const sesSender = "app@example.test"

func sesRoleHandler(t *testing.T, relay string) *sesHandler {
	h := newSESHandler(fake.NewSimpleClientset(), "default", relay,
		roleChecker(dpAllow([]string{"ses:SendEmail", "ses:SendRawEmail"}, "Identity::"+sesSender)), discardLogger())
	return h
}

func sesCall(h *sesHandler, claims iam.Claims, vals url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := formReq(vals)
	h.serve(w, r, claims, "req-1")
	return w
}

// While the relay does not exist (the mail component is off), SES is a service this shim does not front:
// nothing is accepted that could never be delivered.
func TestSES_NotFrontedWithoutTheRelay(t *testing.T) {
	h := sesRoleHandler(t, "smtp-relay.mail.svc.cluster.local:587")
	lookups := 0
	h.lookup = func(context.Context, string) ([]string, error) { lookups++; return nil, errors.New("no such host") }
	for i := 0; i < 3; i++ {
		w := sesCall(h, ecrRoleClaims(), url.Values{"Action": {"SendEmail"}, "Source": {sesSender},
			"Destination.ToAddresses.member.1": {"ops@example.test"}, "Message.Subject.Data": {"s"}, "Message.Body.Text.Data": {"b"}})
		if w.Code != 501 || !strings.Contains(w.Body.String(), "ses&#39; is not fronted") {
			t.Fatalf("without a relay SendEmail = %d %s, want 501 not fronted", w.Code, w.Body)
		}
	}
	if lookups != 1 {
		t.Fatalf("the relay was looked up %d times in one TTL, want 1 (cached)", lookups)
	}
	// The name resolves once the mail component is on — after the cached answer expires.
	h.relayAt = h.relayAt.Add(-sesRelayCheckTTL)
	h.lookup = func(context.Context, string) ([]string, error) { return []string{"10.0.0.1"}, nil }
	if !h.relayExists(context.Background()) {
		t.Fatal("a relay whose name resolves must be served")
	}
}

// An instance role sends as the identity its policy names, with SendEmail and SendRawEmail, and the relay
// receives each message; sending as another identity, or with no policy, is AccessDenied.
func TestSES_InstanceRoleSendsThroughTheRelay(t *testing.T) {
	relay := newFakeSMTP(t)
	h := sesRoleHandler(t, relay.ln.Addr().String()) // an IP literal: always "exists"

	w := sesCall(h, ecrRoleClaims(), url.Values{"Action": {"SendEmail"}, "Source": {"App <" + sesSender + ">"},
		"Destination.ToAddresses.member.1": {"ops@example.test"},
		"Message.Subject.Data":             {"fixture hello"}, "Message.Body.Text.Data": {"sent by the instance role"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<SendEmailResult><MessageId>") {
		t.Fatalf("SendEmail = %d %s", w.Code, w.Body)
	}
	raw := "From: " + sesSender + "\r\nTo: ops@example.test\r\nSubject: fixture raw\r\n\r\nraw body\r\n"
	w = sesCall(h, ecrRoleClaims(), url.Values{"Action": {"SendRawEmail"},
		"RawMessage.Data": {base64.StdEncoding.EncodeToString([]byte(raw))}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<SendRawEmailResult><MessageId>") {
		t.Fatalf("SendRawEmail = %d %s", w.Code, w.Body)
	}
	msgs := relay.got()
	if len(msgs) != 2 {
		t.Fatalf("relay received %d messages, want 2", len(msgs))
	}
	if msgs[0].from != sesSender || len(msgs[0].to) != 1 || msgs[0].to[0] != "ops@example.test" ||
		!strings.Contains(msgs[0].data, "Subject: fixture hello") || !strings.Contains(msgs[0].data, "sent by the instance role") {
		t.Errorf("SendEmail message = %+v", msgs[0])
	}
	if msgs[1].from != sesSender || !strings.Contains(msgs[1].data, "Subject: fixture raw") {
		t.Errorf("SendRawEmail message = %+v", msgs[1])
	}

	// Another identity than the policy names.
	w = sesCall(h, ecrRoleClaims(), url.Values{"Action": {"SendEmail"}, "Source": {"ceo@example.test"},
		"Destination.ToAddresses.member.1": {"ops@example.test"}, "Message.Subject.Data": {"s"}, "Message.Body.Text.Data": {"b"}})
	if w.Code != 403 || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("sending as an identity the role has no grant on = %d %s, want AccessDenied", w.Code, w.Body)
	}
	// A role with no SES policy at all.
	none := newSESHandler(fake.NewSimpleClientset(), "default", relay.ln.Addr().String(),
		roleChecker(dpAllow([]string{"s3:GetObject"}, "*")), discardLogger())
	w = sesCall(none, ecrRoleClaims(), url.Values{"Action": {"SendRawEmail"},
		"RawMessage.Data": {base64.StdEncoding.EncodeToString([]byte(raw))}})
	if w.Code != 403 || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("a role without ses:SendRawEmail = %d %s, want AccessDenied", w.Code, w.Body)
	}
	if len(relay.got()) != 2 {
		t.Fatalf("a denied send reached the relay: %d messages", len(relay.got()))
	}
}
