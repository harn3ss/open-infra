package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func formReq(vals url.Values) *http.Request {
	r, _ := http.NewRequest("POST", "/", strings.NewReader(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	return r
}

func TestSESAddrList(t *testing.T) {
	r := formReq(url.Values{
		"Destination.ToAddresses.member.1": {"a@x.test"},
		"Destination.ToAddresses.member.2": {"Bob <b@x.test>"},
	})
	got := sesAddrList(r, "Destination.ToAddresses.member")
	if len(got) != 2 || got[0] != "a@x.test" || got[1] != "Bob <b@x.test>" {
		t.Fatalf("sesAddrList = %v", got)
	}
}

func TestEmailAddr(t *testing.T) {
	for in, want := range map[string]string{
		"a@x.test":       "a@x.test",
		"Bob <b@x.test>": "b@x.test",
		"  c@x.test  ":   "c@x.test",
		"":               "",
	} {
		if got := emailAddr(in); got != want {
			t.Errorf("emailAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildMIME_Multipart(t *testing.T) {
	msg := string(buildMIME("noreply@x.test", []string{"to@x.test"}, []string{"cc@x.test"}, "Hi", "plain body", "<b>html body</b>"))
	for _, want := range []string{
		"From: noreply@x.test\r\n",
		"To: to@x.test\r\n",
		"Cc: cc@x.test\r\n",
		"Subject: Hi\r\n",
		"MIME-Version: 1.0\r\n",
		"multipart/alternative; boundary=",
		"text/plain; charset=UTF-8",
		"plain body",
		"text/html; charset=UTF-8",
		"<b>html body</b>",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("buildMIME missing %q in:\n%s", want, msg)
		}
	}
}

func TestBuildMIME_TextOnly(t *testing.T) {
	msg := string(buildMIME("f@x.test", []string{"t@x.test"}, nil, "S", "just text", ""))
	if !strings.Contains(msg, "Content-Type: text/plain; charset=UTF-8") || strings.Contains(msg, "multipart") {
		t.Fatalf("text-only MIME wrong:\n%s", msg)
	}
}

func TestEnvelopeFromRaw(t *testing.T) {
	raw := "From: Alice <a@x.test>\r\nTo: b@x.test, c@x.test\r\nSubject: Hi\r\n\r\nbody\r\n"
	from, to := envelopeFromRaw([]byte(raw))
	if from != "a@x.test" {
		t.Errorf("from = %q", from)
	}
	if len(to) != 2 || to[0] != "b@x.test" || to[1] != "c@x.test" {
		t.Errorf("to = %v", to)
	}
}
