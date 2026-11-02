package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	"k8s.io/client-go/kubernetes/fake"
)

const sesDomain = "example.test"

func sesHandlerWith(relay string, authz *dataplaneauthz.Checker) *sesHandler {
	return newSESHandler(fake.NewSimpleClientset(), "default", relay, authz, discardLogger())
}

func sesSendForm(from string) url.Values {
	return url.Values{"Action": {"SendEmail"}, "Source": {from}, "Destination.ToAddresses.member.1": {"ops@example.test"},
		"Message.Subject.Data": {"s"}, "Message.Body.Text.Data": {"b"}}
}

func sesRawForm(source, headerFrom string) url.Values {
	raw := "From: " + headerFrom + "\r\nTo: ops@example.test\r\nSubject: raw\r\n\r\nraw body\r\n"
	v := url.Values{"Action": {"SendRawEmail"}, "RawMessage.Data": {base64.StdEncoding.EncodeToString([]byte(raw))}}
	if source != "" {
		v.Set("Source", source)
	}
	return v
}

// A role granted ses:Send* on its DOMAIN identity (arn:aws:ses:…:identity/example.test, the usual verified-
// domain setup) sends as any address at that domain; not as an address at another domain.
func TestSES_DomainIdentityAuthorizesItsAddresses(t *testing.T) {
	relay := newFakeSMTP(t)
	h := sesHandlerWith(relay.ln.Addr().String(), roleChecker(dpAllow([]string{"ses:SendEmail", "ses:SendRawEmail"}, "Identity::"+sesDomain)))
	for _, v := range []url.Values{sesSendForm("App <app@" + sesDomain + ">"), sesRawForm("", "billing@"+sesDomain)} {
		if w := sesCall(h, ecrRoleClaims(), v); w.Code != 200 {
			t.Fatalf("%s as an address of the granted domain = %d %s", v.Get("Action"), w.Code, w.Body)
		}
	}
	if w := sesCall(h, ecrRoleClaims(), sesSendForm("app@other.test")); w.Code != 403 || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("an address at another domain = %d %s, want AccessDenied", w.Code, w.Body)
	}
	if n := len(relay.got()); n != 2 {
		t.Fatalf("relay received %d messages, want 2", n)
	}
}

// An explicit Deny on either identity wins over an Allow on the other: a Deny on one address is not lifted
// by a grant on its domain, and a Deny on the domain is not lifted by a grant on one address.
func TestSES_ExplicitDenyOnEitherIdentityWins(t *testing.T) {
	relay := newFakeSMTP(t)
	send := []string{"ses:SendEmail"}
	cases := []struct {
		name  string
		stmts []policyengine.Statement
		from  string
		allow bool
	}{
		{"domain grant", []policyengine.Statement{dpAllow(send, "Identity::"+sesDomain)}, "app@" + sesDomain, true},
		{"address grant", []policyengine.Statement{dpAllow(send, "Identity::app@"+sesDomain)}, "app@" + sesDomain, true},
		{"domain grant, address denied", []policyengine.Statement{dpAllow(send, "Identity::"+sesDomain), dpDeny(send, "Identity::app@"+sesDomain)}, "app@" + sesDomain, false},
		{"domain grant, another address denied", []policyengine.Statement{dpAllow(send, "Identity::"+sesDomain), dpDeny(send, "Identity::ceo@"+sesDomain)}, "app@" + sesDomain, true},
		{"address grant, domain denied", []policyengine.Statement{dpAllow(send, "Identity::app@"+sesDomain), dpDeny(send, "Identity::"+sesDomain)}, "app@" + sesDomain, false},
		{"wildcard grant", []policyengine.Statement{dpAllow(send, "Identity::*")}, "app@" + sesDomain, true},
		{"no grant", nil, "app@" + sesDomain, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := sesHandlerWith(relay.ln.Addr().String(), roleChecker(tc.stmts...))
			w := sesCall(h, ecrRoleClaims(), sesSendForm(tc.from))
			if got := w.Code == 200; got != tc.allow {
				t.Fatalf("allowed = %v (%d %s), want %v", got, w.Code, w.Body, tc.allow)
			}
		})
	}
}

// A permission boundary that covers only the domain identity does not stop a domain grant: the boundary
// refuses the address identity, but that is not an explicit Deny.
func TestSES_BoundaryOnTheDomainLetsADomainGrantSend(t *testing.T) {
	relay := newFakeSMTP(t)
	send := []string{"ses:SendEmail"}
	authz := dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{
			Docs: []dataplaneauthz.PolicyDoc{
				{Name: "role-access", AppliesTo: []string{"Role::" + ecrTestRole}, Statements: []policyengine.Statement{dpAllow(send, "Identity::"+sesDomain)}},
				{Name: "ceiling", Statements: []policyengine.Statement{dpAllow(send, "Identity::"+sesDomain)}},
			},
			Boundary: map[string]string{"Role::" + ecrTestRole: "ceiling"},
		}, nil
	}, time.Minute)
	h := sesHandlerWith(relay.ln.Addr().String(), authz)
	if w := sesCall(h, ecrRoleClaims(), sesSendForm("app@"+sesDomain)); w.Code != 200 {
		t.Fatalf("domain grant inside a domain-only boundary = %d %s, want sent", w.Code, w.Body)
	}
	if w := sesCall(h, ecrRoleClaims(), sesSendForm("app@other.test")); w.Code != 403 {
		t.Fatalf("outside the boundary = %d %s, want AccessDenied", w.Code, w.Body)
	}
}

// SendRawEmail is authorized as its Source AND every address in the message's From header: a role allowed
// to send as one identity cannot put another in From.
func TestSES_RawFromHeaderIsAuthorizedWithSource(t *testing.T) {
	relay := newFakeSMTP(t)
	h := sesRoleHandler(t, relay.ln.Addr().String()) // granted on Identity::<sesSender> only
	if w := sesCall(h, ecrRoleClaims(), sesRawForm(sesSender, sesSender)); w.Code != 200 {
		t.Fatalf("Source and From both the granted identity = %d %s", w.Code, w.Body)
	}
	if w := sesCall(h, ecrRoleClaims(), sesRawForm(sesSender, "ceo@example.test")); w.Code != 403 || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("a From header naming another identity = %d %s, want AccessDenied", w.Code, w.Body)
	}
	if w := sesCall(h, ecrRoleClaims(), sesRawForm(sesSender, sesSender+", ceo@example.test")); w.Code != 403 {
		t.Fatalf("a From list including another identity = %d %s, want AccessDenied", w.Code, w.Body)
	}
	if n := len(relay.got()); n != 1 {
		t.Fatalf("relay received %d messages, want only the authorized one", n)
	}
}

// A User whose data-plane policy governs SES (additive over the coarse grant) is held to it the same way:
// its domain grant sends as an address of that domain, and not as another.
func TestSES_UserDomainGrant(t *testing.T) {
	relay := newFakeSMTP(t)
	authz := dataplaneauthz.New(func(context.Context) (dataplaneauthz.Snapshot, error) {
		return dataplaneauthz.Snapshot{Docs: []dataplaneauthz.PolicyDoc{{AppliesTo: []string{"User::tester"},
			Statements: []policyengine.Statement{dpAllow([]string{"ses:SendEmail"}, "Identity::"+sesDomain)}}}}, nil
	}, time.Minute)
	h := newSESHandler(ecrCS(true), "default", relay.ln.Addr().String(), authz, discardLogger())
	user := iam.Claims{Sub: "tester", Groups: []string{"openinfra:powerusers", "openinfra:users"}}
	if w := sesCall(h, user, sesSendForm("app@"+sesDomain)); w.Code != 200 {
		t.Fatalf("user with a domain grant = %d %s", w.Code, w.Body)
	}
	if w := sesCall(h, user, sesSendForm("app@other.test")); w.Code != 403 {
		t.Fatalf("user sending as another domain = %d %s, want AccessDenied", w.Code, w.Body)
	}
}

// --- SES v2 ---

func sesV2Call(h *sesHandler, claims iam.Claims, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req-v2")
	return w
}

func v2ErrorType(w *httptest.ResponseRecorder) string { return w.Header().Get("x-amzn-ErrorType") }

// SES v2 SendEmail (what `aws sesv2 send-email` and SESv2Client send): Simple and Raw content reach the
// relay as the authorized identity; the same identity rules as v1 apply, in v2's JSON error dialect.
func TestSESv2_SendEmail(t *testing.T) {
	relay := newFakeSMTP(t)
	h := sesHandlerWith(relay.ln.Addr().String(), roleChecker(dpAllow([]string{"ses:SendEmail"}, "Identity::"+sesDomain)))
	from := "app@" + sesDomain

	w := sesV2Call(h, ecrRoleClaims(), http.MethodPost, "/v2/email/outbound-emails", map[string]any{
		"FromEmailAddress": "App <" + from + ">",
		"Destination":      map[string]any{"ToAddresses": []string{"ops@example.test"}, "BccAddresses": []string{"audit@example.test"}},
		"ReplyToAddresses": []string{"help@example.test"},
		"Content": map[string]any{"Simple": map[string]any{
			"Subject": map[string]any{"Data": "v2 hello"},
			"Body":    map[string]any{"Text": map[string]any{"Data": "sent through SES v2"}, "Html": map[string]any{"Data": "<p>v2</p>"}},
			"Headers": []map[string]string{{"Name": "X-App", "Value": "fixture"}},
		}},
	})
	var resp struct{ MessageId string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil || resp.MessageId == "" {
		t.Fatalf("v2 SendEmail Simple = %d %s", w.Code, w.Body)
	}
	raw := "From: billing@" + sesDomain + "\r\nTo: ops@example.test\r\nSubject: v2 raw\r\n\r\nraw v2\r\n"
	w = sesV2Call(h, ecrRoleClaims(), http.MethodPost, "/v2/email/outbound-emails", map[string]any{
		"Content": map[string]any{"Raw": map[string]any{"Data": base64.StdEncoding.EncodeToString([]byte(raw))}},
	})
	if w.Code != 200 {
		t.Fatalf("v2 SendEmail Raw = %d %s", w.Code, w.Body)
	}
	msgs := relay.got()
	if len(msgs) != 2 {
		t.Fatalf("relay received %d messages, want 2", len(msgs))
	}
	m := msgs[0]
	if m.from != from || len(m.to) != 2 || !strings.Contains(m.data, "Subject: v2 hello") || !strings.Contains(m.data, "Reply-To: help@example.test") ||
		!strings.Contains(m.data, "X-App: fixture") || !strings.Contains(m.data, "multipart/alternative") || strings.Contains(m.data, "audit@example.test") {
		t.Errorf("v2 Simple message = %+v", m)
	}
	if msgs[1].from != "billing@"+sesDomain || !strings.Contains(msgs[1].data, "Subject: v2 raw") {
		t.Errorf("v2 Raw message = %+v", msgs[1])
	}

	// Another domain; a Raw message whose From header names another identity than FromEmailAddress.
	w = sesV2Call(h, ecrRoleClaims(), http.MethodPost, "/v2/email/outbound-emails", map[string]any{
		"FromEmailAddress": "app@other.test", "Destination": map[string]any{"ToAddresses": []string{"ops@example.test"}},
		"Content": map[string]any{"Simple": map[string]any{"Subject": map[string]any{"Data": "x"}, "Body": map[string]any{"Text": map[string]any{"Data": "x"}}}},
	})
	if w.Code != 403 || v2ErrorType(w) != "AccessDeniedException" {
		t.Fatalf("v2 as another domain = %d %s %q, want AccessDeniedException", w.Code, w.Body, v2ErrorType(w))
	}
	spoof := "From: ceo@other.test\r\nTo: ops@example.test\r\nSubject: spoof\r\n\r\nx\r\n"
	w = sesV2Call(h, ecrRoleClaims(), http.MethodPost, "/v2/email/outbound-emails", map[string]any{
		"FromEmailAddress": from,
		"Content":          map[string]any{"Raw": map[string]any{"Data": base64.StdEncoding.EncodeToString([]byte(spoof))}},
	})
	if w.Code != 403 || v2ErrorType(w) != "AccessDeniedException" {
		t.Fatalf("v2 Raw with a From header outside the grant = %d %s, want AccessDeniedException", w.Code, w.Body)
	}
	if n := len(relay.got()); n != 2 {
		t.Fatalf("a denied v2 send reached the relay: %d messages", n)
	}

	// Template content and malformed requests are refused in v2's dialect.
	w = sesV2Call(h, ecrRoleClaims(), http.MethodPost, "/v2/email/outbound-emails", map[string]any{
		"FromEmailAddress": from, "Destination": map[string]any{"ToAddresses": []string{"ops@example.test"}},
		"Content": map[string]any{"Template": map[string]any{"TemplateName": "welcome"}},
	})
	if w.Code != 400 || v2ErrorType(w) != "BadRequestException" || !strings.Contains(w.Body.String(), "Template") {
		t.Fatalf("v2 Template = %d %s", w.Code, w.Body)
	}
	w = sesV2Call(h, ecrRoleClaims(), http.MethodPost, "/v2/email/outbound-emails", map[string]any{"FromEmailAddress": from})
	if w.Code != 400 || v2ErrorType(w) != "BadRequestException" {
		t.Fatalf("v2 with no content = %d %s", w.Code, w.Body)
	}
}

func TestSESv2_OtherOperations(t *testing.T) {
	relay := newFakeSMTP(t)
	h := sesHandlerWith(relay.ln.Addr().String(), roleChecker(dpAllow([]string{"ses:*"}, "*")))
	w := sesV2Call(h, ecrRoleClaims(), http.MethodGet, "/v2/email/account", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"SendingEnabled":true`) {
		t.Fatalf("v2 GetAccount = %d %s", w.Code, w.Body)
	}
	w = sesV2Call(h, ecrRoleClaims(), http.MethodPost, "/v2/email/identities", map[string]any{"EmailIdentity": sesDomain})
	if w.Code != 400 || v2ErrorType(w) != "BadRequestException" || !strings.Contains(w.Body.String(), "operator concern") {
		t.Fatalf("v2 CreateEmailIdentity = %d %s", w.Code, w.Body)
	}
	w = sesV2Call(h, ecrRoleClaims(), http.MethodGet, "/v2/email/templates", nil)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "not implemented") {
		t.Fatalf("an unserved v2 operation = %d %s", w.Code, w.Body)
	}
	// A role with no SES grant cannot read the account either.
	none := sesHandlerWith(relay.ln.Addr().String(), roleChecker(dpAllow([]string{"s3:GetObject"}, "*")))
	if w := sesV2Call(none, ecrRoleClaims(), http.MethodGet, "/v2/email/account", nil); w.Code != 403 {
		t.Fatalf("v2 GetAccount without a grant = %d %s", w.Code, w.Body)
	}
	// With the relay off, v2 answers as not fronted — in its own dialect.
	off := sesHandlerWith("smtp-relay.mail.svc.cluster.local:587", roleChecker(dpAllow([]string{"ses:*"}, "*")))
	off.lookup = func(context.Context, string) ([]string, error) { return nil, errors.New("no such host") }
	if w := sesV2Call(off, ecrRoleClaims(), http.MethodPost, "/v2/email/outbound-emails", map[string]any{}); w.Code != 501 || !strings.Contains(w.Body.String(), "not fronted") {
		t.Fatalf("v2 with the relay off = %d %s", w.Code, w.Body)
	}
	// A v2 signature failure is written in v2's dialect.
	aw := httptest.NewRecorder()
	h.authFailure(aw, httptest.NewRequest(http.MethodPost, "/v2/email/outbound-emails", nil), "req-x")
	if aw.Code != 403 || v2ErrorType(aw) != "SignatureDoesNotMatch" {
		t.Fatalf("v2 auth failure = %d %q", aw.Code, v2ErrorType(aw))
	}
}
