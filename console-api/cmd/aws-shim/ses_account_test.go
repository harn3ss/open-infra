package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
)

// sesMemberClaims is the member account's bob, whom sesAccountHandler's policy lets use SES.
var sesMemberClaims = iam.Claims{Sub: "bob", Account: testMember}

// sesAccountHandler is an SES front door over a capturing relay in which the member account's bob may
// use SES on every identity (the management account's caller is decided as before accounts).
func sesAccountHandler(t *testing.T) (*sesHandler, *fakeSMTP) {
	t.Helper()
	relay := newFakeSMTP(t)
	authz := checkerInMode(t, "legacy", dataplaneauthz.PolicyDoc{Name: "ses", AppliesTo: []string{"User::" + memberHome + "/bob"},
		Statements: []policyengine.Statement{dpAllow([]string{"ses:*"}, "*")}})
	return newSESHandler(csWithSAR(true), "default", relay.ln.Addr().String(), authz, discardLogger()), relay
}

// sesMemberReq is r as the router hands a member account's request to an account-scoped door.
func sesMemberReq(r *http.Request) *http.Request {
	ctx := awsidentity.WithIdentity(withAccountHome(r.Context(), memberHome), awsidentity.Current().ForAccount(testMember, memberHome))
	return r.WithContext(inAccountScope(ctx))
}

func sesMemberCall(h *sesHandler, claims iam.Claims, vals url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.serve(w, sesMemberReq(formReq(vals)), claims, "req-m")
	return w
}

func sesV2MemberCall(h *sesHandler, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.serve(w, sesMemberReq(r), sesMemberClaims, "req-v2m")
	return w
}

// A member account has verified no identity: whatever it sends as — the management account's verified
// sender included — is refused as AWS refuses an unverified identity, and nothing reaches the relay; the
// management account sends as before.
func TestSES_MemberAccountHasNoVerifiedIdentities(t *testing.T) {
	h, relay := sesAccountHandler(t)
	unverified := "Email address is not verified. The following identities failed the check in region US-EAST-1: "
	for _, v := range []url.Values{sesSendForm("App <" + sesSender + ">"), sesRawForm("", sesSender), sesRawForm(sesSender, "billing@"+sesDomain)} {
		w := sesMemberCall(h, sesMemberClaims, v)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "<Code>MessageRejected</Code>") ||
			!strings.Contains(w.Body.String(), unverified+sesSender) {
			t.Errorf("member %s = %d %s, want MessageRejected (unverified)", v.Get("Action"), w.Code, w.Body.String())
		}
	}
	if w := sesMemberCall(h, sesMemberClaims, sesRawForm(sesSender, "billing@"+sesDomain)); !strings.Contains(w.Body.String(), sesSender+", billing@"+sesDomain) {
		t.Errorf("a raw message's every sender is named: %s", w.Body.String())
	}
	if n := len(relay.got()); n != 0 {
		t.Fatalf("the relay received %d messages from a member account", n)
	}
	// The member's principal is still decided on its own policy first: one with none is AccessDenied.
	if w := sesMemberCall(h, iam.Claims{Sub: "eve", Account: testMember}, sesSendForm(sesSender)); w.Code != http.StatusForbidden {
		t.Errorf("a member principal with no policy = %d %s, want 403", w.Code, w.Body.String())
	}
	// The management account sends as before.
	if w := sesCall(h, iam.Claims{Sub: "u"}, sesSendForm(sesSender)); w.Code != http.StatusOK {
		t.Fatalf("the management account's SendEmail = %d %s", w.Code, w.Body.String())
	}
	if n := len(relay.got()); n != 1 {
		t.Errorf("the relay received %d messages, want the management account's one", n)
	}
	// A member account lists no identities; the management account's listing is as it was.
	w := sesMemberCall(h, sesMemberClaims, url.Values{"Action": {"ListIdentities"}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<ListIdentitiesResult><Identities/></ListIdentitiesResult>") {
		t.Errorf("member ListIdentities = %d %s", w.Code, w.Body.String())
	}
	w = sesMemberCall(h, sesMemberClaims, url.Values{"Action": {"GetIdentityVerificationAttributes"}, "Identities.member.1": {sesDomain}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<VerificationAttributes/>") {
		t.Errorf("member GetIdentityVerificationAttributes = %d %s", w.Code, w.Body.String())
	}
	if w := sesCall(h, iam.Claims{Sub: "u"}, url.Values{"Action": {"ListIdentities"}}); !strings.Contains(w.Body.String(), "not implemented") {
		t.Errorf("the management account's ListIdentities changed: %d %s", w.Code, w.Body.String())
	}
}

// SES v2 likewise: a member account's SendEmail is MessageRejected and reaches no relay, its account is
// not out of the sandbox, it lists no identities and any it names does not exist; the management
// account's answers are unchanged.
func TestSESv2_MemberAccountHasNoVerifiedIdentities(t *testing.T) {
	h, relay := sesAccountHandler(t)
	send := map[string]any{
		"FromEmailAddress": sesSender,
		"Destination":      map[string]any{"ToAddresses": []string{"ops@example.test"}},
		"Content":          map[string]any{"Simple": map[string]any{"Subject": map[string]any{"Data": "s"}, "Body": map[string]any{"Text": map[string]any{"Data": "b"}}}},
	}
	w := sesV2MemberCall(h, http.MethodPost, "/v2/email/outbound-emails", send)
	if w.Code != http.StatusBadRequest || v2ErrorType(w) != "MessageRejected" ||
		!strings.Contains(w.Body.String(), "The following identities failed the check in region US-EAST-1: "+sesSender) {
		t.Errorf("member v2 SendEmail = %d %s %s", w.Code, v2ErrorType(w), w.Body.String())
	}
	raw := "From: billing@" + sesDomain + "\r\nTo: ops@example.test\r\nSubject: r\r\n\r\nr\r\n"
	w = sesV2MemberCall(h, http.MethodPost, "/v2/email/outbound-emails", map[string]any{
		"Content": map[string]any{"Raw": map[string]any{"Data": base64.StdEncoding.EncodeToString([]byte(raw))}}})
	if w.Code != http.StatusBadRequest || v2ErrorType(w) != "MessageRejected" {
		t.Errorf("member v2 SendEmail (raw) = %d %s %s", w.Code, v2ErrorType(w), w.Body.String())
	}
	if n := len(relay.got()); n != 0 {
		t.Fatalf("the relay received %d messages from a member account", n)
	}
	if w := sesV2Call(h, iam.Claims{Sub: "u"}, http.MethodPost, "/v2/email/outbound-emails", send); w.Code != http.StatusOK {
		t.Fatalf("the management account's v2 SendEmail = %d %s", w.Code, w.Body.String())
	}

	account := func(w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var out map[string]any
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("GetAccount = %d %s", w.Code, w.Body.String())
		}
		return out
	}
	if a := account(sesV2MemberCall(h, http.MethodGet, "/v2/email/account", nil)); a["ProductionAccessEnabled"] != false || a["SendingEnabled"] != true {
		t.Errorf("member GetAccount = %v", a)
	}
	if a := account(sesV2Call(h, iam.Claims{Sub: "u"}, http.MethodGet, "/v2/email/account", nil)); a["ProductionAccessEnabled"] != true {
		t.Errorf("the management account's GetAccount = %v", a)
	}

	w = sesV2MemberCall(h, http.MethodGet, "/v2/email/identities", nil)
	var list struct{ EmailIdentities []any }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &list) != nil || list.EmailIdentities == nil || len(list.EmailIdentities) != 0 {
		t.Errorf("member ListEmailIdentities = %d %s", w.Code, w.Body.String())
	}
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		w = sesV2MemberCall(h, m, "/v2/email/identities/"+sesDomain, nil)
		if w.Code != http.StatusNotFound || v2ErrorType(w) != "NotFoundException" || !strings.Contains(w.Body.String(), "Email identity "+sesDomain+" does not exist.") {
			t.Errorf("member %s identity = %d %s %s", m, w.Code, v2ErrorType(w), w.Body.String())
		}
	}
	if w := sesV2Call(h, iam.Claims{Sub: "u"}, http.MethodGet, "/v2/email/identities/"+sesDomain, nil); w.Code != http.StatusBadRequest || v2ErrorType(w) != "BadRequestException" {
		t.Errorf("the management account's GetEmailIdentity changed: %d %s", w.Code, w.Body.String())
	}
}

// SES is an account-scoped front door under both of its signing names.
func TestSES_AccountScoped(t *testing.T) {
	if !accountScopedServices["ses"] || !accountScopedServices["email"] {
		t.Error("ses/email are not registered as account-scoped")
	}
}
