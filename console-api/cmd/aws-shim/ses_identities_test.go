package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A member account's verified identities are the ones the operator verified for it (its kind: Account's
// spec.ses.verifiedIdentities): it sends as them through v1 and v2, lists exactly them, and, once its
// Account grants production access, is out of the sandbox. An address it has not verified is still refused.
func TestSES_MemberAccountSendsAsItsVerifiedIdentities(t *testing.T) {
	h, relay := sesAccountHandler(t)
	h.dyn = accountsDyn(sesAccountObj(testMember, map[string]any{
		"verifiedIdentities": []any{sesDomain, "alerts@other.test"}, "productionAccessEnabled": true}))
	for _, v := range []url.Values{sesSendForm("App <" + sesSender + ">"), sesRawForm("", "alerts@other.test")} {
		if w := sesMemberCall(h, sesMemberClaims, v); w.Code != http.StatusOK {
			t.Errorf("member %s as a verified identity = %d %s", v.Get("Action"), w.Code, w.Body.String())
		}
	}
	if w := sesMemberCall(h, sesMemberClaims, sesSendForm("ceo@other.test")); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "failed the check in region US-EAST-1: ceo@other.test<") {
		t.Errorf("member send as an unverified address = %d %s", w.Code, w.Body.String())
	}
	send := map[string]any{
		"FromEmailAddress": "billing@" + sesDomain,
		"Destination":      map[string]any{"ToAddresses": []string{"customer@elsewhere.test"}},
		"Content":          map[string]any{"Simple": map[string]any{"Subject": map[string]any{"Data": "s"}, "Body": map[string]any{"Text": map[string]any{"Data": "b"}}}},
	}
	if w := sesV2MemberCall(h, http.MethodPost, "/v2/email/outbound-emails", send); w.Code != http.StatusOK {
		t.Errorf("member v2 SendEmail as an address of a verified domain = %d %s", w.Code, w.Body.String())
	}
	if n := len(relay.got()); n != 3 {
		t.Fatalf("the relay received %d messages, want the 3 verified sends", n)
	}
	w := sesMemberCall(h, sesMemberClaims, url.Values{"Action": {"ListIdentities"}})
	if !strings.Contains(w.Body.String(), "<Identities><member>"+sesDomain+"</member><member>alerts@other.test</member></Identities>") {
		t.Errorf("member ListIdentities = %s", w.Body.String())
	}
	w = sesMemberCall(h, sesMemberClaims, url.Values{"Action": {"GetIdentityVerificationAttributes"},
		"Identities.member.1": {sesDomain}, "Identities.member.2": {"nobody@nowhere.test"}})
	if body := w.Body.String(); !strings.Contains(body, "<key>"+sesDomain+"</key><value><VerificationStatus>Success</VerificationStatus>") ||
		strings.Contains(body, "nobody@nowhere.test") {
		t.Errorf("member GetIdentityVerificationAttributes = %s", body)
	}
	var list struct {
		EmailIdentities []struct{ IdentityType, IdentityName, VerificationStatus string }
	}
	w = sesV2MemberCall(h, http.MethodGet, "/v2/email/identities", nil)
	if json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.EmailIdentities) != 2 ||
		list.EmailIdentities[0].IdentityType != "DOMAIN" || list.EmailIdentities[1].IdentityType != "EMAIL_ADDRESS" ||
		list.EmailIdentities[0].VerificationStatus != "SUCCESS" {
		t.Errorf("member ListEmailIdentities = %s", w.Body.String())
	}
	if w := sesV2MemberCall(h, http.MethodGet, "/v2/email/identities/"+sesDomain, nil); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"VerifiedForSendingStatus":true`) {
		t.Errorf("member GetEmailIdentity of a verified domain = %d %s", w.Code, w.Body.String())
	}
	if w := sesV2MemberCall(h, http.MethodGet, "/v2/email/identities/app@"+sesDomain, nil); w.Code != http.StatusNotFound {
		t.Errorf("an address at a verified domain is not an identity of its own: GetEmailIdentity = %d %s", w.Code, w.Body.String())
	}
	if w := sesV2MemberCall(h, http.MethodDelete, "/v2/email/identities/"+sesDomain, nil); w.Code != http.StatusBadRequest {
		t.Errorf("member DeleteEmailIdentity of an operator-verified identity = %d %s", w.Code, w.Body.String())
	}
	var acct map[string]any
	if w := sesV2MemberCall(h, http.MethodGet, "/v2/email/account", nil); json.Unmarshal(w.Body.Bytes(), &acct) != nil ||
		acct["ProductionAccessEnabled"] != true {
		t.Errorf("member GetAccount with production access = %s", w.Body.String())
	}
}

// In the sandbox (no production access) a member account sends only to its verified identities too.
func TestSES_MemberAccountSandboxRecipients(t *testing.T) {
	h, relay := sesAccountHandler(t)
	h.dyn = accountsDyn(sesAccountObj(testMember, map[string]any{"verifiedIdentities": []any{sesDomain}}))
	out := sesSendForm(sesSender)
	out.Set("Destination.ToAddresses.member.1", "ops@other-domain.test")
	if w := sesMemberCall(h, sesMemberClaims, out); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "failed the check in region US-EAST-1: ops@other-domain.test<") {
		t.Errorf("a sandboxed send to an unverified recipient = %d %s", w.Code, w.Body.String())
	}
	v := sesSendForm(sesSender)
	v.Set("Destination.ToAddresses.member.1", "ops@"+sesDomain)
	if w := sesMemberCall(h, sesMemberClaims, v); w.Code != http.StatusOK {
		t.Errorf("a sandboxed send to a verified recipient = %d %s", w.Code, w.Body.String())
	}
	if n := len(relay.got()); n != 1 {
		t.Fatalf("the relay received %d messages, want 1", n)
	}
}
