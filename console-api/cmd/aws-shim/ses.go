// AWS SES front door (the SES v1 Query protocol: SendEmail / SendRawEmail) over the in-cluster SMTP
// relay — the kind: EmailSender substrate (platform/mail/relay.yaml, or relay-capture.yaml on a test
// cluster). SES's control surface is faithful here; actual internet DELIVERABILITY is an operator
// concern, exactly as AWS gates SES behind domain verification + DKIM/SPF: the relay forwards through a
// smarthost the operator configures (RELAYHOST) for the sending domain.
//
// The doorway is served only while the relay exists: SES_SMTP_RELAY names it (host:port; the shim's
// manifest sets the platform relay's address), and while that name does not resolve — the mail component
// is off — SES answers as a service this shim does not front, rather than accepting mail that can never
// be delivered (which would be a false-green). Turning the mail component on serves it, with no restart.
//
// Identity verification (VerifyEmailIdentity/VerifyDomainIdentity) is refused honestly — a verified
// identity is backed by the domain's DNS (SPF/DKIM/DMARC), which this shim cannot fake. Who may send as an
// identity is the caller's policy: ses:SendEmail / ses:SendRawEmail on Identity::<the From address> or on
// its domain's identity (Identity::<domain>), for every address the message is sent as. Identities are
// an account's own: those the relay sends as are the management account's, and a member account's are
// the ones the operator verified for it (sesAccountIdentities), so its sends as any other are refused as
// AWS refuses an unverified identity's.
//
// SES v2 (REST-JSON, /v2/email/…) is served by the same handler (sesv2.go): SendEmail, with the same
// relay and the same authorization. The SES SMTP interface (ses_smtp.go) sends each message through this
// handler's SendRawEmail, as the IAM user whose SMTP credentials signed in.
package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const sesXMLNamespace = "http://ses.amazonaws.com/doc/2010-12-01/"

type sesHandler struct {
	cs        kubernetes.Interface
	authzNS   string
	relayAddr string // SMTP relay submission endpoint, host:port (e.g. smtp-relay.mail.svc.cluster.local:587)
	authz     *dataplaneauthz.Checker
	logger    *slog.Logger

	// lookup resolves the relay's host (net.DefaultResolver; a stub in tests). The answer is cached for
	// sesRelayCheckTTL, so a burst of sends costs one lookup.
	lookup    func(ctx context.Context, host string) ([]string, error)
	relayMu   sync.Mutex
	relayAt   time.Time
	relayLive bool

	// dyn is the shim's own client: it reads a member account's kind: Account for the SES identities the
	// operator verified for it (accountIdentities). nil: a member account has none.
	dyn        dynamic.Interface
	accountsMu sync.Mutex
	accounts   map[string]sesAccountEntry
}

// sesRelayCheckTTL is how long the shim trusts its last answer to "does the relay exist".
const sesRelayCheckTTL = 30 * time.Second

func newSESHandler(cs kubernetes.Interface, authzNS, relayAddr string, authz *dataplaneauthz.Checker, logger *slog.Logger) *sesHandler {
	return &sesHandler{cs: cs, authzNS: authzNS, relayAddr: relayAddr, authz: authz, logger: logger,
		lookup: net.DefaultResolver.LookupHost}
}

// relayExists reports whether the relay's host resolves (the mail component is on). An IP literal always
// exists: the operator named it directly.
func (h *sesHandler) relayExists(ctx context.Context) bool {
	host := h.relayAddr
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	h.relayMu.Lock()
	defer h.relayMu.Unlock()
	if !h.relayAt.IsZero() && time.Since(h.relayAt) < sesRelayCheckTTL {
		return h.relayLive
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := h.lookup(lctx, host)
	h.relayLive, h.relayAt = err == nil && len(addrs) > 0, time.Now()
	return h.relayLive
}

func (h *sesHandler) authFailure(w http.ResponseWriter, r *http.Request, requestID string) {
	if r != nil && isSESv2(r) {
		sesV2Error(w, http.StatusForbidden, authCode(r, "SignatureDoesNotMatch"), requestID,
			authMessage(r, "The request signature we calculated does not match the signature you provided."))
		return
	}
	writeQueryError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", sesXMLNamespace)
}

func (h *sesHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if isSESv2(r) {
		h.serveV2(w, r, claims, requestID)
		return
	}
	if !h.relayExists(r.Context()) {
		// The mail component is off: there is nowhere to deliver, so SES is not fronted here.
		writeUnsupportedService(w, r, "ses", requestID)
		return
	}
	_ = r.ParseForm()
	op := r.PostFormValue("Action")
	if op == "" {
		op = r.URL.Query().Get("Action")
	}
	verb := ""
	switch op {
	case "GetSendQuota", "GetSendStatistics", "ListIdentities", "GetIdentityVerificationAttributes":
		verb = "get"
	case "SendEmail", "SendRawEmail", "VerifyEmailIdentity", "VerifyDomainIdentity":
		verb = "create"
	default:
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"the SES action '"+op+"' is not implemented by this open-infra shim.", sesXMLNamespace)
		return
	}

	// Resource for authz: the sending identities. Coarse at the RBAC layer, scopable at the fine-grained
	// Cedar data-plane layer (ses:SendEmail on the identity). A send is authorized as EVERY address it
	// sends as: SendEmail's Source; SendRawEmail's Source AND each address in the message's From header
	// (a raw message with no Source is sent as its From header, as SES does) — so a principal allowed to
	// send as one identity cannot name another in From.
	var senders []string
	if s := emailAddr(r.PostFormValue("Source")); s != "" {
		senders = append(senders, s)
	}
	if op == "SendRawEmail" {
		if data, err := b64Decode(r.PostFormValue("RawMessage.Data")); err == nil {
			senders = appendUnique(senders, rawFromAddrs(data)...)
		}
	}
	first := ""
	if len(senders) > 0 {
		first = senders[0]
	}
	// In legacy the coarse SubjectAccessReview first; in enforce IAM policy alone decides below.
	enforce := enforcing(r.Context(), h.authz, claims)
	if !enforce {
		if allowed, reason := coarseOnly(r.Context(), h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, first)(); !allowed {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, sesXMLNamespace)
			return
		}
	}
	if len(senders) > 0 {
		for _, s := range senders {
			if denied, reason := h.identityDenied(r.Context(), claims, "ses:"+op, s, r); denied {
				writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, sesXMLNamespace)
				return
			}
		}
	} else {
		// An assumed role is checked on every op: a Verify*Identity on the identity it names, the
		// identity-less ops (GetSendQuota, ListIdentities, …) on Identity::*.
		identity := ""
		if claims.AssumedRole != "" || enforce {
			identity = formFirst(r, "EmailAddress", "Domain")
		}
		if ok, reason := decide(r.Context(), r, h.authz, claims, "ses:"+op, "Identity", identity,
			dataPlaneOnly(r.Context(), r, h.authz, claims, "ses:"+op, "Identity", identity)); !ok {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, sesXMLNamespace)
			return
		}
	}

	// A member account sends only as the identities verified for it (sesAccountIdentities), and, while it
	// is in the sandbox, only to them; it lists exactly those.
	if sesMemberAccount(r.Context(), claims) {
		ids := h.accountIdentities(r.Context(), claims)
		switch op {
		case "SendEmail", "SendRawEmail":
			if len(senders) == 0 {
				writeQueryError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
					op+" needs a Source (or, for SendRawEmail, a From header in the message).", sesXMLNamespace)
				return
			}
			if failed := ids.failing(senders, sesV1Recipients(r, op)); len(failed) > 0 {
				writeQueryError(w, http.StatusBadRequest, "MessageRejected", requestID, sesUnverified(r.Context(), failed), sesXMLNamespace)
				return
			}
		case "ListIdentities":
			var b strings.Builder
			for _, id := range ids.verified {
				b.WriteString("<member>" + xmlEscape(id) + "</member>")
			}
			h.writeXML(w, requestID, sesEmptyResult("ListIdentities", xmlList("Identities", b.String()), requestID))
			return
		case "GetIdentityVerificationAttributes":
			var b strings.Builder
			for _, id := range sesAddrList(r, "Identities.member") {
				if ids.isIdentity(id) {
					b.WriteString("<entry><key>" + xmlEscape(id) + "</key><value><VerificationStatus>Success</VerificationStatus></value></entry>")
				}
			}
			h.writeXML(w, requestID, sesEmptyResult("GetIdentityVerificationAttributes", xmlList("VerificationAttributes", b.String()), requestID))
			return
		}
	}

	switch op {
	case "SendEmail":
		h.sendEmail(w, r, requestID)
	case "SendRawEmail":
		h.sendRawEmail(w, r, requestID)
	case "GetSendQuota":
		h.getSendQuota(w, requestID)
	case "VerifyEmailIdentity", "VerifyDomainIdentity":
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"SES identity verification is an operator concern (the sending domain's SPF/DKIM/DMARC records + the relay smarthost); this shim will not report a verified identity the DNS does not back.", sesXMLNamespace)
	default:
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"SES "+op+" is recognized but not implemented by the open-infra shim.", sesXMLNamespace)
	}
}

// SES identities are an account's own, as on AWS. The identities this shim sends as — the sending
// domains the operator backs with DNS (SPF/DKIM/DMARC) and the relay's smarthost — are the management
// account's, the installation's own. A member account's verified identities are the ones the operator has
// verified for it (its kind: Account's spec.ses.verifiedIdentities: domains and email addresses): SES
// verifies an identity by proving its owner controls it, a DNS record or a confirmation link, and here the
// operator, who holds the DNS and the relay, does that for the account. A member account's send as any
// other address is refused as AWS refuses one from an identity the account has not verified
// (MessageRejected), and its listings are its verified identities. A member account is in the SES sandbox
// until its Account sets spec.ses.productionAccessEnabled: it then also sends only to its verified
// identities, as AWS's sandbox allows. The management account's sends and answers are unchanged. So SES
// keeps each account's identities apart, and is an account-scoped front door: a member account's principal
// is decided on its own account's identities.
func init() {
	accountScopedServices["ses"] = true
	accountScopedServices["email"] = true
}

// sesAccountIdentities is what a member account's kind: Account says of its SES identities.
type sesAccountIdentities struct {
	verified   []string // domain and email-address identities, lower-cased
	production bool     // out of the sandbox (spec.ses.productionAccessEnabled)
}

// has reports whether addr is a verified identity, or an address of a verified domain identity (SES's
// rule: a verified domain sends as any address at it; a subdomain is an identity of its own).
func (a sesAccountIdentities) has(addr string) bool {
	addr = strings.ToLower(strings.TrimSpace(addr))
	dom := identityDomain(addr)
	for _, id := range a.verified {
		if id == addr || (dom != "" && id == dom) {
			return true
		}
	}
	return false
}

// isIdentity reports whether id is itself one of the verified identities (an address at a verified domain
// sends, but is not an identity of its own).
func (a sesAccountIdentities) isIdentity(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, v := range a.verified {
		if v == id {
			return true
		}
	}
	return false
}

// xmlList is the element name holding inner, or the empty element when there is nothing in it.
func xmlList(name, inner string) string {
	if inner == "" {
		return "<" + name + "/>"
	}
	return "<" + name + ">" + inner + "</" + name + ">"
}

// failing is every identity of a send that fails SES's verification check: each sender that is not
// verified, and, in the sandbox, each recipient that is not.
func (a sesAccountIdentities) failing(senders, rcpts []string) []string {
	var out []string
	for _, s := range senders {
		if !a.has(s) {
			out = appendUnique(out, s)
		}
	}
	if !a.production {
		for _, rc := range rcpts {
			if !a.has(rc) {
				out = appendUnique(out, rc)
			}
		}
	}
	return out
}

// sesAccountsTTL is how long the shim trusts what it last read of an account's identities.
const sesAccountsTTL = 30 * time.Second

type sesAccountEntry struct {
	at  time.Time
	ids sesAccountIdentities
}

// accountIdentities is the caller's member account's SES identities, read from its kind: Account (cached
// for sesAccountsTTL). An account the shim cannot read has none verified and is in the sandbox — it fails
// closed.
func (h *sesHandler) accountIdentities(ctx context.Context, claims iam.Claims) sesAccountIdentities {
	acct := claims.Account
	if acct == "" {
		acct = callerAccount(ctx)
	}
	if h.dyn == nil || acct == "" {
		return sesAccountIdentities{}
	}
	h.accountsMu.Lock()
	if e, ok := h.accounts[acct]; ok && time.Since(e.at) < sesAccountsTTL {
		h.accountsMu.Unlock()
		return e.ids
	}
	h.accountsMu.Unlock()
	var ids sesAccountIdentities
	if a, err := h.dyn.Resource(gvrAccounts).Get(ctx, acct, metav1.GetOptions{}); err == nil {
		spec, _ := a.Object["spec"].(map[string]any)
		ses, _ := spec["ses"].(map[string]any)
		items, _ := ses["verifiedIdentities"].([]any)
		for _, it := range items {
			if s, _ := it.(string); strings.TrimSpace(s) != "" {
				ids.verified = appendUnique(ids.verified, strings.ToLower(strings.TrimSpace(s)))
			}
		}
		ids.production, _ = ses["productionAccessEnabled"].(bool)
	} else if !apierrors.IsNotFound(err) {
		h.logger.Warn("ses: the account's identities could not be read; none are verified until they can", "account", acct, "error", err.Error())
		return ids // not cached: the next send reads again
	}
	h.accountsMu.Lock()
	if h.accounts == nil {
		h.accounts = map[string]sesAccountEntry{}
	}
	h.accounts[acct] = sesAccountEntry{at: time.Now(), ids: ids}
	h.accountsMu.Unlock()
	return ids
}

// sesInSandbox reports whether the caller's account is in the SES sandbox: a member account until its
// operator grants it production access; never the management account.
func (h *sesHandler) sesInSandbox(ctx context.Context, claims iam.Claims) bool {
	return sesMemberAccount(ctx, claims) && !h.accountIdentities(ctx, claims).production
}

// sesV1Recipients is every recipient of a v1 send: SendEmail's destinations; SendRawEmail's Destinations,
// else its To/Cc/Bcc headers.
func sesV1Recipients(r *http.Request, op string) []string {
	if op == "SendEmail" {
		return addrsOnly(append(append(sesAddrList(r, "Destination.ToAddresses.member"),
			sesAddrList(r, "Destination.CcAddresses.member")...), sesAddrList(r, "Destination.BccAddresses.member")...))
	}
	if rcpts := addrsOnly(sesAddrList(r, "Destinations.member")); len(rcpts) > 0 {
		return rcpts
	}
	if data, err := b64Decode(r.PostFormValue("RawMessage.Data")); err == nil {
		_, to := envelopeFromRaw(data)
		return to
	}
	return nil
}

// sesMemberAccount reports whether the request acts in a member account (the router's identity on the
// request, or a member account's claims made in-process).
func sesMemberAccount(ctx context.Context, claims iam.Claims) bool {
	return isMemberRequest(ctx) || memberAccount(claims)
}

// sesUnverified is AWS's MessageRejected message for a message sent as identities the account has not
// verified, in the request's region.
func sesUnverified(ctx context.Context, identities []string) string {
	return "Email address is not verified. The following identities failed the check in region " +
		strings.ToUpper(awsidentity.FromContext(ctx).Region) + ": " + strings.Join(identities, ", ")
}

// sesEmptyResult is a v1 Query response whose result holds one empty element (inner).
func sesEmptyResult(action, inner, requestID string) string {
	return `<?xml version="1.0"?><` + action + `Response xmlns="` + sesXMLNamespace + `"><` + action + `Result>` + inner +
		`</` + action + `Result><ResponseMetadata><RequestId>` + xmlEscape(requestID) + `</RequestId></ResponseMetadata></` + action + `Response>`
}

// identityDenied authorizes sending as addr the way SES does: on its email address identity
// (Identity::<addr>) or its domain identity (Identity::<domain>), so a role granted ses:SendEmail on
// identity/example.com sends as any address at example.com. An explicit Deny on either wins — a Deny on
// one address is not lifted by a grant on its domain, nor a Deny on the domain by a grant on one address.
// The permission boundary is not an explicit Deny: a boundary that covers only the domain identity
// still lets a domain grant send.
func (h *sesHandler) identityDenied(ctx context.Context, claims iam.Claims, action, addr string, r *http.Request) (bool, string) {
	if enforcing(ctx, h.authz, claims) {
		return h.identityDeniedIAM(ctx, claims, action, addr, r)
	}
	denied, explicit, reason := dataPlaneVerdict(ctx, h.authz, claims, action, "Identity", addr, r)
	dom := identityDomain(addr)
	if dom == "" || (denied && explicit) {
		return denied, reason
	}
	dDenied, dExplicit, dReason := dataPlaneVerdict(ctx, h.authz, claims, action, "Identity", dom, r)
	switch {
	case dDenied && dExplicit:
		return true, dReason
	case !denied || !dDenied:
		return false, ""
	}
	return true, reason + " — sending as " + addr + " needs " + action + " on its address identity or its domain identity (" + dom + ")"
}

// identityDeniedIAM is identityDenied in enforce: IAM policy on the address identity and on its domain
// identity — an explicit Deny on either refuses, an allow on either sends.
func (h *sesHandler) identityDeniedIAM(ctx context.Context, claims iam.Claims, action, addr string, r *http.Request) (bool, string) {
	da := decision(ctx, r, h.authz, claims, action, "Identity", addr, nil)
	dom := identityDomain(addr)
	if dom == "" || da.ExplicitDeny {
		return !da.Allowed, da.Reason
	}
	dd := decision(ctx, r, h.authz, claims, action, "Identity", dom, nil)
	switch {
	case dd.ExplicitDeny:
		return true, dd.Reason
	case da.Allowed || dd.Allowed:
		return false, ""
	}
	return true, da.Reason + " — sending as " + addr + " needs " + action + " on its address identity or its domain identity (" + dom + ")"
}

// sendEmail — SES v1 SendEmail (structured Source/Destination/Message). Builds an RFC 5322 message and
// submits it to the relay. A returned MessageId means the relay ACCEPTED the message for delivery; final
// internet deliverability depends on the relay's smarthost + the domain's DNS (operator concern).
func (h *sesHandler) sendEmail(w http.ResponseWriter, r *http.Request, requestID string) {
	from := r.PostFormValue("Source")
	to := sesAddrList(r, "Destination.ToAddresses.member")
	cc := sesAddrList(r, "Destination.CcAddresses.member")
	bcc := sesAddrList(r, "Destination.BccAddresses.member")
	subject := r.PostFormValue("Message.Subject.Data")
	text := r.PostFormValue("Message.Body.Text.Data")
	html := r.PostFormValue("Message.Body.Html.Data")
	if strings.TrimSpace(from) == "" || len(to)+len(cc)+len(bcc) == 0 {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"SendEmail requires a Source and at least one destination address.", sesXMLNamespace)
		return
	}
	msg := buildMIMEMessage(mimeParts{From: from, To: to, Cc: cc, ReplyTo: sesAddrList(r, "ReplyToAddresses.member"),
		Subject: subject, Text: text, HTML: html})
	rcpts := append(append(append([]string{}, to...), cc...), bcc...)
	if err := h.smtpSend(emailAddr(from), addrsOnly(rcpts), msg); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeSendResult(w, requestID, "SendEmail")
}

// sendRawEmail — SES v1 SendRawEmail (the caller supplies the full MIME message, base64 in
// RawMessage.Data). We submit it verbatim; Source/Destinations override the envelope if given.
func (h *sesHandler) sendRawEmail(w http.ResponseWriter, r *http.Request, requestID string) {
	raw := r.PostFormValue("RawMessage.Data")
	if raw == "" {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"SendRawEmail requires RawMessage.Data (base64-encoded MIME).", sesXMLNamespace)
		return
	}
	data, err := b64Decode(raw)
	if err != nil {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"RawMessage.Data is not valid base64.", sesXMLNamespace)
		return
	}
	from := emailAddr(r.PostFormValue("Source"))
	rcpts := addrsOnly(sesAddrList(r, "Destinations.member"))
	if from == "" || len(rcpts) == 0 {
		// Fall back to the headers in the raw message.
		hf, ht := envelopeFromRaw(data)
		if from == "" {
			from = hf
		}
		if len(rcpts) == 0 {
			rcpts = ht
		}
	}
	if from == "" || len(rcpts) == 0 {
		writeQueryError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
			"SendRawEmail needs a Source + Destinations, or From/To headers in the raw message.", sesXMLNamespace)
		return
	}
	if err := h.smtpSend(from, rcpts, data); err != nil {
		h.internal(w, requestID, err)
		return
	}
	h.writeSendResult(w, requestID, "SendRawEmail")
}

// getSendQuota — SDKs probe this before sending. We report an effectively-unbounded local quota; the
// real limit is the operator's smarthost, not this shim.
func (h *sesHandler) getSendQuota(w http.ResponseWriter, requestID string) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString(`<GetSendQuotaResponse xmlns="` + sesXMLNamespace + `"><GetSendQuotaResult>`)
	b.WriteString(`<Max24HourSend>-1</Max24HourSend><MaxSendRate>-1</MaxSendRate><SentLast24Hours>0</SentLast24Hours>`)
	b.WriteString(`</GetSendQuotaResult><ResponseMetadata><RequestId>` + xmlEscape(requestID) + `</RequestId></ResponseMetadata></GetSendQuotaResponse>`)
	h.writeXML(w, requestID, b.String())
}

// smtpSend submits a message to the relay. The relay accepts in-cluster submission on :587; it is
// network-guarded (no per-sender credential in this slice), so no SMTP AUTH. STARTTLS is used when the
// relay advertises it (internal cert → skip verification; the hop is in-cluster).
func (h *sesHandler) smtpSend(from string, to []string, msg []byte) error {
	c, err := smtp.Dial(h.relayAddr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	host := h.relayAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	_ = c.Hello("aws-shim")
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true}); err != nil { //nolint:gosec // in-cluster hop, internal cert
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (h *sesHandler) internal(w http.ResponseWriter, requestID string, err error) {
	h.logger.Error("ses relay submission failed", "error", err.Error())
	writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID,
		"the SES relay could not accept the message: "+err.Error(), sesXMLNamespace)
}

func (h *sesHandler) writeSendResult(w http.ResponseWriter, requestID, action string) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString(`<` + action + `Response xmlns="` + sesXMLNamespace + `"><` + action + `Result>`)
	b.WriteString(`<MessageId>` + xmlEscape(uuidLike()) + `@open-infra-ses</MessageId>`)
	b.WriteString(`</` + action + `Result><ResponseMetadata><RequestId>` + xmlEscape(requestID) + `</RequestId></ResponseMetadata></` + action + `Response>`)
	h.writeXML(w, requestID, b.String())
}

func (h *sesHandler) writeXML(w http.ResponseWriter, requestID, body string) {
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}
