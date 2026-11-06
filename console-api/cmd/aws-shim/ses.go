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
// an account's own: those the relay sends as are the management account's, and a member account has none
// (sesMemberAccount), so its sends are refused as AWS refuses an unverified identity's.
//
// SES v2 (REST-JSON, /v2/email/…) is served by the same handler (sesv2.go): SendEmail, with the same
// relay and the same authorization.
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
		sesV2Error(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
			"The request signature we calculated does not match the signature you provided.")
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

	// A member account has no verified identities of its own (sesMemberAccount): it sends as none, and
	// lists none.
	if sesMemberAccount(r.Context(), claims) {
		switch op {
		case "SendEmail", "SendRawEmail":
			if len(senders) == 0 {
				writeQueryError(w, http.StatusBadRequest, "InvalidParameterValue", requestID,
					op+" needs a Source (or, for SendRawEmail, a From header in the message).", sesXMLNamespace)
				return
			}
			writeQueryError(w, http.StatusBadRequest, "MessageRejected", requestID, sesUnverified(r.Context(), senders), sesXMLNamespace)
			return
		case "ListIdentities":
			h.writeXML(w, requestID, sesEmptyResult("ListIdentities", "<Identities/>", requestID))
			return
		case "GetIdentityVerificationAttributes":
			h.writeXML(w, requestID, sesEmptyResult("GetIdentityVerificationAttributes", "<VerificationAttributes/>", requestID))
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
// account's, the installation's own. A member account has verified none, and can verify none here
// (identity verification is the operator's, for every account), so its identities are none at all: a send
// as any address is refused as AWS refuses one from an identity the account has not verified
// (MessageRejected), and its identity listings are empty. The management account's sends and answers are
// unchanged. So SES keeps each account's identities apart, and is an account-scoped front door: a member
// account's principal is decided on its own account's identities.
func init() {
	accountScopedServices["ses"] = true
	accountScopedServices["email"] = true
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
