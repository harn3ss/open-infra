// AWS SES front door (the SES v1 Query protocol: SendEmail / SendRawEmail) over the in-cluster SMTP
// relay — the kind: EmailSender substrate (platform/mail/relay.yaml). SES's control surface is faithful
// here; actual internet DELIVERABILITY is an operator concern, exactly as AWS gates SES behind domain
// verification + DKIM/SPF: the relay forwards through a smarthost the operator configures (RELAYHOST)
// for the sending domain. This doorway is therefore OFF until the operator enables the mail relay and
// points SES_SMTP_RELAY at it (host:port); unset, SES requests fall through to the unsupported-service
// response rather than accepting mail that can never be delivered (which would be a false-green).
//
// Identity verification (VerifyEmailIdentity/VerifyDomainIdentity) is refused honestly — a verified
// identity is backed by the domain's DNS (SPF/DKIM/DMARC), which this shim cannot fake.
package main

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"

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
}

func newSESHandler(cs kubernetes.Interface, authzNS, relayAddr string, authz *dataplaneauthz.Checker, logger *slog.Logger) *sesHandler {
	return &sesHandler{cs: cs, authzNS: authzNS, relayAddr: relayAddr, authz: authz, logger: logger}
}

func (h *sesHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeQueryError(w, http.StatusForbidden, "SignatureDoesNotMatch", requestID,
		"The request signature we calculated does not match the signature you provided.", sesXMLNamespace)
}

func (h *sesHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
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

	// Resource for authz: the sending identity (From address). Coarse at the RBAC layer, scopable at the
	// fine-grained Cedar data-plane layer (ses:SendEmail on the identity).
	source := r.PostFormValue("Source")
	if source == "" {
		source = r.PostFormValue("FromEmailAddress")
	}
	if allowed, reason := iam.CanDo(r.Context(), h.cs, claims, verb, "openinfra.dev", "applications", h.authzNS, emailAddr(source)); !allowed {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, sesXMLNamespace)
		return
	}
	if source != "" {
		if denied, reason := deniedByDataPlane(r.Context(), h.authz, claims, "ses:"+op, "Identity", emailAddr(source), r); denied {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, reason, sesXMLNamespace)
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
	msg := buildMIME(from, to, cc, subject, text, html)
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
