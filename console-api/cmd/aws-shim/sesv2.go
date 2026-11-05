// SES v2 (the REST-JSON API under /v2/email/, signed for service "ses"): SendEmail, over the same relay and
// with the same authorization as v1 (ses.go) — what `aws sesv2 send-email` and the SDKs' SESv2Client send.
// IAM names v2's send action ses:SendEmail whatever the content (Simple, Raw or Template), and it is
// authorized on every address the message is sent as: FromEmailAddress and, for Raw content, each address
// in the message's From header, each on its address identity or its domain identity.
//
// GetAccount answers like v1's GetSendQuota (an unbounded local quota; the real limit is the relay's
// smarthost). Every other v2 operation is refused by name, never faked.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// sesV2Prefix is the path every SES v2 operation is under.
const sesV2Prefix = "/v2/email/"

// sesV2MaxBody caps a v2 request body: a Raw message is base64 in JSON, and SES's own message limit is far
// below what this admits (the relay is the real limit).
const sesV2MaxBody = 16 << 20

func isSESv2(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, sesV2Prefix) }

// sesV2Error writes SES v2's REST-JSON error dialect: the error type in x-amzn-ErrorType (which the SDKs
// key off) and a JSON message body.
func sesV2Error(w http.ResponseWriter, status int, errorType, requestID, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-ErrorType", errorType)
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}

func sesV2JSON(w http.ResponseWriter, requestID string, obj any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(obj)
}

type sesV2Text struct {
	Data    string `json:"Data"`
	Charset string `json:"Charset"`
}

// sesV2SendEmail is the SendEmail request body (the fields this shim acts on).
type sesV2SendEmail struct {
	FromEmailAddress string `json:"FromEmailAddress"`
	Destination      *struct {
		ToAddresses  []string `json:"ToAddresses"`
		CcAddresses  []string `json:"CcAddresses"`
		BccAddresses []string `json:"BccAddresses"`
	} `json:"Destination"`
	ReplyToAddresses []string `json:"ReplyToAddresses"`
	Content          struct {
		Simple *struct {
			Subject sesV2Text `json:"Subject"`
			Body    struct {
				Text *sesV2Text `json:"Text"`
				Html *sesV2Text `json:"Html"`
			} `json:"Body"`
			Headers []struct {
				Name  string `json:"Name"`
				Value string `json:"Value"`
			} `json:"Headers"`
		} `json:"Simple"`
		Raw *struct {
			Data []byte `json:"Data"` // a blob: base64 on the wire
		} `json:"Raw"`
		Template json.RawMessage `json:"Template"`
	} `json:"Content"`
}

// sesV2Op names a v2 request by its method and route, for authorization and for an honest refusal.
func sesV2Op(r *http.Request) string {
	p := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, sesV2Prefix), "/")
	switch {
	case r.Method == http.MethodPost && p == "outbound-emails":
		return "SendEmail"
	case r.Method == http.MethodPost && p == "outbound-bulk-emails":
		return "SendBulkEmail"
	case r.Method == http.MethodGet && p == "account":
		return "GetAccount"
	case p == "identities" && r.Method == http.MethodPost:
		return "CreateEmailIdentity"
	case p == "identities" && r.Method == http.MethodGet:
		return "ListEmailIdentities"
	case strings.HasPrefix(p, "identities/") && r.Method == http.MethodGet:
		return "GetEmailIdentity"
	case strings.HasPrefix(p, "identities/") && r.Method == http.MethodDelete:
		return "DeleteEmailIdentity"
	}
	return r.Method + " " + sesV2Prefix + p
}

func (h *sesHandler) serveV2(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if !h.relayExists(r.Context()) {
		sesV2Error(w, http.StatusNotImplemented, "NotImplemented", requestID,
			"AWS service 'ses' is not fronted by this open-infra shim")
		return
	}
	switch op := sesV2Op(r); op {
	case "SendEmail":
		h.v2SendEmail(w, r, claims, requestID)
	case "GetAccount":
		if ok, reason := decide(r.Context(), r, h.authz, claims, "ses:GetAccount", "Identity", "",
			coarseThenDataPlane(r.Context(), r, h.cs, h.authz, claims, "get", "openinfra.dev", "applications", h.authzNS, "",
				"ses:GetAccount", "Identity", "")); !ok {
			sesV2Error(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
		sesV2JSON(w, requestID, map[string]any{
			"SendQuota":               map[string]any{"Max24HourSend": -1, "MaxSendRate": -1, "SentLast24Hours": 0},
			"SendingEnabled":          true,
			"ProductionAccessEnabled": true,
			"EnforcementStatus":       "HEALTHY",
		})
	case "CreateEmailIdentity":
		sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID,
			"SES identity verification is an operator concern (the sending domain's SPF/DKIM/DMARC records + the relay smarthost); this shim will not report a verified identity the DNS does not back.")
	default:
		sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID,
			"SES v2 "+op+" is not implemented by the open-infra shim (SES v2 SendEmail and GetAccount are served).")
	}
}

// v2SendEmail — SES v2 SendEmail. Simple content is built into an RFC 5322 message as v1's SendEmail is;
// Raw content is submitted verbatim (FromEmailAddress and Destination override the envelope if given, else
// its From/To/Cc/Bcc headers); Template content is refused (templates are not served).
func (h *sesHandler) v2SendEmail(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, sesV2MaxBody+1))
		if err != nil {
			sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID, "the request body could not be read")
			return
		}
		body = b
	}
	if len(body) > sesV2MaxBody {
		sesV2Error(w, http.StatusBadRequest, "MessageRejected", requestID, "the message is larger than this shim accepts (16 MiB)")
		return
	}
	var req sesV2SendEmail
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&req); err != nil {
		sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID, "the request body is not valid SendEmail JSON: "+err.Error())
		return
	}
	c := req.Content
	kinds := 0
	for _, set := range []bool{c.Simple != nil, c.Raw != nil, len(c.Template) > 0 && string(c.Template) != "null"} {
		if set {
			kinds++
		}
	}
	if kinds != 1 {
		sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID, "Content must have exactly one of Simple, Raw or Template.")
		return
	}
	if c.Simple == nil && c.Raw == nil {
		sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID,
			"Template content is not implemented by the open-infra shim (email templates are not served); send Simple or Raw content.")
		return
	}

	var to, cc, bcc []string
	if d := req.Destination; d != nil {
		to, cc, bcc = d.ToAddresses, d.CcAddresses, d.BccAddresses
	}
	from := emailAddr(req.FromEmailAddress)

	// Every address the message is sent as.
	var senders []string
	if from != "" {
		senders = append(senders, from)
	}
	if c.Raw != nil {
		senders = appendUnique(senders, rawFromAddrs(c.Raw.Data)...)
	}
	if len(senders) == 0 {
		sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID,
			"SendEmail needs a FromEmailAddress (or, for Raw content, a From header in the message).")
		return
	}
	// In legacy the coarse SubjectAccessReview first; in enforce IAM policy alone (identityDenied).
	if !enforcing(r.Context(), h.authz, claims) {
		if allowed, reason := coarseOnly(r.Context(), h.cs, claims, "create", "openinfra.dev", "applications", h.authzNS, senders[0])(); !allowed {
			sesV2Error(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
	}
	for _, s := range senders {
		if denied, reason := h.identityDenied(r.Context(), claims, "ses:SendEmail", s, r); denied {
			sesV2Error(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
	}

	var msg []byte
	var rcpts []string
	if c.Simple != nil {
		s := c.Simple
		var text, html string
		if s.Body.Text != nil {
			text = s.Body.Text.Data
		}
		if s.Body.Html != nil {
			html = s.Body.Html.Data
		}
		if len(to)+len(cc)+len(bcc) == 0 {
			sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID, "SendEmail needs at least one destination address.")
			return
		}
		p := mimeParts{From: req.FromEmailAddress, To: to, Cc: cc, ReplyTo: req.ReplyToAddresses,
			Subject: s.Subject.Data, Text: text, HTML: html}
		for _, hd := range s.Headers {
			p.Headers = append(p.Headers, [2]string{hd.Name, hd.Value})
		}
		msg = buildMIMEMessage(p)
		rcpts = addrsOnly(append(append(append([]string{}, to...), cc...), bcc...))
	} else {
		msg = c.Raw.Data
		if len(msg) == 0 {
			sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID, "Raw content needs Data (the base64-encoded MIME message).")
			return
		}
		rcpts = addrsOnly(append(append(append([]string{}, to...), cc...), bcc...))
		if from == "" || len(rcpts) == 0 {
			hf, ht := envelopeFromRaw(msg)
			if from == "" {
				from = hf
			}
			if len(rcpts) == 0 {
				rcpts = ht
			}
		}
		if len(rcpts) == 0 {
			sesV2Error(w, http.StatusBadRequest, "BadRequestException", requestID,
				"SendEmail with Raw content needs a Destination, or To/Cc/Bcc headers in the message.")
			return
		}
	}
	if from == "" {
		from = senders[0]
	}
	if err := h.smtpSend(from, rcpts, msg); err != nil {
		h.logger.Error("ses relay submission failed", "error", err.Error())
		sesV2Error(w, http.StatusInternalServerError, "InternalFailure", requestID, "the SES relay could not accept the message: "+err.Error())
		return
	}
	sesV2JSON(w, requestID, map[string]string{"MessageId": uuidLike() + "@open-infra-ses"})
}
