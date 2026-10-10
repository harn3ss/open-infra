// SES message assembly + query-protocol helpers (pure functions; unit-tested in ses_test.go).
package main

import (
	"encoding/base64"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

// sesAddrList collects an AWS query-protocol indexed list (prefix.1, prefix.2, ...) into a slice.
func sesAddrList(r *http.Request, prefix string) []string {
	var out []string
	for i := 1; i <= 50; i++ {
		if v := r.PostFormValue(prefix + "." + itoa(i)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// emailAddr extracts the bare address from a "Name <addr@host>" or bare "addr@host" string.
func emailAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if a, err := mail.ParseAddress(s); err == nil {
		return a.Address
	}
	return s
}

func addrsOnly(in []string) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		if e := emailAddr(a); e != "" {
			out = append(out, e)
		}
	}
	return out
}

func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

// buildMIME assembles an RFC 5322 message from SES SendEmail fields. text+html -> multipart/alternative;
// otherwise a single text or html part.
func buildMIME(from string, to, cc []string, subject, text, html string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	if len(to) > 0 {
		b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	}
	if len(cc) > 0 {
		b.WriteString("Cc: " + strings.Join(cc, ", ") + "\r\n")
	}
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	switch {
	case text != "" && html != "":
		boundary := "oi-" + uuidLike()
		b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
		b.WriteString("--" + boundary + "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + text + "\r\n")
		b.WriteString("--" + boundary + "\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + html + "\r\n")
		b.WriteString("--" + boundary + "--\r\n")
	case html != "":
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n" + html + "\r\n")
	default:
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n" + text + "\r\n")
	}
	return []byte(b.String())
}

// envelopeFromRaw extracts the envelope From + recipient addresses from a raw MIME message's headers
// (used by SendRawEmail when the caller omits Source/Destinations).
func envelopeFromRaw(data []byte) (from string, to []string) {
	m, err := mail.ReadMessage(strings.NewReader(string(data)))
	if err != nil {
		return "", nil
	}
	from = emailAddr(m.Header.Get("From"))
	for _, hdr := range []string{"To", "Cc", "Bcc"} {
		if list, lerr := m.Header.AddressList(hdr); lerr == nil {
			for _, a := range list {
				to = append(to, a.Address)
			}
		}
	}
	return from, to
}
