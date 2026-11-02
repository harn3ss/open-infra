// SES message assembly + query-protocol helpers (pure functions; unit-tested in ses_test.go).
package main

import (
	"encoding/base64"
	"mime"
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
	return buildMIMEMessage(mimeParts{From: from, To: to, Cc: cc, Subject: subject, Text: text, HTML: html})
}

// mimeParts is a structured message (SES v1 SendEmail, SES v2 SendEmail's Simple content).
type mimeParts struct {
	From            string
	To, Cc, ReplyTo []string
	Subject         string
	Text, HTML      string
	Headers         [][2]string // extra headers (SES v2 Simple.Headers), name + value
}

// buildMIMEMessage assembles an RFC 5322 message from p. A non-ASCII subject is RFC 2047 encoded; extra
// headers are written as given, minus any line break (no header injection).
func buildMIMEMessage(p mimeParts) []byte {
	clean := func(s string) string { return strings.NewReplacer("\r", "", "\n", "").Replace(s) }
	var b strings.Builder
	b.WriteString("From: " + clean(p.From) + "\r\n")
	if len(p.To) > 0 {
		b.WriteString("To: " + clean(strings.Join(p.To, ", ")) + "\r\n")
	}
	if len(p.Cc) > 0 {
		b.WriteString("Cc: " + clean(strings.Join(p.Cc, ", ")) + "\r\n")
	}
	if len(p.ReplyTo) > 0 {
		b.WriteString("Reply-To: " + clean(strings.Join(p.ReplyTo, ", ")) + "\r\n")
	}
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", clean(p.Subject)) + "\r\n")
	for _, h := range p.Headers {
		if n := clean(h[0]); n != "" && !strings.Contains(n, ":") {
			b.WriteString(n + ": " + clean(h[1]) + "\r\n")
		}
	}
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	switch {
	case p.Text != "" && p.HTML != "":
		boundary := "oi-" + uuidLike()
		b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
		b.WriteString("--" + boundary + "\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + p.Text + "\r\n")
		b.WriteString("--" + boundary + "\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + p.HTML + "\r\n")
		b.WriteString("--" + boundary + "--\r\n")
	case p.HTML != "":
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n" + p.HTML + "\r\n")
	default:
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n" + p.Text + "\r\n")
	}
	return []byte(b.String())
}

// identityDomain is the domain identity an email address belongs to ("app@example.com" -> "example.com"),
// or "" for anything that is not an address.
func identityDomain(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i > 0 && i < len(addr)-1 {
		return addr[i+1:]
	}
	return ""
}

// rawFromAddrs is every address in a raw message's From header (RFC 5322 allows a list).
func rawFromAddrs(data []byte) []string {
	m, err := mail.ReadMessage(strings.NewReader(string(data)))
	if err != nil {
		return nil
	}
	list, err := m.Header.AddressList("From")
	if err != nil {
		if a := emailAddr(m.Header.Get("From")); a != "" {
			return []string{a}
		}
		return nil
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out
}

// appendUnique appends each non-empty value of add not already in list.
func appendUnique(list []string, add ...string) []string {
	for _, a := range add {
		if a == "" {
			continue
		}
		dup := false
		for _, l := range list {
			if l == a {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, a)
		}
	}
	return list
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
