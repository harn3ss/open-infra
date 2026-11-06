// The Amazon SES SMTP interface (AWS's email-smtp.<region>.amazonaws.com): an SMTP submission endpoint
// that sends each message as SES SendRawEmail, as the IAM user whose SMTP credentials signed in.
//
//   - Credentials are SES SMTP credentials: the user name is an IAM user's access key id, the password is
//     derived from the key's secret with AWS's version-4 algorithm (sesSMTPPassword). The shim derives it
//     from the stored secret and compares in constant time. A key that does not exist, is inactive, or whose
//     owner no longer exists is refused exactly like a wrong password: 535 Authentication Credentials
//     Invalid. Temporary (session) credentials are not SMTP credentials, as on AWS.
//   - The connection must be encrypted: STARTTLS on the submission port, or TLS from the first byte on the
//     TLS Wrapper port. AUTH is advertised before STARTTLS, as SES advertises it, and answered 530 Must
//     issue a STARTTLS command first until the connection is encrypted. Mail before AUTH is 530
//     Authentication required.
//   - A message is SendRawEmail with Source = MAIL FROM, Destinations = the RCPT TO addresses and the
//     message as received: the SES front door (ses.go) authorizes it — ses:SendRawEmail on every address it
//     is sent as (MAIL FROM and each address of its From header), on the address identity or its domain
//     identity, through the one IAM evaluator — checks the account has verified those identities, and
//     hands it to the platform relay. Its refusals are SES's SMTP replies: 554 Access denied: …, 554
//     Message rejected: Email address is not verified. …; a delivered message is 250 Ok <MessageId>.
//   - AUTH failures are rate-limited per client address and per access key id (454 Temporary
//     authentication failure past the limit), so neither a key nor the key store can be hammered.
//
// Nothing here logs a password, a secret or a message body.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

const (
	// sesSMTPDomain is the name the endpoint greets with, SES's own.
	sesSMTPDomain = "email-smtp.amazonaws.com"
	// sesSMTPMaxMessageBytes is SES's SMTP message size limit (its EHLO SIZE).
	sesSMTPMaxMessageBytes = 10485760
	// sesSMTPMaxRecipients is SES's limit on the recipients of one message.
	sesSMTPMaxRecipients = 50
	// SES's alternate submission ports, where an unprivileged process can listen: STARTTLS and TLS Wrapper.
	// The Service maps the usual 587 and 465 onto them.
	defaultSESSMTPAddr  = ":2587"
	defaultSESSMTPSAddr = ":2465"
)

// The constants of SES's SMTP password derivation (version 4). They never change.
const (
	sesSMTPDate     = "11111111"
	sesSMTPService  = "ses"
	sesSMTPTerminal = "aws4_request"
	sesSMTPMessage  = "SendRawEmail"
	sesSMTPVersion  = 0x04
)

// sesSMTPPassword is the SES SMTP password of a secret access key in region, AWS's algorithm ("Obtaining
// Amazon SES SMTP credentials"): an HMAC-SHA256 chain keyed with "AWS4"+secret over the date 11111111, the
// region, "ses", "aws4_request" and the message "SendRawEmail", prefixed with the version byte 0x04 and
// base64-encoded. A password is valid in the region it was derived for only.
func sesSMTPPassword(secretAccessKey, region string) string {
	sign := func(key []byte, msg string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(msg))
		return m.Sum(nil)
	}
	sig := sign([]byte("AWS4"+secretAccessKey), sesSMTPDate)
	sig = sign(sig, region)
	sig = sign(sig, sesSMTPService)
	sig = sign(sig, sesSMTPTerminal)
	sig = sign(sig, sesSMTPMessage)
	return base64.StdEncoding.EncodeToString(append([]byte{sesSMTPVersion}, sig...))
}

// sesSMTPReply is one of SES's SMTP replies: its code and text, with no enhanced status code (SES sends
// none).
func sesSMTPReply(code int, text string) *smtp.SMTPError {
	text = strings.Join(strings.Fields(text), " ") // one line: a reason never splits the reply
	return &smtp.SMTPError{Code: code, EnhancedCode: smtp.NoEnhancedCode, Message: text}
}

var (
	errSESSMTPStartTLSFirst   = sesSMTPReply(530, "Must issue a STARTTLS command first")
	errSESSMTPAuthRequired    = sesSMTPReply(530, "Authentication required")
	errSESSMTPCredentials     = sesSMTPReply(535, "Authentication Credentials Invalid")
	errSESSMTPAuthTemporary   = sesSMTPReply(454, "Temporary authentication failure")
	errSESSMTPTooLong         = sesSMTPReply(552, "Message is too long.")
	errSESSMTPServiceFailure  = sesSMTPReply(451, "Temporary service failure")
	errSESSMTPAlreadySignedIn = sesSMTPReply(503, "Already authenticated")
)

// sesSMTPBackend is the SMTP interface: the SES front door it sends through, the access-key store and
// account directory it authenticates against, and its AUTH failure limiter.
type sesSMTPBackend struct {
	ses     *sesHandler
	auth    *authenticator
	limiter *authFailureLimiter
	logger  *slog.Logger
	// failDelay is how long a failed AUTH waits before it is answered (a guess per connection costs that).
	failDelay time.Duration
	// sendTimeout bounds one message's authorization and hand-off to the relay.
	sendTimeout time.Duration
}

func newSESSMTPBackend(ses *sesHandler, auth *authenticator, logger *slog.Logger) *sesSMTPBackend {
	return &sesSMTPBackend{ses: ses, auth: auth, limiter: newAuthFailureLimiter(10, 5*time.Minute),
		logger: logger, failDelay: 500 * time.Millisecond, sendTimeout: time.Minute}
}

// newSESSMTPServer is the SMTP server of the interface. tlsConfig nil leaves STARTTLS unoffered (then AUTH
// is always 530: SES never takes credentials over a clear connection).
func newSESSMTPServer(b *sesSMTPBackend, tlsConfig *tls.Config) *smtp.Server {
	s := smtp.NewServer(b)
	s.Domain = sesSMTPDomain
	s.TLSConfig = tlsConfig
	// AUTH is advertised before STARTTLS, as SES advertises it; the session refuses it on a clear
	// connection with SES's 530 (sesSMTPSession.Auth), so credentials only ever cross an encrypted one.
	s.AllowInsecureAuth = true
	s.MaxMessageBytes = sesSMTPMaxMessageBytes
	s.MaxRecipients = sesSMTPMaxRecipients
	s.ReadTimeout = time.Minute
	s.WriteTimeout = time.Minute
	s.ErrorLog = slogSMTPLogger{b.logger}
	return s
}

// startSESSMTP serves the SMTP interface for the SES front door ses: STARTTLS submission on
// SES_SMTP_LISTEN_ADDR (default :2587) and, with a certificate, TLS Wrapper on SES_SMTPS_LISTEN_ADDR
// (default :2465); "off" turns either off. The certificate is the shim's in-cluster one
// (INTERNAL_TLS_CERT_FILE / INTERNAL_TLS_KEY_FILE, re-read on renewal): without it STARTTLS is not offered,
// so no credential is ever taken. A listener that cannot start reports on errs. It returns the server to
// shut down, or nil when the interface is off.
func startSESSMTP(ses *sesHandler, auth *authenticator, logger *slog.Logger, errs chan<- error) *smtp.Server {
	addr := getenv("SES_SMTP_LISTEN_ADDR", defaultSESSMTPAddr)
	if addr == "off" {
		return nil
	}
	var tlsConfig *tls.Config
	if cert, key := getenv("INTERNAL_TLS_CERT_FILE", ""), getenv("INTERNAL_TLS_KEY_FILE", ""); cert != "" && key != "" {
		rl := newCertReloader(cert, key, logger)
		rl.label = "SES SMTP"
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: rl.GetCertificate}
	} else {
		logger.Warn("SES SMTP interface has no certificate (INTERNAL_TLS_CERT_FILE/INTERNAL_TLS_KEY_FILE): STARTTLS is not offered, so every AUTH is refused")
	}
	srv := newSESSMTPServer(newSESSMTPBackend(ses, auth, logger), tlsConfig)
	report := func(err error) {
		select {
		case errs <- err:
		default: // another listener already reported: the shim is stopping either way
		}
	}
	serve := func(name, addr string, implicitTLS bool) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			report(fmt.Errorf("SES SMTP (%s) listener: %w", name, err))
			return
		}
		if implicitTLS {
			ln = tls.NewListener(ln, tlsConfig)
		}
		logger.Info("SES SMTP interface listening", "mode", name, "addr", addr)
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, smtp.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				report(fmt.Errorf("SES SMTP (%s): %w", name, err))
			}
		}()
	}
	serve("STARTTLS", addr, false)
	if s := getenv("SES_SMTPS_LISTEN_ADDR", defaultSESSMTPSAddr); s != "off" && tlsConfig != nil {
		serve("TLS Wrapper", s, true)
	}
	return srv
}

type slogSMTPLogger struct{ l *slog.Logger }

func (s slogSMTPLogger) Printf(format string, v ...interface{}) {
	s.l.Warn("ses smtp: " + fmt.Sprintf(format, v...))
}
func (s slogSMTPLogger) Println(v ...interface{}) { s.l.Warn("ses smtp: " + fmt.Sprintln(v...)) }

func (b *sesSMTPBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	remote := ""
	if a := c.Conn().RemoteAddr(); a != nil {
		remote = a.String()
	}
	return &sesSMTPSession{b: b, conn: c, remote: remote}, nil
}

// sesSMTPSession is one SMTP session: who signed in, and the message being built.
type sesSMTPSession struct {
	b      *sesSMTPBackend
	conn   *smtp.Conn
	remote string

	claims *iam.Claims // the signed-in IAM user; nil before AUTH
	keyID  string
	from   string
	rcpts  []string
}

func (s *sesSMTPSession) encrypted() (tls.ConnectionState, bool) {
	return s.conn.TLSConnectionState()
}

func (s *sesSMTPSession) AuthMechanisms() []string { return []string{sasl.Plain, sasl.Login} }

func (s *sesSMTPSession) Auth(mech string) (sasl.Server, error) {
	if _, ok := s.encrypted(); !ok {
		return nil, errSESSMTPStartTLSFirst
	}
	if s.claims != nil {
		return nil, errSESSMTPAlreadySignedIn
	}
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if identity != "" && identity != username {
				password = "" // another authorization identity: SES has none to act as, so it fails
			}
			return s.signIn(username, password)
		}), nil
	case sasl.Login:
		return &saslLoginServer{authenticate: s.signIn}, nil
	}
	return nil, smtp.ErrAuthUnknownMechanism
}

// signIn verifies SES SMTP credentials: username an access key id, password the SMTP password derived from
// its secret. Every failure is the same 535, so nothing tells a missing key from a wrong password.
func (s *sesSMTPSession) signIn(username, password string) error {
	b := s.b
	ip := clientHost(s.remote)
	keyBucket := username
	if len(keyBucket) > 128 {
		keyBucket = keyBucket[:128]
	}
	if b.limiter.blocked("ip:"+ip, "key:"+keyBucket) {
		return errSESSMTPAuthTemporary
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	claims, ok := b.verify(ctx, username, password)
	if !ok {
		b.limiter.fail("ip:"+ip, "key:"+keyBucket)
		b.logger.Warn("ses smtp authentication failed", "remote", ip, "accessKeyId", loggableKeyID(username))
		if b.failDelay > 0 {
			time.Sleep(b.failDelay)
		}
		return errSESSMTPCredentials
	}
	s.claims, s.keyID = &claims, username
	return nil
}

// verify resolves an access key, checks the password is the SMTP password of its secret in the region the
// account sends from, and returns the identity the key acts as (its owner, in its account).
func (b *sesSMTPBackend) verify(ctx context.Context, accessKeyID, password string) (iam.Claims, bool) {
	if accessKeyID == "" || password == "" || b.auth == nil || b.auth.keys == nil {
		return iam.Claims{}, false
	}
	key, ok := b.auth.keys.Lookup(ctx, accessKeyID)
	if !ok {
		return iam.Claims{}, false
	}
	want := sesSMTPPassword(key.SecretKey, awsidentity.Current().Region)
	if subtle.ConstantTimeCompare([]byte(want), []byte(password)) != 1 {
		return iam.Claims{}, false
	}
	return b.auth.keyClaims(ctx, key)
}

var accessKeyIDRe = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)

// loggableKeyID is an access key id as a log may show it (AWS's logs show access key ids); anything else in
// the user name field — a password typed in the wrong box — is never logged.
func loggableKeyID(s string) string {
	if accessKeyIDRe.MatchString(s) {
		return s
	}
	return "(not an access key id)"
}

func clientHost(remote string) string {
	if h, _, err := net.SplitHostPort(remote); err == nil {
		return h
	}
	return remote
}

func (s *sesSMTPSession) Mail(from string, _ *smtp.MailOptions) error {
	if s.claims == nil {
		return errSESSMTPAuthRequired
	}
	if from != "" && !validMailbox(from) {
		return sesSMTPReply(553, "<"+from+"> Invalid email address")
	}
	s.from, s.rcpts = from, nil
	return nil
}

func (s *sesSMTPSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.claims == nil {
		return errSESSMTPAuthRequired
	}
	if !validMailbox(to) {
		return sesSMTPReply(553, "<"+to+"> address unknown")
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

// validMailbox reports whether a is one bare address (local@domain).
func validMailbox(a string) bool {
	p, err := mail.ParseAddress(a)
	return err == nil && p.Address == a && strings.Contains(a, "@")
}

func (s *sesSMTPSession) Data(r io.Reader) error {
	if s.claims == nil {
		return errSESSMTPAuthRequired
	}
	data, err := io.ReadAll(r)
	if err != nil {
		if errors.Is(err, smtp.ErrDataTooLarge) {
			return errSESSMTPTooLong
		}
		return err
	}
	return s.b.send(s, data)
}

func (s *sesSMTPSession) Reset() { s.from, s.rcpts = "", nil }

func (s *sesSMTPSession) Logout() error { return nil }

// send is the message as SES SendRawEmail, through the SES front door, with the signed-in user's identity:
// the same authorization, identity checks and relay hand-off as the Query API's SendRawEmail. Its answer
// becomes SES's SMTP reply.
func (b *sesSMTPBackend) send(s *sesSMTPSession, data []byte) error {
	form := url.Values{
		"Action":          {"SendRawEmail"},
		"Version":         {"2010-12-01"},
		"RawMessage.Data": {base64.StdEncoding.EncodeToString(data)},
	}
	if s.from != "" {
		form.Set("Source", s.from)
	}
	for i, rc := range s.rcpts {
		form.Set("Destinations.member."+strconv.Itoa(i+1), rc)
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", strings.NewReader(form.Encode()))
	if err != nil {
		return errSESSMTPServiceFailure
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = s.remote
	if st, ok := s.encrypted(); ok {
		req.TLS = &st
	}
	claims := *s.claims
	req = b.auth.inCallerAccount(req, claims)
	req = req.WithContext(inAccountScope(req.Context())) // SES keeps each account's identities apart
	requestID := uuidLike()
	rec := &bufferedResponse{header: http.Header{}}
	b.ses.serve(rec, req, claims, requestID)
	reply := sesSMTPAnswer(rec.status(), rec.body.Bytes())
	if reply.Code == 250 {
		b.logger.Info("ses smtp message accepted", "accessKeyId", s.keyID, "recipients", len(s.rcpts), "requestId", requestID)
	} else {
		b.logger.Info("ses smtp message refused", "accessKeyId", s.keyID, "code", reply.Code, "requestId", requestID)
	}
	return reply
}

// sesSMTPAnswer is the SMTP reply to the SES front door's answer to SendRawEmail: SES's own reply texts.
// (A 250 travels as an SMTPError too: it is the reply go-smtp writes for DATA, MessageId included.)
func sesSMTPAnswer(status int, body []byte) *smtp.SMTPError {
	if status == http.StatusOK {
		var ok struct {
			MessageID string `xml:"SendRawEmailResult>MessageId"`
		}
		if xml.Unmarshal(body, &ok) == nil && ok.MessageID != "" {
			return sesSMTPReply(250, "Ok "+ok.MessageID)
		}
		return errSESSMTPServiceFailure
	}
	var er errorResponse
	if xml.Unmarshal(body, &er) != nil {
		return errSESSMTPServiceFailure
	}
	switch er.Error.Code {
	case "MessageRejected":
		return sesSMTPReply(554, "Message rejected: "+er.Error.Message)
	case "AccessDenied":
		return sesSMTPReply(554, "Access denied: "+er.Error.Message)
	case "InvalidParameterValue":
		return sesSMTPReply(554, "Transaction failed: "+er.Error.Message)
	case "Throttling":
		return sesSMTPReply(454, "Throttling failure: "+er.Error.Message)
	}
	// The relay could not take the message, or SES is not served while the mail component is off: a
	// temporary failure the client retries, as SES's own processing errors are.
	return errSESSMTPServiceFailure
}

// bufferedResponse is an http.ResponseWriter that keeps the answer in memory.
type bufferedResponse struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (w *bufferedResponse) Header() http.Header         { return w.header }
func (w *bufferedResponse) Write(b []byte) (int, error) { return w.body.Write(b) }
func (w *bufferedResponse) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}
func (w *bufferedResponse) status() int {
	if w.code == 0 {
		return http.StatusOK
	}
	return w.code
}

// saslLoginServer is the LOGIN mechanism (draft-murchison-sasl-login), which SES and most SMTP clients
// speak beside PLAIN: the server asks for the user name, then the password. A client may send the user name
// with the AUTH command (its initial response).
type saslLoginServer struct {
	authenticate func(username, password string) error
	username     string
	step         int
}

func (l *saslLoginServer) Next(response []byte) ([]byte, bool, error) {
	switch l.step {
	case 0:
		l.step = 1
		if response == nil {
			return []byte("Username:"), false, nil
		}
		l.username = string(response)
		l.step = 2
		return []byte("Password:"), false, nil
	case 1:
		l.username = string(response)
		l.step = 2
		return []byte("Password:"), false, nil
	case 2:
		l.step = 3
		if err := l.authenticate(l.username, string(response)); err != nil {
			return nil, true, err
		}
		return nil, true, nil
	}
	return nil, true, sasl.ErrUnexpectedClientResponse
}

// authFailureLimiter bounds AUTH failures: at most limit within window per key (a client address, an access
// key id). Past it, AUTH is refused with SES's temporary failure without looking at the credentials.
type authFailureLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu    sync.Mutex
	fails map[string][]time.Time
}

// authFailureLimiterMaxKeys bounds the limiter's memory: past it, keys with no failure inside the window are
// dropped, and if every key is still live the oldest failure lists go first.
const authFailureLimiterMaxKeys = 16384

func newAuthFailureLimiter(limit int, window time.Duration) *authFailureLimiter {
	return &authFailureLimiter{limit: limit, window: window, now: time.Now, fails: map[string][]time.Time{}}
}

func (l *authFailureLimiter) recent(key string, now time.Time) []time.Time {
	ts := l.fails[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= l.window {
		i++
	}
	if i == len(ts) {
		delete(l.fails, key)
		return nil
	}
	if i > 0 {
		ts = ts[i:]
		l.fails[key] = ts
	}
	return ts
}

// blocked reports whether any of keys has reached the limit.
func (l *authFailureLimiter) blocked(keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for _, k := range keys {
		if len(l.recent(k, now)) >= l.limit {
			return true
		}
	}
	return false
}

// fail records one failure against each of keys.
func (l *authFailureLimiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.fails) >= authFailureLimiterMaxKeys {
		for k := range l.fails {
			l.recent(k, now)
		}
		for k := range l.fails {
			if len(l.fails) < authFailureLimiterMaxKeys {
				break
			}
			delete(l.fails, k)
		}
	}
	for _, k := range keys {
		ts := l.recent(k, now)
		if len(ts) >= l.limit {
			ts = ts[1:]
		}
		l.fails[k] = append(ts, now)
	}
}
