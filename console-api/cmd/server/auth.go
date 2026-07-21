package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Console authentication.
//
// Until now the console had NO authentication: /api/k8s/* reverse-proxies the Kubernetes API
// with the pod's ServiceAccount token, so anyone who could reach the console had effective
// admin over the platform. This gates every /api route behind a signed session cookie.
//
// The identity backend is chosen at install time via AUTH_MODE (see docs/auth.md):
//
//	local  (default) — users stored in the console-auth Secret, bcrypt hashed
//	ldap / oidc      — reserved; implemented in a later phase
//	none             — NO authentication. Must be set explicitly; logs a loud warning.
//
// v1 is a gate: every authenticated user currently shares the console's ServiceAccount rights.
// Per-user authorization (Kubernetes impersonation + IAM-style roles) is the next phase — the
// session already carries a role so that work slots in without changing the login flow.

const (
	sessionCookie = "oi_session"
	authSecret    = "console-auth"
	sessionTTL    = 12 * time.Hour
	// Mutating requests must carry this header. Combined with SameSite=Lax it blocks
	// cross-site form posts / simple-request CSRF against the API.
	csrfHeader = "X-Openinfra-Console"
)

type userRec struct {
	Hash string `json:"hash"`
	Role string `json:"role"`
}

type authStore struct {
	cs         kubernetes.Interface
	ns         string
	mode       string
	sessionKey []byte
	logger     *slog.Logger
}

func authMode() string {
	m := strings.ToLower(strings.TrimSpace(getenv("AUTH_MODE", "local")))
	if m == "" {
		return "local"
	}
	return m
}

// consoleNamespace resolves the namespace the console runs in (for its auth Secret).
func consoleNamespace() string {
	if v := getenv("CONSOLE_NAMESPACE", ""); v != "" {
		return v
	}
	if b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	return "open-infra-console"
}

// newAuthStore loads (or bootstraps) the console-auth Secret. On a fresh install it generates
// a session-signing key and a random root password, printing the password ONCE to the log —
// the same "grab your root credentials now" moment AWS gives you.
func newAuthStore(cs kubernetes.Interface, logger *slog.Logger) (*authStore, error) {
	a := &authStore{cs: cs, ns: consoleNamespace(), mode: authMode(), logger: logger}
	if a.mode == "none" {
		logger.Warn("AUTH_MODE=none — the console API is UNAUTHENTICATED; anyone who can reach it has admin over this cluster")
		return a, nil
	}

	ctx := context.Background()
	sec, err := cs.CoreV1().Secrets(a.ns).Get(ctx, authSecret, metav1.GetOptions{})
	if err == nil && len(sec.Data["sessionKey"]) > 0 {
		a.sessionKey = sec.Data["sessionKey"]
		return a, nil
	}

	// Bootstrap: session key + root user.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	pw, err := randomPassword(20)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	users, _ := json.Marshal(map[string]userRec{"root": {Hash: string(hash), Role: "root"}})

	newSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: authSecret, Namespace: a.ns},
		Data: map[string][]byte{
			"sessionKey": key,
			"users":      users,
		},
	}
	if _, err := cs.CoreV1().Secrets(a.ns).Create(ctx, newSec, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return nil, fmt.Errorf("create %s secret: %w", authSecret, err)
		}
		// Raced with another replica — re-read.
		sec, err2 := cs.CoreV1().Secrets(a.ns).Get(ctx, authSecret, metav1.GetOptions{})
		if err2 != nil {
			return nil, err2
		}
		a.sessionKey = sec.Data["sessionKey"]
		return a, nil
	}

	a.sessionKey = key
	logger.Warn("════════ open-infra console: ROOT CREDENTIALS (shown once) ════════")
	logger.Warn("root user created", "username", "root", "password", pw)
	logger.Warn("Store this now. It is not recoverable — rotate by deleting the console-auth Secret.")
	logger.Warn("═══════════════════════════════════════════════════════════════════")
	return a, nil
}

func randomPassword(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n], nil
}

// users re-reads the user map so changes to the Secret take effect without a restart.
func (a *authStore) users(ctx context.Context) map[string]userRec {
	sec, err := a.cs.CoreV1().Secrets(a.ns).Get(ctx, authSecret, metav1.GetOptions{})
	if err != nil {
		return nil
	}
	var m map[string]userRec
	if err := json.Unmarshal(sec.Data["users"], &m); err != nil {
		return nil
	}
	return m
}

func (a *authStore) verify(ctx context.Context, user, pass string) (string, bool) {
	rec, ok := a.users(ctx)[user]
	if !ok {
		// Compare against a dummy hash so a missing user costs the same as a wrong
		// password (don't leak which usernames exist via timing).
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin"), []byte(pass))
		return "", false
	}
	if bcrypt.CompareHashAndPassword([]byte(rec.Hash), []byte(pass)) != nil {
		return "", false
	}
	role := rec.Role
	if role == "" {
		role = "user"
	}
	return role, true
}

type sessionClaims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Exp  int64  `json:"exp"`
}

func (a *authStore) issue(user, role string) (string, error) {
	c, err := json.Marshal(sessionClaims{Sub: user, Role: role, Exp: time.Now().Add(sessionTTL).Unix()})
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(c)
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (a *authStore) parse(tok string) (sessionClaims, bool) {
	var out sessionClaims
	body, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return out, false
	}
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return out, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return out, false
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, false
	}
	if time.Now().Unix() > out.Exp {
		return out, false
	}
	return out, true
}

func (a *authStore) setCookie(w http.ResponseWriter, r *http.Request, tok string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// requireAuth gates every /api route. Login/logout/me are exempt (handled inside).
func (a *authStore) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.mode == "none" {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		claims, ok := a.parse(c.Value)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}
		// CSRF: state-changing requests must carry the console's header. SameSite=Lax
		// already blocks cross-site form posts; this stops the simple-request bypass.
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if r.Header.Get(csrfHeader) == "" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing " + csrfHeader})
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUser{}, claims)))
	})
}

type ctxUser struct{}

// POST /api/auth/login
func handleLogin(a *authStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Username, Password string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
			return
		}
		if a.mode != "local" && a.mode != "none" {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "AUTH_MODE=" + a.mode + " is not implemented yet"})
			return
		}
		role, ok := a.verify(r.Context(), in.Username, in.Password)
		if !ok {
			a.logger.Warn("failed console login", "user", in.Username, "remote", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
			return
		}
		tok, err := a.issue(in.Username, role)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not start session"})
			return
		}
		a.setCookie(w, r, tok, sessionTTL)
		a.logger.Info("console login", "user", in.Username, "role", role)
		writeJSON(w, http.StatusOK, map[string]string{"user": in.Username, "role": role})
	}
}

// POST /api/auth/logout
func handleLogout(a *authStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.setCookie(w, r, "", -1)
		writeJSON(w, http.StatusOK, map[string]string{"status": "signed out"})
	}
}

// GET /api/auth/me — who am I (used by the UI to decide login vs app).
func handleMe(a *authStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.mode == "none" {
			writeJSON(w, http.StatusOK, map[string]any{"user": "anonymous", "role": "root", "authDisabled": true})
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
			return
		}
		claims, ok := a.parse(c.Value)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": claims.Sub, "role": claims.Role})
	}
}
