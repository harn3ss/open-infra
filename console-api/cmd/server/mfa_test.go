package main

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	"github.com/harn3ss/open-infra/console-api/internal/mfa"
)

// mfaAlice is lpAuth's alice with a virtual MFA device enabled; it returns the device's seed.
func mfaAlice(t *testing.T) (*authStore, *fakeAPI, []byte) {
	t.Helper()
	a, api := lpAuth(t, nil)
	api.objects[userPath("alice")]["metadata"].(map[string]any)["uid"] = "uid-alice"
	store := a.mfaStore()
	_, seed, err := store.Create(context.Background(), iam.ManagementAccount, "alice-phone", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := mfa.StepAt(time.Now())
	if err := store.Enable(context.Background(), iam.ManagementAccount, "alice-phone", lpConsoleNS, "alice", "uid-alice",
		mfa.Code(seed, s-1), mfa.Code(seed, s)); err != nil {
		t.Fatal(err)
	}
	return a, api, seed
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 && c.Value != "" {
			return c
		}
	}
	return nil
}

func loginMFA(a *authStore, challenge *http.Cookie, code string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"code": code})
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login/mfa", bytes.NewReader(b))
	r.Header.Set(csrfHeader, "1")
	if challenge != nil {
		r.AddCookie(challenge)
	}
	w := httptest.NewRecorder()
	handleLoginMFA(a)(w, r)
	return w
}

// A user with an MFA device signs in in two steps, as on the AWS console: the password earns only the MFA
// step, and the code the session — which carries MFA for IAM policy.
func TestConsole_SignInWithMFA(t *testing.T) {
	a, _, seed := mfaAlice(t)
	w, session := lpLogin(t, a, "alice", "Old-Pass-1")
	if w.Code != 200 || session != nil || !strings.Contains(w.Body.String(), `"mfaRequired":true`) {
		t.Fatalf("the password step must ask for the code and start no session: %d %s %v", w.Code, w.Body.String(), session)
	}
	ch := cookieNamed(w, mfaChallengeCookie)
	if ch == nil || !ch.HttpOnly || ch.Path != "/api/auth/" {
		t.Fatalf("challenge cookie %+v", ch)
	}
	// The challenge is never a session: its signature is for its own purpose.
	if code := lpGuarded(a, &http.Cookie{Name: sessionCookie, Value: ch.Value}); code != http.StatusUnauthorized {
		t.Fatalf("a challenge passed as a session: %d", code)
	}
	if w := loginMFA(a, nil, "123456"); w.Code != http.StatusUnauthorized {
		t.Fatalf("no challenge: %d", w.Code)
	}
	if w := loginMFA(a, ch, "12345"); w.Code != http.StatusBadRequest {
		t.Fatalf("a malformed code: %d", w.Code)
	}
	if w := loginMFA(a, ch, "000000"); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "InvalidAuthenticationCode") {
		t.Fatalf("a wrong code: %d %s", w.Code, w.Body.String())
	}
	good := mfa.Code(seed, mfa.StepAt(time.Now())+1)
	w = loginMFA(a, ch, good)
	if w.Code != 200 {
		t.Fatalf("the right code: %d %s", w.Code, w.Body.String())
	}
	sess := cookieNamed(w, sessionCookie)
	if sess == nil || lpGuarded(a, sess) != http.StatusOK {
		t.Fatal("the MFA step must start a whole session")
	}
	claims, ok := a.parse(sess.Value)
	if !ok || !claims.MFAPresent() || claims.Sub != "alice" || len(claims.Groups) == 0 {
		t.Fatalf("the session must carry MFA: %+v", claims)
	}
	// The code cannot be used again, with a fresh challenge either.
	w, _ = lpLogin(t, a, "alice", "Old-Pass-1")
	if w := loginMFA(a, cookieNamed(w, mfaChallengeCookie), good); w.Code != http.StatusUnauthorized {
		t.Fatalf("a replayed code: %d %s", w.Code, w.Body.String())
	}
	// A tampered or expired challenge is refused.
	if w := loginMFA(a, &http.Cookie{Name: mfaChallengeCookie, Value: ch.Value + "x"}, good); w.Code != http.StatusUnauthorized {
		t.Fatalf("a tampered challenge: %d", w.Code)
	}
	old, _ := a.signChallenge(mfaChallenge{Sub: "alice", Role: "readonly", Exp: time.Now().Add(-time.Second).Unix()})
	if w := loginMFA(a, &http.Cookie{Name: mfaChallengeCookie, Value: old}, good); w.Code != http.StatusUnauthorized {
		t.Fatalf("an expired challenge: %d", w.Code)
	}
}

// Without a device, the sign-in is one step and the session is a temporary credential without MFA; a
// session issued before sessions carried it is read the same way.
func TestConsole_SignInWithoutMFA(t *testing.T) {
	a, _ := lpAuth(t, nil)
	w, sess := lpLogin(t, a, "alice", "Old-Pass-1")
	if w.Code != 200 || sess == nil || strings.Contains(w.Body.String(), "mfaRequired") {
		t.Fatalf("sign-in: %d %s", w.Code, w.Body.String())
	}
	claims, ok := a.parse(sess.Value)
	if !ok || claims.MFA == nil || claims.MFA.Present {
		t.Fatalf("a session without MFA: %+v", claims.MFA)
	}
	tok, _ := a.issueSession(iam.Claims{Sub: "alice"}, false)
	if c, _ := a.parse(tok); c.MFA == nil || c.MFA.Present {
		t.Fatalf("an older session: %+v", c.MFA)
	}
}

// mfaRoutes serves the console's MFA device routes (their handlers' own checks; the IAM route gate is
// iam_authz.go's) as the signed-in caller.
func mfaRoutes(a *authStore) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := chi.NewRouter()
	rt.Get("/api/iam/users/{name}/mfa-devices", handleIAMMFADevicesList(a.cs, a, logger))
	rt.Post("/api/iam/users/{name}/mfa-devices", handleIAMMFADeviceCreate(a.cs, a, logger))
	rt.Post("/api/iam/users/{name}/mfa-devices/enable", handleIAMMFADeviceEnable(a.cs, a, logger))
	rt.Delete("/api/iam/users/{name}/mfa-devices", handleIAMMFADeviceRemove(a.cs, a, logger))
	rt.Delete("/api/iam/users/{name}/mfa-devices/pending", handleIAMMFADeviceCancel(a.cs, a, logger))
	return rt
}

func asUser(r *http.Request, user string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxUser{}, sessionClaims{Claims: iam.Claims{Sub: user, MFA: iam.NoMFA()}}))
}

func mfaCall(h http.Handler, user, method, path string, body any) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, asUser(httptest.NewRequest(method, path, rd), user))
	return w
}

// A user assigns its own virtual MFA device from "Security credentials": the QR code and seed once, then
// two consecutive codes; it lists it, and removes it (deactivated and deleted).
func TestConsole_AssignAndRemoveMFADevice(t *testing.T) {
	a, api := lpAuth(t, nil)
	api.objects[userPath("alice")]["metadata"].(map[string]any)["uid"] = "uid-alice"
	h := mfaRoutes(a)

	w := mfaCall(h, "alice", http.MethodPost, "/api/iam/users/alice/mfa-devices", map[string]string{"deviceName": "alice-phone"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct{ SerialNumber, Base32StringSeed, QrCodePng string }
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	img, _ := base64.StdEncoding.DecodeString(created.QrCodePng)
	if _, err := png.Decode(bytes.NewReader(img)); err != nil || created.SerialNumber != "arn:aws:iam::000000000000:mfa/alice-phone" {
		t.Fatalf("created %+v (%v)", created, err)
	}
	seed, err := base32Decode(created.Base32StringSeed)
	if err != nil {
		t.Fatal(err)
	}
	if w := mfaCall(h, "alice", http.MethodPost, "/api/iam/users/alice/mfa-devices", map[string]string{"deviceName": "has space"}); w.Code != 400 {
		t.Fatalf("an invalid name: %d", w.Code)
	}
	s := mfa.StepAt(time.Now())
	if w := mfaCall(h, "alice", http.MethodPost, "/api/iam/users/alice/mfa-devices/enable", map[string]string{
		"serialNumber": created.SerialNumber, "authenticationCode1": "111111", "authenticationCode2": "222222"}); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "InvalidAuthenticationCode") {
		t.Fatalf("wrong codes: %d %s", w.Code, w.Body.String())
	}
	if w := mfaCall(h, "alice", http.MethodPost, "/api/iam/users/alice/mfa-devices/enable", map[string]string{
		"serialNumber": created.SerialNumber, "authenticationCode1": mfa.Code(seed, s-1), "authenticationCode2": mfa.Code(seed, s)}); w.Code != 200 {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	w = mfaCall(h, "alice", http.MethodGet, "/api/iam/users/alice/mfa-devices", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), created.SerialNumber) || strings.Contains(w.Body.String(), created.Base32StringSeed) {
		t.Fatalf("list (never the seed): %d %s", w.Code, w.Body.String())
	}
	// An assigned device is removed, not cancelled.
	q := "?serialNumber=" + url.QueryEscape(created.SerialNumber)
	if w := mfaCall(h, "alice", http.MethodDelete, "/api/iam/users/alice/mfa-devices/pending"+q, nil); w.Code != http.StatusConflict {
		t.Fatalf("cancel of an assigned device: %d %s", w.Code, w.Body.String())
	}
	if w := mfaCall(h, "alice", http.MethodDelete, "/api/iam/users/alice/mfa-devices"+q, nil); w.Code != 200 {
		t.Fatalf("remove: %d %s", w.Code, w.Body.String())
	}
	if _, err := a.mfaStore().Get(context.Background(), iam.ManagementAccount, "alice-phone"); err == nil {
		t.Fatal("a removed device must be deleted")
	}
	// The root user has none.
	if w := mfaCall(h, "root", http.MethodGet, "/api/iam/users/root/mfa-devices", nil); w.Code != 400 {
		t.Fatalf("root: %d", w.Code)
	}
}

// Deleting a user from the console removes its MFA devices too.
func TestConsole_DeleteUserRemovesItsMFADevices(t *testing.T) {
	a, _, _ := mfaAlice(t)
	u, ok := a.rawUser(context.Background(), "alice")
	if !ok {
		t.Fatal("no alice")
	}
	if err := a.removeUserMFADevices(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if devs, _ := a.mfaStore().List(context.Background(), iam.ManagementAccount); len(devs) != 0 {
		t.Fatalf("devices left: %+v", devs)
	}
}

// Once IAM policy decides, a console session's MFA is what AWS's "deny unless MFA" policy reads: the
// session signed in with MFA lists buckets, the one without is denied by the explicit Deny.
func TestConsoleGate_DenyUnlessMFA(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},
	  {"Effect":"Deny","NotAction":["iam:ListMFADevices","iam:CreateVirtualMFADevice","iam:EnableMFADevice"],"Resource":"*",
	   "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`
	z := newTestAuthz(t, iamauthz.ModeEnforce, testWorld(t, map[string]string{"mfa-required": doc}, map[string][]string{"User::alice": {"mfa-required"}}), true)
	h := testRoutes(z)
	without, with := userClaims("alice"), userClaims("alice")
	without.MFA, with.MFA = iam.NoMFA(), iam.WithMFA(time.Now().Add(-time.Minute))
	if got := serve(h, as(httptest.NewRequest(http.MethodGet, "/api/buckets", nil), without)); got.Code != http.StatusForbidden {
		t.Errorf("a session without MFA: %d, want 403", got.Code)
	}
	if got := serve(h, as(httptest.NewRequest(http.MethodGet, "/api/buckets", nil), with)); got.Code != 200 {
		t.Errorf("a session with MFA: %d %s", got.Code, got.Body)
	}
}

func base32Decode(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
