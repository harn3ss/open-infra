package main

// Multi-factor authentication in the console (internal/mfa: the same virtual MFA devices the aws-shim's
// IAM front door manages).
//
// Sign-in, as the AWS console does it: a user with an MFA device assigned signs in with its password, and
// is then asked for the code its device shows. The password step answers {"mfaRequired": true} and an
// HttpOnly challenge cookie (signed with the session key, for this purpose only, valid five minutes); POST
// /api/auth/login/mfa with the code then starts the session. A console session is a temporary
// credential: one started with MFA carries aws:MultiFactorAuthPresent true and aws:MultiFactorAuthAge, one
// without carries aws:MultiFactorAuthPresent false, and IAM policy decides with them (s3authz.RequestContext).
//
// A user's "Security credentials" → "Assign MFA device": the console creates a virtual device (its QR code
// and seed shown once), enables it on two consecutive codes, lists the user's devices and removes one
// (DeactivateMFADevice, then DeleteVirtualMFADevice) — each route the IAM action AWS's console calls. A
// user manages its own devices; an administrator another user's.
//
// The root user is the console's break-glass sign-in (console-auth): it has no MFA device here, so a lost
// device or an unreachable credential store can never lock it out.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/mfa"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
)

const (
	// mfaChallengeCookie carries a sign-in that passed its password and owes an MFA code.
	mfaChallengeCookie = "oi_mfa"
	mfaChallengeTTL    = 5 * time.Minute
	// mfaChallengeDomain separates a challenge's signature from a session's: one is never the other.
	mfaChallengeDomain = "openinfra-mfa-challenge:"
)

// mfaStore is the credential store's virtual MFA devices.
func (a *authStore) mfaStore() mfa.Store {
	return mfa.Store{CS: a.cs, NS: getenv("KEYS_NAMESPACE", "open-infra-aws-shim")}
}

// mfaDevices is the devices assigned to the management account's user u. A credential store that does not
// exist holds none.
func (a *authStore) mfaDevices(ctx context.Context, u crdUser) ([]mfa.Device, error) {
	devices, err := a.mfaStore().ForUser(ctx, a.accountID(), a.ns, u.Metadata.Name, u.Metadata.UID)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return devices, err
}

// mfaChallenge is a sign-in that passed its password: who, as what, and whether it must change its
// password next — everything the session will carry once the code verifies.
type mfaChallenge struct {
	Sub     string   `json:"sub"`
	Role    string   `json:"role"`
	Groups  []string `json:"groups,omitempty"`
	PwReset bool     `json:"pwReset,omitempty"`
	Exp     int64    `json:"exp"`
}

func (a *authStore) challengeMAC(body string) string {
	mac := hmac.New(sha256.New, a.sessionKey)
	mac.Write([]byte(mfaChallengeDomain + body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *authStore) signChallenge(c mfaChallenge) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(b)
	return body + "." + a.challengeMAC(body), nil
}

func (a *authStore) parseChallenge(tok string) (mfaChallenge, bool) {
	var c mfaChallenge
	body, sig, ok := strings.Cut(tok, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(sig), []byte(a.challengeMAC(body))) != 1 {
		return c, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Sub == "" || time.Now().Unix() > c.Exp {
		return mfaChallenge{}, false
	}
	return c, true
}

func (a *authStore) setChallengeCookie(w http.ResponseWriter, r *http.Request, tok string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: mfaChallengeCookie, Value: tok, Path: "/api/auth/", HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds()),
	})
}

// POST /api/auth/login/mfa {code} — the second step of a sign-in whose user has an MFA device.
func handleLoginMFA(a *authStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(csrfHeader) == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing " + csrfHeader})
			return
		}
		ck, err := r.Cookie(mfaChallengeCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "SignInAgain", "error": "sign in again: the MFA step has expired"})
			return
		}
		ch, ok := a.parseChallenge(ck.Value)
		if !ok {
			a.setChallengeCookie(w, r, "", -1)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "SignInAgain", "error": "sign in again: the MFA step has expired"})
			return
		}
		var in struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !mfa.WellFormed(strings.TrimSpace(in.Code)) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "ValidationError", "error": "the MFA code is the six digits your device shows"})
			return
		}
		u, ok := a.crdUserByName(r.Context(), ch.Sub)
		if !ok {
			a.setChallengeCookie(w, r, "", -1)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "SignInAgain", "error": "sign in again"})
			return
		}
		err = a.mfaStore().VerifyAny(r.Context(), a.accountID(), a.ns, ch.Sub, u.Metadata.UID, strings.TrimSpace(in.Code))
		switch {
		case errors.Is(err, mfa.ErrLocked):
			a.logger.Warn("console MFA refused", "user", ch.Sub, "reason", "device locked after repeated wrong codes", "remote", r.RemoteAddr)
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"code": "MFADeviceLocked",
				"error": "too many wrong codes: wait a few minutes and try again"})
			return
		case errors.Is(err, mfa.ErrInvalidCode):
			a.logger.Warn("console MFA refused", "user", ch.Sub, "reason", mfaReason(err), "remote", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "InvalidAuthenticationCode", "error": "the MFA code is not valid"})
			return
		case errors.Is(err, mfa.ErrNotFound):
			// The device was removed after the password step: start over.
			a.setChallengeCookie(w, r, "", -1)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "SignInAgain", "error": "sign in again"})
			return
		case err != nil:
			a.logger.Error("console MFA: the credential store is not reachable", "user", ch.Sub, "error", err.Error())
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the MFA code could not be checked; try again"})
			return
		}
		tok, err := a.issueSession(iam.Claims{Sub: ch.Sub, Role: ch.Role, Groups: ch.Groups, MFA: iam.WithMFA(time.Now())}, ch.PwReset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not start session"})
			return
		}
		a.setChallengeCookie(w, r, "", -1)
		a.setCookie(w, r, tok, sessionTTL)
		a.logger.Info("console login", "user", ch.Sub, "role", ch.Role, "mfa", true, "passwordResetRequired", ch.PwReset)
		writeJSON(w, http.StatusOK, map[string]any{"user": ch.Sub, "role": ch.Role, "passwordResetRequired": ch.PwReset})
	}
}

// mfaReason is why a code was refused, for the log (never the code).
func mfaReason(err error) string {
	switch {
	case errors.Is(err, mfa.ErrReplayed):
		return "a code already used"
	case errors.Is(err, mfa.ErrLocked):
		return "device locked"
	}
	return "wrong code"
}

// ── "Assign MFA device" ─────────────────────────────────────────────────────────

// mfaDeviceView is a device as the console shows it (never its seed).
type mfaDeviceView struct {
	SerialNumber string `json:"serialNumber"`
	Name         string `json:"name"`
	Type         string `json:"type"` // "Virtual" (an authenticator app)
	EnableDate   string `json:"enableDate,omitempty"`
	Created      string `json:"created,omitempty"`
}

func mfaView(account string, d mfa.Device) mfaDeviceView {
	v := mfaDeviceView{SerialNumber: d.SerialNumber(account), Name: d.Name, Type: "Virtual"}
	if !d.EnableDate.IsZero() {
		v.EnableDate = d.EnableDate.UTC().Format(time.RFC3339)
	}
	if !d.Created.IsZero() {
		v.Created = d.Created.UTC().Format(time.RFC3339)
	}
	return v
}

// mfaARN is a virtual MFA device's ARN in the caller's account, from its name.
func mfaARN(r *http.Request, name string) string {
	return mfa.SerialNumber(callerAccount(r), "/", name)
}

// queryMFAARN is the device a route names by its ?serialNumber= (its ARN), "*" when none.
func queryMFAARN(r *http.Request) string {
	if _, path, name, ok := mfa.ParseSerial(r.URL.Query().Get("serialNumber")); ok {
		return mfa.SerialNumber(callerAccount(r), path, name)
	}
	return "*"
}

// mfaUserFor is the user an MFA route names, after the self-service-or-administrator check (verb "get"
// to read, "update" to change). It writes the answer when the caller may not proceed.
func mfaUserFor(w http.ResponseWriter, r *http.Request, cs kubernetes.Interface, auth *authStore, logger *slog.Logger, verb string) (crdUser, bool) {
	name := chi.URLParam(r, "name")
	if reservedRootName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "root is the break-glass account: it has no MFA device here"})
		return crdUser{}, false
	}
	if !authorizeAccessKey(w, r, cs, auth, logger, verb, name) {
		return crdUser{}, false
	}
	u, ok := auth.rawUser(r.Context(), name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"errorCode": "NoSuchEntity", "error": "no such user"})
		return crdUser{}, false
	}
	return u, true
}

func writeMFAErr(w http.ResponseWriter, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, mfa.ErrInvalidCode):
		writeJSON(w, http.StatusForbidden, map[string]string{"errorCode": "InvalidAuthenticationCode",
			"error": "The MFA codes are not valid. Enter two consecutive codes from the device."})
	case errors.Is(err, mfa.ErrAssigned):
		writeJSON(w, http.StatusConflict, map[string]string{"errorCode": "EntityAlreadyExists", "error": "MFA Device is already in use."})
	case errors.Is(err, mfa.ErrExists):
		writeJSON(w, http.StatusConflict, map[string]string{"errorCode": "EntityAlreadyExists", "error": "An MFA device with that name already exists."})
	case errors.Is(err, mfa.ErrLimit):
		writeJSON(w, http.StatusConflict, map[string]string{"errorCode": "LimitExceeded", "error": "A user can have at most 8 MFA devices."})
	case errors.Is(err, mfa.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"errorCode": "NoSuchEntity", "error": "no such MFA device"})
	default:
		logger.Error("iam: MFA device store", "error", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "the MFA device store is not reachable (is the aws-shim deployed?)"})
	}
}

// GET /api/iam/users/{name}/mfa-devices — iam:ListMFADevices.
func handleIAMMFADevicesList(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The account whose IAM this page manages: the session's (iam_scope.go).
		auth, scoped := iamAuth(w, r, auth)
		if !scoped {
			return
		}
		u, ok := mfaUserFor(w, r, cs, auth, logger, "get")
		if !ok {
			return
		}
		devices, err := auth.mfaDevices(r.Context(), u)
		if err != nil {
			writeMFAErr(w, logger, err)
			return
		}
		out := make([]mfaDeviceView, 0, len(devices))
		for _, d := range devices {
			out = append(out, mfaView(auth.accountID(), d))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// POST /api/iam/users/{name}/mfa-devices {deviceName} — iam:CreateVirtualMFADevice: a new, unassigned
// virtual device, answered with its QR code and seed — the only time either is shown.
func handleIAMMFADeviceCreate(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The account whose IAM this page manages: the session's (iam_scope.go).
		auth, scoped := iamAuth(w, r, auth)
		if !scoped {
			return
		}
		var in struct {
			DeviceName string `json:"deviceName"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !mfa.ValidName(in.DeviceName) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"errorCode": "ValidationError",
				"error": "a device name is letters, digits and + = , . @ _ - (no spaces)"})
			return
		}
		u, ok := mfaUserFor(w, r, cs, auth, logger, "update")
		if !ok {
			return
		}
		_, seed, err := auth.mfaStore().Create(r.Context(), auth.accountID(), in.DeviceName, "/", nil)
		if err != nil {
			writeMFAErr(w, logger, err)
			return
		}
		acctName := getenv("ACCOUNT_ALIAS", "")
		if acctName == "" {
			acctName = callerAccount(r)
		}
		uri := mfa.OTPAuthURI(in.DeviceName, acctName, seed)
		png, err := mfa.QRCodePNG(uri)
		if err != nil {
			_ = auth.mfaStore().Delete(context.Background(), auth.accountID(), in.DeviceName)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not draw the QR code"})
			return
		}
		logger.Info("iam: virtual MFA device created", "user", u.Metadata.Name, "device", in.DeviceName, "by", subjectOf(r))
		writeJSON(w, http.StatusCreated, map[string]string{
			"serialNumber":     mfa.SerialNumber(callerAccount(r), "/", in.DeviceName),
			"name":             in.DeviceName,
			"base32StringSeed": mfa.Base32(seed),
			"qrCodePng":        base64.StdEncoding.EncodeToString(png),
		})
	}
}

// mfaDeviceName is the device a request names by its serial number, in the console's account.
func mfaDeviceName(w http.ResponseWriter, r *http.Request, serial string) (string, bool) {
	acct, path, name, ok := mfa.ParseSerial(serial)
	if !ok || acct != callerAccount(r) || path != "/" {
		writeJSON(w, http.StatusNotFound, map[string]string{"errorCode": "NoSuchEntity", "error": "no such MFA device"})
		return "", false
	}
	return name, true
}

// POST /api/iam/users/{name}/mfa-devices/enable {serialNumber, authenticationCode1, authenticationCode2} —
// iam:EnableMFADevice: two consecutive codes from the device assign it to the user.
func handleIAMMFADeviceEnable(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The account whose IAM this page manages: the session's (iam_scope.go).
		auth, scoped := iamAuth(w, r, auth)
		if !scoped {
			return
		}
		var in struct {
			SerialNumber string `json:"serialNumber"`
			Code1        string `json:"authenticationCode1"`
			Code2        string `json:"authenticationCode2"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !mfa.WellFormed(in.Code1) || !mfa.WellFormed(in.Code2) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"errorCode": "ValidationError", "error": "enter two six-digit codes from the device"})
			return
		}
		u, ok := mfaUserFor(w, r, cs, auth, logger, "update")
		if !ok {
			return
		}
		name, ok := mfaDeviceName(w, r, in.SerialNumber)
		if !ok {
			return
		}
		if err := auth.mfaStore().Enable(r.Context(), auth.accountID(), name, auth.ns, u.Metadata.Name, u.Metadata.UID, in.Code1, in.Code2); err != nil {
			if errors.Is(err, mfa.ErrInvalidCode) {
				logger.Warn("iam: MFA device not enabled", "user", u.Metadata.Name, "device", name, "reason", mfaReason(err), "by", subjectOf(r))
			}
			writeMFAErr(w, logger, err)
			return
		}
		logger.Info("iam: MFA device enabled", "user", u.Metadata.Name, "device", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"serialNumber": in.SerialNumber})
	}
}

// DELETE /api/iam/users/{name}/mfa-devices?serialNumber= — iam:DeactivateMFADevice, then (as the AWS
// console's "Remove" does) iam:DeleteVirtualMFADevice when the caller may: the device is gone.
func handleIAMMFADeviceRemove(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The account whose IAM this page manages: the session's (iam_scope.go).
		auth, scoped := iamAuth(w, r, auth)
		if !scoped {
			return
		}
		u, ok := mfaUserFor(w, r, cs, auth, logger, "update")
		if !ok {
			return
		}
		serial := r.URL.Query().Get("serialNumber")
		name, ok := mfaDeviceName(w, r, serial)
		if !ok {
			return
		}
		// "Remove" is both actions: ask for the second before doing the first.
		if !consoleIAM.require(w, r, "iam:DeleteVirtualMFADevice", serial) {
			return
		}
		store := auth.mfaStore()
		if err := store.Deactivate(r.Context(), auth.accountID(), name, auth.ns, u.Metadata.Name); err != nil {
			writeMFAErr(w, logger, err)
			return
		}
		if err := store.Delete(r.Context(), auth.accountID(), name); err != nil {
			logger.Warn("iam: MFA device deactivated but not deleted", "user", u.Metadata.Name, "device", name, "error", err.Error())
		}
		logger.Info("iam: MFA device removed", "user", u.Metadata.Name, "device", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"serialNumber": serial})
	}
}

// DELETE /api/iam/users/{name}/mfa-devices/pending?serialNumber= — iam:DeleteVirtualMFADevice of a device
// not yet assigned (an "Assign MFA device" cancelled before its codes were entered). An assigned device is
// refused: it is removed, not cancelled.
func handleIAMMFADeviceCancel(cs kubernetes.Interface, auth *authStore, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The account whose IAM this page manages: the session's (iam_scope.go).
		auth, scoped := iamAuth(w, r, auth)
		if !scoped {
			return
		}
		if _, ok := mfaUserFor(w, r, cs, auth, logger, "update"); !ok {
			return
		}
		name, ok := mfaDeviceName(w, r, r.URL.Query().Get("serialNumber"))
		if !ok {
			return
		}
		if err := auth.mfaStore().Delete(r.Context(), auth.accountID(), name); err != nil {
			if errors.Is(err, mfa.ErrAssigned) {
				writeJSON(w, http.StatusConflict, map[string]string{"errorCode": "DeleteConflict", "error": "MFA VirtualDevice in use. Must deactivate first."})
				return
			}
			writeMFAErr(w, logger, err)
			return
		}
		logger.Info("iam: virtual MFA device deleted", "device", name, "by", subjectOf(r))
		writeJSON(w, http.StatusOK, map[string]string{"name": name})
	}
}

// removeUserMFADevices deactivates and deletes every MFA device of user u (the console deletes a user's
// credentials with the user, as the AWS console does). Best-effort; it reports what it could not remove.
func (a *authStore) removeUserMFADevices(ctx context.Context, u crdUser) error {
	devices, err := a.mfaDevices(ctx, u)
	if err != nil {
		return err
	}
	var last error
	for _, d := range devices {
		if err := a.mfaStore().Deactivate(ctx, a.accountID(), d.Name, a.ns, u.Metadata.Name); err != nil {
			last = err
			continue
		}
		if err := a.mfaStore().Delete(ctx, a.accountID(), d.Name); err != nil {
			last = err
		}
	}
	return last
}
