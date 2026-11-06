package main

// STS and MFA: GetSessionToken (an IAM user's own temporary credentials, with or without MFA) and the
// SerialNumber + TokenCode that GetSessionToken and AssumeRole accept. A session minted with a valid code
// carries MFA — aws:MultiFactorAuthPresent true and aws:MultiFactorAuthAge, the seconds since — to every
// later request it signs; one minted without carries aws:MultiFactorAuthPresent false; long-term access
// keys carry neither (s3authz.RequestContext). A wrong code is AWS's AccessDenied.

import (
	"context"
	"encoding/xml"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/awssts"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/mfa"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
)

// AWS's answers to an MFA code that does not verify, and to a device that is not the caller's.
const (
	mfaInvalidCode   = "MultiFactorAuthentication failed with invalid MFA one time pass code. "
	mfaUnknownDevice = "MultiFactorAuthentication failed, unable to validate MFA code. Please verify your MFA serial number is valid and associated with this user."
)

// mfaChecker verifies an IAM user's MFA code: the device serial must be the user's own, in its account.
type mfaChecker interface {
	// verify checks code from the device serial assigned to user of account acct ("" = the management
	// account). It answers when the user was authenticated, or AWS's message why not.
	verify(ctx context.Context, acct, user, serial, code string) (time.Time, string)
}

// shimMFA checks codes against the credential store's devices (internal/mfa).
type shimMFA struct {
	store   mfa.Store
	dyn     dynamic.Interface
	usersNS string // the management account's IAM home
	account string // the account id the install presents for the management account
	homes   accountHomes
	logger  *slog.Logger
}

func (m *shimMFA) verify(ctx context.Context, acct, user, serial, code string) (time.Time, string) {
	if m == nil || m.dyn == nil {
		return time.Time{}, mfaUnknownDevice
	}
	storeAcct, presented, home := iam.ManagementAccount, m.account, m.usersNS
	if acct != "" && (m.homes == nil || !m.homes.IsManagement(acct)) {
		h, ok := "", false
		if m.homes != nil {
			h, ok = m.homes.HomeOf(acct)
		}
		if !ok {
			return time.Time{}, mfaUnknownDevice
		}
		storeAcct, presented, home = acct, acct, h
	}
	sAcct, path, name, ok := mfa.ParseSerial(serial)
	if !ok || sAcct != presented {
		return time.Time{}, mfaUnknownDevice
	}
	u, err := m.dyn.Resource(gvrUsers).Namespace(home).Get(ctx, user, metav1.GetOptions{})
	if err != nil {
		return time.Time{}, mfaUnknownDevice
	}
	d, err := m.store.Get(ctx, storeAcct, name)
	if err != nil || d.Path != path {
		return time.Time{}, mfaUnknownDevice
	}
	err = m.store.Verify(ctx, storeAcct, name, home, user, string(u.GetUID()), code)
	switch {
	case err == nil:
		return time.Now(), ""
	case errors.Is(err, mfa.ErrInvalidCode):
		if m.logger != nil {
			m.logger.Info("sts mfa refused", "user", user, "serialNumber", serial, "reason", mfaRefusal(err))
		}
		return time.Time{}, mfaInvalidCode
	}
	return time.Time{}, mfaUnknownDevice
}

// mfaParams reads SerialNumber and TokenCode: both or neither, a six-digit code. ok=false writes the
// answer: a malformed code is a ValidationError, one without the other AWS's AccessDenied.
func mfaParams(w http.ResponseWriter, r *http.Request, requestID string) (serial, code string, ok bool) {
	serial, code = r.PostFormValue("SerialNumber"), r.PostFormValue("TokenCode")
	if code != "" && !mfa.WellFormed(code) {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"1 validation error detected: Value at 'tokenCode' failed to satisfy constraint: Member must have length 6 and satisfy regular expression pattern: [\\d]*", stsXMLNamespace)
		return "", "", false
	}
	if serial != "" && (len(serial) < 9 || len(serial) > 256) {
		writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
			"1 validation error detected: Value at 'serialNumber' failed to satisfy constraint: Member must have length between 9 and 256", stsXMLNamespace)
		return "", "", false
	}
	if (serial == "") != (code == "") {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, mfaUnknownDevice, stsXMLNamespace)
		return "", "", false
	}
	return serial, code, true
}

// memberAcct is the account a session of claims records: a member account's id, "" for the management
// account (whose sessions always were unmarked).
func (h *stsHandler) memberAcct(c iam.Claims) string {
	if c.Account == "" || c.Account == h.account || (h.accounts != nil && h.accounts.IsManagement(c.Account)) {
		return ""
	}
	return c.Account
}

// getSessionToken implements sts:GetSessionToken: an IAM user's own temporary credentials, called with its
// long-term access key — authenticated with MFA when it presents its device's SerialNumber and a TokenCode.
// No policy grants or denies it (AWS: authentication operations are not controlled by policy). The
// session acts as the user, with the user's permissions; it cannot call IAM without MFA, nor STS but
// AssumeRole and GetCallerIdentity.
func (h *stsHandler) getSessionToken(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	if h.minter == nil {
		writeQueryError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"sts:GetSessionToken is not enabled on this shim (no signing key configured)", stsXMLNamespace)
		return
	}
	_ = r.ParseForm()
	if claims.AssumedRole != "" || claims.MFA != nil || claims.UserSession {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, "Cannot call GetSessionToken with session credentials", stsXMLNamespace)
		return
	}
	if claims.Sub == "" {
		writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, "GetSessionToken must be called with an IAM user's access key", stsXMLNamespace)
		return
	}
	ttl := awssts.DefaultUserSessionDuration
	if v := r.PostFormValue("DurationSeconds"); v != "" {
		secs, err := strconv.Atoi(v)
		if err != nil || secs < 900 || secs > int(awssts.MaxUserSessionDuration/time.Second) {
			writeQueryError(w, http.StatusBadRequest, "ValidationError", requestID,
				"1 validation error detected: Value '"+v+"' at 'durationSeconds' failed to satisfy constraint: Member must have value between 900 and 129600", stsXMLNamespace)
			return
		}
		ttl = time.Duration(secs) * time.Second
	}
	serial, code, ok := mfaParams(w, r, requestID)
	if !ok {
		return
	}
	sess := awssts.Session{User: claims.Sub, Account: h.memberAcct(claims), SessionName: claims.Sub, Caller: claims.Sub}
	if serial != "" {
		if h.mfa == nil {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, mfaUnknownDevice, stsXMLNamespace)
			return
		}
		at, why := h.mfa.verify(r.Context(), h.memberAcct(claims), claims.Sub, serial, code)
		if why != "" {
			writeQueryError(w, http.StatusForbidden, "AccessDenied", requestID, why, stsXMLNamespace)
			return
		}
		sess.MFA, sess.MFAAuthTime = true, at.Unix()
	}
	akid, sk, token, exp, err := h.minter.MintSession(sess, ttl, awssts.MaxUserSessionDuration)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "could not mint credentials", stsXMLNamespace)
		return
	}
	if h.logger != nil {
		h.logger.Info("sts GetSessionToken", "user", claims.Sub, "account", h.callerAccount(claims), "mfa", sess.MFA)
	}
	var resp getSessionTokenResponse
	resp.Result.Credentials.AccessKeyId = akid
	resp.Result.Credentials.SecretAccessKey = sk
	resp.Result.Credentials.SessionToken = token
	resp.Result.Credentials.Expiration = exp.UTC().Format(time.RFC3339)
	resp.ResponseMetadata.RequestId = requestID
	out, err := xml.Marshal(resp)
	if err != nil {
		writeQueryError(w, http.StatusInternalServerError, "InternalFailure", requestID, "internal error", stsXMLNamespace)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(out)
}

// getSessionTokenResponse is the STS GetSessionToken XML body.
type getSessionTokenResponse struct {
	XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetSessionTokenResponse"`
	Result  struct {
		Credentials struct {
			AccessKeyId     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
	} `xml:"GetSessionTokenResult"`
	ResponseMetadata struct {
		RequestId string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}
