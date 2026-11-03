package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
)

// An ECR authorization token lasts 12 hours, but never past the session it was minted from: role
// credentials that expire in an hour must not leave a registry credential that pulls for eleven more.
func TestECRTokenTTL_CappedAtTheSession(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		exp  time.Time
		want time.Duration
	}{
		{"long-term keys", time.Time{}, 12 * time.Hour},
		{"a session ending in an hour", now.Add(time.Hour), time.Hour},
		{"a session ending in a day", now.Add(24 * time.Hour), 12 * time.Hour},
		{"an expired session", now.Add(-time.Second), -time.Second},
	} {
		if got := ecrTokenTTL(iam.Claims{SessionExpiry: c.exp}, now); got != c.want {
			t.Errorf("%s: ttl = %v, want %v", c.name, got, c.want)
		}
	}
}

// Through the front door: the credential's own expiry and the expiresAt the caller is told both follow
// the session, and a session already over gets no token.
func TestECR_GetAuthorizationToken_ExpiresWithTheSession(t *testing.T) {
	h := tokenModeECR(t, true, roleChecker(pullPolicy()...))
	claims := ecrRoleClaims()
	claims.SessionExpiry = time.Now().Add(time.Hour)
	w, cred := getAuthToken(t, h, claims)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		AuthorizationData []struct {
			ExpiresAt float64 `json:"expiresAt"`
		} `json:"authorizationData"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.AuthorizationData) != 1 {
		t.Fatalf("bad body: %v %s", err, w.Body.String())
	}
	if d := time.Unix(int64(resp.AuthorizationData[0].ExpiresAt), 0).Sub(claims.SessionExpiry); d > time.Second || d < -5*time.Second {
		t.Errorf("expiresAt is %v from the session's end, want the session's end", d)
	}
	parts := strings.Split(cred, ".")
	if len(parts) != 3 {
		t.Fatalf("credential is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var jwt struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &jwt); err != nil {
		t.Fatal(err)
	}
	if d := time.Unix(jwt.Exp, 0).Sub(claims.SessionExpiry); d > time.Second || d < -5*time.Second {
		t.Errorf("the credential's exp is %v from the session's end, want the session's end", d)
	}

	claims.SessionExpiry = time.Now().Add(-time.Minute)
	w = httptest.NewRecorder()
	h.serve(w, ecrRequest("GetAuthorizationToken", `{}`), claims, "req-tok")
	assertECSErrorType(t, w, http.StatusBadRequest, "ExpiredTokenException")
}
