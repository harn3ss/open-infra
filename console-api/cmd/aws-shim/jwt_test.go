package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// testIssuer is a minimal in-process OIDC provider: it serves discovery + a JWKS containing one signing
// key, and can mint tokens with that key (or a second, UNKNOWN key that isn't in the JWKS). This lets
// the negative tests exercise the REAL coreos/go-oidc verification path — the only honest way to prove
// an auth bypass can't sneak through.
type testIssuer struct {
	url     string
	kid     string
	signer  jose.Signer // signs with the key published in the JWKS
	unknown jose.Signer // signs with a key NOT in the JWKS (unknown-key case)
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "test-key-1"
	mkSigner := func(k *rsa.PrivateKey, id string) jose.Signer {
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", id))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ti := &testIssuer{kid: kid, signer: mkSigner(key, kid), unknown: mkSigner(other, "unknown-kid")}

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                ti.url,
			"jwks_uri":                              ti.url + "/jwks",
			"authorization_endpoint":                ti.url + "/auth",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	ti.url = ts.URL
	return ti
}

// mint signs a token with the PUBLISHED key. Override claims via the map.
func (ti *testIssuer) mint(t *testing.T, claims map[string]any) string {
	t.Helper()
	return ti.sign(t, ti.signer, claims)
}

func (ti *testIssuer) sign(t *testing.T, signer jose.Signer, claims map[string]any) string {
	t.Helper()
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (ti *testIssuer) baseClaims(aud string) map[string]any {
	return map[string]any{
		"iss":            ti.url,
		"sub":            "user-123",
		"aud":            aud,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"cognito:groups": []string{"Admin", "Ops"},
	}
}

const testAudience = "open-infra-appsync"

func newAuth(t *testing.T, ti *testIssuer, groupsClaim, mode string) *jwtAuthenticator {
	t.Helper()
	j, err := newJWTAuthenticator(context.Background(), ti.url, testAudience, groupsClaim, mode)
	if err != nil {
		t.Fatalf("newJWTAuthenticator: %v", err)
	}
	return j
}

// A valid token verifies: subject + groups extracted, mode returned.
func TestJWT_ValidToken(t *testing.T) {
	ti := newTestIssuer(t)
	j := newAuth(t, ti, "cognito:groups", "aws_cognito_user_pools")
	claims, mode, err := j.verify(context.Background(), ti.mint(t, ti.baseClaims(testAudience)))
	if err != nil {
		t.Fatalf("valid token should verify: %v", err)
	}
	if claims.Sub != "user-123" {
		t.Errorf("sub = %q", claims.Sub)
	}
	if mode != "aws_cognito_user_pools" {
		t.Errorf("mode = %q", mode)
	}
	// Groups are namespaced (iam.GroupsFromSpec): openinfra:<g> + openinfra:users.
	want := map[string]bool{"openinfra:Admin": true, "openinfra:Ops": true, "openinfra:users": true}
	if len(claims.Groups) != len(want) {
		t.Fatalf("groups = %v, want %v", claims.Groups, want)
	}
	for _, g := range claims.Groups {
		if !want[g] {
			t.Errorf("unexpected group %q in %v", g, claims.Groups)
		}
	}
}

// The negatives — where an edge auth bypass hides. Each MUST be rejected.
func TestJWT_Negatives(t *testing.T) {
	ti := newTestIssuer(t)
	j := newAuth(t, ti, "cognito:groups", "aws_oidc")

	t.Run("expired", func(t *testing.T) {
		c := ti.baseClaims(testAudience)
		c["exp"] = time.Now().Add(-time.Hour).Unix()
		if _, _, err := j.verify(context.Background(), ti.mint(t, c)); err == nil {
			t.Fatal("expired token must be rejected")
		}
	})
	t.Run("wrong-aud", func(t *testing.T) {
		if _, _, err := j.verify(context.Background(), ti.mint(t, ti.baseClaims("some-other-audience"))); err == nil {
			t.Fatal("wrong-audience token must be rejected")
		}
	})
	t.Run("wrong-iss", func(t *testing.T) {
		c := ti.baseClaims(testAudience)
		c["iss"] = "https://evil.example.com"
		if _, _, err := j.verify(context.Background(), ti.mint(t, c)); err == nil {
			t.Fatal("wrong-issuer token must be rejected")
		}
	})
	t.Run("alg-none", func(t *testing.T) {
		// A hand-crafted unsigned token (header alg:none, empty signature) — the classic bypass.
		b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
		exp := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
		none := b64(`{"alg":"none","typ":"JWT"}`) + "." +
			b64(`{"iss":"`+ti.url+`","sub":"user-123","aud":"`+testAudience+`","exp":`+exp+`}`) + "."
		if _, _, err := j.verify(context.Background(), none); err == nil {
			t.Fatal("alg:none token must be rejected")
		}
	})
	t.Run("unknown-key", func(t *testing.T) {
		// Signed by a key that is NOT in the JWKS.
		tok := ti.sign(t, ti.unknown, ti.baseClaims(testAudience))
		if _, _, err := j.verify(context.Background(), tok); err == nil {
			t.Fatal("token signed by an unknown key must be rejected")
		}
	})
}

// The verified token's groups must be NAMESPACED (iam.GroupsFromSpec) before becoming impersonation
// groups — so an untrusted claim like "system:masters" can never collide with a real cluster group,
// and an empty claim resolves to the unprivileged authenticated set, not a role.
func TestJWT_GroupsNamespaced(t *testing.T) {
	ti := newTestIssuer(t)
	j := newAuth(t, ti, "cognito:groups", "aws_cognito_user_pools")

	// A hostile claim "system:masters" must be prefixed, never passed through raw.
	c := ti.baseClaims(testAudience)
	c["cognito:groups"] = []string{"system:masters", "Admins"}
	claims, _, err := j.verify(context.Background(), ti.mint(t, c))
	if err != nil {
		t.Fatal(err)
	}
	has := func(g string) bool {
		for _, x := range claims.Groups {
			if x == g {
				return true
			}
		}
		return false
	}
	if has("system:masters") {
		t.Fatalf("raw cluster group leaked into impersonation groups: %v", claims.Groups)
	}
	if !has("openinfra:system:masters") || !has("openinfra:Admins") || !has("openinfra:users") {
		t.Errorf("groups should be namespaced + include openinfra:users, got %v", claims.Groups)
	}

	// Empty groups claim → just the authenticated set (no role fallback).
	c2 := ti.baseClaims(testAudience)
	delete(c2, "cognito:groups")
	claims2, _, err := j.verify(context.Background(), ti.mint(t, c2))
	if err != nil {
		t.Fatal(err)
	}
	if len(claims2.Groups) != 1 || claims2.Groups[0] != "openinfra:users" {
		t.Errorf("empty groups should resolve to [openinfra:users], got %v", claims2.Groups)
	}
}

func TestBearerToken_Classification(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"AWS4-HMAC-SHA256 Credential=...", false}, // SigV4, not a bearer
		{"", false},
		{"Bearer aaa.bbb.ccc", true},
		{"bearer aaa.bbb.ccc", true},
		{"aaa.bbb.ccc", true}, // raw JWT
		{"aaa.bbb.", true},    // alg:none shape (empty sig) — still routed so the verifier rejects it
		{"not-a-jwt", false},
		{"aaa.bbb", false}, // only two segments
	}
	for _, c := range cases {
		if _, ok := bearerToken(c.in); ok != c.want {
			t.Errorf("bearerToken(%q) = %v, want %v", c.in, ok, c.want)
		}
	}
}

func TestResolveGroupsClaim(t *testing.T) {
	// Explicit override ALWAYS wins.
	if got := resolveGroupsClaim("roles", "https://cognito-idp.us-east-1.amazonaws.com/pool"); got != "roles" {
		t.Errorf("override should win, got %q", got)
	}
	// Cognito issuer → cognito:groups default; other → groups default.
	if got := resolveGroupsClaim("", "https://cognito-idp.us-east-1.amazonaws.com/pool"); got != "cognito:groups" {
		t.Errorf("cognito default = %q", got)
	}
	if got := resolveGroupsClaim("", "https://accounts.google.com"); got != "groups" {
		t.Errorf("oidc default = %q", got)
	}
}
