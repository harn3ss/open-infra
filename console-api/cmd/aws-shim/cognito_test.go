package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func testSigner(t *testing.T) *cognitoSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return &cognitoSigner{priv: key, kid: "test-kid"}
}

func TestJWTMintVerifyRoundTrip(t *testing.T) {
	s := testSigner(t)
	claims := map[string]any{"iss": "http://x/cognito/p1", "sub": "u-1", "token_use": "access", "username": "alice", "_pool": "p1", "exp": float64(4102444800)}
	tok, err := s.mint(claims)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := verifyRS256(tok, s)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got["username"] != "alice" || got["token_use"] != "access" {
		t.Errorf("round-trip claims wrong: %v", got)
	}
	// a token signed by a DIFFERENT key must NOT verify (the whole point of JWKS)
	other := testSigner(t)
	if _, err := verifyRS256(tok, other); err == nil {
		t.Error("a token signed by a different key must fail verification")
	}
	// a tampered payload must NOT verify
	if _, err := verifyRS256(tok[:len(tok)-4]+"AAAA", s); err == nil {
		t.Error("a tampered signature must fail verification")
	}
}

func TestJWTExpiredRejected(t *testing.T) {
	s := testSigner(t)
	tok, _ := s.mint(map[string]any{"token_use": "access", "exp": float64(1000)}) // long past
	if _, err := verifyRS256(tok, s); err == nil {
		t.Error("an expired token must be rejected")
	}
}

func TestJWKSShape(t *testing.T) {
	s := testSigner(t)
	jwks := s.jwks()
	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
	k := keys[0].(map[string]any)
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["kid"] != "test-kid" || k["use"] != "sig" {
		t.Errorf("jwks key shape wrong: %v", k)
	}
	if k["n"] == "" || k["e"] == "" {
		t.Error("jwks key missing modulus/exponent")
	}
}

func TestPasswordPolicyEnforce(t *testing.T) {
	p := defaultPasswordPolicy() // 8, upper+lower+number+symbol
	if err := p.enforce("Aa1!aaaa"); err != nil {
		t.Errorf("a compliant password should pass: %v", err)
	}
	for _, bad := range []string{"alllowercase1!", "ALLUPPER1!", "NoNumbers!!", "NoSymbol11a"} {
		if err := p.enforce(bad); err == nil {
			t.Errorf("password %q should fail the default policy", bad)
		}
	}
	if err := p.enforce("Aa1!aa"); err == nil {
		t.Error("a 6-char password should fail the min-length 8")
	}
	// a relaxed policy
	relaxed := passwordPolicy{MinLength: 4}
	if err := relaxed.enforce("abcd"); err != nil {
		t.Errorf("relaxed policy should accept 'abcd': %v", err)
	}
}

func TestParsePasswordPolicy(t *testing.T) {
	body := map[string]any{"Policies": map[string]any{"PasswordPolicy": map[string]any{
		"MinimumLength": float64(12), "RequireSymbols": false, "RequireUppercase": true,
	}}}
	p := parsePasswordPolicy(body)
	if p.MinLength != 12 || p.RequireSymbol != false || p.RequireUpper != true {
		t.Errorf("parsed policy wrong: %+v", p)
	}
	// defaults when absent
	d := parsePasswordPolicy(map[string]any{})
	if d.MinLength != 8 || !d.RequireNumber {
		t.Errorf("default policy wrong: %+v", d)
	}
}

func TestPoolIssuerFromPath(t *testing.T) {
	id, rest, ok := poolIssuerFromPath("/cognito/us-east-1_abc/.well-known/jwks.json")
	if !ok || id != "us-east-1_abc" || rest != "/.well-known/jwks.json" {
		t.Errorf("poolIssuerFromPath = (%q,%q,%v)", id, rest, ok)
	}
	if _, _, ok := poolIssuerFromPath("/v2/apis"); ok {
		t.Error("/v2/apis is not a cognito well-known path")
	}
}

func TestCognitoOpClassification(t *testing.T) {
	for _, op := range []string{"SignUp", "InitiateAuth", "GetUser", "GlobalSignOut", "ConfirmSignUp"} {
		if !cognitoPublicOp(op) {
			t.Errorf("%s should be a public op", op)
		}
	}
	for _, op := range []string{"CreateUserPool", "AdminCreateUser", "DeleteUserPool", "AdminSetUserPassword"} {
		if !cognitoAdminOp(op) {
			t.Errorf("%s should be an admin op", op)
		}
	}
	if cognitoAdminOp("SignUp") {
		t.Error("SignUp must not be an admin op")
	}
}
