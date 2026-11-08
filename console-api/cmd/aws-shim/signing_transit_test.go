package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func jwtHeader(t *testing.T, tok string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.SplitN(tok, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	_ = json.Unmarshal(b, &h)
	return h
}

// Cognito with its key in Transit: tokens carry the Transit version's thumbprint as kid and verify; the JWKS
// lists it and the retired key (under its old kid) so a refresh token the old key issued keeps working; the
// Secret is deleted once no replica of the previous version can still read it; OpenBao down, nothing is
// issued.
func TestCognitoTransit_SignsAndRetiresTheSecretKey(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	old, err := loadOrCreateSigner(ctx, cs, shimNS)
	if err != nil {
		t.Fatal(err)
	}
	far := float64(now.Add(60 * 24 * time.Hour).Unix())
	oldRefresh, err := old.mint(map[string]any{"token_use": "refresh", "exp": far})
	if err != nil {
		t.Fatal(err)
	}
	f, tr := fakeTransitKey(t, "cognito", now.Add(-time.Hour), cs, &now)
	s := newTransitCognitoSigner(tr)
	tok, err := s.mint(map[string]any{"token_use": "access", "exp": far})
	if err != nil {
		t.Fatal(err)
	}
	if kid := jwtHeader(t, tok)["kid"]; kid != jwkThumbprint(&f.keys[0].PublicKey) {
		t.Fatalf("kid %v, want the Transit version's thumbprint", kid)
	}
	if _, err := verifyRS256(tok, s); err != nil {
		t.Fatalf("a token Transit signed: %v", err)
	}
	if _, err := verifyRS256(oldRefresh, s); err != nil {
		t.Fatalf("a refresh token the previous key issued keeps working: %v", err)
	}
	keys := s.jwks()["keys"].([]any)
	if len(keys) != 2 || keys[1].(map[string]any)["kid"] != cognitoKID {
		t.Fatalf("JWKS: %v", keys)
	}
	now = now.Add(retireGrace + time.Minute)
	if _, err := verifyRS256(oldRefresh, s); err != nil {
		t.Fatalf("after the Secret goes, the old refresh token verifies from the record: %v", err)
	}
	if _, err := cs.CoreV1().Secrets(shimNS).Get(ctx, cognitoSigningSecret, metav1.GetOptions{}); err == nil {
		t.Fatal("the Cognito key's Secret is deleted")
	}
	now = now.Add(cognitoRefreshTTL*time.Second + time.Hour)
	if _, err := verifyRS256(oldRefresh, s); err == nil {
		t.Fatal("past a refresh token's lifetime, the previous key no longer verifies")
	}
	if _, err := verifyRS256(tok, s); err != nil {
		t.Fatalf("the Transit key still verifies: %v", err)
	}
	f.down = true
	now = now.Add(2 * time.Minute)
	down := newTransitCognitoSigner(func() *transitSigning { _, t2 := fakeTransitKey(t, "cognito", now, cs, &now); return t2 }())
	down.transit.key.v.addr = "http://127.0.0.1:1" // unreachable
	if _, err := down.mint(map[string]any{}); err == nil {
		t.Fatal("with OpenBao unreachable, nothing is signed")
	}
}

// ECR with its key in Transit: registry tokens carry the Transit version's certificate (a self-signed CA,
// the same on every replica); the bundle published for the registry holds it and the retired key's
// certificate; a caller credential the old key issued keeps working for its lifetime.
func TestECRTransit_SignsPublishesAndRetiresTheSecretKey(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	old, err := loadOrCreateECRTokenSigner(ctx, cs, shimNS)
	if err != nil {
		t.Fatal(err)
	}
	oldCred, err := old.mintCaller(ecrCaller{Sub: "alice"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f, tr := fakeTransitKey(t, "ecr-token", now.Add(-time.Hour), cs, &now)
	s := newTransitECRSigner(tr)
	var published [][]byte
	s.publish = func(b []byte) error { published = append(published, b); return nil }
	tok, err := s.mintRegistry("user::alice", "openinfra-ecr", "ecr-registry", []ecrAccess{{Type: "repository", Name: "app", Actions: []string{"pull"}}}, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	x5c := jwtHeader(t, tok)["x5c"].([]any)
	der, _ := base64.StdEncoding.DecodeString(x5c[0].(string))
	c, err := x509.ParseCertificate(der)
	if err != nil || !c.IsCA || !c.PublicKey.(*rsa.PublicKey).Equal(&f.keys[0].PublicKey) || c.CheckSignatureFrom(c) != nil {
		t.Fatalf("x5c is the Transit version's self-signed CA certificate: %v", err)
	}
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(c.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], sig) != nil {
		t.Fatal("the registry token verifies under its x5c certificate")
	}
	if len(published) != 1 || strings.Count(string(published[0]), "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("published bundles: %d", len(published))
	}
	if got, err := s.verifyCaller(oldCred); err != nil || got.Sub != "alice" {
		t.Fatalf("a credential the previous key issued keeps working: %v", err)
	}
	// Another replica makes the same certificate.
	_, tr2 := fakeTransitKey(t, "ecr-token", now.Add(-time.Hour), cs, &now)
	tr2.key.v.addr = s.transit.key.v.addr
	first := func(b []byte) string { return strings.SplitAfter(string(b), "-----END CERTIFICATE-----\n")[0] }
	if b, err := newTransitECRSigner(tr2).bundle(); err != nil || first(b) != first(published[0]) || !strings.Contains(first(b), "BEGIN CERTIFICATE") {
		t.Fatalf("another replica's certificate differs: %v", err)
	}
	now = now.Add(retireGrace + time.Minute)
	if _, err := s.keys(); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Secrets(shimNS).Get(ctx, ecrTokenSigningSecret, metav1.GetOptions{}); err == nil {
		t.Fatal("the ECR key's Secret is deleted")
	}
	now = now.Add(ecrCredentialLifetime + time.Hour)
	if _, err := s.verifyCaller(oldCred); err == nil {
		t.Fatal("past a credential's lifetime, the previous key no longer verifies")
	}
	if _, err := s.keys(); err != nil {
		t.Fatal(err)
	}
	if last := published[len(published)-1]; strings.Count(string(last), "BEGIN CERTIFICATE") != 1 {
		t.Fatal("once the previous key retires, the bundle holds the Transit certificate alone")
	}
}
