package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func newTestECRSigner(t *testing.T) *ecrTokenSigner {
	t.Helper()
	s, _, err := newECRTokenSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

func TestECRToken_CallerRoundTrip(t *testing.T) {
	s := newTestECRSigner(t)
	tok, err := s.mintCaller(ecrCaller{Sub: "alice", Groups: []string{"openinfra:powerusers"}}, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := s.verifyCaller(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Sub != "alice" || len(got.Groups) != 1 || got.Groups[0] != "openinfra:powerusers" {
		t.Fatalf("identity mismatch: %+v", got)
	}
	// A tampered token is rejected.
	if _, err := s.verifyCaller(tok + "x"); err == nil {
		t.Fatal("tampered token must be rejected")
	}
	// An expired token is rejected.
	expTok, _ := s.mintCaller(ecrCaller{Sub: "bob"}, -time.Second)
	if _, err := s.verifyCaller(expTok); err == nil {
		t.Fatal("expired token must be rejected")
	}
	// A different signer must not validate it.
	other := newTestECRSigner(t)
	if _, err := other.verifyCaller(tok); err == nil {
		t.Fatal("a token from another signer must be rejected")
	}
}

func TestECRToken_RegistryTokenShape(t *testing.T) {
	s := newTestECRSigner(t)
	access := []ecrAccess{{Type: "repository", Name: "team-a/app", Actions: []string{"pull", "push"}}}
	tok, err := s.mintRegistry("user::alice", "openinfra-ecr", "ecr-registry", access, 5*time.Minute)
	if err != nil {
		t.Fatalf("mint registry: %v", err)
	}
	parts := strings.SplitN(tok, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("malformed registry token")
	}
	// Header carries x5c = the signer's cert (so the registry can trust it against rootcertbundle).
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr struct {
		Alg string   `json:"alg"`
		X5c []string `json:"x5c"`
	}
	_ = json.Unmarshal(hb, &hdr)
	if hdr.Alg != "RS256" || len(hdr.X5c) != 1 {
		t.Fatalf("header should be RS256 with one x5c cert: %s", string(hb))
	}
	if certB64 := base64.StdEncoding.EncodeToString(s.certDER); hdr.X5c[0] != certB64 {
		t.Fatalf("x5c cert does not match the signer cert")
	}
	// Claims carry the granted per-repo access.
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Iss    string      `json:"iss"`
		Aud    string      `json:"aud"`
		Sub    string      `json:"sub"`
		Access []ecrAccess `json:"access"`
	}
	if err := json.Unmarshal(pb, &claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	if claims.Iss != "openinfra-ecr" || claims.Aud != "ecr-registry" || claims.Sub != "user::alice" {
		t.Fatalf("iss/aud/sub wrong: %+v", claims)
	}
	if len(claims.Access) != 1 || claims.Access[0].Name != "team-a/app" ||
		len(claims.Access[0].Actions) != 2 {
		t.Fatalf("access claim wrong: %+v", claims.Access)
	}
}
