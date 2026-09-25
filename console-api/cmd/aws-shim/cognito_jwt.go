// Cognito token machinery for the aws-shim (polyhedron#171): the RSA signing key, the JWKS + OIDC
// discovery documents a pool exposes, RS256 JWT minting, and the password policy. The token contract is the
// heart of Cognito — InitiateAuth must return REAL, signed, JWKS-verifiable JWTs, or every downstream
// verification (apps, the API Gateway JWT authorizer #169) is theater. These are hand-built RS256 JWTs so
// the JWKS the shim serves genuinely verifies them.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"unicode"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const cognitoSigningSecret = "cognito-signing-key"
const cognitoKID = "cognito-key-1"

// cognitoSigner holds the shim's RSA signing key. One key signs every pool's tokens; each pool's JWKS
// serves this key, and tokens carry the pool's issuer, so a verifier fetches the pool's JWKS and validates.
type cognitoSigner struct {
	priv *rsa.PrivateKey
	kid  string
}

// loadOrCreateSigner reads the RSA key from a Secret (so tokens survive a restart), creating it on first
// use. nil (with a logged reason) if it cannot be established — SecureString-style honest degradation.
func loadOrCreateSigner(ctx context.Context, cs kubernetes.Interface, ns string) (*cognitoSigner, error) {
	sec, err := cs.CoreV1().Secrets(ns).Get(ctx, cognitoSigningSecret, metav1.GetOptions{})
	if err == nil {
		if pemBytes, ok := sec.Data["private.pem"]; ok {
			block, _ := pem.Decode(pemBytes)
			if block != nil {
				if key, perr := x509.ParsePKCS1PrivateKey(block.Bytes); perr == nil {
					return &cognitoSigner{priv: key, kid: cognitoKID}, nil
				}
			}
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}
	// create
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_, err = cs.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: cognitoSigningSecret, Namespace: ns,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "open-infra-aws-shim"}},
		Data: map[string][]byte{"private.pem": pemBytes},
	}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		// raced with another replica; re-read
		if sec, gerr := cs.CoreV1().Secrets(ns).Get(ctx, cognitoSigningSecret, metav1.GetOptions{}); gerr == nil {
			if block, _ := pem.Decode(sec.Data["private.pem"]); block != nil {
				if k, perr := x509.ParsePKCS1PrivateKey(block.Bytes); perr == nil {
					return &cognitoSigner{priv: k, kid: cognitoKID}, nil
				}
			}
		}
	} else if err != nil {
		return nil, err
	}
	return &cognitoSigner{priv: key, kid: cognitoKID}, nil
}

var errBadToken = errors.New("invalid token")

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// rsaVerify checks an RS256 signature against the signer's public key.
func rsaVerify(s *cognitoSigner, h [32]byte, sig []byte) error {
	pub := s.priv.Public().(*rsa.PublicKey)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
}

// jwks returns the pool's JSON Web Key Set (the public half of the signing key).
func (s *cognitoSigner) jwks() map[string]any {
	pub := s.priv.Public().(*rsa.PublicKey)
	n := b64url(pub.N.Bytes())
	e := b64url(big.NewInt(int64(pub.E)).Bytes())
	return map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.kid, "n": n, "e": e,
	}}}
}

// discovery returns the minimal OIDC discovery document for a pool issuer, enough for go-oidc (the API
// Gateway JWT authorizer #169) to discover the JWKS and verify.
func discovery(issuer string) map[string]any {
	return map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"response_types_supported":              []any{"code", "token", "id_token"},
		"subject_types_supported":               []any{"public"},
		"id_token_signing_alg_values_supported": []any{"RS256"},
	}
}

// mint builds a signed RS256 JWT from the claims.
func (s *cognitoSigner) mint(claims map[string]any) (string, error) {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": s.kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	signing := b64url(hb) + "." + b64url(cb)
	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.priv, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64url(sig), nil
}

// --- password policy ---

type passwordPolicy struct {
	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireNumber bool
	RequireSymbol bool
}

func defaultPasswordPolicy() passwordPolicy {
	// Cognito's defaults: 8 chars, upper+lower+number+symbol required.
	return passwordPolicy{MinLength: 8, RequireUpper: true, RequireLower: true, RequireNumber: true, RequireSymbol: true}
}

// enforce returns an error describing the first unmet requirement, or nil. A configured policy that is not
// actually enforced would be an IA-5 false green, so this is the single checkpoint SignUp/SetPassword use.
func (p passwordPolicy) enforce(pw string) error {
	if len(pw) < p.MinLength {
		return errors.New("password does not satisfy the minimum length of " + itoa(p.MinLength))
	}
	var hasUpper, hasLower, hasNumber, hasSymbol bool
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsNumber(r):
			hasNumber = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	if p.RequireUpper && !hasUpper {
		return errors.New("password must contain an uppercase letter")
	}
	if p.RequireLower && !hasLower {
		return errors.New("password must contain a lowercase letter")
	}
	if p.RequireNumber && !hasNumber {
		return errors.New("password must contain a number")
	}
	if p.RequireSymbol && !hasSymbol {
		return errors.New("password must contain a symbol")
	}
	return nil
}

// parsePasswordPolicy reads a CreateUserPool Policies.PasswordPolicy body into a passwordPolicy (Cognito
// defaults for any field not present).
func parsePasswordPolicy(body map[string]any) passwordPolicy {
	p := defaultPasswordPolicy()
	pol, _ := body["Policies"].(map[string]any)
	pw, _ := pol["PasswordPolicy"].(map[string]any)
	if pw == nil {
		return p
	}
	if v, ok := pw["MinimumLength"]; ok {
		p.MinLength = toInt(v)
	}
	if v, ok := pw["RequireUppercase"].(bool); ok {
		p.RequireUpper = v
	}
	if v, ok := pw["RequireLowercase"].(bool); ok {
		p.RequireLower = v
	}
	if v, ok := pw["RequireNumbers"].(bool); ok {
		p.RequireNumber = v
	}
	if v, ok := pw["RequireSymbols"].(bool); ok {
		p.RequireSymbol = v
	}
	return p
}

func (p passwordPolicy) toJSON() map[string]any {
	return map[string]any{"PasswordPolicy": map[string]any{
		"MinimumLength": p.MinLength, "RequireUppercase": p.RequireUpper, "RequireLowercase": p.RequireLower,
		"RequireNumbers": p.RequireNumber, "RequireSymbols": p.RequireSymbol,
	}}
}

// poolIssuerFromPath extracts the pool id from a /cognito/<poolId>/.well-known/... data-plane path.
func poolIssuerFromPath(path string) (poolID, rest string, ok bool) {
	const prefix = "/cognito/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	r := strings.TrimPrefix(path, prefix)
	i := strings.IndexByte(r, '/')
	if i < 0 {
		return r, "", r != ""
	}
	return r[:i], r[i:], r[:i] != ""
}
