// The instance identity key in OpenBao Transit (#359).
//
// With INSTANCE_IDENTITY_TRANSIT_KEY set to <mount>/<key> (openinfra/transit/instance-identity), documents
// are signed by an RSA Transit key that OpenBao holds and never exports, as AWS signs instance identity
// documents with a key no instance and no operator holds. The shim logs in with its own ServiceAccount token
// (role INSTANCE_IDENTITY_VAULT_ROLE, default aws-shim-identity), whose policy may sign with that one key and
// read its public half, and nothing else. A key that can be exported or backed up in plaintext is refused.
//
// Each key version has a self-signed certificate made from the version alone (its serial from the public key,
// its validity from the version's creation time; PKCS#1 v1.5 signatures are deterministic), so every replica
// and every restart serves the same certificate and none is stored.
//
// Rotation is the Transit key's rotation (`bao write -f openinfra/transit/keys/instance-identity/rotate`): the
// new version signs at once, and each replaced version keeps verifying for one document lifetime after its
// successor was created, which covers every document it signed. Nothing else is done by hand.
//
// A key left in the Secret the shim used before (instance-identity-signing-key) is trusted to verify, never to
// sign, until the Secret is deleted, so documents it signed before the switch stay valid for their hour.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/vaultclient"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// identityTransit signs with one Transit key.
type identityTransit struct {
	v          *vaultTransit // logs in with the identity role, not KMS's
	mount, key string

	mu    sync.Mutex
	certs map[int]*x509.Certificate // by key version, made once
}

// newIdentityTransit is the Transit key spec names (<mount>/<key>), reached at addr with role.
func newIdentityTransit(spec, addr, role, tokenPath string) (*identityTransit, error) {
	spec = strings.Trim(spec, "/")
	i := strings.LastIndexByte(spec, '/')
	if i <= 0 || i == len(spec)-1 {
		return nil, fmt.Errorf("INSTANCE_IDENTITY_TRANSIT_KEY %q is not <mount>/<key>", spec)
	}
	if addr == "" {
		return nil, errors.New("INSTANCE_IDENTITY_TRANSIT_KEY is set but VAULT_ADDR is not")
	}
	return &identityTransit{
		v:     &vaultTransit{addr: addr, role: role, tokenPath: tokenPath, hc: vaultclient.HTTPClient(15 * time.Second)},
		mount: spec[:i], key: spec[i+1:], certs: map[int]*x509.Certificate{},
	}, nil
}

func (t *identityTransit) String() string { return t.mount + "/" + t.key }

// transitKeyVersion is one version's public half.
type transitKeyVersion struct {
	version int
	pub     *rsa.PublicKey
	created time.Time
}

// versions reads the key's versions, newest first. The key must be RSA and must never leave OpenBao.
func (t *identityTransit) versions(ctx context.Context) ([]transitKeyVersion, error) {
	out, err := t.v.call(ctx, http.MethodGet, t.mount+"/keys/"+t.key, nil)
	if err != nil {
		return nil, err
	}
	data, _ := out["data"].(map[string]any)
	if typ, _ := data["type"].(string); !strings.HasPrefix(typ, "rsa-") {
		return nil, fmt.Errorf("the Transit key %s is %q, not an RSA key", t, typ)
	}
	if exp, _ := data["exportable"].(bool); exp {
		return nil, fmt.Errorf("the Transit key %s is exportable: an instance identity key must never leave OpenBao", t)
	}
	if b, _ := data["allow_plaintext_backup"].(bool); b {
		return nil, fmt.Errorf("the Transit key %s allows a plaintext backup: an instance identity key must never leave OpenBao", t)
	}
	keys, _ := data["keys"].(map[string]any)
	var vs []transitKeyVersion
	for name, raw := range keys {
		n, err := strconv.Atoi(name)
		if err != nil || n < 1 {
			continue
		}
		m, _ := raw.(map[string]any)
		ps, _ := m["public_key"].(string)
		b, _ := pem.Decode([]byte(ps))
		if b == nil {
			return nil, fmt.Errorf("the Transit key %s version %d has no public key", t, n)
		}
		pk, err := x509.ParsePKIXPublicKey(b.Bytes)
		rp, ok := pk.(*rsa.PublicKey)
		if err != nil || !ok || rp.N.BitLen() < 2048 {
			return nil, fmt.Errorf("the Transit key %s version %d is not an RSA key of at least 2048 bits", t, n)
		}
		ct, _ := m["creation_time"].(string)
		created, err := time.Parse(time.RFC3339Nano, ct)
		if err != nil {
			return nil, fmt.Errorf("the Transit key %s version %d has no creation time", t, n)
		}
		vs = append(vs, transitKeyVersion{version: n, pub: rp, created: created.UTC()})
	}
	if len(vs) == 0 {
		return nil, fmt.Errorf("the Transit key %s has no versions", t)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].version > vs[j].version })
	return vs, nil
}

// signDigest is RSA PKCS#1 v1.5 over a SHA-256 digest, by that version of the key.
func (t *identityTransit) signDigest(ctx context.Context, version int, digest []byte) ([]byte, error) {
	out, err := t.v.call(ctx, http.MethodPost, t.mount+"/sign/"+t.key+"/sha2-256", map[string]any{
		"input": base64.StdEncoding.EncodeToString(digest), "prehashed": true,
		"signature_algorithm": "pkcs1v15", "key_version": version,
	})
	if err != nil {
		return nil, err
	}
	// <prefix>:v<version>:<base64>, the prefix being "vault" (OpenBao keeps Vault's).
	parts := strings.SplitN(dataString(out, "signature"), ":", 3)
	if len(parts) != 3 || parts[1] != "v"+strconv.Itoa(version) {
		return nil, fmt.Errorf("the Transit key %s did not sign with version %d", t, version)
	}
	return base64.StdEncoding.DecodeString(parts[2])
}

// certificate is a version's self-signed certificate, made from the version alone (identityCertTemplate),
// signed by it.
func (t *identityTransit) certificate(ctx context.Context, v transitKeyVersion) (*x509.Certificate, error) {
	t.mu.Lock()
	c := t.certs[v.version]
	t.mu.Unlock()
	if c != nil {
		if pub, ok := c.PublicKey.(*rsa.PublicKey); ok && pub.Equal(v.pub) {
			return c, nil
		}
	}
	tmpl := identityCertTemplate(v.pub, v.created)
	signer := digestSigner{ctx: ctx, pub: v.pub, sign: func(ctx context.Context, d []byte) ([]byte, error) {
		return t.signDigest(ctx, v.version, d)
	}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, v.pub, signer)
	if err != nil {
		return nil, fmt.Errorf("the certificate of Transit key %s version %d: %w", t, v.version, err)
	}
	if c, err = x509.ParseCertificate(der); err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.certs[v.version] = c
	t.mu.Unlock()
	return c, nil
}

// identityCertTemplate is the certificate of a key version: its serial from the public key, valid from an
// hour before the version was created for ten years. Nothing in it is random.
func identityCertTemplate(pub *rsa.PublicKey, created time.Time) *x509.Certificate {
	h := sha256.Sum256(x509.MarshalPKCS1PublicKey(pub))
	serial := new(big.Int).SetBytes(h[:16])
	serial.SetBit(serial, 127, 0) // positive in 16 bytes,
	serial.SetBit(serial, 126, 1) // and never zero
	created = created.UTC().Truncate(time.Second)
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"open-infra"}, CommonName: "open-infra instance identity"},
		NotBefore:    created.Add(-time.Hour),
		NotAfter:     created.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}

// digestSigner is a crypto.Signer whose key is elsewhere: RSA PKCS#1 v1.5 with SHA-256 only.
type digestSigner struct {
	ctx  context.Context
	pub  crypto.PublicKey
	sign func(ctx context.Context, digest []byte) ([]byte, error)
}

func (d digestSigner) Public() crypto.PublicKey { return d.pub }

func (d digestSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, pss := opts.(*rsa.PSSOptions); pss || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("the instance identity key signs RSA PKCS#1 v1.5 with SHA-256 only")
	}
	return d.sign(d.ctx, digest)
}

// loadTransit is the key material with the key in Transit: the latest version signs; it and every version
// replaced less than a document's lifetime ago verify, with their certificates; then the certificates left in
// the old Secret, which verify only.
func (s *identitySigner) loadTransit(ctx context.Context) (*identityKeys, error) {
	vs, err := s.transit.versions(ctx)
	if err != nil {
		return nil, err
	}
	now := s.clock()
	keep := vs[:1]
	for i := 1; i < len(vs) && now.Sub(vs[i-1].created) < s.ttl+identityClockSkew; i++ {
		keep = vs[:i+1] // vs[i] was replaced when vs[i-1] was made: what it signed is still unexpired
	}
	k := &identityKeys{}
	for _, v := range keep {
		c, err := s.transit.certificate(ctx, v)
		if err != nil {
			return nil, err
		}
		if k.cert == nil {
			k.cert = c
		}
		k.pubs = append(k.pubs, v.pub)
		k.certPEM = append(k.certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	latest := vs[0].version
	k.sign = func(ctx context.Context, digest []byte) ([]byte, error) {
		return s.transit.signDigest(ctx, latest, digest)
	}

	sec, err := s.cs.CoreV1().Secrets(s.ns).Get(ctx, s.name, metav1.GetOptions{})
	switch {
	case err == nil:
		raw := append(append(append([]byte{}, sec.Data[identityCertFile]...), '\n'), sec.Data[identityRetiredFile]...)
		certs, _ := parseCertsPEM(raw)
		for _, c := range certs {
			if rp, ok := c.PublicKey.(*rsa.PublicKey); ok {
				k.pubs = append(k.pubs, rp)
				k.certPEM = append(k.certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
			}
		}
		if len(certs) > 0 && sec.ResourceVersion != s.rv {
			s.rv = sec.ResourceVersion
			s.logger.Warn("instance identity: documents signed with the key in the Secret still verify (it no longer signs); delete the Secret an hour after the switch",
				"secret", s.ns+"/"+s.name, "transit", s.transit.String())
		}
	case !apierrors.IsNotFound(err):
		s.logger.Warn("instance identity: cannot read the previous key's Secret; its documents do not verify", "secret", s.ns+"/"+s.name, "error", err.Error())
	}
	return k, nil
}
