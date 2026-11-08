// The shim's signing keys in OpenBao Transit (#359): the instance identity key, the Cognito user pools'
// token key and the ECR token key, as AWS signs each with a key no customer and no operator holds.
//
// Each is an RSA Transit key that OpenBao generated and never exports (one that is exportable, or allows a
// plaintext backup, is refused). The shim signs with it — RSA PKCS#1 v1.5 over a SHA-256 digest, pinned to
// the version whose public half it publishes — through its own role, whose policy may sign with these keys
// and read their public halves, nothing else.
//
// Rotation is the key's Transit rotation: the new version signs within a minute, and each replaced version
// keeps verifying for the longest time a signature by it is relied on (lifetime) after its successor was
// made, which covers everything it signed. Where a key has certificates (instance identity, ECR), each
// version's is made from the version alone — serial from its public key, validity from its creation time —
// so every replica serves the same bytes and none is stored.
//
// A key the shim kept in a Secret before is retired, not abandoned: its public halves are recorded in a
// ConfigMap (verifying until lifetime has passed), and the Secret is deleted once the record is
// retireGrace old, so a replica still running the previous version (which reads the Secret) is gone first.
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
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/vaultclient"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// signingKeyReload is how often the key's versions are read again (a rotation applies within it).
	signingKeyReload = time.Minute
	// retireGrace is how long a retired key's Secret stays after its public halves are recorded.
	retireGrace = 10 * time.Minute
	// retiredKeysFile is the ConfigMap key holding a retired key's public halves.
	retiredKeysFile = "retired.json"
)

// transitRSAKey is one RSA Transit key.
type transitRSAKey struct {
	v          *vaultTransit // logs in with the shim's signing role, not KMS's
	mount, key string

	mu    sync.Mutex
	certs map[int]*x509.Certificate // by key version, made once
}

// newTransitRSAKey is the Transit key spec names (<mount>/<key>), reached at addr with role.
func newTransitRSAKey(spec, addr, role, tokenPath string) (*transitRSAKey, error) {
	spec = strings.Trim(spec, "/")
	i := strings.LastIndexByte(spec, '/')
	if i <= 0 || i == len(spec)-1 {
		return nil, fmt.Errorf("the Transit key %q is not <mount>/<key>", spec)
	}
	if addr == "" {
		return nil, fmt.Errorf("the Transit key %s is named but VAULT_ADDR is not set", spec)
	}
	return &transitRSAKey{
		v:     &vaultTransit{addr: addr, role: role, tokenPath: tokenPath, hc: vaultclient.HTTPClient(15 * time.Second)},
		mount: spec[:i], key: spec[i+1:], certs: map[int]*x509.Certificate{},
	}, nil
}

func (t *transitRSAKey) String() string { return t.mount + "/" + t.key }

// transitKeyVersion is one version's public half.
type transitKeyVersion struct {
	version int
	pub     *rsa.PublicKey
	created time.Time
}

// versions reads the key's versions, newest first. The key must be RSA and must never leave OpenBao.
func (t *transitRSAKey) versions(ctx context.Context) ([]transitKeyVersion, error) {
	out, err := t.v.call(ctx, http.MethodGet, t.mount+"/keys/"+t.key, nil)
	if err != nil {
		return nil, err
	}
	data, _ := out["data"].(map[string]any)
	if typ, _ := data["type"].(string); !strings.HasPrefix(typ, "rsa-") {
		return nil, fmt.Errorf("the Transit key %s is %q, not an RSA key", t, typ)
	}
	if exp, _ := data["exportable"].(bool); exp {
		return nil, fmt.Errorf("the Transit key %s is exportable: a signing key must never leave OpenBao", t)
	}
	if b, _ := data["allow_plaintext_backup"].(bool); b {
		return nil, fmt.Errorf("the Transit key %s allows a plaintext backup: a signing key must never leave OpenBao", t)
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
func (t *transitRSAKey) signDigest(ctx context.Context, version int, digest []byte) ([]byte, error) {
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

// certificate is a version's self-signed certificate from tmpl, signed by that version, made once.
func (t *transitRSAKey) certificate(ctx context.Context, v transitKeyVersion, tmpl func(*rsa.PublicKey, time.Time) *x509.Certificate) (*x509.Certificate, error) {
	t.mu.Lock()
	c := t.certs[v.version]
	t.mu.Unlock()
	if c != nil {
		if pub, ok := c.PublicKey.(*rsa.PublicKey); ok && pub.Equal(v.pub) {
			return c, nil
		}
	}
	tm := tmpl(v.pub, v.created)
	signer := digestSigner{ctx: ctx, pub: v.pub, sign: func(ctx context.Context, d []byte) ([]byte, error) {
		return t.signDigest(ctx, v.version, d)
	}}
	der, err := x509.CreateCertificate(rand.Reader, tm, tm, v.pub, signer)
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

// keySerial is a certificate serial made from a public key: positive, 16 bytes, never zero.
func keySerial(pub *rsa.PublicKey) *big.Int {
	h := sha256.Sum256(x509.MarshalPKCS1PublicKey(pub))
	serial := new(big.Int).SetBytes(h[:16])
	serial.SetBit(serial, 127, 0)
	serial.SetBit(serial, 126, 1)
	return serial
}

// jwkThumbprint is an RSA public key's RFC 7638 thumbprint (base64url SHA-256), used as its JWKS kid.
func jwkThumbprint(pub *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	h := sha256.Sum256([]byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`))
	return base64.RawURLEncoding.EncodeToString(h[:])
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
		return nil, errors.New("a signing key signs RSA PKCS#1 v1.5 with SHA-256 only")
	}
	return d.sign(d.ctx, digest)
}

// signingPub is a public key that verifies: its JWKS kid and, where the key has one, its certificate.
type signingPub struct {
	kid  string
	pub  *rsa.PublicKey
	cert *x509.Certificate
}

// signingKeys is a signing key at one moment: sign is the current version; verify holds the current
// version's public half first, then the replaced and retired ones still relied on.
type signingKeys struct {
	sign   func(ctx context.Context, digest []byte) ([]byte, error)
	verify []signingPub
}

// current is the public half that signs.
func (k *signingKeys) current() signingPub { return k.verify[0] }

// verifies reports whether sig is a signature over digest by any key that verifies.
func (k *signingKeys) verifies(digest, sig []byte) bool {
	for _, p := range k.verify {
		if rsa.VerifyPKCS1v15(p.pub, crypto.SHA256, digest, sig) == nil {
			return true
		}
	}
	return false
}

// certsPEM is the certificates of the keys that verify, current first.
func (k *signingKeys) certsPEM() []byte {
	var out []byte
	for _, p := range k.verify {
		if p.cert != nil {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.cert.Raw})...)
		}
	}
	return out
}

// staticSigningKeys is a key held in memory (the Secret mode).
func staticSigningKeys(key *rsa.PrivateKey, kid string, cert *x509.Certificate) *signingKeys {
	return &signingKeys{
		sign: func(_ context.Context, digest []byte) ([]byte, error) {
			return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
		},
		verify: []signingPub{{kid: kid, pub: &key.PublicKey, cert: cert}},
	}
}

// transitSigning is a signing key in Transit, with the replaced and retired versions that still verify.
type transitSigning struct {
	key *transitRSAKey
	// lifetime is the longest a signature by the key is relied on after it is made.
	lifetime time.Duration
	// cert makes a version's certificate (nil: the key has none).
	cert func(*rsa.PublicKey, time.Time) *x509.Certificate
	// The key the shim kept in Secret legacySecret before: legacyPubs reads its public halves, which are
	// recorded in ConfigMap retiredCM before the Secret is deleted.
	legacySecret, retiredCM string
	legacyPubs              func(data map[string][]byte) []signingPub

	cs     kubernetes.Interface
	ns     string
	logger *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	cached  *signingKeys
	checked time.Time
}

func (t *transitSigning) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// keys is the key now: read again at most once a minute; a failed read keeps the loaded key.
func (t *transitSigning) keys(ctx context.Context) (*signingKeys, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.clock()
	if t.cached != nil && now.Sub(t.checked) < signingKeyReload {
		return t.cached, nil
	}
	k, err := t.load(ctx, now)
	if err != nil {
		if t.cached != nil {
			t.logger.Warn("signing key: cannot read the Transit key again; keeping the loaded one", "key", t.key.String(), "error", err.Error())
			t.checked = now
			return t.cached, nil
		}
		return nil, err
	}
	t.cached, t.checked = k, now
	return k, nil
}

func (t *transitSigning) load(ctx context.Context, now time.Time) (*signingKeys, error) {
	vs, err := t.key.versions(ctx)
	if err != nil {
		return nil, err
	}
	keep := vs[:1]
	for i := 1; i < len(vs) && now.Sub(vs[i-1].created) < t.lifetime+identityClockSkew; i++ {
		keep = vs[:i+1] // vs[i] was replaced when vs[i-1] was made: what it signed may still be relied on
	}
	k := &signingKeys{}
	for _, v := range keep {
		p := signingPub{kid: jwkThumbprint(v.pub), pub: v.pub}
		if t.cert != nil {
			if p.cert, err = t.key.certificate(ctx, v, t.cert); err != nil {
				return nil, err
			}
		}
		k.verify = append(k.verify, p)
	}
	latest := vs[0].version
	k.sign = func(ctx context.Context, digest []byte) ([]byte, error) { return t.key.signDigest(ctx, latest, digest) }
	k.verify = append(k.verify, t.retired(ctx, now)...)
	return k, nil
}

// retiredRecord is ConfigMap retiredCM's content: a retired key's public halves and until when they verify.
type retiredRecord struct {
	RecordedAt  time.Time    `json:"recordedAt"`
	VerifyUntil time.Time    `json:"verifyUntil"`
	Keys        []retiredPub `json:"keys"`
}

type retiredPub struct {
	Kid         string `json:"kid,omitempty"`
	PublicKey   string `json:"publicKey"`
	Certificate string `json:"certificate,omitempty"`
}

// retired retires the key left in the legacy Secret, if any — its public halves recorded, then (retireGrace
// later, once every one of them is recorded) the Secret deleted — and returns the recorded public halves
// while they still verify. Failures are logged: they cost verification of what the old key signed, never
// signing.
func (t *transitSigning) retired(ctx context.Context, now time.Time) []signingPub {
	if t.legacySecret == "" || t.cs == nil {
		return nil
	}
	var rec *retiredRecord
	cm, err := t.cs.CoreV1().ConfigMaps(t.ns).Get(ctx, t.retiredCM, metav1.GetOptions{})
	switch {
	case err == nil:
		var r retiredRecord
		if jerr := json.Unmarshal([]byte(cm.Data[retiredKeysFile]), &r); jerr == nil {
			rec = &r
		} else {
			t.logger.Warn("signing key: the retired key's record is unreadable", "configmap", t.ns+"/"+t.retiredCM, "error", jerr.Error())
		}
	case !apierrors.IsNotFound(err):
		t.logger.Warn("signing key: cannot read the retired key's record", "configmap", t.ns+"/"+t.retiredCM, "error", err.Error())
		return nil
	}

	sec, err := t.cs.CoreV1().Secrets(t.ns).Get(ctx, t.legacySecret, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.logger.Warn("signing key: cannot read the previous key's Secret", "secret", t.ns+"/"+t.legacySecret, "error", err.Error())
	}
	if err == nil {
		pubs := t.legacyPubs(sec.Data)
		if rec == nil && len(pubs) > 0 {
			r := retiredRecord{RecordedAt: now, VerifyUntil: now.Add(t.lifetime + retireGrace + identityClockSkew)}
			for _, p := range pubs {
				der, _ := x509.MarshalPKIXPublicKey(p.pub)
				rp := retiredPub{Kid: p.kid, PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
				if p.cert != nil {
					rp.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.cert.Raw}))
				}
				r.Keys = append(r.Keys, rp)
			}
			body, _ := json.Marshal(r)
			_, cerr := t.cs.CoreV1().ConfigMaps(t.ns).Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: t.retiredCM, Namespace: t.ns,
					Labels: map[string]string{"app.kubernetes.io/managed-by": "aws-shim"},
					Annotations: map[string]string{"openinfra.dev/purpose": "The public halves of a signing key that moved to OpenBao Transit " +
						t.key.String() + ": what it signed verifies until verifyUntil. Public data."}},
				Data: map[string]string{retiredKeysFile: string(body)},
			}, metav1.CreateOptions{})
			switch {
			case cerr == nil:
				rec = &r
				t.logger.Info("signing key: the previous key's public halves are recorded; its Secret goes once no replica can still read it",
					"secret", t.ns+"/"+t.legacySecret, "configmap", t.ns+"/"+t.retiredCM, "verifyUntil", r.VerifyUntil.Format(time.RFC3339))
			case apierrors.IsAlreadyExists(cerr):
				return nil // another replica recorded it: read on the next load
			default:
				t.logger.Warn("signing key: cannot record the previous key's public halves; its Secret stays", "error", cerr.Error())
				return nil
			}
		}
		if rec != nil && now.Sub(rec.RecordedAt) >= retireGrace && recordHolds(rec, pubs) {
			if derr := t.cs.CoreV1().Secrets(t.ns).Delete(ctx, t.legacySecret, metav1.DeleteOptions{}); derr == nil || apierrors.IsNotFound(derr) {
				t.logger.Info("signing key: deleted the previous key's Secret; its public halves verify from the record",
					"secret", t.ns+"/"+t.legacySecret, "transit", t.key.String())
			} else {
				t.logger.Warn("signing key: cannot delete the previous key's Secret", "secret", t.ns+"/"+t.legacySecret, "error", derr.Error())
			}
		} else if rec != nil && !recordHolds(rec, pubs) {
			t.logger.Warn("signing key: the previous key's Secret holds a key its record does not; the Secret stays", "secret", t.ns+"/"+t.legacySecret)
		}
	}
	if rec == nil || !now.Before(rec.VerifyUntil) {
		return nil
	}
	var out []signingPub
	for _, rp := range rec.Keys {
		b, _ := pem.Decode([]byte(rp.PublicKey))
		if b == nil {
			continue
		}
		pk, err := x509.ParsePKIXPublicKey(b.Bytes)
		pub, ok := pk.(*rsa.PublicKey)
		if err != nil || !ok {
			continue
		}
		p := signingPub{kid: rp.Kid, pub: pub}
		if cb, _ := pem.Decode([]byte(rp.Certificate)); cb != nil {
			if c, err := x509.ParseCertificate(cb.Bytes); err == nil {
				p.cert = c
			}
		}
		out = append(out, p)
	}
	return out
}

// recordHolds reports whether every key in pubs is in the record.
func recordHolds(rec *retiredRecord, pubs []signingPub) bool {
	have := map[string]bool{}
	for _, rp := range rec.Keys {
		if b, _ := pem.Decode([]byte(rp.PublicKey)); b != nil {
			have[string(b.Bytes)] = true
		}
	}
	for _, p := range pubs {
		der, _ := x509.MarshalPKIXPublicKey(p.pub)
		if !have[string(der)] {
			return false
		}
	}
	return true
}

// refreshSigningKey calls load every signingKeyReload, so a rotation is picked up, the registry's bundle
// republished and a previous key retired even when nothing signs for a while. Runs for the process's life.
func refreshSigningKey(logger *slog.Logger, key string, load func() error) {
	for {
		if err := load(); err != nil {
			logger.Warn("signing key: cannot read the Transit key", "key", key, "error", err.Error())
		}
		time.Sleep(signingKeyReload)
	}
}

// transitSigningFromEnv is the Transit signing key named by env (<mount>/<key>), or nil when it is unset.
// The role is the shim's signing role. A misconfigured key is an error: the caller signs nothing then.
func transitSigningFromEnv(env string, lifetime time.Duration, cs kubernetes.Interface, ns string, logger *slog.Logger) (*transitSigning, error) {
	spec := getenv(env, "")
	if spec == "" {
		return nil, nil
	}
	k, err := newTransitRSAKey(spec, getenv("VAULT_ADDR", ""), getenv("SIGNING_VAULT_ROLE", "aws-shim-identity"),
		getenv("STS_SA_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"))
	if err != nil {
		return nil, err
	}
	return &transitSigning{key: k, lifetime: lifetime, cs: cs, ns: ns, logger: logger}, nil
}
