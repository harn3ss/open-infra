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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeTransit is OpenBao's Transit for one RSA key: login, read the key, sign a prehashed digest.
type fakeTransit struct {
	t    *testing.T
	name string // the key's name under openinfra/transit (default instance-identity)
	sync.Mutex
	keys       []*rsa.PrivateKey
	created    []time.Time
	exportable bool
	down       bool
	role       string
	signedWith []int
}

func (f *fakeTransit) keyName() string {
	if f.name == "" {
		return "instance-identity"
	}
	return f.name
}

// fakeTransitKey serves a fake Transit with key name (one version, made at created) and returns it and a
// transitSigning for it, with the clock now.
func fakeTransitKey(t *testing.T, name string, created time.Time, cs *fake.Clientset, now *time.Time) (*fakeTransit, *transitSigning) {
	t.Helper()
	f := &fakeTransit{t: t, name: name}
	f.rotate(created)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := newTransitRSAKey("openinfra/transit/"+name, srv.URL, "aws-shim-identity", tok)
	if err != nil {
		t.Fatal(err)
	}
	return f, &transitSigning{key: k, cs: cs, ns: shimNS, logger: discardLogger(), now: func() time.Time { return *now }}
}

func (f *fakeTransit) rotate(at time.Time) {
	f.Lock()
	defer f.Unlock()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	f.keys, f.created = append(f.keys, k), append(f.created, at)
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.Lock()
	defer f.Unlock()
	if f.down {
		http.Error(w, `{"errors":["sealed"]}`, http.StatusServiceUnavailable)
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	reply := func(v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
	switch {
	case r.URL.Path == "/v1/auth/kubernetes/login":
		f.role, _ = in["role"].(string)
		reply(map[string]any{"auth": map[string]any{"client_token": "s.identity", "lease_duration": 1200}})
	case r.Header.Get("X-Vault-Token") != "s.identity":
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/openinfra/transit/keys/"+f.keyName():
		keys := map[string]any{}
		for i, k := range f.keys {
			der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
			keys[strconv.Itoa(i+1)] = map[string]any{"name": "rsa-2048", "creation_time": f.created[i].Format(time.RFC3339Nano),
				"public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
		}
		reply(map[string]any{"data": map[string]any{"type": "rsa-2048", "exportable": f.exportable, "allow_plaintext_backup": false,
			"latest_version": len(f.keys), "keys": keys}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/openinfra/transit/sign/"+f.keyName()+"/sha2-256":
		v, _ := in["key_version"].(float64)
		if in["prehashed"] != true || in["signature_algorithm"] != "pkcs1v15" || int(v) < 1 || int(v) > len(f.keys) {
			http.Error(w, `{"errors":["bad request"]}`, http.StatusBadRequest)
			return
		}
		digest, _ := base64.StdEncoding.DecodeString(in["input"].(string))
		sig, err := rsa.SignPKCS1v15(nil, f.keys[int(v)-1], crypto.SHA256, digest)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"errors":[%q]}`, err.Error()), http.StatusBadRequest)
			return
		}
		f.signedWith = append(f.signedWith, int(v))
		reply(map[string]any{"data": map[string]any{"signature": fmt.Sprintf("vault:v%d:%s", int(v), base64.StdEncoding.EncodeToString(sig)), "key_version": int(v)}})
	default:
		http.Error(w, `{"errors":["unsupported path"]}`, http.StatusNotFound)
	}
}

// transitIDSigner is a signer whose key is in a fake Transit (one version, made an hour before now).
func transitIDSigner(t *testing.T, cs *fake.Clientset, now *time.Time) (*identitySigner, *fakeTransit) {
	t.Helper()
	f := &fakeTransit{t: t}
	f.rotate(now.Add(-time.Hour))
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return transitSignerAt(t, cs, now, srv.URL), f
}

func transitSignerAt(t *testing.T, cs *fake.Clientset, now *time.Time, addr string) *identitySigner {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err := newTransitRSAKey("openinfra/transit/instance-identity", addr, "aws-shim-identity", tok)
	if err != nil {
		t.Fatal(err)
	}
	s := newIdentitySigner(cs, shimNS, time.Hour, discardLogger())
	s.now = func() time.Time { return *now }
	s.useTransit(&transitSigning{key: tr})
	return s
}

func firstCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	certs, err := parseCertsPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certs[0]
}

// The key in Transit signs; its signature verifies under the certificate served, as EC2's does under AWS's
// published certificate; the shim logs in with the identity role and makes no Secret.
func TestIdentityTransit_SignsWithTheKeyInOpenBao(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	s, f := transitIDSigner(t, cs, &now)
	ctx := context.Background()
	doc := []byte("{\n  \"instanceId\" : \"i-0123456789abcdef0\"\n}")
	sig, p7, err := s.sign(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !s.verify(ctx, doc, sig) || s.verify(ctx, []byte(`{"instanceId" : "i-0123456789abcdef1"}`), sig) {
		t.Fatal("a signature verifies for the bytes signed, and only those")
	}
	if f.role != "aws-shim-identity" {
		t.Fatalf("logged in as %q, want the identity role", f.role)
	}
	k, _ := s.current(ctx)
	c := firstCert(t, k.certPEM)
	raw, _ := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sig), ""))
	sum := sha256.Sum256(doc)
	if err := rsa.VerifyPKCS1v15(c.PublicKey.(*rsa.PublicKey), crypto.SHA256, sum[:], raw); err != nil {
		t.Fatalf("the signature does not verify under the served certificate: %v", err)
	}
	if !c.PublicKey.(*rsa.PublicKey).Equal(&f.keys[0].PublicKey) || c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) != nil {
		t.Fatal("the certificate is the Transit key's, signed by it")
	}
	if _, err := cs.CoreV1().Secrets(shimNS).Get(ctx, identityKeySecretName, metav1.GetOptions{}); err == nil {
		t.Fatal("with the key in Transit, no key Secret is made")
	}
	// The PKCS#7 verifies with openssl against the served certificate.
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl to verify the PKCS#7 with")
	}
	der, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(p7, "\n", ""))
	dir := t.TempDir()
	in, cert, out := filepath.Join(dir, "p7.der"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "doc")
	_ = os.WriteFile(in, der, 0o600)
	_ = os.WriteFile(cert, k.certPEM, 0o600)
	if b, err := exec.Command(ossl, "cms", "-verify", "-inform", "DER", "-in", in, "-noverify", "-nointern", "-certfile", cert, "-binary", "-out", out).CombinedOutput(); err != nil {
		t.Fatalf("openssl cms -verify: %v\n%s", err, b)
	}
	if got, _ := os.ReadFile(out); string(got) != string(doc) {
		t.Fatalf("openssl recovered %q", got)
	}
}

// Every replica and every restart serves the same certificate for a key version, and none is stored.
func TestIdentityTransit_CertificateIsTheSameEverywhere(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	f := &fakeTransit{t: t}
	f.rotate(now.Add(-time.Hour))
	srv := httptest.NewServer(f)
	defer srv.Close()
	ctx := context.Background()
	a := transitSignerAt(t, fake.NewSimpleClientset(), &now, srv.URL)
	b := transitSignerAt(t, fake.NewSimpleClientset(), &now, srv.URL)
	ka, err := a.current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := b.current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(ka.certPEM) != string(kb.certPEM) {
		t.Fatal("two replicas made different certificates for the same key version")
	}
	c := firstCert(t, ka.certPEM)
	if c.NotBefore.After(now.Add(-time.Hour)) || c.Subject.CommonName != "open-infra instance identity" || c.SerialNumber.Sign() <= 0 {
		t.Fatalf("certificate: %v %q %v", c.NotBefore, c.Subject.CommonName, c.SerialNumber)
	}
}

// Rotation is the Transit key's: the new version signs at once, and the replaced one verifies for one
// document lifetime after its successor was made, then no longer.
func TestIdentityTransit_Rotation(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	s, f := transitIDSigner(t, cs, &now)
	ctx := context.Background()
	old := []byte(`{"instanceId" : "i-0000000000000000a"}`)
	oldSig, _, err := s.sign(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	f.rotate(now)
	now = now.Add(2 * time.Minute) // the shim reads the key again
	doc := []byte(`{"instanceId" : "i-0000000000000000b"}`)
	if _, _, err := s.sign(ctx, doc); err != nil {
		t.Fatal(err)
	}
	if last := f.signedWith[len(f.signedWith)-1]; last != 2 {
		t.Fatalf("signed with version %d after the rotation, want 2", last)
	}
	k, _ := s.current(ctx)
	if n := strings.Count(string(k.certPEM), "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("certificates served after a rotation: %d, want the new one and the replaced one", n)
	}
	if !firstCert(t, k.certPEM).PublicKey.(*rsa.PublicKey).Equal(&f.keys[1].PublicKey) {
		t.Fatal("the new version's certificate comes first")
	}
	if !s.verify(ctx, old, oldSig) {
		t.Fatal("a document the replaced version signed verifies within its lifetime")
	}
	now = now.Add(time.Hour + identityClockSkew)
	if s.verify(ctx, old, oldSig) {
		t.Fatal("the replaced version verifies once everything it signed has expired")
	}
	if k, _ := s.current(ctx); strings.Count(string(k.certPEM), "BEGIN CERTIFICATE") != 1 {
		t.Fatal("the replaced version's certificate is no longer served")
	}
}

// A key that can leave OpenBao is refused: nothing is signed.
func TestIdentityTransit_RefusesAnExportableKey(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	s, f := transitIDSigner(t, fake.NewSimpleClientset(), &now)
	f.exportable = true
	if _, _, err := s.sign(context.Background(), []byte("{}")); err == nil || !strings.Contains(err.Error(), "exportable") {
		t.Fatalf("an exportable key: %v", err)
	}
}

// OpenBao unreachable, or the key misconfigured: nothing is signed, nothing verifies, and the shim never
// falls back to a key in a Secret.
func TestIdentityTransit_FailsClosed(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	s, f := transitIDSigner(t, cs, &now)
	f.down = true
	ctx := context.Background()
	if _, _, err := s.sign(ctx, []byte("{}")); err == nil {
		t.Fatal("signed with OpenBao down")
	}
	if s.verify(ctx, []byte("{}"), "AAAA") {
		t.Fatal("verified with OpenBao down")
	}
	if _, err := cs.CoreV1().Secrets(shimNS).Get(ctx, identityKeySecretName, metav1.GetOptions{}); err == nil {
		t.Fatal("made a key Secret with OpenBao down")
	}
	bad := newIdentitySigner(cs, shimNS, time.Hour, discardLogger())
	_, bad.transitErr = newTransitRSAKey("instance-identity", "https://openbao", "r", "/t")
	if bad.transitErr == nil {
		t.Fatal("a spec without a mount is refused")
	}
	if _, _, err := bad.sign(ctx, []byte("{}")); err == nil {
		t.Fatal("signed with a misconfigured key")
	}
	if _, err := cs.CoreV1().Secrets(shimNS).Get(ctx, identityKeySecretName, metav1.GetOptions{}); err == nil {
		t.Fatal("made a key Secret with a misconfigured Transit key")
	}
	if _, err := newTransitRSAKey("openinfra/transit/instance-identity", "", "r", "/t"); err == nil {
		t.Fatal("a Transit key without VAULT_ADDR is refused")
	}
}

// After the switch, the key in the Secret is retired: its public halves are recorded in a ConfigMap (public
// data only), the Secret is deleted once no replica of the previous version can still read it, documents it
// signed verify for their lifetime, and it never signs again.
func TestIdentityTransit_PreviousSecretKeyIsRetired(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	before := newIdentitySigner(cs, shimNS, time.Hour, discardLogger())
	before.now = func() time.Time { return now }
	doc := []byte(`{"instanceId" : "i-0000000000000000c"}`)
	oldSig, _, err := before.sign(ctx, doc) // makes the Secret
	if err != nil {
		t.Fatal(err)
	}
	s, f := transitIDSigner(t, cs, &now)
	if !s.verify(ctx, doc, oldSig) {
		t.Fatal("a document the previous key signed verifies after the switch")
	}
	cm, err := cs.CoreV1().ConfigMaps(shimNS).Get(ctx, identityRetiredConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the previous key's public halves are recorded: %v", err)
	}
	if body := cm.Data[retiredKeysFile]; !strings.Contains(body, "PUBLIC KEY") || strings.Contains(body, "PRIVATE") {
		t.Fatalf("the record holds public halves only: %.80q", body)
	}
	if _, err := cs.CoreV1().Secrets(shimNS).Get(ctx, identityKeySecretName, metav1.GetOptions{}); err != nil {
		t.Fatal("the Secret stays while a replica of the previous version may still read it")
	}
	sig, _, err := s.sign(ctx, doc)
	if err != nil || sig == oldSig || len(f.signedWith) == 0 {
		t.Fatalf("after the switch, Transit signs, never the Secret's key: %v", err)
	}
	now = now.Add(retireGrace + time.Minute)
	if !s.verify(ctx, doc, oldSig) {
		t.Fatal("within its lifetime, the previous key's document verifies from the record")
	}
	if _, err := cs.CoreV1().Secrets(shimNS).Get(ctx, identityKeySecretName, metav1.GetOptions{}); err == nil {
		t.Fatal("the Secret is deleted once the record is old enough")
	}
	k, _ := s.current(ctx)
	if n := strings.Count(string(k.certPEM), "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("certificates served while the retired key verifies: %d, want 2", n)
	}
	now = now.Add(time.Hour + identityClockSkew)
	if s.verify(ctx, doc, oldSig) {
		t.Fatal("once its lifetime has passed, the previous key's documents no longer verify")
	}
	if !s.verify(ctx, doc, sig) {
		t.Fatal("the Transit key's documents still verify")
	}
}

// A Secret holding a key its record does not is left alone: a replica of the previous version made a new
// key after the record, and deleting it would lose what that key signed.
func TestTransitSigning_KeepsASecretTheRecordDoesNotHold(t *testing.T) {
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	before := newIdentitySigner(cs, shimNS, time.Hour, discardLogger())
	before.now = func() time.Time { return now }
	if _, _, err := before.sign(ctx, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	s, _ := transitIDSigner(t, cs, &now)
	if _, err := s.current(ctx); err != nil { // records the key
		t.Fatal(err)
	}
	// The previous version replaces the Secret's key after the record was made.
	if err := cs.CoreV1().Secrets(shimNS).Delete(ctx, identityKeySecretName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	other := newIdentitySigner(cs, shimNS, time.Hour, discardLogger())
	other.now = func() time.Time { return now }
	if _, _, err := other.sign(ctx, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(retireGrace + time.Minute)
	if _, err := s.current(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().Secrets(shimNS).Get(ctx, identityKeySecretName, metav1.GetOptions{}); err != nil {
		t.Fatal("a Secret whose key the record does not hold stays")
	}
}
