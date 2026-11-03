package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func testIDSigner(t *testing.T) (*identitySigner, *fake.Clientset, *time.Time) {
	t.Helper()
	cs := fake.NewSimpleClientset()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	s := newIdentitySigner(cs, shimNS, time.Hour, discardLogger())
	s.now = func() time.Time { return now }
	return s, cs, &now
}

// The key is made once, in a Secret in the shim's namespace that backups skip, and another replica uses
// the same key; a signature verifies only for the bytes signed, and only by this key.
func TestIdentitySigner_KeySecretAndSignatures(t *testing.T) {
	s, cs, _ := testIDSigner(t)
	ctx := context.Background()
	doc := []byte(`{"instanceId" : "i-0123456789abcdef0"}`)
	sig, p7, err := s.sign(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	sec, err := cs.CoreV1().Secrets(shimNS).Get(ctx, identityKeySecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("the signing key is a Secret in the shim's namespace: %v", err)
	}
	if sec.Labels["velero.io/exclude-from-backup"] != "true" || len(sec.Data[identityKeyFile]) == 0 || len(sec.Data[identityCertFile]) == 0 {
		t.Fatalf("Secret: %+v", sec.Labels)
	}
	if !s.verify(ctx, doc, sig) {
		t.Fatal("its own signature must verify")
	}
	if !s.verify(ctx, doc, strings.ReplaceAll(sig, "\n", "")) {
		t.Fatal("cfn-bootstrap sends the signature with its newlines removed")
	}
	if s.verify(ctx, []byte(`{"instanceId" : "i-0123456789abcdef1"}`), sig) {
		t.Fatal("a signature must not verify another document")
	}
	if p7 == "" {
		t.Fatal("no PKCS#7")
	}
	other := newIdentitySigner(cs, shimNS, time.Hour, discardLogger())
	if !other.verify(ctx, doc, sig) {
		t.Fatal("another replica reads the same key")
	}
	// A key that is not the platform's: its signatures are refused.
	forger, _, _ := testIDSigner(t)
	fsig, _, _ := forger.sign(ctx, doc)
	if s.verify(ctx, doc, fsig) {
		t.Fatal("a signature by another key must not verify")
	}
}

// Rotation: a new key signs at once; the retired key's documents verify until it leaves retired.pem.
func TestIdentitySigner_Rotation(t *testing.T) {
	s, cs, now := testIDSigner(t)
	ctx := context.Background()
	doc := []byte(`{"a" : 1}`)
	oldSig, _, _ := s.sign(ctx, doc)
	sec, _ := cs.CoreV1().Secrets(shimNS).Get(ctx, identityKeySecretName, metav1.GetOptions{})
	newKey, newCert, err := newIdentityKeyPair(*now)
	if err != nil {
		t.Fatal(err)
	}
	sec.Data[identityRetiredFile] = sec.Data[identityCertFile]
	sec.Data[identityKeyFile], sec.Data[identityCertFile] = newKey, newCert
	sec.ResourceVersion = "2"
	if _, err := cs.CoreV1().Secrets(shimNS).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * identityKeyReload) // the shim re-reads the Secret
	newSig, _, _ := s.sign(ctx, doc)
	if newSig == oldSig || !s.verify(ctx, doc, newSig) || !s.verify(ctx, doc, oldSig) {
		t.Fatal("after rotation the new key signs and the retired one still verifies")
	}
	delete(sec.Data, identityRetiredFile)
	sec.ResourceVersion = "3"
	_, _ = cs.CoreV1().Secrets(shimNS).Update(ctx, sec, metav1.UpdateOptions{})
	*now = now.Add(2 * identityKeyReload)
	if s.verify(ctx, doc, oldSig) {
		t.Fatal("a key dropped from retired.pem no longer verifies")
	}
	k, _ := s.current(ctx)
	if c, _ := parseCertsPEM(k.certPEM); len(c) != 1 {
		t.Fatalf("the published certificates follow the Secret: %d", len(c))
	}
}

// The document is EC2's, in the metadata agent's field order, with the expiry last and no trailing newline.
func TestIdentityDocument_Shape(t *testing.T) {
	doc := identityDocument(identityFields{AccountID: "000000000000", Architecture: "x86_64", AvailabilityZone: "us-east-1a",
		ImageID: "ami-1", InstanceID: "i-0123456789abcdef0", PendingTime: "2026-11-03T10:00:00Z", Region: "us-east-1"},
		time.Date(2026, 11, 3, 13, 0, 0, 0, time.UTC))
	if strings.HasSuffix(string(doc), "\n") || !strings.HasPrefix(string(doc), "{\n  \"accountId\" : \"000000000000\",\n") {
		t.Fatalf("document:\n%s", doc)
	}
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	if m["instanceId"] != "i-0123456789abcdef0" || m["openinfraNotAfter"] != "2026-11-03T13:00:00Z" || m["version"] != "2017-09-30" ||
		m["instanceType"] != nil || m["privateIp"] != nil {
		t.Fatalf("fields: %v", m)
	}
	if !strings.HasSuffix(string(doc), "\"openinfraNotAfter\" : \"2026-11-03T13:00:00Z\"\n}") {
		t.Fatalf("the expiry is the last field:\n%s", doc)
	}
}

// The PKCS#7 SignedData carries the document and verifies with the certificate (openssl, when present),
// and its structure is what RFC 5652 says.
func TestIdentityPKCS7(t *testing.T) {
	s, _, _ := testIDSigner(t)
	ctx := context.Background()
	doc := []byte("{\n  \"instanceId\" : \"i-0123456789abcdef0\"\n}")
	_, p7, err := s.sign(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(p7, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	var ci struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil || !ci.Type.Equal(oidSignedData) {
		t.Fatalf("ContentInfo: %v %v", err, ci.Type)
	}
	var sd struct {
		Version int
		Digests asn1.RawValue
		Encap   struct {
			Type    asn1.ObjectIdentifier
			Content []byte `asn1:"explicit,tag:0"`
		}
		Certs   asn1.RawValue `asn1:"tag:0"`
		Signers asn1.RawValue
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("SignedData: %v", err)
	}
	if sd.Version != 1 || string(sd.Encap.Content) != string(doc) || !sd.Encap.Type.Equal(oidData) {
		t.Fatalf("SignedData: v%d %q", sd.Version, sd.Encap.Content)
	}
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl to verify the PKCS#7 with")
	}
	k, _ := s.current(ctx)
	dir := t.TempDir()
	in, cert, out := filepath.Join(dir, "p7.der"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "doc")
	_ = os.WriteFile(in, der, 0o600)
	_ = os.WriteFile(cert, k.certPEM, 0o600)
	if b, err := exec.Command(ossl, "cms", "-verify", "-inform", "DER", "-in", in, "-noverify", "-certfile", cert, "-binary", "-out", out).CombinedOutput(); err != nil {
		t.Fatalf("openssl cms -verify: %v\n%s", err, b)
	}
	if got, _ := os.ReadFile(out); string(got) != string(doc) {
		t.Fatalf("openssl recovered %q", got)
	}
	// The same check with the signer's certificate as the only trust: a different certificate fails.
	forger, _, _ := testIDSigner(t)
	fk, _ := forger.current(ctx)
	_ = os.WriteFile(cert, fk.certPEM, 0o600)
	if b, err := exec.Command(ossl, "cms", "-verify", "-inform", "DER", "-in", in, "-noverify", "-nointern", "-certfile", cert, "-binary", "-out", out).CombinedOutput(); err == nil {
		t.Fatalf("a PKCS#7 must not verify with another certificate:\n%s", b)
	}
}

// --- the cluster objects a VM is ---

var vmiGVRTest = schema.GroupVersionResource{Group: "kubevirt.io", Version: "v1", Resource: "virtualmachineinstances"}

func identityDyn() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		vmClaimGVR: "VirtualMachineList", vmXRGVR: "XVirtualMachineList", vmiGVRTest: "VirtualMachineInstanceList",
		{Version: "v1", Resource: "secrets"}: "SecretList", {Version: "v1", Resource: "configmaps"}: "ConfigMapList",
	})
}

// addVM puts claim ns/name, its composite (uid) bound to it (or to boundTo when set) and, when phase is
// set, its VMI in that phase.
func addVM(t *testing.T, dyn *dynamicfake.FakeDynamicClient, ns, name, uid, phase string, boundTo ...string) {
	t.Helper()
	xrName := name + "-xr"
	claim := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "openinfra.dev/v1", "kind": "VirtualMachine",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec":     map[string]any{"os": "ubuntu-24.04", "cpu": int64(2), "memory": "4Gi", "resourceRef": map[string]any{"name": xrName}},
		"status":   map[string]any{"ip": "10.16.0.42"},
	}}
	if len(boundTo) == 1 {
		unstructured.SetNestedField(claim.Object, boundTo[0], "spec", "resourceRef", "name")
	}
	if err := dyn.Tracker().Create(vmClaimGVR, claim, ns); err != nil {
		t.Fatal(err)
	}
	if len(boundTo) == 0 {
		xr := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "openinfra.dev/v1", "kind": "XVirtualMachine",
			"metadata": map[string]any{"name": xrName, "uid": uid, "creationTimestamp": "2026-11-03T10:00:00Z"},
			"spec":     map[string]any{"claimRef": map[string]any{"namespace": ns, "name": name}},
		}}
		xr.SetUID(types.UID(uid))
		if err := dyn.Tracker().Create(vmXRGVR, xr, ""); err != nil {
			t.Fatal(err)
		}
	}
	if phase != "" {
		vmi := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "kubevirt.io/v1", "kind": "VirtualMachineInstance",
			"metadata": map[string]any{"name": name, "namespace": ns},
			"status":   map[string]any{"phase": phase},
		}}
		if err := dyn.Tracker().Create(vmiGVRTest, vmi, ns); err != nil {
			t.Fatal(err)
		}
	}
}

func testIdentityHandler(t *testing.T, dyn *dynamicfake.FakeDynamicClient, byToken map[string]saIdentity) (*vmIdentityHandler, *identitySigner) {
	t.Helper()
	s, _, _ := testIDSigner(t)
	return &vmIdentityHandler{resolver: fakeSAResolver{byToken: byToken}, dyn: dyn, signer: s,
		account: "000000000000", region: "us-east-1", logger: discardLogger()}, s
}

func getIdentity(h *vmIdentityHandler, token string, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://shim"+vmIdentityPath, nil)
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	for _, m := range mutate {
		m(req)
	}
	rr := httptest.NewRecorder()
	h.serve(rr, req, "req")
	return rr
}

// /v1/vm-identity: a VM's token gets its own document, built from the cluster (the instance id from its
// composite's uid), signed; a role-less VM gets one too, as every EC2 instance has one.
func TestVMIdentity_SignedDocumentForTheTokensVM(t *testing.T) {
	dyn := identityDyn()
	addVM(t, dyn, "apps", "web", "uid-web", "Running")
	h, s := testIdentityHandler(t, dyn, map[string]saIdentity{"tok-web": {namespace: "apps", vmName: "web"}})
	rr := getIdentity(h, "tok-web")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body)
	}
	var out signedIdentity
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(out.Document), &doc)
	if doc["instanceId"] != instanceIDForUID("uid-web") || doc["accountId"] != "000000000000" || doc["region"] != "us-east-1" ||
		doc["imageId"] != imageIDForOS("ubuntu-24.04") || doc["privateIp"] != "10.16.0.42" || doc["pendingTime"] != "2026-11-03T10:00:00Z" ||
		doc["instanceType"] != "t3.medium" {
		t.Fatalf("document: %s", out.Document)
	}
	if !s.verify(context.Background(), []byte(out.Document), out.Signature) || out.RSA2048 == "" || out.PKCS7 != out.RSA2048 || out.ExpiresInSeconds != 3600 {
		t.Fatalf("signatures: %+v", out)
	}
	if doc["openinfraNotAfter"] != "2026-11-03T13:00:00Z" {
		t.Fatalf("an hour's validity: %v", doc["openinfraNotAfter"])
	}
	// The certificate is public (in-cluster).
	cert := httptest.NewRecorder()
	h.serve(cert, httptest.NewRequest(http.MethodGet, "https://shim"+vmIdentityCertPath, nil), "req")
	if b, _ := pem.Decode(cert.Body.Bytes()); cert.Code != http.StatusOK || b == nil {
		t.Fatalf("certificate: %d", cert.Code)
	} else if _, err := x509.ParseCertificate(b.Bytes); err != nil {
		t.Fatal(err)
	}
}

// Refusals: no token, a token the TokenReview rejects, a write, a call through the LAN Ingress, a VM that
// is gone, and a claim that names another VM's composite (never signed as that VM).
func TestVMIdentity_Refusals(t *testing.T) {
	dyn := identityDyn()
	addVM(t, dyn, "apps", "victim", "uid-victim", "Running")
	addVM(t, dyn, "apps", "evil", "", "Running", "victim-xr") // its resourceRef points at victim's composite
	h, _ := testIdentityHandler(t, dyn, map[string]saIdentity{
		"tok-evil": {namespace: "apps", vmName: "evil"}, "tok-gone": {namespace: "apps", vmName: "gone"}})
	if rr := getIdentity(h, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rr.Code)
	}
	if rr := getIdentity(h, "forged"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token: %d", rr.Code)
	}
	if rr := getIdentity(h, "tok-evil", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "192.0.2.1") }); rr.Code != http.StatusNotFound {
		t.Fatalf("through the LAN Ingress: %d", rr.Code)
	}
	post := httptest.NewRequest(http.MethodPost, "https://shim"+vmIdentityPath, nil)
	post.Header.Set("Authorization", "tok-evil")
	prr := httptest.NewRecorder()
	h.serve(prr, post, "req")
	if prr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", prr.Code)
	}
	if rr := getIdentity(h, "tok-gone"); rr.Code != http.StatusNotFound {
		t.Fatalf("a VM that is gone: %d", rr.Code)
	}
	rr := getIdentity(h, "tok-evil")
	if rr.Code == http.StatusOK || strings.Contains(rr.Body.String(), instanceIDForUID("uid-victim")) {
		t.Fatalf("a claim bound to another VM's composite must never get that VM's document: %d %s", rr.Code, rr.Body)
	}
}

// The agent's token is accepted only over TLS.
func TestVMIdentity_TLSOnly(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	g := plaintextVMCredsGuard(next, true)
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://shim"+vmIdentityPath, nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("plaintext /v1/vm-identity must be 404, got %d", rr.Code)
	}
}
