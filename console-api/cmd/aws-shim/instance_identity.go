// EC2 instance identity documents, signed.
//
// On EC2 every instance can read a JSON identity document and AWS's signatures of it from its instance
// metadata (latest/dynamic/instance-identity/document, signature, pkcs7, rsa2048). aws-cfn-bootstrap's
// cfn-init, cfn-signal and cfn-hup run with no credentials sign their CloudFormation calls with it:
// `Authorization: CFN_V1 <base64 document>:<signature>`. CloudFormation then accepts the call as the
// instance, for the instance's own stack.
//
// Here the platform signs. A VM's metadata agent fetches its document from /v1/vm-identity on the shim's
// in-cluster TLS port, identified by its per-VM ServiceAccount token exactly as /v1/vm-credentials
// identifies it (a TokenReview, bound to the VM's own launcher pod: k8sSARoleResolver). The shim builds the
// document itself from the cluster: the instance id is derived from the VM composite's uid (the id the
// EC2, SSM and CloudFormation APIs use), the composite must be bound to this very claim, and nothing in the
// request shapes the document. The agent serves the document and signatures byte for byte.
//
// The signing key is an RSA-2048 key in a Secret in the shim's own namespace (identityKeySecretName),
// created on first use, readable only by the shim (and cluster admins), never a ConfigMap and never in the
// guest. The document carries openinfraNotAfter, an expiry EC2's document has no field for: a document is
// valid for an hour (INSTANCE_IDENTITY_TTL), so one copied out of a guest stops working; the agent fetches a
// fresh one at half-life. Rotation: put the new key.pem/cert.pem in the Secret and append the old cert.pem to
// retired.pem. The shim re-reads the Secret every minute and signs with the new key at once; documents the
// old key signed still verify until retired.pem drops it, which is safe once they have expired (an hour).
//
// The `signature` is base64 RSA-SHA256 (PKCS#1 v1.5) over the document's bytes, as EC2's is. `rsa2048` and
// `pkcs7` are a PKCS#7 (CMS) SignedData holding the document, RSA-SHA256, with the signing certificate.
// On EC2 `pkcs7` is DSA-signed; here both are RSA. The certificates (current, then retired) are public at
// /v1/vm-identity/certificate, so an in-cluster verifier can check a document the way one checks EC2's
// against AWS's published certificate.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	// identityKeySecretName holds the signing key (key.pem), its certificate (cert.pem) and the certificates
	// of retired keys still accepted when verifying (retired.pem), in the shim's namespace.
	identityKeySecretName = "instance-identity-signing-key"
	identityKeyFile       = "key.pem"
	identityCertFile      = "cert.pem"
	identityRetiredFile   = "retired.pem"

	vmIdentityPath     = "/v1/vm-identity"
	vmIdentityCertPath = "/v1/vm-identity/certificate"

	defaultIdentityTTL = time.Hour
	identityKeyReload  = time.Minute
	identityDocVersion = "2017-09-30"
	// identityNotAfterField is the document's expiry (RFC 3339, UTC).
	identityNotAfterField = "openinfraNotAfter"
)

// isVMIdentityPath reports whether a (cleaned) path is the identity endpoint or its certificate.
func isVMIdentityPath(p string) bool { return p == vmIdentityPath || p == vmIdentityCertPath }

// identityKeys is the loaded key material.
type identityKeys struct {
	key     *rsa.PrivateKey
	cert    *x509.Certificate
	pubs    []*rsa.PublicKey // the current key's first, then the retired ones
	certPEM []byte           // the current certificate, then the retired ones
}

// identitySigner signs and verifies instance identity documents with the key in the Secret.
type identitySigner struct {
	cs     kubernetes.Interface
	ns     string
	name   string
	ttl    time.Duration
	logger *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	keys    *identityKeys
	rv      string
	checked time.Time
}

func newIdentitySigner(cs kubernetes.Interface, ns string, ttl time.Duration, logger *slog.Logger) *identitySigner {
	if ttl <= 0 {
		ttl = defaultIdentityTTL
	}
	return &identitySigner{cs: cs, ns: ns, name: identityKeySecretName, ttl: ttl, logger: logger}
}

func (s *identitySigner) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// current returns the key material: the Secret is re-read at most once a minute (so a rotation applies
// without a restart) and created, with a new key, if it does not exist. A failed re-read keeps the loaded
// key.
func (s *identitySigner) current(ctx context.Context) (*identityKeys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if s.keys != nil && now.Sub(s.checked) < identityKeyReload {
		return s.keys, nil
	}
	sec, err := s.cs.CoreV1().Secrets(s.ns).Get(ctx, s.name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		sec, err = s.create(ctx)
	}
	if err == nil && s.keys != nil && sec.ResourceVersion == s.rv {
		s.checked = now
		return s.keys, nil
	}
	var k *identityKeys
	if err == nil {
		k, err = parseIdentityKeys(sec.Data)
	}
	if err != nil {
		if s.keys != nil {
			s.logger.Warn("instance identity: cannot re-read the signing key; keeping the loaded one", "secret", s.ns+"/"+s.name, "error", err.Error())
			s.checked = now
			return s.keys, nil
		}
		return nil, err
	}
	s.keys, s.rv, s.checked = k, sec.ResourceVersion, now
	return k, nil
}

// create makes the Secret with a new key. Another replica may create it first: then its key is used.
func (s *identitySigner) create(ctx context.Context) (*corev1.Secret, error) {
	keyPEM, certPEM, err := newIdentityKeyPair(s.clock())
	if err != nil {
		return nil, err
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.name, Namespace: s.ns,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "aws-shim",
				// A lost key costs nothing (the shim makes a new one and documents are refreshed within the
				// hour), so it is not copied into backups.
				"velero.io/exclude-from-backup": "true",
			},
			Annotations: map[string]string{
				"openinfra.dev/purpose": "Signs EC2 instance identity documents for VM guests (CFN_V1). Rotate: new key.pem/cert.pem, old cert.pem appended to retired.pem; drop it from retired.pem after an hour.",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{identityKeyFile: keyPEM, identityCertFile: certPEM},
	}
	out, err := s.cs.CoreV1().Secrets(s.ns).Create(ctx, sec, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return s.cs.CoreV1().Secrets(s.ns).Get(ctx, s.name, metav1.GetOptions{})
	}
	if err == nil {
		s.logger.Info("instance identity: created the signing key", "secret", s.ns+"/"+s.name)
	}
	return out, err
}

// newIdentityKeyPair is a new RSA-2048 key and a self-signed certificate for it (PEM).
func newIdentityKeyPair(now time.Time) (keyPEM, certPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"open-infra"}, CommonName: "open-infra instance identity"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// parseIdentityKeys reads the Secret's data. The certificate must be the key's.
func parseIdentityKeys(data map[string][]byte) (*identityKeys, error) {
	kb, _ := pem.Decode(data[identityKeyFile])
	if kb == nil {
		return nil, fmt.Errorf("%s: no PEM private key", identityKeyFile)
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an RSA key", identityKeyFile)
		}
		key = rk
	} else if rk, err1 := x509.ParsePKCS1PrivateKey(kb.Bytes); err1 == nil {
		key = rk
	} else {
		return nil, fmt.Errorf("%s: %v", identityKeyFile, err)
	}
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("%s: an RSA key of at least 2048 bits is required", identityKeyFile)
	}
	certs, err := parseCertsPEM(data[identityCertFile])
	if err != nil || len(certs) != 1 {
		return nil, fmt.Errorf("%s: want exactly one certificate (%v)", identityCertFile, err)
	}
	pub, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("%s is not the certificate of %s", identityCertFile, identityKeyFile)
	}
	k := &identityKeys{key: key, cert: certs[0], pubs: []*rsa.PublicKey{pub}, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw})}
	if raw := data[identityRetiredFile]; len(bytes.TrimSpace(raw)) > 0 {
		retired, err := parseCertsPEM(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", identityRetiredFile, err)
		}
		for _, c := range retired {
			rp, ok := c.PublicKey.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("%s: a certificate without an RSA key", identityRetiredFile)
			}
			k.pubs = append(k.pubs, rp)
			k.certPEM = append(k.certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
	}
	return k, nil
}

func parseCertsPEM(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificate")
	}
	return out, nil
}

// signedIdentity is what /v1/vm-identity returns: the document and its signatures, as the guest serves them.
type signedIdentity struct {
	Document         string `json:"document"`
	Signature        string `json:"signature"`
	PKCS7            string `json:"pkcs7"`
	RSA2048          string `json:"rsa2048"`
	ExpiresInSeconds int    `json:"expiresInSeconds"`
}

// sign signs a document: the base64 RSA-SHA256 signature and the base64 PKCS#7 SignedData, each wrapped at
// 64 columns as EC2 serves them.
func (s *identitySigner) sign(ctx context.Context, doc []byte) (signature, pkcs7 string, err error) {
	k, err := s.current(ctx)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(doc)
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", "", err
	}
	p7, err := pkcs7SignedData(doc, k.cert, k.key, s.clock())
	if err != nil {
		return "", "", err
	}
	return wrap64(base64.StdEncoding.EncodeToString(sig)), wrap64(base64.StdEncoding.EncodeToString(p7)), nil
}

// verify reports whether sig (base64; whitespace ignored) is a signature of doc by the current key or a
// retired one.
func (s *identitySigner) verify(ctx context.Context, doc []byte, sig string) bool {
	k, err := s.current(ctx)
	if err != nil {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(sig), ""))
	if err != nil || len(raw) == 0 {
		return false
	}
	sum := sha256.Sum256(doc)
	for _, pub := range k.pubs {
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], raw) == nil {
			return true
		}
	}
	return false
}

func wrap64(s string) string {
	var b strings.Builder
	for len(s) > 64 {
		b.WriteString(s[:64])
		b.WriteByte('\n')
		s = s[64:]
	}
	b.WriteString(s)
	return b.String()
}

// --- the document ---

// identityFields are a document's values.
type identityFields struct {
	AccountID, Architecture, AvailabilityZone, ImageID, InstanceID, InstanceType, PendingTime, PrivateIP, Region string
}

// identityDocument renders a document as EC2 does (two-space indent, `"key" : value`, EC2's fields in the
// metadata agent's order), with the expiry last and no trailing newline — aws-cfn-bootstrap strips trailing
// whitespace before it signs a call with the document, so the bytes signed are the bytes sent.
func identityDocument(f identityFields, notAfter time.Time) []byte {
	str := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	fields := []struct {
		k string
		v any
	}{
		{"accountId", f.AccountID},
		{"architecture", f.Architecture},
		{"availabilityZone", f.AvailabilityZone},
		{"billingProducts", nil},
		{"devpayProductCodes", nil},
		{"marketplaceProductCodes", nil},
		{"imageId", f.ImageID},
		{"instanceId", f.InstanceID},
		{"instanceType", str(f.InstanceType)},
		{"kernelId", nil},
		{"pendingTime", f.PendingTime},
		{"privateIp", str(f.PrivateIP)},
		{"ramdiskId", nil},
		{"region", f.Region},
		{"version", identityDocVersion},
		{identityNotAfterField, notAfter.UTC().Format(time.RFC3339)},
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, fv := range fields {
		kj, _ := json.Marshal(fv.k)
		vj, _ := json.Marshal(fv.v)
		b.WriteString("  ")
		b.Write(kj)
		b.WriteString(" : ")
		b.Write(vj)
		if i < len(fields)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}")
	return b.Bytes()
}

// identityClaims are the document fields a verifier relies on.
type identityClaims struct {
	AccountID  string `json:"accountId"`
	InstanceID string `json:"instanceId"`
	Region     string `json:"region"`
	NotAfter   string `json:"openinfraNotAfter"`
}

// errVMGone is a VM that no longer exists (or is being deleted).
var errVMGone = errors.New("the VM is gone")

// boundVM is a VM claim and its composite, bound to each other.
type boundVM struct {
	claim, xr  *unstructured.Unstructured
	instanceID string
}

// readBoundVM reads VM claim ns/name and its composite with the shim's client, and derives the instance id
// from the composite's uid (instanceIDForUID — what the guest, the EC2 API and CloudFormation's Ref report).
// The composite must name this claim in spec.claimRef: a claim whose spec.resourceRef points at another VM's
// composite is never taken for that VM. errVMGone when the claim is missing or being deleted.
func readBoundVM(ctx context.Context, dyn dynamic.Interface, ns, name string) (*boundVM, error) {
	if dyn == nil {
		return nil, errors.New("the shim cannot read VMs")
	}
	claim, err := dyn.Resource(vmClaimGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, errVMGone
	}
	if err != nil {
		return nil, err
	}
	if claim.GetDeletionTimestamp() != nil {
		return nil, errVMGone
	}
	ref, _, _ := unstructured.NestedString(claim.Object, "spec", "resourceRef", "name")
	if ref == "" {
		return nil, errors.New("the VM has no composite yet")
	}
	xr, err := dyn.Resource(vmXRGVR).Get(ctx, ref, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, errVMGone
	}
	if err != nil {
		return nil, err
	}
	cns, _, _ := unstructured.NestedString(xr.Object, "spec", "claimRef", "namespace")
	cname, _, _ := unstructured.NestedString(xr.Object, "spec", "claimRef", "name")
	if cns != ns || cname != name || string(xr.GetUID()) == "" {
		return nil, fmt.Errorf("the composite %s is not bound to VM %s/%s", ref, ns, name)
	}
	return &boundVM{claim: claim, xr: xr, instanceID: instanceIDForUID(string(xr.GetUID()))}, nil
}

// vmRunning reports whether VM ns/name's instance (its KubeVirt VMI) is running.
func vmRunning(ctx context.Context, dyn dynamic.Interface, ns, name string) bool {
	vmi, err := dyn.Resource(vmiGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil || vmi.GetDeletionTimestamp() != nil {
		return false
	}
	phase, _, _ := unstructured.NestedString(vmi.Object, "status", "phase")
	return phase == "Running"
}

// identityFieldsOf is a bound VM's document values, as the EC2 API describes the instance.
func identityFieldsOf(vm *boundVM, account, region string) identityFields {
	spec, _, _ := unstructured.NestedMap(vm.claim.Object, "spec")
	osName, _ := spec["os"].(string)
	if osName == "" {
		osName = "ubuntu-24.04"
	}
	arch := "x86_64"
	if vm.claim.GetAnnotations()["openinfra.dev/arch"] == "arm64" {
		arch = "arm64"
	}
	ip, _, _ := unstructured.NestedString(vm.claim.Object, "status", "ip")
	return identityFields{
		AccountID:        account,
		Architecture:     arch,
		AvailabilityZone: region + "a",
		ImageID:          imageIDForOS(osName),
		InstanceID:       vm.instanceID,
		InstanceType:     claimInstanceType(vm.claim),
		PendingTime:      vm.xr.GetCreationTimestamp().UTC().Format("2006-01-02T15:04:05Z"),
		PrivateIP:        ip,
		Region:           region,
	}
}

// claimInstanceType is the instance type the EC2 API reports for a VM: its template's InstanceType, else the
// type of its shape.
func claimInstanceType(claim *unstructured.Unstructured) string {
	if t := cfn.ParseAWSView(claim.GetAnnotations()).InstanceType; t != "" {
		return t
	}
	spec, _, _ := unstructured.NestedMap(claim.Object, "spec")
	cpu, _ := spec["cpu"].(int64)
	if cpu == 0 {
		cpu = 2
	}
	mem, _ := spec["memory"].(string)
	if mem == "" {
		mem = "2Gi"
	}
	return cfn.InstanceTypeForShape(int(cpu), mem)
}

// --- the endpoint ---

// vmIdentityHandler serves /v1/vm-identity (a VM's signed document) and /v1/vm-identity/certificate.
type vmIdentityHandler struct {
	resolver saRoleResolver
	dyn      dynamic.Interface
	signer   *identitySigner
	account  string
	region   string
	logger   *slog.Logger
}

func (h *vmIdentityHandler) serve(w http.ResponseWriter, r *http.Request, requestID string) {
	if refuseIfProxied(w, r) { // in-cluster only, as /v1/vm-credentials
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if path.Clean("/"+r.URL.Path) == vmIdentityCertPath {
		k, err := h.signer.current(r.Context())
		if err != nil {
			http.Error(w, "the instance identity key is not available; retry", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(k.certPEM)
		return
	}
	token := strings.TrimPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ")
	if token == "" {
		http.Error(w, "missing instance identity token", http.StatusUnauthorized)
		return
	}
	id, ok := h.resolver.resolveSARole(r.Context(), token)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	vm, err := readBoundVM(r.Context(), h.dyn, id.namespace, id.vmName)
	if errors.Is(err, errVMGone) {
		http.Error(w, "the VM is gone", http.StatusNotFound)
		return
	}
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("vm-identity: cannot read the VM", "vm", id.namespace+"/"+id.vmName, "error", err.Error())
		}
		http.Error(w, "the VM could not be read; retry", http.StatusServiceUnavailable)
		return
	}
	notAfter := h.signer.clock().Add(h.signer.ttl).Truncate(time.Second)
	doc := identityDocument(identityFieldsOf(vm, h.account, h.region), notAfter)
	sig, p7, err := h.signer.sign(r.Context(), doc)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("vm-identity: cannot sign", "error", err.Error())
		}
		http.Error(w, "the instance identity key is not available; retry", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(signedIdentity{Document: string(doc), Signature: sig, PKCS7: p7, RSA2048: p7,
		ExpiresInSeconds: int(h.signer.ttl / time.Second)})
}

// --- verification (CFN_V1) ---

// verifyIdentity checks a CFN_V1 Authorization header — `CFN_V1 <base64 document>:<signature>`, as
// aws-cfn-bootstrap writes it — and returns the document's claims: the signature must be the platform's, the
// document unexpired (and not valid for longer than a document is issued for), and its account and region
// this shim's.
func (s *identitySigner) verifyIdentity(ctx context.Context, header, account, region string) (*identityClaims, error) {
	const scheme = "CFN_V1 "
	if !strings.HasPrefix(header, scheme) {
		return nil, errors.New("not a CFN_V1 authorization")
	}
	if len(header) > 16<<10 {
		return nil, errors.New("the CFN_V1 authorization is too large")
	}
	rest := strings.TrimSpace(header[len(scheme):])
	i := strings.IndexByte(rest, ':')
	if i <= 0 || i == len(rest)-1 {
		return nil, errors.New("the CFN_V1 authorization is not <base64 document>:<signature>")
	}
	doc, err := base64.StdEncoding.DecodeString(rest[:i])
	if err != nil {
		return nil, errors.New("the CFN_V1 document is not base64")
	}
	if !s.verify(ctx, doc, rest[i+1:]) {
		return nil, errors.New("the instance identity document's signature does not verify")
	}
	var c identityClaims
	if err := json.Unmarshal(doc, &c); err != nil {
		return nil, errors.New("the instance identity document is not JSON")
	}
	exp, err := time.Parse(time.RFC3339, c.NotAfter)
	if err != nil {
		return nil, errors.New("the instance identity document has no expiry")
	}
	now := s.clock()
	if !now.Before(exp) {
		return nil, errors.New("the instance identity document has expired")
	}
	if exp.Sub(now) > s.ttl+5*time.Minute {
		return nil, errors.New("the instance identity document is valid for longer than one is issued for")
	}
	if c.AccountID != account || c.Region != region {
		return nil, errors.New("the instance identity document is for another account or region")
	}
	if !instanceIDRe.MatchString(c.InstanceID) {
		return nil, errors.New("the instance identity document names no instance")
	}
	return &c, nil
}

// --- PKCS#7 (CMS) SignedData, RFC 5652 ---

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
)

func derTLV(tag byte, content []byte) []byte {
	n := len(content)
	var l []byte
	switch {
	case n < 0x80:
		l = []byte{byte(n)}
	case n < 0x100:
		l = []byte{0x81, byte(n)}
	case n < 0x10000:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	default:
		l = []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	out := append([]byte{tag}, l...)
	return append(out, content...)
}

func derSeq(parts ...[]byte) []byte { return derTLV(0x30, bytes.Join(parts, nil)) }

// derSetOf is a DER SET OF: its elements sorted by their encodings.
func derSetOf(parts ...[]byte) []byte {
	s := append([][]byte(nil), parts...)
	sort.Slice(s, func(i, j int) bool { return bytes.Compare(s[i], s[j]) < 0 })
	return derTLV(0x31, bytes.Join(s, nil))
}

func mustDER(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func derAlgID(oid asn1.ObjectIdentifier) []byte { return derSeq(mustDER(oid), []byte{0x05, 0x00}) }

// pkcs7SignedData is a DER ContentInfo holding a SignedData of content (attached), signed with key over
// the content type, signing time and message digest attributes, with cert included.
func pkcs7SignedData(content []byte, cert *x509.Certificate, key *rsa.PrivateKey, at time.Time) ([]byte, error) {
	digest := sha256.Sum256(content)
	signedAttrs := derSetOf(
		derSeq(mustDER(oidContentType), derSetOf(mustDER(oidData))),
		derSeq(mustDER(oidSigningTime), derSetOf(mustDER(at.UTC().Truncate(time.Second)))),
		derSeq(mustDER(oidMessageDigest), derSetOf(mustDER(digest[:]))),
	)
	// The signature covers the attributes' DER as a SET (RFC 5652 §5.4); they travel [0] IMPLICIT.
	h := sha256.Sum256(signedAttrs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return nil, err
	}
	implicitAttrs := append([]byte{0xA0}, signedAttrs[1:]...)
	signerInfo := derSeq(
		mustDER(1),
		derSeq(cert.RawIssuer, mustDER(cert.SerialNumber)),
		derAlgID(oidSHA256),
		implicitAttrs,
		derAlgID(oidRSAEncryption),
		mustDER(sig),
	)
	signedData := derSeq(
		mustDER(1),
		derSetOf(derAlgID(oidSHA256)),
		derSeq(mustDER(oidData), derTLV(0xA0, mustDER(content))),
		derTLV(0xA0, cert.Raw),
		derSetOf(signerInfo),
	)
	return derSeq(mustDER(oidSignedData), derTLV(0xA0, signedData)), nil
}
