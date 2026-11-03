package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func fakePEM(typ, body string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: []byte(body)}))
}

// acmFixture is the lift-and-shift stack (its distribution is the StaticSite fixture-site, whose TLS is the
// stack's certificate), with the site's cert-manager Certificate (ready as given) and its request.
func acmFixture(t *testing.T, allow func(a *authzv1.ResourceAttributes) bool, ready bool) (*acmHandler, string) {
	t.Helper()
	f := newCFFixture(t, allow)
	f.dyn = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "secrets"}:    "SecretList",
		{Version: "v1", Resource: "configmaps"}: "ConfigMapList",
		certManagerCertificateGVR:               "CertificateList",
		certManagerRequestGVR:                   "CertificateRequestList",
	})
	f.door.shimDyn = f.dyn
	f.door.account = "000000000000"
	f.seedTemplateStack(t)
	status := "False"
	if ready {
		status = "True"
	}
	cert := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
		"metadata": map[string]any{"name": "staticsite-fixture-site-tls", "namespace": opsNS},
		"spec":     map[string]any{"secretName": "staticsite-fixture-site-tls", "issuerRef": map[string]any{"name": "openinfra-acm", "kind": "ClusterIssuer"}},
		"status": map[string]any{"revision": int64(2), "notBefore": "2026-11-01T00:00:00Z", "notAfter": "2027-01-30T00:00:00Z",
			"conditions": []any{map[string]any{"type": "Ready", "status": status}}}}}
	bundle := fakePEM("CERTIFICATE", "leaf") + fakePEM("RSA PRIVATE KEY", "never") + fakePEM("CERTIFICATE", "intermediate")
	req := func(name, rev, leaf string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"apiVersion": "cert-manager.io/v1", "kind": "CertificateRequest",
			"metadata": map[string]any{"name": name, "namespace": opsNS, "annotations": map[string]any{
				"cert-manager.io/certificate-name": "staticsite-fixture-site-tls", "cert-manager.io/certificate-revision": rev}},
			"status": map[string]any{"certificate": base64.StdEncoding.EncodeToString([]byte(leaf)),
				"ca": base64.StdEncoding.EncodeToString([]byte(fakePEM("CERTIFICATE", "root")))}}}
	}
	ctx := context.Background()
	for _, o := range []*unstructured.Unstructured{
		req("staticsite-fixture-site-tls-1", "1", fakePEM("CERTIFICATE", "old-leaf")), req("staticsite-fixture-site-tls-2", "2", bundle),
	} {
		if _, err := f.dyn.Resource(certManagerRequestGVR).Namespace(opsNS).Create(ctx, o, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.dyn.Resource(certManagerCertificateGVR).Namespace(opsNS).Create(ctx, cert, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	certs, err := newACMHandler(f.door, discardLogger()).certificates(ctx)
	if err != nil || len(certs) != 1 {
		t.Fatalf("certificates = %v %v", certs, err)
	}
	return newACMHandler(f.door, discardLogger()), certs[0].arn
}

func acmCall(h *acmHandler, claims iam.Claims, op, body string) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "http://acm/", strings.NewReader(body))
	req.Header.Set("X-Amz-Target", "CertificateManager."+op)
	w := httptest.NewRecorder()
	h.serve(w, req, claims, "r")
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestACM_DescribeGetListAStacksCertificate(t *testing.T) {
	h, arn := acmFixture(t, allowAll, true)
	u := iam.Claims{Sub: "u"}
	if !strings.HasPrefix(arn, "arn:aws:acm:") || !strings.Contains(arn, ":certificate/") {
		t.Fatalf("the certificate's ARN is %q", arn)
	}
	code, out := acmCall(h, u, "DescribeCertificate", `{"CertificateArn":"`+arn+`"}`)
	c, _ := out["Certificate"].(map[string]any)
	if code != 200 || c["Status"] != "ISSUED" || c["DomainName"] != "site.example.test" || c["Issuer"] != "openinfra-acm" ||
		c["NotAfter"] == nil || c["Type"] != "AMAZON_ISSUED" {
		t.Fatalf("DescribeCertificate = %d %v", code, out)
	}
	if inUse, _ := c["InUseBy"].([]any); len(inUse) != 1 || !strings.HasPrefix(inUse[0].(string), "arn:aws:cloudfront::000000000000:distribution/E") {
		t.Errorf("InUseBy = %v", c["InUseBy"])
	}

	code, out = acmCall(h, u, "GetCertificate", `{"CertificateArn":"`+arn+`"}`)
	leaf, chain := fnStr(out["Certificate"]), fnStr(out["CertificateChain"])
	if code != 200 || leaf != fakePEM("CERTIFICATE", "leaf") || chain != fakePEM("CERTIFICATE", "intermediate")+fakePEM("CERTIFICATE", "root") {
		t.Fatalf("GetCertificate = %d leaf %q chain %q", code, leaf, chain)
	}
	if strings.Contains(leaf+chain, "PRIVATE KEY") {
		t.Fatal("GetCertificate answered a private key")
	}

	code, out = acmCall(h, u, "ListCertificates", `{}`)
	if l, _ := out["CertificateSummaryList"].([]any); code != 200 || len(l) != 1 || l[0].(map[string]any)["CertificateArn"] != arn || l[0].(map[string]any)["InUse"] != true {
		t.Errorf("ListCertificates = %d %v", code, out)
	}
	if _, out := acmCall(h, u, "ListCertificates", `{"CertificateStatuses":["PENDING_VALIDATION"]}`); len(out["CertificateSummaryList"].([]any)) != 0 {
		t.Errorf("ListCertificates filtered to PENDING_VALIDATION = %v", out)
	}
}

func TestACM_NotFoundAndNotIssued(t *testing.T) {
	h, arn := acmFixture(t, allowAll, false)
	u := iam.Claims{Sub: "u"}
	if code, out := acmCall(h, u, "DescribeCertificate", `{"CertificateArn":"arn:aws:acm:us-east-1:000000000000:certificate/00000000-0000-0000-0000-000000000000"}`); code != 400 || out["__type"] != "ResourceNotFoundException" {
		t.Errorf("DescribeCertificate of an unknown ARN = %d %v", code, out)
	}
	if code, out := acmCall(h, u, "DescribeCertificate", `{"CertificateArn":"not-an-arn"}`); code != 400 || out["__type"] != "InvalidArnException" {
		t.Errorf("DescribeCertificate of a malformed ARN = %d %v", code, out)
	}
	if _, out := acmCall(h, u, "DescribeCertificate", `{"CertificateArn":"`+arn+`"}`); out["Certificate"].(map[string]any)["Status"] != "PENDING_VALIDATION" {
		t.Errorf("a certificate not yet ready = %v", out)
	}
	if code, out := acmCall(h, u, "GetCertificate", `{"CertificateArn":"`+arn+`"}`); code != 400 || out["__type"] != "RequestInProgressException" {
		t.Errorf("GetCertificate before issue = %d %v", code, out)
	}
	if code, out := acmCall(h, u, "RequestCertificate", `{"DomainName":"x.example.test"}`); code != 400 || out["__type"] != "InvalidAction" {
		t.Errorf("RequestCertificate = %d %v", code, out)
	}
}

func TestACM_Denied(t *testing.T) {
	// No read on the stack: refused, and not listed.
	h, arn := acmFixture(t, func(a *authzv1.ResourceAttributes) bool { return a.Name != "fixture" }, true)
	u := iam.Claims{Sub: "u"}
	for _, op := range []string{"DescribeCertificate", "GetCertificate"} {
		if code, out := acmCall(h, u, op, `{"CertificateArn":"`+arn+`"}`); code != http.StatusForbidden {
			t.Errorf("%s without the stack read = %d %v", op, code, out)
		}
	}
	if _, out := acmCall(h, u, "ListCertificates", `{}`); len(out["CertificateSummaryList"].([]any)) != 0 {
		t.Errorf("ListCertificates listed a certificate of a stack the caller may not read: %v", out)
	}
	// The data plane: a Deny of acm:GetCertificate; an assumed role needs a grant.
	h, arn = acmFixture(t, allowAll, true)
	id, _ := acmCertificateID(arn)
	h.cfn.authz = userPolicy(dpAllow([]string{"acm:*"}, "*"), dpDeny([]string{"acm:GetCertificate"}, "Certificate::"+id))
	if code, _ := acmCall(h, testUser, "GetCertificate", `{"CertificateArn":"`+arn+`"}`); code != http.StatusForbidden {
		t.Errorf("GetCertificate under a Deny = %d", code)
	}
	if code, _ := acmCall(h, testUser, "DescribeCertificate", `{"CertificateArn":"`+arn+`"}`); code != 200 {
		t.Errorf("DescribeCertificate (not denied) = %d", code)
	}
	h.cfn.authz = roleChecker(dpAllow([]string{"acm:DescribeCertificate"}, "Certificate::"+id))
	if code, _ := acmCall(h, ecrRoleClaims(), "DescribeCertificate", `{"CertificateArn":"`+arn+`"}`); code != 200 {
		t.Errorf("DescribeCertificate by a role granted it = %d", code)
	}
	if code, _ := acmCall(h, ecrRoleClaims(), "ListCertificates", `{}`); code != http.StatusForbidden {
		t.Errorf("ListCertificates by a role not granted it = %d", code)
	}
}
