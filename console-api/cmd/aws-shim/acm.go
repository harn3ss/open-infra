// ACM (SigV4 service `acm`, AWS JSON 1.1, X-Amz-Target: CertificateManager.<Op>): ListCertificates,
// DescribeCertificate and GetCertificate over a CloudFormation stack's certificates.
//
// A stack's AWS::CertificateManager::Certificate is the TLS certificate of the CloudFront distribution in
// the same stack that names it (cfn/translate_cloudfront.go): it provisions nothing of its own; the
// distribution's kind: StaticSite gets its certificate from cert-manager — the platform's ACM-style CA
// (ClusterIssuer openinfra-acm, constrained to the operator's validated domains) or, with no validated
// domains, the self-signed openinfra-issuer — as the cert-manager Certificate staticsite-<site>-tls in the
// site's namespace. So a certificate is found in its stack's template (cfn.TemplateResources), under the ARN
// its Ref gave the distribution, and answered from the cert-manager Certificate of the site(s) using it:
// ISSUED once that Certificate is Ready, its validity, issuer and the distributions it is in use by.
// GetCertificate answers the certificate and its chain from the current CertificateRequest's status (what
// cert-manager issued); the private key lives only in the site's TLS Secret, which this front door never
// reads.
//
// Authorization: acm:<Action> on Certificate::<certificate id> (ListCertificates on Certificate::*), and for
// a User the read on the certificate's stack that DescribeStackResources needs (a certificate belongs to its
// stack and to nothing else). ListCertificates lists only the certificates of stacks the caller may read.
//
// Accounts: a certificate is its stack's, and a stack its account's (cfn_accounts.go): a request finds
// certificates among its own account's stacks alone (their ARNs, the Refs the stacks gave them, name that
// account), and the distributions a certificate is in use by are named in that account.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/awserr"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const acmCertificateType = "AWS::CertificateManager::Certificate"

var (
	certManagerCertificateGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	certManagerRequestGVR     = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificaterequests"}
)

type acmHandler struct {
	cfn    *cfnDoorway // the stack records the certificates are found in, and the authorization clients
	logger *slog.Logger
}

func init() { accountScopedServices["acm"] = true }

func newACMHandler(c *cfnDoorway, logger *slog.Logger) *acmHandler {
	return &acmHandler{cfn: c, logger: logger}
}

func (h *acmHandler) authFailure(w http.ResponseWriter, _ *http.Request, requestID string) {
	writeACMError(w, http.StatusForbidden, "InvalidSignatureException", requestID,
		"The request signature we calculated does not match the signature you provided.")
}

func writeACMError(w http.ResponseWriter, status int, code, requestID, message string) {
	message = awserr.Clean(message) // a Kubernetes error passed through is said in AWS's terms
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

func writeACMJSON(w http.ResponseWriter, requestID string, body any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("x-amzn-RequestId", requestID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

// acmAction is the IAM action an ACM operation is authorized as ("" for one not served).
func acmAction(op string) string {
	switch op {
	case "ListCertificates":
		return "acm:ListCertificates"
	case "DescribeCertificate":
		return "acm:DescribeCertificate"
	case "GetCertificate":
		return "acm:GetCertificate"
	}
	return ""
}

func (h *acmHandler) serve(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string) {
	op := opFromTarget(r.Header.Get("X-Amz-Target"))
	action := acmAction(op)
	if action == "" {
		writeACMError(w, http.StatusBadRequest, "InvalidAction", requestID,
			"ACM "+op+" is not served by the open-infra shim (served: ListCertificates, DescribeCertificate, GetCertificate); a certificate is created with its stack.")
		return
	}
	if h.cfn.cs == nil && claims.AssumedRole == "" {
		writeACMError(w, http.StatusForbidden, "AccessDeniedException", requestID, "ACM authorization is not configured on this shim")
		return
	}
	body := readJSONBody(r)
	ctx := r.Context()
	switch op {
	case "ListCertificates":
		if ok, reason := decide(ctx, r, h.cfn.authz, claims, action, "Certificate", "",
			dataPlaneOnly(ctx, r, h.cfn.authz, claims, action, "Certificate", "")); !ok {
			writeACMError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
			return
		}
		h.listCertificates(w, r, claims, requestID, body)
		return
	}
	arn := fnStr(body["CertificateArn"])
	id, ok := acmCertificateID(arn)
	if !ok {
		writeACMError(w, http.StatusBadRequest, "InvalidArnException", requestID, "The certificate ARN "+arn+" is not valid.")
		return
	}
	if ok, reason := decide(ctx, r, h.cfn.authz, claims, action, "Certificate", id,
		scopedDataPlaneOnly(ctx, r, h.cfn.authz, claims, action, "Certificate", id)); !ok {
		writeACMError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
		return
	}
	certs, err := h.certificates(ctx)
	if err != nil {
		h.logger.Warn("acm: reading the stack records failed", "error", err.Error())
		writeACMError(w, http.StatusServiceUnavailable, "ServiceUnavailableException", requestID, "The certificate could not be read; retry.")
		return
	}
	for _, c := range certs {
		if c.arn != arn {
			continue
		}
		// A member account's principal is decided by IAM policy alone (above): the coarse RBAC check knows
		// no accounts.
		if !memberAccount(claims) {
			if allowed, reason := h.cfn.canDo(ctx, claims, "get", c.rec.Name); !allowed {
				writeACMError(w, http.StatusForbidden, "AccessDeniedException", requestID, reason)
				return
			}
		}
		if op == "DescribeCertificate" {
			writeACMJSON(w, requestID, map[string]any{"Certificate": h.describe(ctx, c)})
			return
		}
		leaf, chain, issued := h.issued(ctx, c)
		if !issued {
			writeACMError(w, http.StatusBadRequest, "RequestInProgressException", requestID, "Certificate "+arn+" is not yet issued.")
			return
		}
		writeACMJSON(w, requestID, map[string]any{"Certificate": leaf, "CertificateChain": chain})
		return
	}
	writeACMError(w, http.StatusBadRequest, "ResourceNotFoundException", requestID, "Could not find certificate "+arn+".")
}

// acmCertificateID is the id of arn:aws:acm:<region>:<account>:certificate/<id>.
func acmCertificateID(arn string) (string, bool) {
	if !strings.HasPrefix(arn, "arn:") {
		return "", false
	}
	i := strings.Index(arn, ":certificate/")
	if i < 0 || !strings.Contains(arn[:i], ":acm:") {
		return "", false
	}
	id := arn[i+len(":certificate/"):]
	return id, id != "" && cfResourceIDRe.MatchString(id)
}

// acmCertificate is a stack's certificate: the stack, its template resource, and the StaticSites of the
// stack's distributions that use it.
type acmCertificate struct {
	rec   *cfn.StackRecord
	arn   string
	res   cfn.TemplateResource
	sites []acmSite
}

type acmSite struct{ ns, name, distID string }

// certificates is the certificates of every stack of the request's account, in ARN order.
func (h *acmHandler) certificates(ctx context.Context) ([]acmCertificate, error) {
	cf := &cloudFrontHandler{cfn: h.cfn}
	recs, err := cf.stackRecords(ctx)
	if err != nil {
		return nil, err
	}
	var out []acmCertificate
	for _, rec := range recs {
		trs := templateResources(rec, recs, acmCertificateType, cloudFrontDistributionType)
		for _, tr := range trs {
			if tr.Type != acmCertificateType || tr.Ref == "" {
				continue
			}
			c := acmCertificate{rec: rec, arn: tr.Ref, res: tr}
			for _, d := range trs {
				if d.Type != cloudFrontDistributionType {
					continue
				}
				dc, _ := d.Properties["DistributionConfig"].(map[string]any)
				vc, _ := dc["ViewerCertificate"].(map[string]any)
				if fnStr(vc["AcmCertificateArn"]) != c.arn {
					continue
				}
				if site := distributionIn(rec, d.Ref, h.cfn.nsFor(ctx)); site != nil {
					c.sites = append(c.sites, acmSite{ns: site.ns, name: site.site, distID: d.Ref})
				}
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].arn < out[j].arn })
	return out, nil
}

// siteCertificate is the cert-manager Certificate of the first site using c (nil when none is readable).
func (h *acmHandler) siteCertificate(ctx context.Context, c acmCertificate) *unstructured.Unstructured {
	for _, s := range c.sites {
		u, err := h.cfn.shimDyn.Resource(certManagerCertificateGVR).Namespace(s.ns).Get(ctx, "staticsite-"+s.name+"-tls", metav1.GetOptions{})
		if err == nil {
			return u
		}
		if !apierrors.IsNotFound(err) {
			h.logger.Debug("acm: reading a site certificate failed", "site", s.ns+"/"+s.name, "error", err.Error())
		}
	}
	return nil
}

// acmStatus is the certificate's ACM status: ISSUED once its cert-manager Certificate is Ready.
func acmStatus(cm *unstructured.Unstructured) string {
	if cm == nil {
		return "PENDING_VALIDATION"
	}
	conds, _, _ := unstructured.NestedSlice(cm.Object, "status", "conditions")
	for _, c := range conds {
		m, _ := c.(map[string]any)
		if fnStr(m["type"]) == "Ready" && fnStr(m["status"]) == "True" {
			return "ISSUED"
		}
	}
	return "PENDING_VALIDATION"
}

// acmNames are the certificate's DomainName and SubjectAlternativeNames (which include the DomainName,
// as ACM lists them).
func acmNames(c acmCertificate) (string, []string) {
	domain := strings.ToLower(fnStr(c.res.Properties["DomainName"]))
	names := []string{domain}
	for _, s := range cfStrings(c.res.Properties["SubjectAlternativeNames"]) {
		if s = strings.ToLower(s); s != domain {
			names = append(names, s)
		}
	}
	return domain, names
}

// acmEpoch is an ACM timestamp (epoch seconds) from an RFC 3339 time; nil when it does not parse.
func acmEpoch(s string) any {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return json.Number(strconv.FormatInt(t.Unix(), 10))
}

// acmKeyAlgorithm is ACM's name for the site certificate's key (cert-manager's default is RSA 2048).
func acmKeyAlgorithm(cm *unstructured.Unstructured) string {
	if cm == nil {
		return "RSA_2048"
	}
	alg, _, _ := unstructured.NestedString(cm.Object, "spec", "privateKey", "algorithm")
	size, _, _ := unstructured.NestedInt64(cm.Object, "spec", "privateKey", "size")
	switch strings.ToUpper(alg) {
	case "ECDSA":
		switch size {
		case 384:
			return "EC_secp384r1"
		case 521:
			return "EC_secp521r1"
		}
		return "EC_prime256v1"
	case "ED25519":
		return "ED25519"
	}
	switch size {
	case 3072:
		return "RSA_3072"
	case 4096:
		return "RSA_4096"
	}
	return "RSA_2048"
}

// describe is the certificate in DescribeCertificate's CertificateDetail shape.
func (h *acmHandler) describe(ctx context.Context, c acmCertificate) map[string]any {
	cm := h.siteCertificate(ctx, c)
	domain, names := acmNames(c)
	status := acmStatus(cm)
	method := cfOrDefault(fnStr(c.res.Properties["ValidationMethod"]), "DNS")
	validations := make([]any, 0, len(names))
	for _, n := range names {
		v := "PENDING_VALIDATION"
		if status == "ISSUED" {
			v = "SUCCESS"
		}
		validations = append(validations, map[string]any{"DomainName": n, "ValidationDomain": n, "ValidationStatus": v, "ValidationMethod": method})
	}
	inUse := make([]string, 0, len(c.sites))
	for _, s := range c.sites {
		inUse = append(inUse, (&cloudFrontHandler{cfn: h.cfn}).distributionARN(ctx, s.distID))
	}
	out := map[string]any{
		"CertificateArn": c.arn, "DomainName": domain, "SubjectAlternativeNames": names, "Status": status,
		"Type": "AMAZON_ISSUED", "KeyAlgorithm": acmKeyAlgorithm(cm), "InUseBy": inUse,
		"DomainValidationOptions": validations, "RenewalEligibility": "ELIGIBLE",
	}
	if t := acmEpoch(c.rec.CreatedAt); t != nil {
		out["CreatedAt"] = t
	}
	if cm != nil {
		issuer, _, _ := unstructured.NestedString(cm.Object, "spec", "issuerRef", "name")
		if issuer != "" {
			out["Issuer"] = issuer
		}
		nb, _, _ := unstructured.NestedString(cm.Object, "status", "notBefore")
		na, _, _ := unstructured.NestedString(cm.Object, "status", "notAfter")
		if t := acmEpoch(nb); t != nil && status == "ISSUED" {
			out["NotBefore"], out["IssuedAt"] = t, t
		}
		if t := acmEpoch(na); t != nil && status == "ISSUED" {
			out["NotAfter"] = t
		}
	}
	return out
}

// summary is the certificate in ListCertificates' CertificateSummary shape.
func (h *acmHandler) summary(ctx context.Context, c acmCertificate) map[string]any {
	d := h.describe(ctx, c)
	out := map[string]any{"CertificateArn": d["CertificateArn"], "DomainName": d["DomainName"],
		"SubjectAlternativeNameSummaries": d["SubjectAlternativeNames"], "Status": d["Status"], "Type": d["Type"],
		"KeyAlgorithm": d["KeyAlgorithm"], "InUse": len(c.sites) > 0, "RenewalEligibility": "ELIGIBLE"}
	for _, k := range []string{"CreatedAt", "IssuedAt", "NotBefore", "NotAfter"} {
		if v, ok := d[k]; ok {
			out[k] = v
		}
	}
	return out
}

// issued is the certificate cert-manager issued for the site — the leaf and its chain, PEM — read from the
// current CertificateRequest's status (the request carries no private key).
func (h *acmHandler) issued(ctx context.Context, c acmCertificate) (leaf, chain string, ok bool) {
	cm := h.siteCertificate(ctx, c)
	if acmStatus(cm) != "ISSUED" {
		return "", "", false
	}
	revision, _, _ := unstructured.NestedInt64(cm.Object, "status", "revision")
	list, err := h.cfn.shimDyn.Resource(certManagerRequestGVR).Namespace(cm.GetNamespace()).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.logger.Debug("acm: listing certificate requests failed", "namespace", cm.GetNamespace(), "error", err.Error())
		return "", "", false
	}
	for i := range list.Items {
		cr := &list.Items[i]
		ann := cr.GetAnnotations()
		if ann["cert-manager.io/certificate-name"] != cm.GetName() || ann["cert-manager.io/certificate-revision"] != strconv.FormatInt(revision, 10) {
			continue
		}
		certB64, _, _ := unstructured.NestedString(cr.Object, "status", "certificate")
		caB64, _, _ := unstructured.NestedString(cr.Object, "status", "ca")
		bundle, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil || len(bundle) == 0 {
			return "", "", false
		}
		ca, _ := base64.StdEncoding.DecodeString(caB64)
		blocks := pemCertificates(append(append(bundle, '\n'), ca...))
		if len(blocks) == 0 {
			return "", "", false
		}
		return blocks[0], strings.Join(blocks[1:], ""), true
	}
	return "", "", false
}

// pemCertificates is the CERTIFICATE blocks of PEM data, in order and each once; any other block (a key)
// is dropped.
func pemCertificates(data []byte) []string {
	var out []string
	seen := map[string]bool{}
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return out
		}
		if blk.Type != "CERTIFICATE" || seen[string(blk.Bytes)] {
			continue
		}
		seen[string(blk.Bytes)] = true
		out = append(out, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})))
	}
}

// listCertificates lists the certificates of the stacks the caller may read, in ARN order, paged by
// NextToken (the last ARN answered) and MaxItems (default and ceiling 1000), optionally only those whose
// status is one of CertificateStatuses.
func (h *acmHandler) listCertificates(w http.ResponseWriter, r *http.Request, claims iam.Claims, requestID string, body map[string]any) {
	ctx := r.Context()
	max := 1000
	if v, ok := body["MaxItems"].(float64); ok {
		if v < 1 || v > 1000 {
			writeACMError(w, http.StatusBadRequest, "ValidationException", requestID, "MaxItems must be between 1 and 1000.")
			return
		}
		max = int(v)
	}
	want := map[string]bool{}
	for _, s := range stringSlice(body["CertificateStatuses"]) {
		want[s] = true
	}
	after := fnStr(body["NextToken"])
	certs, err := h.certificates(ctx)
	if err != nil {
		h.logger.Warn("acm: reading the stack records failed", "error", err.Error())
		writeACMError(w, http.StatusServiceUnavailable, "ServiceUnavailableException", requestID, "The certificates could not be read; retry.")
		return
	}
	readable := map[string]bool{}
	items := []any{}
	next := ""
	for _, c := range certs {
		if c.arn <= after {
			continue
		}
		ok, seen := readable[c.rec.Name]
		if !seen {
			ok = true
			if !memberAccount(claims) { // a member account's principal: IAM policy decided ListCertificates
				ok, _ = h.cfn.canDo(ctx, claims, "get", c.rec.Name)
			}
			readable[c.rec.Name] = ok
		}
		if !ok {
			continue
		}
		s := h.summary(ctx, c)
		if len(want) > 0 && !want[fnStr(s["Status"])] {
			continue
		}
		if len(items) == max {
			next = fnStr(items[len(items)-1].(map[string]any)["CertificateArn"])
			break
		}
		items = append(items, s)
	}
	out := map[string]any{"CertificateSummaryList": items}
	if next != "" {
		out["NextToken"] = next
	}
	writeACMJSON(w, requestID, out)
}
