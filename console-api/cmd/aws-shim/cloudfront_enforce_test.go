package main

import (
	"net/http"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
)

// In enforce IAM policy alone decides CloudFront's and ACM's reads, as every front door's: the legacy
// coarse RBAC check (which under enforce no user's RBAC answers) is not asked. Here the SubjectAccessReview
// refuses everything, so a read can only be allowed by the caller's IAM policy, and is refused without it.
func TestEnforce_CloudFrontAndACMReadsAreIAMPolicyAlone(t *testing.T) {
	denyAll := func(*authzv1.ResourceAttributes) bool { return false }
	tester := iam.Claims{Sub: "tester"}

	f := newCFFixture(t, denyAll)
	refs := f.seedTemplateStack(t)
	f.door.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"cloudfront:*"}, "*")))
	for _, path := range []string{
		"response-headers-policy/" + refs[cfRHPType],
		"origin-access-control/" + refs[cfOACType],
		"distribution/" + refs[cloudFrontDistributionType],
	} {
		if w := cfGet(f, tester, path); w.Code != http.StatusOK {
			t.Errorf("GET %s with cloudfront:* = %d %.200s", path, w.Code, w.Body.String())
		}
	}
	f.door.authz = checkerInMode(t, "enforce")
	if w := cfGet(f, tester, "response-headers-policy/"+refs[cfRHPType]); w.Code != http.StatusForbidden {
		t.Errorf("GetResponseHeadersPolicy with no policy = %d", w.Code)
	}

	h, arn := acmFixture(t, denyAll, true)
	h.cfn.authz = checkerInMode(t, "enforce", userDoc(dpAllow([]string{"acm:*"}, "*")))
	if code, out := acmCall(h, tester, "DescribeCertificate", `{"CertificateArn":"`+arn+`"}`); code != 200 {
		t.Errorf("DescribeCertificate with acm:* = %d %v", code, out)
	}
	if code, out := acmCall(h, tester, "ListCertificates", `{}`); code != 200 || len(out["CertificateSummaryList"].([]any)) != 1 {
		t.Errorf("ListCertificates with acm:* = %d %v", code, out)
	}
	h.cfn.authz = checkerInMode(t, "enforce")
	if code, _ := acmCall(h, tester, "DescribeCertificate", `{"CertificateArn":"`+arn+`"}`); code != http.StatusBadRequest && code != http.StatusForbidden {
		t.Errorf("DescribeCertificate with no policy = %d", code)
	}
}
