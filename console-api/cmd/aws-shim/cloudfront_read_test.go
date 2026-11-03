package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var cfFixtureParams = map[string]string{"SiteDomain": "site.example.test", "AppRepositoryName": "fixture-app",
	"SesSenderAddress": "app@example.test"}

// seedTemplateStack records stack "fixture", deployed from the lift-and-shift template, whose
// distribution is the StaticSite fixture-site; it returns the Refs the stack's CloudFront resources got.
func (f *cfFixture) seedTemplateStack(t *testing.T) map[string]string {
	t.Helper()
	tmpl, err := os.ReadFile("../../../cfn/testdata/lift-and-shift/template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	trs, err := cfn.TemplateResources(tmpl, cfFixtureParams, nil, "fixture", cloudFrontDistributionType, cfOACType, cfRHPType)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]string{}
	for _, tr := range trs {
		refs[tr.Type] = tr.Ref
	}
	rec := cfn.StackRecord{Name: "fixture", Namespace: opsNS, Status: "CREATE_COMPLETE", Template: string(tmpl), Parameters: cfFixtureParams,
		CreatedAt: "2026-11-01T10:00:00Z", UpdatedAt: "2026-11-02T10:00:00Z",
		Resources: []cfn.StackResource{{LogicalID: "SiteDistribution", APIVersion: "openinfra.dev/v1", Kind: "StaticSite", Name: "fixture-site",
			Type: cloudFrontDistributionType, PhysicalID: refs[cloudFrontDistributionType],
			Spec: map[string]any{"domain": "site.example.test", "bucket": "fixture-site", "spa": true, "indexDocument": "index.html"}}}}
	data, _ := json.Marshal(rec)
	obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata": map[string]any{"name": "cfn-stack-fixture", "namespace": shimNS,
			"labels": map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": "fixture"}},
		"data": map[string]any{"stack.json": base64.StdEncoding.EncodeToString(data)}}}
	if _, err := f.dyn.Resource(secretGVR).Namespace(shimNS).Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	return refs
}

func cfGet(f *cfFixture, claims iam.Claims, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.h.serve(w, httptest.NewRequest(http.MethodGet, "http://cloudfront/2020-05-31/"+path, nil), claims, "r")
	return w
}

func TestParseCFRoute_Reads(t *testing.T) {
	for path, want := range map[string]cfRoute{
		"/2020-05-31/distribution":                         {op: "ListDistributions"},
		"/2020-05-31/distribution/E1":                      {op: "GetDistribution", distID: "E1"},
		"/2020-05-31/distribution/E1/config":               {op: "GetDistributionConfig", distID: "E1"},
		"/2020-05-31/cache-policy/p-1":                     {op: "GetCachePolicy", resID: "p-1"},
		"/2020-05-31/origin-request-policy/p-1":            {op: "GetOriginRequestPolicy", resID: "p-1"},
		"/2020-05-31/response-headers-policy/p-1":          {op: "GetResponseHeadersPolicy", resID: "p-1"},
		"/2020-05-31/origin-access-control/E2":             {op: "GetOriginAccessControl", resID: "E2"},
		"/2020-05-31/origin-access-identity/cloudfront/E3": {op: "GetCloudFrontOriginAccessIdentity", resID: "E3"},
		"/2020-05-31/distribution/E1/invalidation":         {op: "ListInvalidations", distID: "E1"},
		"/2020-05-31/distribution/E1/invalidation/I1":      {op: "GetInvalidation", distID: "E1", invID: "I1"},
	} {
		if got, ok := parseCFRoute(http.MethodGet, path); !ok || got != want {
			t.Errorf("GET %s = %+v %v, want %+v", path, got, ok, want)
		}
	}
}

// A stack's distribution reads back with the configuration the stack deployed — the ids of its own
// headers policy and origin access control, its certificate's ARN — and those read back by those ids.
func TestCloudFrontReads_TheStacksDistributionAndPolicies(t *testing.T) {
	f := newCFFixture(t, allowAll)
	refs := f.seedTemplateStack(t)
	dist := refs[cloudFrontDistributionType]
	u := iam.Claims{Sub: "u"}

	w := cfGet(f, u, "distribution/"+dist)
	var d struct {
		ID         string `xml:"Id"`
		Status     string `xml:"Status"`
		DomainName string `xml:"DomainName"`
		Config     struct {
			Aliases struct {
				Items []string `xml:"Items>CNAME"`
			} `xml:"Aliases"`
			DefaultRootObject string `xml:"DefaultRootObject"`
			Origins           []struct {
				ID  string `xml:"Id"`
				OAC string `xml:"OriginAccessControlId"`
			} `xml:"Origins>Items>Origin"`
			Behavior struct {
				Headers string `xml:"ResponseHeadersPolicyId"`
				Cache   string `xml:"CachePolicyId"`
			} `xml:"DefaultCacheBehavior"`
			Errors []struct {
				Code string `xml:"ErrorCode"`
			} `xml:"CustomErrorResponses>Items>CustomErrorResponse"`
			Cert string `xml:"ViewerCertificate>ACMCertificateArn"`
		} `xml:"DistributionConfig"`
	}
	if err := xml.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 {
		t.Fatalf("GetDistribution = %d %v %s", w.Code, err, w.Body)
	}
	if d.ID != dist || d.Status != "Deployed" || d.DomainName != "site.example.test" || len(d.Config.Aliases.Items) != 1 ||
		d.Config.DefaultRootObject != "index.html" || len(d.Config.Origins) != 1 || d.Config.Origins[0].OAC != refs[cfOACType] ||
		d.Config.Behavior.Headers != refs[cfRHPType] || d.Config.Behavior.Cache != "658327ea-f89d-4fab-a63d-7e88639e58f6" ||
		len(d.Config.Errors) != 2 || !strings.Contains(d.Config.Cert, ":certificate/") || w.Header().Get("ETag") == "" {
		t.Errorf("GetDistribution = %+v", d)
	}
	if w := cfGet(f, u, "distribution/"+dist+"/config"); w.Code != 200 || !strings.HasPrefix(strings.SplitN(w.Body.String(), "\n", 2)[1], "<DistributionConfig") {
		t.Errorf("GetDistributionConfig = %d %s", w.Code, w.Body)
	}

	w = cfGet(f, u, "response-headers-policy/"+refs[cfRHPType])
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<FrameOption>DENY</FrameOption>") ||
		!strings.Contains(w.Body.String(), "<Header>X-Fixture</Header>") || !strings.Contains(w.Body.String(), "<Name>fixture-site-headers</Name>") {
		t.Errorf("GetResponseHeadersPolicy = %d %s", w.Code, w.Body)
	}
	w = cfGet(f, u, "origin-access-control/"+refs[cfOACType])
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<SigningProtocol>sigv4</SigningProtocol>") || !strings.Contains(w.Body.String(), "<Name>fixture-site</Name>") {
		t.Errorf("GetOriginAccessControl = %d %s", w.Code, w.Body)
	}

	// ListDistributions lists both stacks' distributions, a page at a time.
	w = cfGet(f, u, "distribution?MaxItems=1")
	var l struct {
		NextMarker  string   `xml:"NextMarker"`
		IsTruncated bool     `xml:"IsTruncated"`
		IDs         []string `xml:"Items>DistributionSummary>Id"`
	}
	_ = xml.Unmarshal(w.Body.Bytes(), &l)
	if w.Code != 200 || len(l.IDs) != 1 || !l.IsTruncated || l.NextMarker != l.IDs[0] {
		t.Fatalf("ListDistributions page 1 = %d %s", w.Code, w.Body)
	}
	first := l.IDs[0]
	l.IDs = nil
	w = cfGet(f, u, "distribution?MaxItems=1&Marker="+first)
	_ = xml.Unmarshal(w.Body.Bytes(), &l)
	if len(l.IDs) != 1 || l.IDs[0] == first {
		t.Errorf("ListDistributions page 2 = %s", w.Body)
	}
}

func TestCloudFrontReads_NotFoundAndDenied(t *testing.T) {
	f := newCFFixture(t, allowAll)
	refs := f.seedTemplateStack(t)
	u := iam.Claims{Sub: "u"}
	for path, code := range map[string]string{
		"distribution/ENOPE":                         "NoSuchDistribution",
		"distribution/ENOPE/config":                  "NoSuchDistribution",
		"cache-policy/00000000-0000-0000-0000-00000": "NoSuchCachePolicy",
		"origin-access-control/ENOPE":                "NoSuchOriginAccessControl",
		"origin-access-identity/cloudfront/ENOPE":    "NoSuchCloudFrontOriginAccessIdentity",
		"origin-request-policy/nope":                 "NoSuchOriginRequestPolicy",
	} {
		if w := cfGet(f, u, path); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), code) {
			t.Errorf("GET %s = %d %s, want %s", path, w.Code, w.Body, code)
		}
	}

	// No get on the site / the stack: refused, and the listing leaves the site out.
	f = newCFFixture(t, func(a *authzv1.ResourceAttributes) bool { return a.Name != "fixture-site" && a.Name != "fixture" })
	refs = f.seedTemplateStack(t)
	dist := refs[cloudFrontDistributionType]
	if w := cfGet(f, u, "distribution/"+dist); w.Code != http.StatusForbidden {
		t.Errorf("GetDistribution without get on its site = %d", w.Code)
	}
	if w := cfGet(f, u, "response-headers-policy/"+refs[cfRHPType]); w.Code != http.StatusForbidden {
		t.Errorf("GetResponseHeadersPolicy without get on its stack = %d", w.Code)
	}
	if w := cfGet(f, u, "distribution"); w.Code != 200 || strings.Contains(w.Body.String(), dist) || !strings.Contains(w.Body.String(), cfTestDist) {
		t.Errorf("ListDistributions = %s, want only the site the caller may read", w.Body)
	}

	// The data plane: a Deny of the action on the resource; an assumed role needs a grant.
	f = newCFFixture(t, allowAll)
	refs = f.seedTemplateStack(t)
	f.door.authz = userPolicy(dpAllow([]string{"cloudfront:*"}, "*"), dpDeny([]string{"cloudfront:GetOriginAccessControl"}, "OriginAccessControl::"+refs[cfOACType]))
	if w := cfGet(f, testUser, "origin-access-control/"+refs[cfOACType]); w.Code != http.StatusForbidden {
		t.Errorf("GetOriginAccessControl under a Deny = %d", w.Code)
	}
	f.door.authz = roleChecker(dpAllow([]string{"cloudfront:GetDistribution"}, "Distribution::"+refs[cloudFrontDistributionType]))
	if w := cfGet(f, ecrRoleClaims(), "distribution/"+refs[cloudFrontDistributionType]); w.Code != 200 {
		t.Errorf("GetDistribution by a role granted it = %d %s", w.Code, w.Body)
	}
	if w := cfGet(f, ecrRoleClaims(), "distribution"); w.Code != http.StatusForbidden {
		t.Errorf("ListDistributions by a role not granted it = %d", w.Code)
	}
}
