package main

// CloudFront's distributions and ACM's certificates are their stacks', and a stack is its account's
// (cfn_accounts.go): a member account finds its own stacks' alone, under ARNs naming its account, and keeps
// its invalidations with its own records; the management account never sees a member account's. A
// WaitConditionHandle URL names its stack in its own account.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

// memberRecords is the record store of the member account's records, as the CloudFormation front door keeps
// them in the shim's namespace.
func memberRecords(dyn dynamic.Interface) recordStore {
	return recordStore{dyn: dyn, ns: shimNS, secret: true, account: testMember}
}

// seedMemberRecord writes a member account's stack record (its name, label and namespace its account's).
func seedMemberRecord(t *testing.T, dyn dynamic.Interface, rec cfn.StackRecord) {
	t.Helper()
	data, _ := json.Marshal(rec)
	st := memberRecords(dyn)
	obj := st.object("cfn-stack-"+rec.Name, map[string]any{"app.kubernetes.io/managed-by": "cfn", "cfn.openinfra.dev/stack": rec.Name}, nil,
		map[string]string{"stack.json": string(data)})
	if _, err := st.client().Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// cfMember calls the CloudFront front door as the member account's bob.
func cfMember(f *cfFixture, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://cloudfront/2020-05-31/"+path, strings.NewReader(body)).WithContext(inAccountScope(memberCtx()))
	w := httptest.NewRecorder()
	f.h.serve(w, r, bobClaims, "r")
	return w
}

const cfMemberDist = "EMEMBER0000001"

func TestCloudFrontAccounts_EachAccountsDistributions(t *testing.T) {
	f := newCFFixture(t, allowAll)
	f.door.account = "000000000000"
	f.door.authz = doorAccountsAuthz(t)
	seedMemberRecord(t, f.dyn, cfn.StackRecord{Name: cfTestStack, Namespace: memberHome, StackID: memberStackID(cfTestStack), Status: "CREATE_COMPLETE",
		Resources: []cfn.StackResource{{LogicalID: "Cdn", APIVersion: "openinfra.dev/v1", Kind: "StaticSite", Name: cfTestSite,
			Type: cloudFrontDistributionType, PhysicalID: cfMemberDist}}})
	alice := iam.Claims{Sub: "alice"}

	// Each account lists its own stacks' distributions, under ARNs naming its account.
	w := cfMember(f, http.MethodGet, "distribution", "")
	if b := w.Body.String(); w.Code != 200 || !strings.Contains(b, "<Id>"+cfMemberDist+"</Id>") || strings.Contains(b, cfTestDist) ||
		!strings.Contains(b, "arn:aws:cloudfront::"+testMember+":distribution/"+cfMemberDist) {
		t.Fatalf("member ListDistributions: %d %s", w.Code, b)
	}
	w = cfGet(f, alice, "distribution")
	if b := w.Body.String(); w.Code != 200 || !strings.Contains(b, "<Id>"+cfTestDist+"</Id>") || strings.Contains(b, cfMemberDist) ||
		!strings.Contains(b, "arn:aws:cloudfront::000000000000:distribution/"+cfTestDist) {
		t.Fatalf("management ListDistributions: %d %s", w.Code, b)
	}
	// Neither reaches the other's distribution.
	if w := cfMember(f, http.MethodGet, "distribution/"+cfTestDist, ""); w.Code != 404 {
		t.Fatalf("a member account read the management account's distribution: %d %s", w.Code, w.Body.String())
	}
	if w := cfGet(f, alice, "distribution/"+cfMemberDist); w.Code != 404 {
		t.Fatalf("the management account read a member account's distribution: %d %s", w.Code, w.Body.String())
	}
	if w := cfMember(f, http.MethodPost, "distribution/"+cfTestDist+"/invalidation", cfBatch("x", "/*")); w.Code != 404 {
		t.Fatalf("a member account invalidated the management account's distribution: %d %s", w.Code, w.Body.String())
	}
	// A member account's invalidation is kept with its own records.
	if w := cfMember(f, http.MethodPost, "distribution/"+cfMemberDist+"/invalidation", cfBatch("ref-1", "/*")); w.Code != 201 {
		t.Fatalf("member CreateInvalidation: %d %s", w.Code, w.Body.String())
	}
	ctx := context.Background()
	if _, err := memberRecords(f.dyn).client().Get(ctx, invalidationsRecordName(cfTestStack), metav1.GetOptions{}); err != nil {
		t.Fatalf("the member account's invalidations record: %v", err)
	}
	if _, err := f.door.recs().client().Get(ctx, invalidationsRecordName(cfTestStack), metav1.GetOptions{}); err == nil {
		t.Fatal("a member account's invalidation was kept with the management account's records")
	}
	if w := cfGet(f, alice, "distribution/"+cfTestDist+"/invalidation"); w.Code != 200 || strings.Contains(w.Body.String(), "<Id>I") {
		t.Fatalf("the management account's distribution lists none of a member account's invalidations: %d %s", w.Code, w.Body.String())
	}
}

// seedMemberTemplateStack records, in the member account, the lift-and-shift stack the management fixture
// has: its own instance (a StackId naming the member account), its CloudFront and ACM Refs its own.
func seedMemberTemplateStack(t *testing.T, dyn dynamic.Interface) map[string]string {
	t.Helper()
	tmpl, err := os.ReadFile("../../../cfn/testdata/lift-and-shift/template.yaml")
	if err != nil {
		t.Fatal(err)
	}
	id := memberStackID("fixture")
	trs, err := cfn.TemplateResourcesForStack(tmpl, cfFixtureParams, nil, "fixture", id, cloudFrontDistributionType, acmCertificateType)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string]string{}
	for _, tr := range trs {
		refs[tr.Type] = tr.Ref
	}
	seedMemberRecord(t, dyn, cfn.StackRecord{Name: "fixture", Namespace: memberHome, StackID: id, Status: "CREATE_COMPLETE",
		Template: string(tmpl), Parameters: cfFixtureParams, CreatedAt: "2026-11-01T10:00:00Z", UpdatedAt: "2026-11-02T10:00:00Z",
		Resources: []cfn.StackResource{{LogicalID: "SiteDistribution", APIVersion: "openinfra.dev/v1", Kind: "StaticSite", Name: "fixture-site",
			Type: cloudFrontDistributionType, PhysicalID: refs[cloudFrontDistributionType],
			Spec: map[string]any{"domain": "site.example.test", "bucket": "fixture-site", "spa": true, "indexDocument": "index.html"}}}})
	return refs
}

func acmMember(h *acmHandler, op, body string) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, "http://acm/", strings.NewReader(body)).WithContext(inAccountScope(memberCtx()))
	req.Header.Set("X-Amz-Target", "CertificateManager."+op)
	w := httptest.NewRecorder()
	h.serve(w, req, bobClaims, "r")
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func listedCertificates(out map[string]any) []string {
	var arns []string
	l, _ := out["CertificateSummaryList"].([]any)
	for _, e := range l {
		arns = append(arns, fnStr(e.(map[string]any)["CertificateArn"]))
	}
	return arns
}

func TestACMAccounts_EachAccountsCertificates(t *testing.T) {
	h, mgmtARN := acmFixture(t, allowAll, true)
	refs := seedMemberTemplateStack(t, h.cfn.shimDyn)
	memberARN := refs[acmCertificateType]
	if !strings.Contains(memberARN, ":"+testMember+":certificate/") || memberARN == mgmtARN {
		t.Fatalf("the member account's stack's certificate ARN names its account: %s (management's %s)", memberARN, mgmtARN)
	}
	h.cfn.authz = doorAccountsAuthz(t)
	alice := iam.Claims{Sub: "alice"}

	if code, out := acmMember(h, "ListCertificates", `{}`); code != 200 || strings.Join(listedCertificates(out), ",") != memberARN {
		t.Fatalf("member ListCertificates lists its own certificate alone: %d %v", code, out)
	}
	if code, out := acmCall(h, alice, "ListCertificates", `{}`); code != 200 || strings.Join(listedCertificates(out), ",") != mgmtARN {
		t.Fatalf("management ListCertificates lists its own certificate alone: %d %v", code, out)
	}
	code, out := acmMember(h, "DescribeCertificate", `{"CertificateArn":"`+memberARN+`"}`)
	c, _ := out["Certificate"].(map[string]any)
	inUse, _ := c["InUseBy"].([]any)
	if code != 200 || len(inUse) != 1 || inUse[0] != "arn:aws:cloudfront::"+testMember+":distribution/"+refs[cloudFrontDistributionType] {
		t.Fatalf("member DescribeCertificate: its distribution named in its account: %d %v", code, out)
	}
	if code, out := acmMember(h, "DescribeCertificate", `{"CertificateArn":"`+mgmtARN+`"}`); code != 400 || out["__type"] != "ResourceNotFoundException" {
		t.Fatalf("a member account described the management account's certificate: %d %v", code, out)
	}
	if code, out := acmCall(h, alice, "DescribeCertificate", `{"CertificateArn":"`+memberARN+`"}`); code != 400 || out["__type"] != "ResourceNotFoundException" {
		t.Fatalf("the management account described a member account's certificate: %d %v", code, out)
	}
}

// A WaitConditionHandle URL of a member account's stack names the stack by its account key, under a
// signature that covers it: a PUT to it signals that stack, in that account, and no rewriting of the URL
// reaches the management account's stack of the same name.
func TestCFNAccounts_WaitConditionHandleNamesItsAccount(t *testing.T) {
	fa := newFakeAPI()
	h := opsDoorway(t, fa, "aws-shim/0001")
	h.accounts = testDirectory()
	h.signals = &signalStore{h: h}
	h.signalBase = "https://shim.example:4567"
	seedMemberStack(fa, cfn.StackRecord{Name: "web", Namespace: memberHome, StackID: memberStackID("web"), Status: "CREATE_IN_PROGRESS"}, nil)
	seedStack(fa, cfn.StackRecord{Name: "web", Status: "CREATE_IN_PROGRESS"}, nil)
	mgmtURL, memberURL := h.signalURL("web", "Handle"), h.signalURLIn(testMember, "web", "Handle")
	if !strings.HasPrefix(mgmtURL, "https://shim.example:4567/cfn-signal/web/Handle?sig=") {
		t.Fatalf("the management account's handle URL is as it always was: %s", mgmtURL)
	}
	if !strings.HasPrefix(memberURL, "https://shim.example:4567/cfn-signal/"+testMember+":web/Handle?sig=") {
		t.Fatalf("a member account's handle URL names its stack in its account: %s", memberURL)
	}
	if opts := h.opts(inAccountScope(memberCtx()), "web", nil); opts.SignalURL("web", "Handle") != memberURL || opts.Namespace != memberHome {
		t.Fatalf("a member account's stack is given its account's handle URLs and namespace: %s %s", opts.SignalURL("web", "Handle"), opts.Namespace)
	}
	srv := h.waitConditionHandler(http.NotFoundHandler())
	put := func(target string) int {
		pu, _ := url.Parse(target)
		req := httptest.NewRequest(http.MethodPut, pu.RequestURI(), strings.NewReader(`{"Status":"SUCCESS","UniqueId":"i-1","Data":"ready"}`))
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code
	}
	if code := put(memberURL); code != http.StatusOK {
		t.Fatalf("a signed PUT to a member account's handle: %d", code)
	}
	if code := put(strings.Replace(memberURL, testMember+":web", "web", 1)); code != http.StatusForbidden {
		t.Fatalf("a member account's signature reached the management account's stack: %d", code)
	}
	if code := put(strings.Replace(memberURL, testMember+":", "923456789012:", 1)); code != http.StatusForbidden {
		t.Fatalf("a member account's signature reached another account's stack: %d", code)
	}
	mctx := inAccount(context.Background(), testMember, memberHome)
	if sigs, _ := h.signals.Signals(mctx, "web", "Handle"); len(sigs) != 1 || sigs[0].Data != "ready" {
		t.Fatalf("the member account's stack received its signal: %+v", sigs)
	}
	if sigs, _ := h.signals.Signals(context.Background(), "web", "Handle"); len(sigs) != 0 {
		t.Fatalf("the management account's stack of the same name received a member account's signal: %+v", sigs)
	}
	if o := fa.get("secrets", shimNS, testMember+"-cfn-signals-web"); o == nil {
		t.Fatal("the member account's signals are kept with its own records")
	} else if l := (&unstructured.Unstructured{Object: o}).GetLabels(); l[labelRecordAccount] != testMember {
		t.Fatalf("the member account's signals record is labelled its account's: %v", l)
	}
}
