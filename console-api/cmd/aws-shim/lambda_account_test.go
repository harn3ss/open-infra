package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/dataplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/policyengine"
	"k8s.io/apimachinery/pkg/runtime"
)

// lambdaTestAccounts is an account directory for the locator: the member account's namespaces.
type lambdaTestAccounts map[string][]string

func (d lambdaTestAccounts) NamespacesOf(account string) []string { return d[account] }
func (d lambdaTestAccounts) Known(account string) bool {
	_, ok := d[account]
	return ok || awsidentity.Current().IsManagement(account)
}

// lambdaMemberData is the member account's second namespace.
const lambdaMemberData = memberHome + "-data"

// lambdaDirectory knows the test member account (its home and a second namespace) and, mislabeled, the
// Lambda API's own namespace: a label never hands a member account the management account's namespace.
func lambdaDirectory() lambdaTestAccounts {
	return lambdaTestAccounts{testMember: {lambdaMemberData, memberHome, "default"}}
}

// lambdaMemberReq is r as the router hands a member account's request to an account-scoped door.
func lambdaMemberReq(r *http.Request) *http.Request {
	ctx := withAccountHome(r.Context(), memberHome)
	ctx = awsidentity.WithIdentity(ctx, awsidentity.Current().ForAccount(testMember, memberHome))
	return r.WithContext(inAccountScope(ctx))
}

// lambdaMemberClaims is the member account's bob, whom lambdaMemberAuthz lets use Lambda.
var lambdaMemberClaims = iam.Claims{Sub: "bob", Account: testMember}

func lambdaMemberAuthz(t *testing.T) *dataplaneauthz.Checker {
	t.Helper()
	return checkerInMode(t, "legacy", dataplaneauthz.PolicyDoc{Name: "fn", AppliesTo: []string{"User::" + memberHome + "/bob"},
		Statements: []policyengine.Statement{dpAllow([]string{"lambda:*"}, "*")}})
}

// lambdaTwoAccounts is a Lambda front door over the management account's functions (default and the
// stack namespace) and the member account's (its home and its second namespace). Both accounts have an
// "orders"; each has one the other lacks.
func lambdaTwoAccounts(t *testing.T) *lambdaHandler {
	t.Helper()
	mgmtOrders := readFn("default", "orders")
	mgmtOrders.Object["spec"].(map[string]any)["memory"] = "512Mi"
	objs := []runtime.Object{mgmtOrders, readFn(testCFNNamespace, "mgmt-only"),
		readFn(memberHome, "orders"), readFn(lambdaMemberData, "member-only")}
	h := readLambda(allowAll, objs...)
	h.fns.accounts = lambdaDirectory()
	h.authz = lambdaMemberAuthz(t)
	return h
}

func lambdaMemberGet(h *lambdaHandler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.serve(w, lambdaMemberReq(httptest.NewRequest(http.MethodGet, "http://lambda"+path, nil)), lambdaMemberClaims, "r-m")
	return w
}

func lambdaConfigOf(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out struct{ Configuration map[string]any }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	return out.Configuration
}

// A member account's functions are in its own namespaces — its home first — and never in the management
// account's, even one a label puts in the member account; the management account's are unchanged.
func TestFnLocator_MemberAccountNamespaces(t *testing.T) {
	l := newFnLocator(fnDyn(), discardLogger(), "default", testCFNNamespace)
	l.accounts = lambdaDirectory()
	if got := l.namespacesFor(context.Background()); !slices.Equal(got, []string{"default", testCFNNamespace}) {
		t.Errorf("the management account's namespaces = %v", got)
	}
	member := lambdaMemberReq(httptest.NewRequest(http.MethodGet, "/", nil)).Context()
	if got := l.namespacesFor(member); !slices.Equal(got, []string{memberHome, lambdaMemberData}) {
		t.Errorf("the member account's namespaces = %v, want its home then its other namespace", got)
	}
	l.accounts = nil
	if got := l.namespacesFor(member); !slices.Equal(got, []string{memberHome}) {
		t.Errorf("without a directory the member account's namespaces = %v, want its home", got)
	}
	noHome := awsidentity.WithIdentity(context.Background(), awsidentity.Current().ForAccount(testMember, ""))
	if got := l.namespacesFor(noHome); len(got) != 0 {
		t.Errorf("a member request with no home and no directory has namespaces %v", got)
	}
	if got := l.namespaceFor(noHome, "orders", "default"); got != noFnNamespace {
		t.Errorf("a member account with no namespace locates a function in %q", got)
	}
	var nilL *fnLocator
	if got := nilL.namespaceFor(member, "orders", "default"); got != memberHome {
		t.Errorf("a nil locator locates a member account's function in %q, want its home", got)
	}
}

// namespaceFor finds the request's account's function: a member account's in its namespaces, never the
// management account's of the same name (not found, it is looked for in the member's home); the
// management account's exactly as namespaceOf does. Answers are remembered per account.
func TestFnLocator_NamespaceForTheRequestsAccount(t *testing.T) {
	dyn := fnDyn(fnClaim("default", "orders"), fnClaim(testCFNNamespace, "mgmt-only"), fnClaim(lambdaMemberData, "orders"))
	l := newFnLocator(dyn, discardLogger(), "default", testCFNNamespace)
	l.accounts = lambdaDirectory()
	mgmt := context.Background()
	member := lambdaMemberReq(httptest.NewRequest(http.MethodGet, "/", nil)).Context()
	if got := l.namespaceFor(member, "orders", "default"); got != lambdaMemberData {
		t.Errorf("the member's orders = %q, want %q", got, lambdaMemberData)
	}
	if got := l.namespaceFor(mgmt, "orders", "default"); got != "default" {
		t.Errorf("the management account's orders = %q", got)
	}
	if got := l.namespaceFor(member, "mgmt-only", "default"); got != memberHome {
		t.Errorf("a function only the management account has resolves for the member to %q, want its home", got)
	}
	if got := l.namespaceFor(mgmt, "mgmt-only", "default"); got != testCFNNamespace {
		t.Errorf("the management account's mgmt-only = %q", got)
	}
	// The two accounts' remembered answers are apart: no name is taken for another account's key.
	if _, ok := l.cache[testMember+":orders"]; ok {
		t.Error("the member's answer was remembered among the management account's")
	}
	if c, ok := l.memberCache[testMember+":orders"]; !ok || c.ns != lambdaMemberData {
		t.Errorf("the member's answer is not remembered as its own: %+v %v", c, ok)
	}
	if got := l.namespaceOf(mgmt, testMember+":orders", "default"); got != "default" {
		t.Errorf("a management lookup of the member's cache key = %q, want the fallback", got)
	}
	// elsewhereFor and forgetFor are the account's own.
	if got, err := l.elsewhereFor(member, "orders", memberHome); err != nil || got != lambdaMemberData {
		t.Errorf("elsewhereFor(member) = %q %v", got, err)
	}
	if got, _ := l.elsewhereFor(member, "mgmt-only", memberHome); got != "" {
		t.Errorf("the management account's function is no collision for the member: %q", got)
	}
	if got, _ := l.elsewhere(mgmt, "orders", testCFNNamespace); got != "default" {
		t.Errorf("elsewhere (management) = %q", got)
	}
	_ = dyn.Tracker().Create(functionClaimGVR, fnClaim(memberHome, "fresh"), memberHome)
	if got := l.namespaceFor(member, "fresh", "default"); got != memberHome {
		t.Fatalf("fresh = %q", got)
	}
	_ = dyn.Tracker().Delete(functionClaimGVR, memberHome, "fresh")
	_ = dyn.Tracker().Create(functionClaimGVR, fnClaim(lambdaMemberData, "fresh"), lambdaMemberData)
	l.forgetFor(member, "fresh")
	if got := l.namespaceFor(member, "fresh", "default"); got != lambdaMemberData {
		t.Errorf("after forgetFor the member's moved function = %q", got)
	}
}

// A member account reads its own function (its ARN carrying the member account); the management
// account's function of the same name is untouched and invisible to it, and the management account reads
// its own as before.
func TestLambdaAccounts_GetFunction(t *testing.T) {
	h := lambdaTwoAccounts(t)
	w := lambdaMemberGet(h, "/2015-03-31/functions/orders")
	c := lambdaConfigOf(t, w)
	if w.Code != http.StatusOK || c["FunctionArn"] != "arn:aws:lambda:us-east-1:"+testMember+":function:orders" || c["MemorySize"] != float64(1024) {
		t.Fatalf("the member's GetFunction = %d %v", w.Code, c)
	}
	w = lambdaGet(h, "/2015-03-31/functions/orders", iam.Claims{Sub: "u"})
	c = lambdaConfigOf(t, w)
	if w.Code != http.StatusOK || c["FunctionArn"] != "arn:aws:lambda:us-east-1:000000000000:function:orders" || c["MemorySize"] != float64(512) {
		t.Fatalf("the management account's GetFunction = %d %v", w.Code, c)
	}
	// Each account's own function is invisible to the other.
	w = lambdaMemberGet(h, "/2015-03-31/functions/mgmt-only/configuration")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "arn:aws:lambda:us-east-1:"+testMember+":function:mgmt-only") {
		t.Errorf("the member reading the management account's function = %d %s, want its own not found", w.Code, w.Body.String())
	}
	if w := lambdaGet(h, "/2015-03-31/functions/member-only", iam.Claims{Sub: "u"}); w.Code != http.StatusNotFound {
		t.Errorf("the management account reading the member's function = %d, want 404", w.Code)
	}
	w = lambdaMemberGet(h, "/2015-03-31/functions/member-only")
	if w.Code != http.StatusOK || lambdaConfigOf(t, w)["FunctionArn"] != "arn:aws:lambda:us-east-1:"+testMember+":function:member-only" {
		t.Errorf("the member's function in its second namespace = %d %s", w.Code, w.Body.String())
	}
	// The member's own ARN names its function.
	w = lambdaMemberGet(h, "/2015-03-31/functions/arn%3Aaws%3Alambda%3Aus-east-1%3A"+testMember+"%3Afunction%3Aorders")
	if w.Code != http.StatusOK || lambdaConfigOf(t, w)["MemorySize"] != float64(1024) {
		t.Errorf("the member's GetFunction by its ARN = %d %s", w.Code, w.Body.String())
	}
	// A member account's principal is decided by its own IAM policy: one without a grant is refused.
	w = httptest.NewRecorder()
	h.serve(w, lambdaMemberReq(httptest.NewRequest(http.MethodGet, "http://lambda/2015-03-31/functions/orders", nil)),
		iam.Claims{Sub: "eve", Account: testMember}, "r-e")
	if w.Code != http.StatusForbidden {
		t.Errorf("a member principal with no policy = %d, want 403", w.Code)
	}
}

// ListFunctions lists the caller's account's functions alone.
func TestLambdaAccounts_ListFunctions(t *testing.T) {
	h := lambdaTwoAccounts(t)
	names := func(w *httptest.ResponseRecorder) []string {
		t.Helper()
		var out struct{ Functions []map[string]any }
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("ListFunctions = %d %s", w.Code, w.Body.String())
		}
		var got []string
		for _, f := range out.Functions {
			got = append(got, f["FunctionName"].(string)+"@"+strings.Split(f["FunctionArn"].(string), ":")[4])
		}
		slices.Sort(got)
		return got
	}
	if got := names(lambdaMemberGet(h, "/2015-03-31/functions/")); !slices.Equal(got, []string{"member-only@" + testMember, "orders@" + testMember}) {
		t.Errorf("the member's ListFunctions = %v", got)
	}
	if got := names(lambdaGet(h, "/2015-03-31/functions/", iam.Claims{Sub: "u"})); !slices.Equal(got, []string{"mgmt-only@000000000000", "orders@000000000000"}) {
		t.Errorf("the management account's ListFunctions = %v", got)
	}
	// A page boundary stays within the member's namespaces.
	w := lambdaMemberGet(h, "/2015-03-31/functions/?MaxItems=1")
	var page struct {
		Functions  []map[string]any
		NextMarker string
	}
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Functions) != 1 || page.NextMarker == "" {
		t.Fatalf("first page = %s", w.Body.String())
	}
	w = lambdaMemberGet(h, "/2015-03-31/functions/?MaxItems=5&Marker="+page.NextMarker)
	var rest struct{ Functions []map[string]any }
	_ = json.Unmarshal(w.Body.Bytes(), &rest)
	if len(rest.Functions) != 1 || rest.Functions[0]["FunctionName"] == page.Functions[0]["FunctionName"] ||
		!strings.Contains(rest.Functions[0]["FunctionArn"].(string), ":"+testMember+":") {
		t.Errorf("second page = %s", w.Body.String())
	}
}

// A member account invokes its own function, where it lives; the management account's of the same name
// is not invoked.
func TestLambdaAccounts_Invoke(t *testing.T) {
	h := lambdaTwoAccounts(t)
	ct := &captureTransport{}
	h.client = &http.Client{Transport: ct}
	invoke := func(member bool, ref string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "http://lambda/2015-03-31/functions/"+ref+"/invocations", strings.NewReader("{}"))
		claims := iam.Claims{Sub: "u"}
		if member {
			r, claims = lambdaMemberReq(r), lambdaMemberClaims
		}
		w := httptest.NewRecorder()
		h.serve(w, r, claims, "r-i")
		return w
	}
	if w := invoke(true, "orders"); w.Code != http.StatusOK {
		t.Fatalf("the member's invoke = %d %s", w.Code, w.Body.String())
	}
	if w := invoke(false, "orders"); w.Code != http.StatusOK {
		t.Fatalf("the management account's invoke = %d %s", w.Code, w.Body.String())
	}
	if w := invoke(true, "member-only"); w.Code != http.StatusOK {
		t.Fatalf("the member's invoke in its second namespace = %d %s", w.Code, w.Body.String())
	}
	want := []string{"orders." + memberHome + ".svc.cluster.local", "orders.default.svc.cluster.local",
		"member-only." + lambdaMemberData + ".svc.cluster.local"}
	if !slices.Equal(ct.hosts, want) {
		t.Errorf("invokes went to %v, want %v", ct.hosts, want)
	}
	// A member's invoke of a name only the management account has is looked for in the member's home,
	// never in the management account's namespace.
	ct.hosts = nil
	_ = invoke(true, "mgmt-only")
	if len(ct.hosts) != 1 || ct.hosts[0] != "mgmt-only."+memberHome+".svc.cluster.local" {
		t.Errorf("the member invoking a name only the management account has went to %v", ct.hosts)
	}
}

// A FunctionName that is another account's ARN is refused as AWS refuses a cross-account call no
// resource-based policy allows; the caller's own function of the same name is never taken for it. The
// management account is refused an ARN naming a member account, and keeps resolving an ARN that carries
// any other account to its own function, as before accounts.
func TestLambdaAccounts_AnotherAccountsARN(t *testing.T) {
	h := lambdaTwoAccounts(t)
	ct := &captureTransport{}
	h.client = &http.Client{Transport: ct}
	arn := func(acct, name string) string {
		return strings.ReplaceAll("arn:aws:lambda:us-east-1:"+acct+":function:"+name, ":", "%3A")
	}
	call := func(member bool, method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://lambda"+path, strings.NewReader("{}"))
		claims := iam.Claims{Sub: "u"}
		if member {
			r, claims = lambdaMemberReq(r), lambdaMemberClaims
		}
		w := httptest.NewRecorder()
		h.serve(w, r, claims, "r-x")
		return w
	}
	denied := func(name string, w *httptest.ResponseRecorder, action string) {
		t.Helper()
		if w.Code != http.StatusForbidden || w.Header().Get("x-amzn-errortype") != "AccessDeniedException" ||
			!strings.Contains(w.Body.String(), "because no resource-based policy allows the "+action+" action") {
			t.Errorf("%s = %d %s %s, want AccessDeniedException (no resource-based policy)", name, w.Code, w.Header().Get("x-amzn-errortype"), w.Body.String())
		}
	}
	denied("member GetFunction of the management account's ARN",
		call(true, http.MethodGet, "/2015-03-31/functions/"+arn("000000000000", "orders")), "lambda:GetFunction")
	denied("member Invoke of the management account's ARN",
		call(true, http.MethodPost, "/2015-03-31/functions/"+arn("000000000000", "orders")+"/invocations"), "lambda:InvokeFunction")
	denied("member Invoke of another member's partial ARN",
		call(true, http.MethodPost, "/2015-03-31/functions/955555555555%3Afunction%3Aorders/invocations"), "lambda:InvokeFunction")
	denied("management GetFunctionConfiguration of the member's ARN",
		call(false, http.MethodGet, "/2015-03-31/functions/"+arn(testMember, "orders")+"/configuration"), "lambda:GetFunctionConfiguration")
	denied("management Invoke of the member's ARN",
		call(false, http.MethodPost, "/2015-03-31/functions/"+arn(testMember, "orders")+"/invocations"), "lambda:InvokeFunction")
	if len(ct.hosts) != 0 {
		t.Errorf("a refused cross-account invoke reached %v", ct.hosts)
	}
	// An ARN carrying an account no directory knows names the management account's function, as it did.
	if w := call(false, http.MethodGet, "/2015-03-31/functions/"+arn("123456789012", "orders")); w.Code != http.StatusOK ||
		lambdaConfigOf(t, w)["MemorySize"] != float64(512) {
		t.Errorf("the management account's GetFunction by an ARN of an unknown account = %d %s", w.Code, w.Body.String())
	}
}

// functionRefAccount reads the account of an ARN or partial ARN, and none from a bare name.
func TestFunctionRefAccount(t *testing.T) {
	for in, want := range map[string]string{
		"orders":      "",
		"orders:live": "",
		"arn:aws:lambda:us-east-1:" + testMember + ":function:orders":      testMember,
		"arn:aws:lambda:us-east-1:" + testMember + ":function:orders:live": testMember,
		testMember + ":function:orders":                                    testMember,
		"arn:aws:lambda:us-east-1:open-infra:function:orders":              "",
		"12345:function:orders":                                            "",
	} {
		if got := functionRefAccount(in); got != want {
			t.Errorf("functionRefAccount(%q) = %q, want %q", in, got, want)
		}
	}
}

// A member account's asynchronous invocation rides its own subject and names its account, so its
// dead-letter is its own; the management account's is exactly as before.
func TestAsyncInvoker_AccountSubjects(t *testing.T) {
	m := asyncMsg("", "orders", "default", "application/json", []byte("{}"), "r-1")
	if m.Subject != "lambda.async.orders" || m.Header.Get("X-Fn-Account") != "" || m.Header.Get("X-Fn-Namespace") != "default" {
		t.Errorf("the management account's message: %s %v", m.Subject, m.Header)
	}
	if m := asyncMsg(awsidentity.Current().AccountID, "orders", "", "", nil, ""); m.Subject != "lambda.async.orders" || m.Header.Get("X-Fn-Account") != "" {
		t.Errorf("the management account named outright: %s %v", m.Subject, m.Header)
	}
	m = asyncMsg(testMember, "orders", memberHome, "", []byte("{}"), "")
	if m.Subject != "lambda.async."+testMember+".orders" || m.Header.Get("X-Fn-Account") != testMember || m.Header.Get("X-Fn-Namespace") != memberHome {
		t.Errorf("the member account's message: %s %v", m.Subject, m.Header)
	}
	if !strings.HasPrefix(m.Subject, strings.TrimSuffix(asyncSubjectAll, ">")) {
		t.Errorf("the member's subject %q is not under the work stream %q", m.Subject, asyncSubjectAll)
	}
	if got := asyncDLQSubject(dlqAccount(""), "orders"); got != "lambda.dlq.orders" {
		t.Errorf("the management account's dead-letter subject = %q", got)
	}
	if got := asyncDLQSubject(dlqAccount(testMember), "orders"); got != "lambda.dlq."+testMember+".orders" {
		t.Errorf("the member account's dead-letter subject = %q", got)
	}
	if got := asyncDLQSubject(dlqAccount("bad.acct"), "orders"); got != "lambda.dlq.unknown.orders" {
		t.Errorf("a malformed account's dead-letter subject = %q", got)
	}
	for _, s := range []string{asyncDLQSubject(testMember, "orders"), asyncDLQSubject("", "orders")} {
		if !strings.HasPrefix(s, strings.TrimSuffix(asyncDLQAll, ">")) || strings.HasPrefix(s, asyncSubjectPre) {
			t.Errorf("dead-letter subject %q must be under %q and not the work subject", s, asyncDLQAll)
		}
	}
}

// Lambda is an account-scoped front door.
func TestLambda_AccountScoped(t *testing.T) {
	if !accountScopedServices["lambda"] {
		t.Error("lambda is not registered as account-scoped")
	}
}
