package main

// Each account's API Gateway APIs, API keys and usage plans are its own (the store-backed tests run on a
// real Postgres, OPENINFRA_TEST_PG_URI; see cfn_services_pg_test.go): the same API name lives in both
// accounts independently, neither account reads, lists, changes or deletes the other's, and an invoke —
// unsigned — acts in the API's own account: its function is that account's, the proxy event names that
// account, and only that account's keys, plans and user pools unlock or authorize it.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/harn3ss/open-infra/cfn"
	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

func TestAPIGateway_IsAccountScoped(t *testing.T) {
	if !accountScopedServices["apigateway"] {
		t.Fatal("apigateway (REST v1 and HTTP v2 share the signing name) must be listed as account-scoped")
	}
}

func TestFnAccountOfURI(t *testing.T) {
	for uri, want := range map[string]string{
		"hello": "",
		"arn:aws:lambda:us-east-1:912345678901:function:hello":      testMember,
		"arn:aws:lambda:us-east-1:912345678901:function:hello:live": testMember,
		"912345678901:function:hello":                               testMember,
		"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:hello/invocations": testMgmt,
		"arn:aws:lambda:us-east-1::function:hello":    "",
		"arn:aws:lambda:us-east-1:abc:function:hello": "",
	} {
		if got := fnAccountOfURI(uri); got != want {
			t.Errorf("fnAccountOfURI(%q) = %q, want %q", uri, got, want)
		}
	}
}

// An API reaches its own account's functions: a member account's API never another account's, and the
// management account's never a member account's the directory knows — any other account an ARN carries
// still names the management account's function, as it always did.
func TestFnOfAnotherAccount(t *testing.T) {
	fns := newFnLocator(nil, discardLogger(), "default")
	fns.accounts = testDirectory()
	mgmt, member := context.Background(), memberCtx()
	for _, c := range []struct {
		ctx   context.Context
		uri   string
		other bool
	}{
		{mgmt, "hello", false},
		{mgmt, "arn:aws:lambda:us-east-1:000000000000:function:hello", false},
		{mgmt, "arn:aws:lambda:us-east-1:123456789012:function:hello", false}, // no account of the organization's
		{mgmt, "arn:aws:lambda:us-east-1:912345678901:function:hello", true},
		{member, "hello", false},
		{member, "912345678901:function:hello", false},
		{member, "arn:aws:lambda:us-east-1:000000000000:function:hello", true},
		{member, "arn:aws:lambda:us-east-1:123456789012:function:hello", true},
	} {
		arn, other := fnOfAnotherAccount(c.ctx, fns, c.uri)
		if other != c.other {
			t.Errorf("fnOfAnotherAccount(%s, %q) = %v, want %v", callerAccount(c.ctx), c.uri, other, c.other)
		}
		if other && !strings.HasSuffix(arn, ":function:hello") {
			t.Errorf("the refused function's ARN = %q", arn)
		}
	}
}

func TestUserPoolOf(t *testing.T) {
	for p, want := range map[string]string{
		"arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_abc": "us-east-1_abc",
		"http://shim/cognito/us-east-1_abc":                                 "us-east-1_abc",
		"https://issuer.example/realm/":                                     "realm",
		"https://issuer.example":                                            "",
		"not-a-provider":                                                    "",
	} {
		if got := userPoolOf(p); got != want {
			t.Errorf("userPoolOf(%q) = %q, want %q", p, got, want)
		}
	}
}

// The proxy event names the account the invoke acts in: the install's own for the management account's
// API, the member account's for a member's.
func TestBuildProxyEvent_NamesTheAPIAccount(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://x/items", nil)
	for _, pfv := range []string{"1.0", "2.0"} {
		ev := buildProxyEvent(pfv, r, "abc", "prod", "GET /items", "/items", nil, nil, "r")
		if got := ev["requestContext"].(map[string]any)["accountId"]; got != awsidentity.Current().AccountID {
			t.Errorf("%s management accountId = %v", pfv, got)
		}
		ev = buildProxyEvent(pfv, r.WithContext(inAPIAccount(r.Context(), testMember, testDirectory().HomeOf)), "abc", "prod", "GET /items", "/items", nil, nil, "r")
		if got := ev["requestContext"].(map[string]any)["accountId"]; got != testMember {
			t.Errorf("%s member accountId = %v", pfv, got)
		}
	}
}

// --- store-backed ---

// agwUpstream stands in for the functions an invoke reaches: it records each request's host and event.
type agwUpstream struct {
	mu     sync.Mutex
	hosts  []string
	events []map[string]any
}

func (u *agwUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	var ev map[string]any
	_ = json.Unmarshal(b, &ev)
	u.mu.Lock()
	u.hosts = append(u.hosts, r.URL.Host)
	u.events = append(u.events, ev)
	u.mu.Unlock()
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"statusCode":200,"body":"ok"}`)), Request: r}, nil
}

func (u *agwUpstream) last(t *testing.T) (string, map[string]any) {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.hosts) == 0 {
		t.Fatal("no function was invoked")
	}
	return u.hosts[len(u.hosts)-1], u.events[len(u.events)-1]
}

func (u *agwUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.hosts)
}

// agwAccountsFixture is the API Gateway door (REST v1 + HTTP v2 behind the mux) on a fresh Postgres, with a
// function "hello" in both the management account's namespace and the member account's home.
type agwAccountsFixture struct {
	v1    *apigwV1Handler
	v2    *apigwHandler
	mux   *apigwMux
	up    *agwUpstream
	pools *cognitoStore
}

func newAGWAccountsFixture(t *testing.T, cognitoIssuerBase string) *agwAccountsFixture {
	t.Helper()
	ctx := context.Background()
	db := freshPGDB(t)
	st, st1, pools := &apigwStore{db: db}, &apigwV1Store{db: db}, &cognitoStore{db: db}
	for _, ensure := range []func(context.Context) error{st.ensureSchema, st1.ensureSchema, pools.ensureSchema} {
		if err := ensure(ctx); err != nil {
			t.Fatal(err)
		}
	}
	fns := newFnLocator(fnDyn(fnClaim("default", "hello"), fnClaim(memberHome, "hello")), discardLogger(), "default")
	fns.accounts = testDirectory()
	up := &agwUpstream{}
	authz := doorAccountsAuthz(t)
	v2 := newAPIGWHandler(csWithSAR(true), "default", testMgmt, "us-east-1", "default", "svc.cluster.local", "http://shim", st, discardLogger())
	v2.authz, v2.fns, v2.homeOf, v2.client = authz, fns, testDirectory().HomeOf, &http.Client{Transport: up}
	v1 := newAPIGWV1Handler(csWithSAR(true), "default", "default", "svc.cluster.local", cognitoIssuerBase, st1, authz, discardLogger())
	v1.fns, v1.homeOf, v1.pools, v1.client = fns, testDirectory().HomeOf, pools, &http.Client{Transport: up}
	return &agwAccountsFixture{v1: v1, v2: v2, mux: &apigwMux{v1: v1, v2: v2}, up: up, pools: pools}
}

// call sends one management request as c, as the router hands it to the door; it answers the status, the
// JSON body and the error type ("" for a success).
func (f *agwAccountsFixture) call(t *testing.T, c doorCaller, method, path, body string) (int, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(method, "http://apigw"+path, strings.NewReader(body)).WithContext(c.ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.mux.serve(w, req, c.claims, "r-1")
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Header().Get("x-amzn-errortype")
}

// invoke sends one unsigned runtime request to an API's invoke URL, as the router hands it to the door.
func (f *agwAccountsFixture) invoke(t *testing.T, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://shim"+apigwInvokePrefix+strings.TrimPrefix(path, "/"), nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	apiID, p, ok := f.mux.invokeTarget(req)
	if !ok {
		t.Fatalf("%s is not an invoke URL", path)
	}
	w := httptest.NewRecorder()
	f.mux.serveInvoke(w, req, apiID, p, "r-i")
	return w
}

// restAPIWithMethod creates, as c, a REST API with GET /<part> integrated as integ (a PutIntegration body),
// deployed to stage prod; it answers the API's id and the resource's.
func (f *agwAccountsFixture) restAPIWithMethod(t *testing.T, c doorCaller, name, part, method, integ string) (string, string) {
	t.Helper()
	code, api, _ := f.call(t, c, "POST", "/restapis", `{"name":"`+name+`"}`)
	if code != http.StatusCreated {
		t.Fatalf("CreateRestApi = %d %v", code, api)
	}
	id, root := api["id"].(string), api["rootResourceId"].(string)
	_, res, _ := f.call(t, c, "POST", "/restapis/"+id+"/resources/"+root, `{"pathPart":"`+part+`"}`)
	rid, _ := res["id"].(string)
	if code, out, _ := f.call(t, c, "PUT", "/restapis/"+id+"/resources/"+rid+"/methods/GET", method); code != http.StatusCreated {
		t.Fatalf("PutMethod = %d %v", code, out)
	}
	if code, out, _ := f.call(t, c, "PUT", "/restapis/"+id+"/resources/"+rid+"/methods/GET/integration", integ); code != http.StatusCreated {
		t.Fatalf("PutIntegration = %d %v", code, out)
	}
	if code, out, _ := f.call(t, c, "POST", "/restapis/"+id+"/deployments", `{"stageName":"prod"}`); code != http.StatusCreated {
		t.Fatalf("CreateDeployment = %d %v", code, out)
	}
	return id, rid
}

func itemIDs(out map[string]any, list, idKey string) []string {
	var ids []string
	items, _ := out[list].([]any)
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			s, _ := m[idKey].(string)
			ids = append(ids, s)
		}
	}
	return ids
}

// APIs made before accounts (no account column) are the management account's: the columns are added with
// nothing to migrate, the management account still lists and reaches them, and a member account does not.
func TestServicesPG_APIGatewayAccountColumnNeedsNoMigration(t *testing.T) {
	ctx := context.Background()
	db := freshPGDB(t)
	if _, err := db.Exec(`
CREATE TABLE agw_apis (api_id text PRIMARY KEY, name text NOT NULL, protocol_type text NOT NULL DEFAULT 'HTTP',
    cors jsonb, created timestamptz NOT NULL DEFAULT now());
CREATE TABLE rest_apis (api_id text PRIMARY KEY, name text NOT NULL, created timestamptz NOT NULL DEFAULT now());
CREATE TABLE rest_api_keys (key_id text PRIMARY KEY, name text NOT NULL DEFAULT '', value text NOT NULL,
    enabled boolean NOT NULL DEFAULT true, created timestamptz NOT NULL DEFAULT now());
CREATE TABLE rest_usage_plans (plan_id text PRIMARY KEY, name text NOT NULL DEFAULT '', created timestamptz NOT NULL DEFAULT now());
INSERT INTO agw_apis (api_id, name) VALUES ('oldhttpapi', 'old-http');
INSERT INTO rest_apis (api_id, name) VALUES ('oldrestapi', 'old-rest');
INSERT INTO rest_api_keys (key_id, name, value) VALUES ('oldkey', 'old', 'old-key-value');
INSERT INTO rest_usage_plans (plan_id, name) VALUES ('oldplan', 'old');`); err != nil {
		t.Fatal(err)
	}
	st, st1 := &apigwStore{db: db}, &apigwV1Store{db: db}
	for i := 0; i < 2; i++ { // and again: the schema is idempotent
		if err := st.ensureSchema(ctx); err != nil {
			t.Fatal(err)
		}
		if err := st1.ensureSchema(ctx); err != nil {
			t.Fatal(err)
		}
	}
	authz := doorAccountsAuthz(t)
	v2 := newAPIGWHandler(csWithSAR(true), "default", testMgmt, "us-east-1", "default", "svc.cluster.local", "http://shim", st, discardLogger())
	v2.authz = authz
	v1 := newAPIGWV1Handler(csWithSAR(true), "default", "default", "svc.cluster.local", "", st1, authz, discardLogger())
	f := &agwAccountsFixture{v1: v1, v2: v2, mux: &apigwMux{v1: v1, v2: v2}}
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()

	for _, c := range []struct{ path, list, id, want string }{
		{"/v2/apis", "items", "apiId", "oldhttpapi"},
		{"/restapis", "item", "id", "oldrestapi"},
		{"/apikeys", "item", "id", "oldkey"},
		{"/usageplans", "item", "id", "oldplan"},
	} {
		if _, out, _ := f.call(t, mgmt, "GET", c.path, ""); strings.Join(itemIDs(out, c.list, c.id), ",") != c.want {
			t.Errorf("the management account's GET %s = %v, want its earlier %s", c.path, out, c.want)
		}
		if _, out, _ := f.call(t, member, "GET", c.path, ""); len(itemIDs(out, c.list, c.id)) != 0 {
			t.Errorf("a member account's GET %s = %v, want none", c.path, out)
		}
	}
	for _, p := range []string{"/v2/apis/oldhttpapi", "/restapis/oldrestapi", "/apikeys/oldkey", "/usageplans/oldplan"} {
		if code, out, _ := f.call(t, mgmt, "GET", p, ""); code != http.StatusOK {
			t.Errorf("the management account's GET %s = %d %v", p, code, out)
		}
		if code, _, typ := f.call(t, member, "GET", p, ""); code != http.StatusNotFound || typ != "NotFoundException" {
			t.Errorf("a member account's GET %s = %d %s, want NotFoundException", p, code, typ)
		}
	}
}

// Each account's REST APIs, API keys and usage plans are its own: the same name in both accounts, each
// listing its own alone, and another account's id is NotFound for every operation that names it.
func TestServicesPG_RestV1EachAccountKeepsItsOwnAPIs(t *testing.T) {
	f := newAGWAccountsFixture(t, "http://shim")
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()

	_, mAPI, _ := f.call(t, mgmt, "POST", "/restapis", `{"name":"orders"}`)
	_, bAPI, _ := f.call(t, member, "POST", "/restapis", `{"name":"orders"}`)
	mID, bID := mAPI["id"].(string), bAPI["id"].(string)
	mRoot := mAPI["rootResourceId"].(string)
	if mID == "" || bID == "" || mID == bID {
		t.Fatalf("CreateRestApi = %v / %v", mAPI, bAPI)
	}
	if _, out, _ := f.call(t, mgmt, "GET", "/restapis", ""); strings.Join(itemIDs(out, "item", "id"), ",") != mID {
		t.Errorf("the management account's GetRestApis = %v, want its own alone", out)
	}
	if _, out, _ := f.call(t, member, "GET", "/restapis", ""); strings.Join(itemIDs(out, "item", "id"), ",") != bID {
		t.Errorf("the member account's GetRestApis = %v, want its own alone", out)
	}
	if code, out, _ := f.call(t, member, "GET", "/restapis/"+bID, ""); code != http.StatusOK || out["name"] != "orders" {
		t.Errorf("the member account's GetRestApi = %d %v", code, out)
	}

	// Every operation naming another account's API is NotFound, and changes nothing.
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/restapis/" + mID, ""},
		{"GET", "/restapis/" + mID + "/resources", ""},
		{"POST", "/restapis/" + mID + "/resources/" + mRoot, `{"pathPart":"x"}`},
		{"PUT", "/restapis/" + mID + "/resources/" + mRoot + "/methods/GET", `{"authorizationType":"NONE"}`},
		{"POST", "/restapis/" + mID + "/deployments", `{"stageName":"prod"}`},
		{"GET", "/restapis/" + mID + "/stages", ""},
		{"POST", "/restapis/" + mID + "/authorizers", `{"name":"a","type":"COGNITO_USER_POOLS","providerARNs":["https://issuer.example"]}`},
		{"DELETE", "/restapis/" + mID, ""},
	} {
		if code, out, typ := f.call(t, member, c.method, c.path, c.body); code != http.StatusNotFound || typ != "NotFoundException" {
			t.Errorf("member %s %s = %d %s %v, want NotFoundException", c.method, c.path, code, typ, out)
		}
	}
	if code, _, typ := f.call(t, mgmt, "GET", "/restapis/"+bID, ""); code != http.StatusNotFound || typ != "NotFoundException" {
		t.Errorf("the management account's GetRestApi of the member's = %d %s", code, typ)
	}
	if code, _, typ := f.call(t, mgmt, "DELETE", "/restapis/"+bID, ""); code != http.StatusNotFound || typ != "NotFoundException" {
		t.Errorf("the management account's DeleteRestApi of the member's = %d %s", code, typ)
	}
	if _, out, _ := f.call(t, mgmt, "GET", "/restapis/"+mID+"/resources", ""); len(itemIDs(out, "item", "id")) != 1 {
		t.Errorf("the management account's API changed: %v", out)
	}
	if code, _, _ := f.call(t, member, "GET", "/restapis/"+bID, ""); code != http.StatusOK {
		t.Errorf("the member account's API is gone: %d", code)
	}

	// API keys: each account lists its own; another account's key is NotFound.
	_, mKey, _ := f.call(t, mgmt, "POST", "/apikeys", `{"name":"k","value":"mgmt-key-value-0000000001"}`)
	_, bKey, _ := f.call(t, member, "POST", "/apikeys", `{"name":"k","value":"member-key-value-00000001"}`)
	mKeyID, bKeyID := mKey["id"].(string), bKey["id"].(string)
	if _, out, _ := f.call(t, mgmt, "GET", "/apikeys", ""); strings.Join(itemIDs(out, "item", "id"), ",") != mKeyID {
		t.Errorf("the management account's GetApiKeys = %v", out)
	}
	if _, out, _ := f.call(t, member, "GET", "/apikeys?includeValues=true", ""); strings.Join(itemIDs(out, "item", "id"), ",") != bKeyID {
		t.Errorf("the member account's GetApiKeys = %v", out)
	}
	if code, _, typ := f.call(t, member, "GET", "/apikeys/"+mKeyID+"?includeValue=true", ""); code != http.StatusNotFound || typ != "NotFoundException" {
		t.Errorf("the member account's GetApiKey of the management account's = %d %s", code, typ)
	}
	if code, _, typ := f.call(t, mgmt, "GET", "/apikeys/"+bKeyID, ""); code != http.StatusNotFound || typ != "NotFoundException" {
		t.Errorf("the management account's GetApiKey of the member's = %d %s", code, typ)
	}

	// Usage plans: a member account's plan names its own APIs; each account lists its own; another
	// account's plan, or key, is NotFound.
	if code, _, typ := f.call(t, member, "POST", "/usageplans", `{"name":"p","apiStages":[{"apiId":"`+mID+`","stage":"prod"}]}`); code != http.StatusNotFound || typ != "NotFoundException" {
		t.Errorf("a member account's plan naming the management account's API = %d %s", code, typ)
	}
	_, mPlan, _ := f.call(t, mgmt, "POST", "/usageplans", `{"name":"p","apiStages":[{"apiId":"`+mID+`","stage":"prod"}]}`)
	code, bPlan, _ := f.call(t, member, "POST", "/usageplans", `{"name":"p","apiStages":[{"apiId":"`+bID+`","stage":"prod"}]}`)
	if code != http.StatusCreated {
		t.Fatalf("the member account's CreateUsagePlan = %d %v", code, bPlan)
	}
	mPlanID, bPlanID := mPlan["id"].(string), bPlan["id"].(string)
	if _, out, _ := f.call(t, mgmt, "GET", "/usageplans", ""); strings.Join(itemIDs(out, "item", "id"), ",") != mPlanID {
		t.Errorf("the management account's GetUsagePlans = %v", out)
	}
	if _, out, _ := f.call(t, member, "GET", "/usageplans", ""); strings.Join(itemIDs(out, "item", "id"), ",") != bPlanID {
		t.Errorf("the member account's GetUsagePlans = %v", out)
	}
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/usageplans/" + mPlanID, ""},
		{"GET", "/usageplans/" + mPlanID + "/keys", ""},
		{"POST", "/usageplans/" + mPlanID + "/keys", `{"keyId":"` + bKeyID + `","keyType":"API_KEY"}`},
		{"POST", "/usageplans/" + bPlanID + "/keys", `{"keyId":"` + mKeyID + `","keyType":"API_KEY"}`}, // another account's key
	} {
		if code, out, typ := f.call(t, member, c.method, c.path, c.body); code != http.StatusNotFound || typ != "NotFoundException" {
			t.Errorf("member %s %s = %d %s %v, want NotFoundException", c.method, c.path, code, typ, out)
		}
	}
	if code, out, _ := f.call(t, member, "POST", "/usageplans/"+bPlanID+"/keys", `{"keyId":"`+bKeyID+`","keyType":"API_KEY"}`); code != http.StatusCreated {
		t.Errorf("the member account associating its own key with its own plan = %d %v", code, out)
	}
	if _, out, _ := f.call(t, mgmt, "GET", "/usageplans/"+mPlanID+"/keys", ""); len(itemIDs(out, "item", "id")) != 0 {
		t.Errorf("the management account's plan gained a key: %v", out)
	}
}

// Each account's HTTP APIs are its own: listed for it alone, and another account's api id NotFound.
func TestServicesPG_HTTPAPIEachAccountKeepsItsOwnAPIs(t *testing.T) {
	f := newAGWAccountsFixture(t, "")
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	_, mAPI, _ := f.call(t, mgmt, "POST", "/v2/apis", `{"name":"web","protocolType":"HTTP"}`)
	_, bAPI, _ := f.call(t, member, "POST", "/v2/apis", `{"name":"web","protocolType":"HTTP"}`)
	mID, bID := mAPI["apiId"].(string), bAPI["apiId"].(string)
	if mID == "" || bID == "" || mID == bID {
		t.Fatalf("CreateApi = %v / %v", mAPI, bAPI)
	}
	if _, out, _ := f.call(t, mgmt, "GET", "/v2/apis", ""); strings.Join(itemIDs(out, "items", "apiId"), ",") != mID {
		t.Errorf("the management account's GetApis = %v", out)
	}
	if _, out, _ := f.call(t, member, "GET", "/v2/apis", ""); strings.Join(itemIDs(out, "items", "apiId"), ",") != bID {
		t.Errorf("the member account's GetApis = %v", out)
	}
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/v2/apis/" + mID, ""},
		{"GET", "/v2/apis/" + mID + "/routes", ""},
		{"POST", "/v2/apis/" + mID + "/routes", `{"routeKey":"GET /x"}`},
		{"POST", "/v2/apis/" + mID + "/integrations", `{"integrationType":"AWS_PROXY","integrationUri":"hello"}`},
		{"POST", "/v2/apis/" + mID + "/stages", `{"stageName":"prod"}`},
		{"GET", "/v2/apis/" + mID + "/stages", ""},
		{"POST", "/v2/apis/" + mID + "/deployments", ""},
		{"POST", "/v2/apis/" + mID + "/authorizers", `{"name":"j","authorizerType":"JWT","jwtConfiguration":{"issuer":"https://issuer.example"}}`},
		{"DELETE", "/v2/apis/" + mID, ""},
	} {
		if code, out, typ := f.call(t, member, c.method, c.path, c.body); code != http.StatusNotFound || typ != "NotFoundException" {
			t.Errorf("member %s %s = %d %s %v, want NotFoundException", c.method, c.path, code, typ, out)
		}
	}
	if code, _, typ := f.call(t, mgmt, "DELETE", "/v2/apis/"+bID, ""); code != http.StatusNotFound || typ != "NotFoundException" {
		t.Errorf("the management account's DeleteApi of the member's = %d %s", code, typ)
	}
	for _, c := range []struct {
		c  doorCaller
		id string
	}{{mgmt, mID}, {member, bID}} {
		if code, out, _ := f.call(t, c.c, "GET", "/v2/apis/"+c.id+"/routes", ""); code != http.StatusOK || len(itemIDs(out, "items", "routeId")) != 0 {
			t.Errorf("%s's API changed: %d %v", c.id, code, out)
		}
	}
}

// An invoke acts in the API's own account: a member account's API invokes its own account's function (in
// its home) and names its account in the proxy event; the management account's invokes the management
// account's function and names the install's account, as before.
func TestServicesPG_APIGatewayInvokeActsInTheAPIAccount(t *testing.T) {
	f := newAGWAccountsFixture(t, "")
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	for _, c := range []struct {
		c       doorCaller
		host    string
		account string
	}{
		{mgmt, "hello.default.svc.cluster.local", awsidentity.Current().AccountID},
		{member, "hello." + memberHome + ".svc.cluster.local", testMember},
	} {
		// HTTP API (v2), quick-created with the function as its target.
		code, api, _ := f.call(t, c.c, "POST", "/v2/apis", `{"name":"web","protocolType":"HTTP","target":"hello","routeKey":"GET /hi"}`)
		if code != http.StatusCreated {
			t.Fatalf("CreateApi = %d %v", code, api)
		}
		if w := f.invoke(t, "GET", api["apiId"].(string)+"/hi", nil); w.Code != http.StatusOK {
			t.Fatalf("v2 invoke = %d %s", w.Code, w.Body.String())
		}
		host, ev := f.up.last(t)
		if rc, _ := ev["requestContext"].(map[string]any); host != c.host || rc["accountId"] != c.account {
			t.Errorf("v2 invoke reached %s naming account %v, want %s and %s", host, rc["accountId"], c.host, c.account)
		}

		// REST API (v1), AWS_PROXY.
		id, _ := f.restAPIWithMethod(t, c.c, "orders", "hi", `{"authorizationType":"NONE"}`, `{"type":"AWS_PROXY","uri":"hello"}`)
		if w := f.invoke(t, "GET", id+"/prod/hi", nil); w.Code != http.StatusOK {
			t.Fatalf("v1 invoke = %d %s", w.Code, w.Body.String())
		}
		host, ev = f.up.last(t)
		if rc, _ := ev["requestContext"].(map[string]any); host != c.host || rc["accountId"] != c.account {
			t.Errorf("v1 invoke reached %s naming account %v, want %s and %s", host, rc["accountId"], c.host, c.account)
		}
	}
}

// An API integrates its own account's functions: a member account's never another account's (the function
// of the same name in its own is never taken for it), and the management account's never a member
// account's — at wiring, from a stack, and on invoke.
func TestServicesPG_APIGatewayIntegratesItsOwnAccountsFunctions(t *testing.T) {
	f := newAGWAccountsFixture(t, "")
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtFn := "arn:aws:lambda:us-east-1:" + testMgmt + ":function:hello"
	memberFn := "arn:aws:lambda:us-east-1:" + testMember + ":function:hello"
	estateFn := "arn:aws:lambda:us-east-1:123456789012:function:hello" // no account of the organization's

	_, mAPI, _ := f.call(t, mgmt, "POST", "/v2/apis", `{"name":"web","protocolType":"HTTP"}`)
	_, bAPI, _ := f.call(t, member, "POST", "/v2/apis", `{"name":"web","protocolType":"HTTP"}`)
	for _, c := range []struct {
		c    doorCaller
		api  string
		uri  string
		want int
	}{
		{member, bAPI["apiId"].(string), mgmtFn, http.StatusForbidden},
		{member, bAPI["apiId"].(string), memberFn, http.StatusCreated},
		{member, bAPI["apiId"].(string), "hello", http.StatusCreated},
		{mgmt, mAPI["apiId"].(string), memberFn, http.StatusForbidden},
		{mgmt, mAPI["apiId"].(string), mgmtFn, http.StatusCreated},
		{mgmt, mAPI["apiId"].(string), estateFn, http.StatusCreated},
	} {
		if code, out, _ := f.call(t, c.c, "POST", "/v2/apis/"+c.api+"/integrations", `{"integrationType":"AWS_PROXY","integrationUri":"`+c.uri+`"}`); code != c.want {
			t.Errorf("%s CreateIntegration %s = %d %v, want %d", callerAccount(c.c.ctx), c.uri, code, out, c.want)
		}
	}
	if code, out, _ := f.call(t, member, "POST", "/v2/apis", `{"name":"q","protocolType":"HTTP","target":"`+mgmtFn+`"}`); code != http.StatusForbidden {
		t.Errorf("a member account quick-creating with another account's function = %d %v", code, out)
	}
	if _, out, _ := f.call(t, member, "GET", "/v2/apis", ""); len(itemIDs(out, "items", "apiId")) != 1 {
		t.Errorf("a refused quick-create left an API: %v", out)
	}

	// REST v1 PutIntegration.
	_, bRest, _ := f.call(t, member, "POST", "/restapis", `{"name":"orders"}`)
	bRestID, bRoot := bRest["id"].(string), bRest["rootResourceId"].(string)
	f.call(t, member, "PUT", "/restapis/"+bRestID+"/resources/"+bRoot+"/methods/GET", `{"authorizationType":"NONE"}`)
	for _, typ := range []string{"AWS_PROXY", "AWS"} {
		if code, out, _ := f.call(t, member, "PUT", "/restapis/"+bRestID+"/resources/"+bRoot+"/methods/GET/integration", `{"type":"`+typ+`","uri":"`+mgmtFn+`"}`); code != http.StatusForbidden {
			t.Errorf("a member account's %s integration of another account's function = %d %v", typ, code, out)
		}
	}

	// A stack of the member account may not integrate another account's function either.
	plan := cfn.RestAPIPlan{LogicalID: "Api", Name: "stacked", Methods: []cfn.RestMethodPlan{{Resource: "<root>", HTTPMethod: "GET",
		Integration: &cfn.RestIntegrationPlan{Type: "AWS_PROXY", URI: mgmtFn}}}, Stages: []cfn.RestStagePlan{{StageName: "prod"}}}
	if id, err := f.v1.provisionRestAPIPlan(member.ctx, plan); err == nil {
		t.Errorf("a member account's stack integrated another account's function: %s", id)
	}

	// On invoke: an integration naming another account's function (stored without the wiring check) is
	// never served by the API's own account's function of that name.
	if err := f.v1.store.putIntegration(context.Background(), bRestID, restIntegration{ResourceID: bRoot, HTTPMethod: "GET", Type: "AWS_PROXY", URI: mgmtFn, PayloadFormatVersion: "1.0"}); err != nil {
		t.Fatal(err)
	}
	f.call(t, member, "POST", "/restapis/"+bRestID+"/deployments", `{"stageName":"prod"}`)
	before := f.up.count()
	if w := f.invoke(t, "GET", bRestID+"/prod/", nil); w.Code != http.StatusBadGateway {
		t.Errorf("invoking another account's function = %d %s, want 502", w.Code, w.Body.String())
	}
	if f.up.count() != before {
		t.Error("an integration naming another account's function invoked one")
	}
}

// An API key unlocks only its own account's APIs: a key and usage plan of another account — even one that
// names the API — never admit a call to it.
func TestServicesPG_RestV1APIKeysUnlockTheirOwnAccountsAPIs(t *testing.T) {
	f := newAGWAccountsFixture(t, "")
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	bID, _ := f.restAPIWithMethod(t, member, "orders", "k", `{"authorizationType":"NONE","apiKeyRequired":true}`, `{"type":"MOCK"}`)
	mID, _ := f.restAPIWithMethod(t, mgmt, "orders", "k", `{"authorizationType":"NONE","apiKeyRequired":true}`, `{"type":"MOCK"}`)

	associate := func(c doorCaller, value, apiID string) {
		t.Helper()
		_, k, _ := f.call(t, c, "POST", "/apikeys", `{"name":"k","value":"`+value+`"}`)
		_, p, _ := f.call(t, c, "POST", "/usageplans", `{"name":"p","apiStages":[{"apiId":"`+apiID+`","stage":"prod"}]}`)
		if code, out, _ := f.call(t, c, "POST", "/usageplans/"+p["id"].(string)+"/keys", `{"keyId":"`+k["id"].(string)+`","keyType":"API_KEY"}`); code != http.StatusCreated {
			t.Fatalf("CreateUsagePlanKey = %d %v", code, out)
		}
	}
	// The management account's key, on a management plan naming the member account's API.
	associate(mgmt, "mgmt-key-value-0000000001", bID)
	associate(member, "member-key-value-00000001", bID)
	associate(mgmt, "mgmt-key-value-0000000002", mID)

	for _, c := range []struct {
		api, key string
		want     int
	}{
		{bID, "member-key-value-00000001", http.StatusOK},
		{bID, "mgmt-key-value-0000000001", http.StatusForbidden},
		{bID, "mgmt-key-value-0000000002", http.StatusForbidden},
		{mID, "mgmt-key-value-0000000002", http.StatusOK},
		{mID, "member-key-value-00000001", http.StatusForbidden},
		{mID, "mgmt-key-value-0000000001", http.StatusForbidden}, // its plan names another API
	} {
		if w := f.invoke(t, "GET", c.api+"/prod/k", map[string]string{"x-api-key": c.key}); w.Code != c.want {
			t.Errorf("invoke %s with %s = %d %s, want %d", c.api, c.key, w.Code, w.Body.String(), c.want)
		}
	}
}

// A COGNITO_USER_POOLS authorizer admits tokens of its own account's user pools alone: another account's
// pool is refused at CreateAuthorizer (and from a stack), and one an authorizer names anyway admits no one
// on invoke — the pool's issuer is never even asked.
func TestServicesPG_RestV1CognitoAuthorizersUseTheirOwnAccountsPools(t *testing.T) {
	var discovered atomic.Int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discovered.Add(1)
		http.NotFound(w, r)
	}))
	defer issuer.Close()
	f := newAGWAccountsFixture(t, issuer.URL)
	ctx := context.Background()
	if err := f.pools.createPool(ctx, cognitoPool{ID: "us-east-1_mgmtpool", Name: "m"}); err != nil {
		t.Fatal(err)
	}
	if err := f.pools.createPool(ctx, cognitoPool{ID: "us-east-1_membpool", Name: "b", Account: testMember}); err != nil {
		t.Fatal(err)
	}
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtPool := "arn:aws:cognito-idp:us-east-1:" + testMgmt + ":userpool/us-east-1_mgmtpool"
	memberPool := "arn:aws:cognito-idp:us-east-1:" + testMember + ":userpool/us-east-1_membpool"
	_, mAPI, _ := f.call(t, mgmt, "POST", "/restapis", `{"name":"orders"}`)
	_, bAPI, _ := f.call(t, member, "POST", "/restapis", `{"name":"orders"}`)
	mID, bID := mAPI["id"].(string), bAPI["id"].(string)

	for _, c := range []struct {
		c        doorCaller
		api      string
		provider string
		want     int
	}{
		{member, bID, mgmtPool, http.StatusBadRequest},
		{member, bID, issuer.URL + "/cognito/us-east-1_mgmtpool", http.StatusBadRequest}, // its issuer
		{member, bID, "arn:aws:cognito-idp:us-east-1:" + testMember + ":userpool/us-east-1_mgmtpool", http.StatusBadRequest},
		{member, bID, memberPool, http.StatusCreated},
		{mgmt, mID, memberPool, http.StatusBadRequest},
		{mgmt, mID, mgmtPool, http.StatusCreated},
	} {
		if code, out, _ := f.call(t, c.c, "POST", "/restapis/"+c.api+"/authorizers", `{"name":"a","type":"COGNITO_USER_POOLS","providerARNs":["`+c.provider+`"]}`); code != c.want {
			t.Errorf("%s CreateAuthorizer %s = %d %v, want %d", callerAccount(c.c.ctx), c.provider, code, out, c.want)
		}
	}
	plan := cfn.RestAPIPlan{LogicalID: "Api", Name: "stacked",
		Authorizers: []cfn.RestAuthorizerPlan{{LogicalID: "Auth", Name: "a", Type: "COGNITO_USER_POOLS", ProviderARNs: []string{mgmtPool}}},
		Stages:      []cfn.RestStagePlan{{StageName: "prod"}}}
	if id, err := f.v1.provisionRestAPIPlan(member.ctx, plan); err == nil {
		t.Errorf("a member account's stack authorized with another account's pool: %s", id)
	}

	// On invoke: the member account's API with an authorizer of its own pool asks the pool's issuer; one
	// naming the management account's pool (stored without the check) is refused without asking it.
	_, az, _ := f.call(t, member, "GET", "/restapis/"+bID+"/authorizers", "")
	own := itemIDs(az, "item", "id")
	if len(own) != 1 {
		t.Fatalf("the member account's authorizers = %v", az)
	}
	if err := f.v1.store.createAuthorizer(ctx, bID, restAuthorizer{ID: "otheraz", Name: "o", Type: "COGNITO_USER_POOLS",
		Issuer: issuer.URL + "/cognito/us-east-1_mgmtpool", ProviderARNs: []string{mgmtPool}}); err != nil {
		t.Fatal(err)
	}
	root := bAPI["rootResourceId"].(string)
	for part, azID := range map[string]string{"own": own[0], "other": "otheraz"} {
		_, res, _ := f.call(t, member, "POST", "/restapis/"+bID+"/resources/"+root, `{"pathPart":"`+part+`"}`)
		rid := res["id"].(string)
		f.call(t, member, "PUT", "/restapis/"+bID+"/resources/"+rid+"/methods/GET", `{"authorizationType":"COGNITO_USER_POOLS","authorizerId":"`+azID+`"}`)
		f.call(t, member, "PUT", "/restapis/"+bID+"/resources/"+rid+"/methods/GET/integration", `{"type":"MOCK"}`)
	}
	f.call(t, member, "POST", "/restapis/"+bID+"/deployments", `{"stageName":"prod"}`)
	bearer := map[string]string{"Authorization": "Bearer not-a-real-token"}
	if w := f.invoke(t, "GET", bID+"/prod/other", bearer); w.Code != http.StatusUnauthorized || discovered.Load() != 0 {
		t.Errorf("another account's pool: invoke = %d, issuer asked %d times; want 401 without asking", w.Code, discovered.Load())
	}
	if w := f.invoke(t, "GET", bID+"/prod/own", bearer); w.Code != http.StatusUnauthorized || discovered.Load() == 0 {
		t.Errorf("its own pool: invoke = %d, issuer asked %d times; want its issuer asked (and the fake token refused)", w.Code, discovered.Load())
	}
}

// A stack's REST API, keys and plans are its account's; a stack never tears down another account's API.
func TestServicesPG_RestV1StackAPIsAreTheirAccounts(t *testing.T) {
	f := newAGWAccountsFixture(t, "")
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	plan := cfn.RestAPIPlan{LogicalID: "Api", Name: "stacked",
		Methods:    []cfn.RestMethodPlan{{Resource: "<root>", HTTPMethod: "GET", APIKeyRequired: true, Integration: &cfn.RestIntegrationPlan{Type: "MOCK"}}},
		Stages:     []cfn.RestStagePlan{{StageName: "prod"}},
		APIKeys:    []cfn.RestAPIKeyPlan{{LogicalID: "Key", Name: "k", Enabled: true, Value: "stack-key-value-000000001"}},
		UsagePlans: []cfn.RestUsagePlanPlan{{LogicalID: "Plan", Name: "p", APIStages: []cfn.RestUsagePlanAPI{{Stage: "prod"}}, Keys: []string{"Key"}}}}
	bID, err := f.v1.provisionRestAPIPlan(member.ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, out, _ := f.call(t, member, "GET", "/restapis", ""); strings.Join(itemIDs(out, "item", "id"), ",") != bID {
		t.Errorf("the member account's GetRestApis = %v, want its stack's API", out)
	}
	for _, p := range []string{"/restapis", "/apikeys", "/usageplans"} {
		if _, out, _ := f.call(t, mgmt, "GET", p, ""); len(itemIDs(out, "item", "id")) != 0 {
			t.Errorf("the management account's GET %s lists the member's stack's: %v", p, out)
		}
		if _, out, _ := f.call(t, member, "GET", p, ""); len(itemIDs(out, "item", "id")) != 1 {
			t.Errorf("the member account's GET %s = %v", p, out)
		}
	}
	if w := f.invoke(t, "GET", bID+"/prod/", map[string]string{"x-api-key": "stack-key-value-000000001"}); w.Code != http.StatusOK {
		t.Errorf("the stack's key on the stack's API = %d %s", w.Code, w.Body.String())
	}

	mID, err := f.v1.provisionRestAPIPlan(mgmt.ctx, cfn.RestAPIPlan{LogicalID: "Api", Name: "mine", Stages: []cfn.RestStagePlan{{StageName: "prod"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.v1.deprovisionRestAPI(member.ctx, mID); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.call(t, mgmt, "GET", "/restapis/"+mID, ""); code != http.StatusOK {
		t.Error("a member account's stack teardown deleted the management account's API")
	}
	if err := f.v1.deprovisionRestAPI(member.ctx, bID); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.call(t, member, "GET", "/restapis/"+bID, ""); code != http.StatusNotFound {
		t.Errorf("the member account's stack teardown left its API: %d", code)
	}
}
