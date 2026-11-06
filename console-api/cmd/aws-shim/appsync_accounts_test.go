package main

// Each account's AppSync APIs are its own: an API belongs to the account of its claim's namespace, the
// management plane finds, changes and lists the caller's account's APIs alone, and an API's ARN names its
// account. The GraphQL data plane is the platform's one engine, the management account's.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
)

// nsAccounts is a namespace → account directory: an unlisted namespace is the management account's.
type nsAccounts map[string]string

func (d nsAccounts) AccountOf(ns string) string {
	if a, ok := d[ns]; ok {
		return a
	}
	return awsidentity.Current().AccountID
}

func appsyncAccountsHandler(t *testing.T) (*appsyncHandler, *fakeAPIStore) {
	t.Helper()
	store := newFakeAPIStore()
	notesAPI(store, "default", "notes")
	notesAPI(store, "apps", "notes")
	notesAPI(store, memberHome, "notes")
	notesAPI(store, "team-a-batch", "jobs") // the member account's other namespace
	notesAPI(store, "team-b", "notes")      // another member account's
	h := newAppsyncHandler(csWithSAR(true), "http://unused", "default", discardLogger())
	h.apis = store
	h.account, h.region = awsidentity.Current().AccountID, "us-east-1"
	h.accounts = nsAccounts{memberHome: testMember, "team-a-batch": testMember, "team-b": "955555555555"}
	h.authz = doorAccountsAuthz(t)
	return h, store
}

func (c doorCaller) appsync(h *appsyncHandler, method, path, body string) (int, map[string]any) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	w := httptest.NewRecorder()
	h.serve(w, httptest.NewRequest(method, "http://appsync"+path, rd).WithContext(c.ctx), c.claims, "r")
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func listedAPIs(out map[string]any) (ids, arns []string) {
	l, _ := out["graphqlApis"].([]any)
	for _, e := range l {
		m, _ := e.(map[string]any)
		ids = append(ids, m["apiId"].(string))
		arns = append(arns, m["arn"].(string))
	}
	return ids, arns
}

func TestAppsyncAccounts_EachAccountReachesItsOwnAPIs(t *testing.T) {
	h, _ := appsyncAccountsHandler(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	mgmtAcct := awsidentity.Current().AccountID

	// The member's bare apiId is the API in its home; its ARN names the member account.
	code, out := member.appsync(h, "GET", "/v1/apis/notes", "")
	api, _ := out["graphqlApi"].(map[string]any)
	if code != 200 || api["arn"] != "arn:aws:appsync:us-east-1:"+testMember+":apis/notes" {
		t.Fatalf("member GetGraphqlApi notes: %d %v", code, out)
	}
	if code, out := member.appsync(h, "GET", "/v1/apis/"+memberHome+".notes/datasources/todos", ""); code != 200 ||
		!strings.Contains(out["dataSource"].(map[string]any)["dataSourceArn"].(string), ":"+testMember+":apis/") {
		t.Fatalf("member GetDataSource: %d %v", code, out)
	}
	if code, _ := member.appsync(h, "GET", "/v1/apis/team-a-batch.jobs", ""); code != 200 {
		t.Fatalf("an API in the member account's other namespace is its own: %d", code)
	}
	// The management account's APIs, and another member account's, are none of the member's.
	for _, id := range []string{"default.notes", "apps.notes", "team-b.notes"} {
		if code, out := member.appsync(h, "GET", "/v1/apis/"+id, ""); code != 404 {
			t.Errorf("a member read %s: %d %v", id, code, out)
		}
		if code, _ := member.appsync(h, "GET", "/v1/apis/"+id+"/types/Query/resolvers/getTodo", ""); code != 404 {
			t.Errorf("a member read a resolver of %s: %d", id, code)
		}
	}

	// The management account: its own as before (a bare apiId is the default namespace's), never a member's.
	code, out = mgmt.appsync(h, "GET", "/v1/apis/notes", "")
	if api, _ := out["graphqlApi"].(map[string]any); code != 200 || api["arn"] != "arn:aws:appsync:us-east-1:"+mgmtAcct+":apis/notes" {
		t.Fatalf("management GetGraphqlApi notes: %d %v", code, out)
	}
	if code, _ := mgmt.appsync(h, "GET", "/v1/apis/apps.notes", ""); code != 200 {
		t.Fatal("management GetGraphqlApi apps.notes")
	}
	if code, _ := mgmt.appsync(h, "GET", "/v1/apis/"+memberHome+".notes", ""); code != 404 {
		t.Fatalf("the management account read a member account's API: %d", code)
	}

	// Listings: each account its own.
	_, out = member.appsync(h, "GET", "/v1/apis", "")
	ids, arns := listedAPIs(out)
	slices.Sort(ids)
	if strings.Join(ids, ",") != "team-a-batch.jobs,"+memberHome+".notes" {
		t.Fatalf("the member account lists its own APIs alone: %v", ids)
	}
	for _, a := range arns {
		if !strings.Contains(a, ":"+testMember+":apis/") {
			t.Errorf("a member account's listed API ARN %q", a)
		}
	}
	_, out = mgmt.appsync(h, "GET", "/v1/apis", "")
	ids, arns = listedAPIs(out)
	slices.Sort(ids)
	if strings.Join(ids, ",") != "apps.notes,default.notes" {
		t.Fatalf("the management account lists its own APIs alone: %v", ids)
	}
	for _, a := range arns {
		if !strings.Contains(a, ":"+mgmtAcct+":apis/") {
			t.Errorf("a management account's listed API ARN %q", a)
		}
	}
}

func TestAppsyncAccounts_EachAccountChangesItsOwnAPIs(t *testing.T) {
	h, store := appsyncAccountsHandler(t)
	mgmt, member := mgmtDoorCaller(), memberDoorCaller()
	body := `{"fieldName":"addTodo","dataSourceName":"todos","requestMappingTemplate":"REQ","responseMappingTemplate":"RESP"}`

	if code, out := member.appsync(h, "POST", "/v1/apis/notes/types/Mutation/resolvers", body); code != 201 {
		t.Fatalf("member CreateResolver on its own API: %d %v", code, out)
	}
	has := func(ns string) bool {
		for _, r := range store.resolvers(ns, "notes") {
			if r.(map[string]any)["field"] == "addTodo" {
				return true
			}
		}
		return false
	}
	if !has(memberHome) || has("default") {
		t.Fatal("the member's CreateResolver must patch its own API alone")
	}
	for _, id := range []string{"default.notes", "apps.notes", "team-b.notes"} {
		if code, _ := member.appsync(h, "POST", "/v1/apis/"+id+"/types/Mutation/resolvers", body); code != 404 {
			t.Errorf("a member changed %s: %d", id, code)
		}
		if code, _ := member.appsync(h, "DELETE", "/v1/apis/"+id+"/datasources/todos", ""); code != 404 {
			t.Errorf("a member deleted a data source of %s: %d", id, code)
		}
	}
	if has("apps") || has("team-b") {
		t.Fatal("a member account's change reached another account's API")
	}
	if code, _ := mgmt.appsync(h, "DELETE", "/v1/apis/"+memberHome+".notes/types/Mutation/resolvers/addTodo", ""); code != 404 || !has(memberHome) {
		t.Fatalf("the management account changed a member account's API: %d", code)
	}
	if code, _ := mgmt.appsync(h, "POST", "/v1/apis/apps.notes/types/Mutation/resolvers", body); code != 201 || !has("apps") {
		t.Fatalf("the management account changes its own API: %d", code)
	}
}

// The GraphQL endpoint fronts the platform's one engine, the management account's: a member account's
// principal reaches it only as across accounts (here: no resource policy, so not at all), as before.
func TestAppsyncAccounts_DataPlaneIsTheManagementAccountsEngine(t *testing.T) {
	var hits int
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{}}`)
	}))
	defer engine.Close()
	h, _ := appsyncAccountsHandler(t)
	h.endpoint = engine.URL
	if code, _ := memberDoorCaller().appsync(h, "POST", "/graphql", `{"query":"{ x }"}`); code != http.StatusForbidden || hits != 0 {
		t.Fatalf("a member account's principal reached the management account's engine: %d (hits %d)", code, hits)
	}
	if code, _ := mgmtDoorCaller().appsync(h, "POST", "/graphql", `{"query":"{ x }"}`); code != http.StatusOK || hits != 1 {
		t.Fatalf("the management account reaches its engine: %d (hits %d)", code, hits)
	}
}
