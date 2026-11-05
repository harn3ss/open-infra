package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const orgMgmt = "000000000000"

func orgAccountObj(id, home, email, alias string, suspended bool) *unstructured.Unstructured {
	spec := map[string]any{"accountId": id, "namespaces": []any{home}, "email": email, "suspended": suspended}
	if alias != "" {
		spec["alias"] = alias
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "organizations.openinfra.dev/v1", "kind": "Account",
		"metadata": map[string]any{"name": id}, "spec": spec,
	}}
}

// orgTestHandler is the front door over a fake cluster holding objs, every caller allowed by RBAC, with
// the namespaces in existing taken.
func orgTestHandler(t *testing.T, sarAllowed bool, existing []string, objs ...runtime.Object) (*organizationsHandler, dynamic.Interface) {
	t.Helper()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrAccounts: "AccountList"}, objs...)
	h := newOrganizationsHandler(csWithSAR(sarAllowed), nil, "default", nil, orgMgmt, discardLogger())
	h.callerDyn = func(string, []string) (dynamic.Interface, error) { return dyn, nil }
	h.namespaceExists = func(_ context.Context, name string) (bool, error) {
		for _, n := range existing {
			if n == name {
				return true, nil
			}
		}
		return false, nil
	}
	h.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return h, dyn
}

var orgAdmin = iam.Claims{Sub: "ops", Groups: []string{"openinfra:admins"}}

func orgCall(t *testing.T, h *organizationsHandler, claims iam.Claims, op string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(b)))
	r.Header.Set("X-Amz-Target", organizationsTargetPrefix+op)
	w := httptest.NewRecorder()
	h.serve(w, r, claims, "req-1")
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func wantOrgError(t *testing.T, w *httptest.ResponseRecorder, out map[string]any, code string) {
	t.Helper()
	if w.Code < 400 || out["__type"] != code {
		t.Fatalf("got %d %v, want %s", w.Code, out, code)
	}
}

func TestOrganizations_DescribeOrganizationAndRoots(t *testing.T) {
	h, _ := orgTestHandler(t, true, nil, orgAccountObj(orgMgmt, "open-infra-console", "ops@example.com", "", false))
	_, out := orgCall(t, h, orgAdmin, "DescribeOrganization", map[string]any{})
	org, _ := out["Organization"].(map[string]any)
	id, _ := org["Id"].(string)
	if !strings.HasPrefix(id, "o-") || len(id) != 12 || org["MasterAccountId"] != orgMgmt || org["MasterAccountEmail"] != "ops@example.com" ||
		org["Arn"] != "arn:aws:organizations::"+orgMgmt+":organization/"+id || org["FeatureSet"] != "ALL" {
		t.Fatalf("organization %v", org)
	}
	_, out = orgCall(t, h, orgAdmin, "ListRoots", map[string]any{})
	roots, _ := out["Roots"].([]any)
	root, _ := roots[0].(map[string]any)
	if len(roots) != 1 || !strings.HasPrefix(root["Id"].(string), "r-") || root["Name"] != "Root" {
		t.Fatalf("roots %v", out)
	}
}

// The management account is listed even before any Account object names it, first; members follow by id.
func TestOrganizations_ListAndDescribeAccounts(t *testing.T) {
	h, _ := orgTestHandler(t, true, nil,
		orgAccountObj("923456789012", "team-b", "b@example.com", "team-b", true),
		orgAccountObj("912345678901", "team-a", "a@example.com", "team-a", false))
	_, out := orgCall(t, h, orgAdmin, "ListAccounts", map[string]any{})
	list, _ := out["Accounts"].([]any)
	if len(list) != 3 {
		t.Fatalf("accounts %v", out)
	}
	ids := []string{}
	for _, a := range list {
		ids = append(ids, a.(map[string]any)["Id"].(string))
	}
	if strings.Join(ids, ",") != orgMgmt+",912345678901,923456789012" {
		t.Errorf("order %v: the management account first, then by id", ids)
	}
	_, out = orgCall(t, h, orgAdmin, "DescribeAccount", map[string]any{"AccountId": "923456789012"})
	a, _ := out["Account"].(map[string]any)
	if a["Status"] != "SUSPENDED" || a["Name"] != "team-b" || a["Email"] != "b@example.com" ||
		!strings.HasSuffix(a["Arn"].(string), "/923456789012") {
		t.Fatalf("account %v", a)
	}
	w, out := orgCall(t, h, orgAdmin, "DescribeAccount", map[string]any{"AccountId": "999999999999"})
	wantOrgError(t, w, out, "AccountNotFoundException")
	w, out = orgCall(t, h, orgAdmin, "DescribeAccount", map[string]any{"AccountId": "abc"})
	wantOrgError(t, w, out, "InvalidInputException")

	// Pagination: one per page.
	_, out = orgCall(t, h, orgAdmin, "ListAccounts", map[string]any{"MaxResults": 1})
	tok, _ := out["NextToken"].(string)
	if len(out["Accounts"].([]any)) != 1 || tok == "" {
		t.Fatalf("page 1 %v", out)
	}
	_, out = orgCall(t, h, orgAdmin, "ListAccounts", map[string]any{"MaxResults": 1, "NextToken": tok})
	if got := out["Accounts"].([]any)[0].(map[string]any)["Id"]; got != "912345678901" {
		t.Errorf("page 2 is %v", got)
	}
	w, out = orgCall(t, h, orgAdmin, "ListAccounts", map[string]any{"MaxResults": 21})
	wantOrgError(t, w, out, "InvalidInputException")

	// By parent: the root holds them all; an unknown parent is ParentNotFound.
	_, root := orgCall(t, h, orgAdmin, "ListRoots", map[string]any{})
	rootID := root["Roots"].([]any)[0].(map[string]any)["Id"]
	_, out = orgCall(t, h, orgAdmin, "ListAccountsForParent", map[string]any{"ParentId": rootID})
	if len(out["Accounts"].([]any)) != 3 {
		t.Errorf("accounts under the root %v", out)
	}
	w, out = orgCall(t, h, orgAdmin, "ListAccountsForParent", map[string]any{"ParentId": "ou-abcd-12345678"})
	wantOrgError(t, w, out, "ParentNotFoundException")
}

// CreateAccount creates a member Account named by its derived id, homed in a new namespace, and its
// status is IN_PROGRESS until the composition reports the account ready.
func TestOrganizations_CreateAccount(t *testing.T) {
	h, dyn := orgTestHandler(t, true, []string{"team-c"})
	_, out := orgCall(t, h, orgAdmin, "CreateAccount", map[string]any{"AccountName": "Team C", "Email": "c@example.com"})
	st, _ := out["CreateAccountStatus"].(map[string]any)
	car, _ := st["Id"].(string)
	if st["State"] != "IN_PROGRESS" || !createRequestRe.MatchString(car) {
		t.Fatalf("status %v", out)
	}
	l, err := dyn.Resource(gvrAccounts).List(context.Background(), metav1.ListOptions{})
	if err != nil || len(l.Items) != 1 {
		t.Fatalf("accounts after create: %v %v", l, err)
	}
	obj := l.Items[0]
	spec := obj.Object["spec"].(map[string]any)
	nss := spec["namespaces"].([]any)
	// "team-c" exists already, so the home is a new namespace.
	if nss[0] != "team-c-2" || obj.GetName() != spec["accountId"] || spec["accountId"] != accounts.DeriveAccountID("team-c-2", 0) ||
		obj.GetAnnotations()[annAccountName] != "Team C" || obj.GetLabels()[labelCreatedBy] != "aws-shim" {
		t.Fatalf("created %v", obj.Object)
	}

	_, out = orgCall(t, h, orgAdmin, "DescribeCreateAccountStatus", map[string]any{"CreateAccountRequestId": car})
	if s := out["CreateAccountStatus"].(map[string]any); s["State"] != "IN_PROGRESS" || s["AccountId"] != obj.GetName() {
		t.Fatalf("describe status %v", out)
	}
	if err := unstructured.SetNestedField(obj.Object, true, "status", "ready"); err != nil {
		t.Fatal(err)
	}
	if _, err := dyn.Resource(gvrAccounts).Update(context.Background(), &obj, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	_, out = orgCall(t, h, orgAdmin, "DescribeCreateAccountStatus", map[string]any{"CreateAccountRequestId": car})
	if s := out["CreateAccountStatus"].(map[string]any); s["State"] != "SUCCEEDED" {
		t.Fatalf("after ready %v", out)
	}
	w, out := orgCall(t, h, orgAdmin, "DescribeCreateAccountStatus", map[string]any{"CreateAccountRequestId": "car-000000000001abcdefgh"})
	wantOrgError(t, w, out, "CreateAccountStatusNotFoundException")

	// The same email again fails, as AWS reports it.
	_, out = orgCall(t, h, orgAdmin, "CreateAccount", map[string]any{"AccountName": "Other", "Email": "C@example.com"})
	if s := out["CreateAccountStatus"].(map[string]any); s["State"] != "FAILED" || s["FailureReason"] != "EMAIL_ALREADY_EXISTS" {
		t.Fatalf("duplicate email %v", out)
	}
	for _, bad := range []map[string]any{
		{"AccountName": "", "Email": "d@example.com"},
		{"AccountName": "D", "Email": "not-an-email"},
		{"AccountName": "D", "Email": "d@example.com", "RoleName": "Custom"},
	} {
		w, out := orgCall(t, h, orgAdmin, "CreateAccount", bad)
		wantOrgError(t, w, out, "InvalidInputException")
	}
}

// A new account's home is never a platform namespace: an account named like one gets the next free name.
func TestOrganizations_CreateAccountNeverHomesInAPlatformNamespace(t *testing.T) {
	h, dyn := orgTestHandler(t, true, nil)
	orgCall(t, h, orgAdmin, "CreateAccount", map[string]any{"AccountName": "monitoring", "Email": "m@example.com"})
	l, _ := dyn.Resource(gvrAccounts).List(context.Background(), metav1.ListOptions{})
	if len(l.Items) != 1 {
		t.Fatalf("accounts %v", l)
	}
	if home := l.Items[0].Object["spec"].(map[string]any)["namespaces"].([]any)[0]; home == "monitoring" {
		t.Fatal("an account was homed in a platform namespace")
	}
}

// RBAC refuses a caller without rights on the Account kind; a member account's caller is refused outright.
func TestOrganizations_Authorization(t *testing.T) {
	h, _ := orgTestHandler(t, false, nil)
	w, out := orgCall(t, h, orgAdmin, "ListAccounts", map[string]any{})
	wantOrgError(t, w, out, "AccessDeniedException")

	h, _ = orgTestHandler(t, true, nil)
	member := orgAdmin
	member.Account = "912345678901" // a principal of a member account
	w, out = orgCall(t, h, member, "DescribeOrganization", map[string]any{})
	wantOrgError(t, w, out, "AccessDeniedException")
	if !strings.Contains(out["Message"].(string), "management account") {
		t.Errorf("message %v should say why", out)
	}

	h, _ = orgTestHandler(t, true, nil)
	w, out = orgCall(t, h, orgAdmin, "CloseAccount", map[string]any{"AccountId": "912345678901"})
	wantOrgError(t, w, out, "UnsupportedAPIEndpointException")
}

func TestHomeNamespaceBase(t *testing.T) {
	for in, want := range map[string]string{"Team C": "team-c", "--Prod/EU--": "prod-eu", "!!!": "account",
		strings.Repeat("a", 80): strings.Repeat("a", 55)} {
		if got := homeNamespaceBase(in); got != want {
			t.Errorf("homeNamespaceBase(%q) = %q, want %q", in, got, want)
		}
	}
}
