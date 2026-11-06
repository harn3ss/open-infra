package main

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/cfn/awsidentity"
	"github.com/harn3ss/open-infra/console-api/internal/accounts"
	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

const (
	testMgmt   = "000000000000"
	testMember = "912345678901"
	memberHome = "team-a"
)

// testDirectory is a directory with the management account's IAM home and one member account (team-a,
// its home), plus a suspended member.
func testDirectory() *accounts.Directory {
	d := accounts.NewDirectory(testMgmt)
	label := func(name, id string, home bool, status string) {
		l := map[string]string{accounts.LabelAccountID: id}
		if home {
			l[accounts.LabelAccountHome] = "true"
		}
		if status != "" {
			l[accounts.LabelAccountStatus] = status
		}
		d.Observe(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: l}})
	}
	label("open-infra-console", testMgmt, true, "")
	label(memberHome, testMember, true, "")
	label("team-b", "923456789012", true, accounts.StatusSuspended)
	return d
}

func accountAuth(t *testing.T, keys fakeKeys) (*authenticator, *[]string) {
	t.Helper()
	var resolvedIn []string
	return &authenticator{
		keys: keys,
		resolve: func(_ context.Context, owner string) ([]string, bool) {
			return []string{"openinfra:users"}, owner != ""
		},
		resolveIn: func(_ context.Context, ns, owner string) ([]string, bool) {
			resolvedIn = append(resolvedIn, ns+"/"+owner)
			return []string{"openinfra:users"}, true
		},
		dir: testDirectory(),
	}, &resolvedIn
}

// A key minted before accounts records none: it acts in its owner's account, the management account,
// and its claims are exactly what they were before accounts (no Account set).
func TestKeyClaims_KeyWithoutAnAccountActsInTheManagementAccount(t *testing.T) {
	a, _ := accountAuth(t, nil)
	c, ok := a.keyClaims(context.Background(), awskeys.Key{AccessKeyID: "OIAK1", Owner: "alice"})
	if !ok || c.Account != "" || c.Sub != "alice" {
		t.Fatalf("old key: %+v ok=%v, want alice in the management account (Account empty)", c, ok)
	}
}

// A key recording a member account acts in it, and its owner is resolved in that account's home.
func TestKeyClaims_MemberAccountKey(t *testing.T) {
	a, resolvedIn := accountAuth(t, nil)
	c, ok := a.keyClaims(context.Background(), awskeys.Key{AccessKeyID: "OIAK2", Owner: "bob", Account: testMember})
	if !ok || c.Account != testMember || c.Sub != "bob" {
		t.Fatalf("member key: %+v ok=%v", c, ok)
	}
	if len(*resolvedIn) != 1 || (*resolvedIn)[0] != memberHome+"/bob" {
		t.Fatalf("the owner must be resolved in the account's home, got %v", *resolvedIn)
	}
}

// A key of a suspended account, or of an account the directory does not know, does not authenticate.
func TestKeyClaims_SuspendedOrUnknownAccountRefused(t *testing.T) {
	a, _ := accountAuth(t, nil)
	for _, acct := range []string{"923456789012", "955555555555"} {
		if c, ok := a.keyClaims(context.Background(), awskeys.Key{AccessKeyID: "OIAK3", Owner: "eve", Account: acct}); ok {
			t.Errorf("account %s: authenticated as %+v, want refused", acct, c)
		}
	}
	// With no member resolver configured a member key never authenticates (fail closed).
	a.resolveIn = nil
	if _, ok := a.keyClaims(context.Background(), awskeys.Key{AccessKeyID: "OIAK4", Owner: "bob", Account: testMember}); ok {
		t.Error("a member key authenticated with no member resolver")
	}
}

// An authenticator with no directory keeps everyone in the management account.
func TestKeyClaims_NoDirectory(t *testing.T) {
	a := &authenticator{resolve: func(context.Context, string) ([]string, bool) { return nil, true }}
	c, ok := a.keyClaims(context.Background(), awskeys.Key{Owner: "alice", Account: testMember})
	if !ok || c.Account != "" {
		t.Fatalf("no directory: %+v ok=%v, want the management account", c, ok)
	}
}

// fakeRolesIn adds namespaced resolution to fakeRoles: key "<ns>/<name>".
type fakeRolesIn struct {
	fakeRoles
	in fakeRoles
}

func (f fakeRolesIn) ResolveIn(ctx context.Context, ns, name string) (resolvedRole, bool) {
	return f.in.Resolve(ctx, ns+"/"+name)
}

func crossAccountSTS(t *testing.T, member fakeRoles) *stsHandler {
	t.Helper()
	m := testMinter(t)
	return &stsHandler{account: testMgmt, minter: m, roles: fakeRolesIn{fakeRoles: fakeRoles{}, in: member},
		accounts: testDirectory(), logger: discardLogger()}
}

// A management-account user assumes a member account's role whose trust names the management account's
// root (as OrganizationAccountAccessRole does): the session acts in the member account, as that account's
// role, and its ARN is the member account's.
func TestAssumeRole_CrossAccountIntoAMemberRole(t *testing.T) {
	h := crossAccountSTS(t, fakeRoles{memberHome + "/admin": {trust: []string{"arn:aws:iam::" + testMgmt + ":root"}}})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("arn:aws:iam::"+testMember+":role/admin", "ops"), iam.Claims{Sub: "alice"}, "rid")
	if w.Code != http.StatusOK {
		t.Fatalf("cross-account assume: %d %s", w.Code, w.Body)
	}
	var resp assumeRoleResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if got, want := resp.Result.AssumedRoleUser.Arn, "arn:aws:sts::"+testMember+":assumed-role/admin/ops"; got != want {
		t.Fatalf("session ARN %q, want %q", got, want)
	}
	// The minted session authenticates in the member account, as the role in that account's home.
	c := resp.Result.Credentials
	req := signedSessionRequest(t, c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	auth := &authenticator{keys: fakeKeys{}, resolve: func(context.Context, string) ([]string, bool) { return nil, false },
		sts: h.minter, dir: testDirectory()}
	claims, err := auth.authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("cross-account session: %v", err)
	}
	if claims.Account != testMember || claims.AssumedRole != memberHome+"/admin" {
		t.Fatalf("session claims %+v, want account %s, role %s/admin", claims, testMember, memberHome)
	}
}

// A role named in AWS's mixed case — OrganizationAccountAccessRole, the object
// organizationaccountaccessrole — acts as its object, which the IAM policy world keys its policies by,
// while its session ARN keeps the AWS name.
func TestAssumeRole_MixedCaseRoleActsAsItsObject(t *testing.T) {
	h := crossAccountSTS(t, fakeRoles{memberHome + "/OrganizationAccountAccessRole": {trust: []string{"arn:aws:iam::" + testMgmt + ":root"}}})
	w := httptest.NewRecorder()
	h.serve(w, assumeRequest("arn:aws:iam::"+testMember+":role/OrganizationAccountAccessRole", "ops"), iam.Claims{Sub: "alice"}, "rid")
	if w.Code != http.StatusOK {
		t.Fatalf("assume: %d %s", w.Code, w.Body)
	}
	var resp assumeRoleResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if got, want := resp.Result.AssumedRoleUser.Arn, "arn:aws:sts::"+testMember+":assumed-role/OrganizationAccountAccessRole/ops"; got != want {
		t.Fatalf("session ARN %q, want %q", got, want)
	}
	c := resp.Result.Credentials
	auth := &authenticator{keys: fakeKeys{}, resolve: func(context.Context, string) ([]string, bool) { return nil, false },
		sts: h.minter, dir: testDirectory()}
	claims, err := auth.authenticate(context.Background(), signedSessionRequest(t, c.AccessKeyId, c.SecretAccessKey, c.SessionToken))
	if err != nil {
		t.Fatal(err)
	}
	if claims.AssumedRole != memberHome+"/organizationaccountaccessrole" {
		t.Fatalf("the session acts as %q, want the role's object %s/organizationaccountaccessrole", claims.AssumedRole, memberHome)
	}
	if !strings.Contains(claims.Sub, "OrganizationAccountAccessRole") {
		t.Errorf("the session's name keeps the AWS role name: %q", claims.Sub)
	}
}

// Trust is checked across accounts as AWS does: an entry naming another account's root, or the right
// account's user of another name, does not admit the caller; a member account's user is admitted by its
// own account's root entry but not by the management account's.
func TestAssumeRole_CrossAccountTrustIsAccountScoped(t *testing.T) {
	roles := fakeRoles{
		memberHome + "/other-root": {trust: []string{"arn:aws:iam::955555555555:root"}},
		memberHome + "/user-bob":   {trust: []string{"arn:aws:iam::" + testMgmt + ":user/bob"}},
		memberHome + "/mgmt-root":  {trust: []string{"arn:aws:iam::" + testMgmt + ":root"}},
	}
	h := crossAccountSTS(t, roles)
	cases := []struct {
		role   string
		claims iam.Claims
		ok     bool
	}{
		{"other-root", iam.Claims{Sub: "alice"}, false},
		{"user-bob", iam.Claims{Sub: "alice"}, false},
		{"user-bob", iam.Claims{Sub: "bob"}, true},
		{"mgmt-root", iam.Claims{Sub: "carol", Account: testMember}, false},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		h.serve(w, assumeRequest("arn:aws:iam::"+testMember+":role/"+tc.role, "s"), tc.claims, "rid")
		if (w.Code == http.StatusOK) != tc.ok {
			t.Errorf("%s as %s@%s: %d, want ok=%v", tc.role, tc.claims.Sub, tc.claims.Account, w.Code, tc.ok)
		}
	}
}

// A RoleArn naming an account the shim does not know, or a suspended one, is AccessDenied (never "not
// found"), and an ARN trust entry never matches a ServiceAccount or OIDC caller.
func TestAssumeRole_UnknownOrSuspendedAccountDenied(t *testing.T) {
	h := crossAccountSTS(t, fakeRoles{"team-b/r": {trust: []string{"*"}}})
	for _, acct := range []string{"923456789012", "955555555555"} {
		w := httptest.NewRecorder()
		h.serve(w, assumeRequest("arn:aws:iam::"+acct+":role/r", "s"), iam.Claims{Sub: "alice"}, "rid")
		if w.Code != http.StatusForbidden {
			t.Errorf("account %s: %d, want 403", acct, w.Code)
		}
	}
	if trusted(trustCaller{kind: "ServiceAccount", name: "system:serviceaccount:a:b", account: testMgmt}, []string{"arn:aws:iam::" + testMgmt + ":root"}) {
		t.Error("an account-root trust entry admitted a ServiceAccount token")
	}
}

// GetCallerIdentity reports the caller's own account.
func TestGetCallerIdentity_MemberAccount(t *testing.T) {
	h := crossAccountSTS(t, nil)
	w := httptest.NewRecorder()
	h.writeCallerIdentity(w, iam.Claims{Sub: "bob", Account: testMember}, "rid")
	var resp getCallerIdentityResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Result.Account != testMember || resp.Result.Arn != "arn:aws:iam::"+testMember+":user/bob" {
		t.Fatalf("caller identity %+v", resp.Result)
	}
}

// A role named in AWS's mixed case (OrganizationAccountAccessRole) resolves to the object of its
// lower-cased name that carries the AWS name; a lower-cased object without that annotation does not
// stand in for it.
func TestRoleResolver_AWSNameAnnotation(t *testing.T) {
	role := func(name, awsName string) *unstructured.Unstructured {
		u := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "iam.openinfra.dev/v1", "kind": "Role",
			"metadata": map[string]any{"name": name, "namespace": memberHome},
			"spec":     map[string]any{"trust": []any{"arn:aws:iam::" + testMgmt + ":root"}},
		}}
		if awsName != "" {
			u.SetAnnotations(map[string]string{awsNameAnnotation: awsName})
		}
		return u
	}
	dyn := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(),
		role("organizationaccountaccessrole", "OrganizationAccountAccessRole"), role("deployer", ""))
	r := &dynRoleResolver{dyn: dyn, ns: "open-infra-console"}
	if got, ok := r.ResolveIn(context.Background(), memberHome, "OrganizationAccountAccessRole"); !ok || len(got.trust) != 1 {
		t.Fatalf("mixed-case AWS name: ok=%v %+v", ok, got)
	}
	if _, ok := r.ResolveIn(context.Background(), memberHome, "Deployer"); ok {
		t.Error("a lower-cased object without the AWS-name annotation stood in for a mixed-case name")
	}
	if _, ok := r.Resolve(context.Background(), "organizationaccountaccessrole"); ok {
		t.Error("Resolve must look only in the IAM home namespace")
	}
}

// The router puts the caller's account identity on a member-account request: ARNs and AWS::AccountId
// built for it are the member account's; a management-account request keeps the install's identity.
func TestRouter_WithAccountIdentity(t *testing.T) {
	rt := &serviceRouter{auth: &authenticator{dir: testDirectory()}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := rt.withAccount(r, iam.Claims{Sub: "alice"}); got != r {
		t.Error("a management-account request must keep its context")
	}
	mr := rt.withAccount(r, iam.Claims{Sub: "bob", Account: testMember})
	id := awsidentity.FromContext(mr.Context())
	if id.AccountID != testMember || id.StackNamespace != memberHome {
		t.Fatalf("member identity %+v, want account %s home %s", id, testMember, memberHome)
	}
}
