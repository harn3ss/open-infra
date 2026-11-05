package main

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/console-api/internal/awskeys"
	"github.com/harn3ss/open-infra/console-api/internal/iam"
	"github.com/harn3ss/open-infra/console-api/internal/loginprofile"
	"golang.org/x/crypto/bcrypt"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	lpUsersNS = "open-infra-console"
	lpStoreNS = "open-infra-aws-shim"
)

func init() { loginBcryptCost = bcrypt.MinCost }

// lpHandler is an IAM front door with users alice (local) and dir (an LDAP user), whose RBAC check
// answers allow (lpAllow flips it for a test without losing the store's objects).
func lpHandler(t *testing.T, allow bool) (*iamHandler, *fake.Clientset) {
	t.Helper()
	lpAllow = allow
	cs := csWithSARFunc(func(*authzv1.ResourceAttributes) bool { return lpAllow })
	dyn := fakeDynWith(gvrUsers)
	for name, src := range map[string]string{"alice": "local", "dir": "ldap"} {
		u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "iam.openinfra.dev/v1", "kind": "User",
			"metadata": map[string]any{"name": name, "namespace": lpUsersNS}, "spec": map[string]any{"source": src}}}
		if _, err := dyn.Resource(gvrUsers).Namespace(lpUsersNS).Create(context.Background(), u, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	return newIAMHandler(cs, dyn, awskeys.NewStore(cs, lpStoreNS), nil, lpUsersNS, "000000000000", "us-east-1", discardLogger()), cs
}

func lpUser(t *testing.T, h *iamHandler, name string) *unstructured.Unstructured {
	t.Helper()
	u, err := h.dyn.Resource(gvrUsers).Namespace(lpUsersNS).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func lpCall(h *iamHandler, claims iam.Claims, kv ...string) (int, string) {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	w := serveWith(h, formOp(v), claims)
	return w.Code, w.Body.String()
}

var lpAdmin = iam.Claims{Sub: "ops", Groups: []string{"openinfra:admins"}}

// lpAllow is the RBAC answer lpHandler's clientset gives.
var lpAllow bool

func TestLoginProfile_Lifecycle(t *testing.T) {
	h, cs := lpHandler(t, true)
	ctx := context.Background()

	if code, body := lpCall(h, lpAdmin, "Action", "GetLoginProfile", "UserName", "alice"); code != 404 || !strings.Contains(body, "NoSuchEntity") {
		t.Fatalf("no profile yet: %d %s", code, body)
	}
	if code, body := lpCall(h, lpAdmin, "Action", "CreateLoginProfile", "UserName", "alice", "Password", "weak"); code != 400 || !strings.Contains(body, "PasswordPolicyViolation") {
		t.Fatalf("AWS's default policy refuses a weak password: %d %s", code, body)
	}
	code, body := lpCall(h, lpAdmin, "Action", "CreateLoginProfile", "UserName", "alice", "Password", "Correct-Horse-1", "PasswordResetRequired", "true")
	if code != 200 || !strings.Contains(body, "<PasswordResetRequired>true</PasswordResetRequired>") || !strings.Contains(body, "<UserName>alice</UserName>") {
		t.Fatalf("CreateLoginProfile: %d %s", code, body)
	}
	if code, body := lpCall(h, lpAdmin, "Action", "CreateLoginProfile", "UserName", "alice", "Password", "Correct-Horse-2"); code != 409 || !strings.Contains(body, "EntityAlreadyExists") {
		t.Fatalf("a second profile: %d %s", code, body)
	}

	// The hash is in the store, not the console namespace, and the User points at it.
	store := loginprofile.Store{CS: cs, NS: lpStoreNS}
	if ok, _ := store.Verify(ctx, lpUsersNS, "alice", "Correct-Horse-1"); !ok {
		t.Fatal("the store does not verify the password just set")
	}
	u := lpUser(t, h, "alice")
	ref, _, _ := unstructured.NestedStringMap(u.Object, "spec", "passwordSecretRef")
	if ref["namespace"] != lpStoreNS || ref["name"] != loginprofile.SecretName(lpUsersNS, "alice") || ref["key"] != loginprofile.HashKey {
		t.Fatalf("passwordSecretRef %v", ref)
	}
	if a := u.GetAnnotations(); a[loginprofile.AnnResetRequired] != "true" || a[loginprofile.AnnCreated] == "" || a[loginprofile.AnnPasswordLastChanged] == "" {
		t.Fatalf("annotations %v", a)
	}
	if code, body := lpCall(h, lpAdmin, "Action", "GetLoginProfile", "UserName", "alice"); code != 200 || !strings.Contains(body, "<PasswordResetRequired>true</PasswordResetRequired>") {
		t.Fatalf("GetLoginProfile: %d %s", code, body)
	}

	// UpdateLoginProfile: a new password, and the reset requirement cleared.
	if code, body := lpCall(h, lpAdmin, "Action", "UpdateLoginProfile", "UserName", "alice", "Password", "Battery-Staple-3", "PasswordResetRequired", "false"); code != 200 {
		t.Fatalf("UpdateLoginProfile: %d %s", code, body)
	}
	if ok, _ := store.Verify(ctx, lpUsersNS, "alice", "Battery-Staple-3"); !ok {
		t.Fatal("UpdateLoginProfile did not set the password")
	}
	if a := lpUser(t, h, "alice").GetAnnotations(); a[loginprofile.AnnResetRequired] != "" {
		t.Fatalf("PasswordResetRequired false must clear the annotation: %v", a)
	}

	// DeleteLoginProfile: the User no longer points anywhere and the hash is gone.
	if code, body := lpCall(h, lpAdmin, "Action", "DeleteLoginProfile", "UserName", "alice"); code != 200 {
		t.Fatalf("DeleteLoginProfile: %d %s", code, body)
	}
	if _, found, _ := unstructured.NestedMap(lpUser(t, h, "alice").Object, "spec", "passwordSecretRef"); found {
		t.Fatal("the User still points at a password")
	}
	if ok, _ := store.Exists(ctx, lpUsersNS, "alice"); ok {
		t.Fatal("the profile Secret survived DeleteLoginProfile")
	}
	for _, op := range []string{"GetLoginProfile", "UpdateLoginProfile", "DeleteLoginProfile"} {
		if code, body := lpCall(h, lpAdmin, "Action", op, "UserName", "alice", "Password", "Correct-Horse-9"); code != 404 || !strings.Contains(body, "Login Profile for User alice cannot be found") {
			t.Errorf("%s with no profile: %d %s", op, code, body)
		}
	}

	// The shim never wrote a Secret into the console namespace.
	if list, _ := cs.CoreV1().Secrets(lpUsersNS).List(ctx, metav1.ListOptions{}); len(list.Items) != 0 {
		t.Fatalf("the shim wrote %d Secret(s) into the console namespace", len(list.Items))
	}
}

func TestLoginProfile_Refusals(t *testing.T) {
	h, _ := lpHandler(t, true)
	for _, tc := range []struct {
		name, user, code, want string
	}{
		{"no such user", "nobody", "404", "The user with name nobody cannot be found"},
		{"the reserved name root", "root", "404", "cannot be found"},
		{"a directory user", "dir", "400", "signs in through its directory"},
	} {
		code, body := lpCall(h, lpAdmin, "Action", "CreateLoginProfile", "UserName", tc.user, "Password", "Correct-Horse-1")
		if strconv.Itoa(code) != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("%s: %d %s", tc.name, code, body)
		}
	}
	// A principal without IAM authority (the coarse check denies) creates nothing.
	hNo, _ := lpHandler(t, false)
	if code, _ := lpCall(hNo, iam.Claims{Sub: "intern"}, "Action", "CreateLoginProfile", "UserName", "alice", "Password", "Correct-Horse-1"); code != 403 {
		t.Fatalf("a principal with no IAM authority created a login profile: %d", code)
	}
}

func TestChangePassword(t *testing.T) {
	h, cs := lpHandler(t, true)
	ctx := context.Background()
	alice := iam.Claims{Sub: "alice"}
	if code, body := lpCall(h, lpAdmin, "Action", "CreateLoginProfile", "UserName", "alice", "Password", "First-Pass-1", "PasswordResetRequired", "true"); code != 200 {
		t.Fatalf("setup: %d %s", code, body)
	}
	store := loginprofile.Store{CS: cs, NS: lpStoreNS}
	if err := store.PutPolicy(ctx, "000000000000", loginprofile.Policy{MinimumPasswordLength: 8, AllowUsersToChangePassword: true, PasswordReusePrevention: 2}); err != nil {
		t.Fatal(err)
	}

	if code, body := lpCall(h, alice, "Action", "ChangePassword", "OldPassword", "wrong", "NewPassword", "Second-Pass-2"); code != 400 || !strings.Contains(body, "InvalidUserType") || !strings.Contains(body, "oldPassword is invalid") {
		t.Fatalf("a wrong old password: %d %s", code, body)
	}
	if code, body := lpCall(h, alice, "Action", "ChangePassword", "OldPassword", "First-Pass-1", "NewPassword", "short"); code != 400 || !strings.Contains(body, "PasswordPolicyViolation") {
		t.Fatalf("the account policy applies to the new password: %d %s", code, body)
	}
	if code, body := lpCall(h, alice, "Action", "ChangePassword", "OldPassword", "First-Pass-1", "NewPassword", "First-Pass-1"); code != 400 || !strings.Contains(body, "last 2 passwords") {
		t.Fatalf("PasswordReusePrevention refuses the current password: %d %s", code, body)
	}
	if code, body := lpCall(h, alice, "Action", "ChangePassword", "OldPassword", "First-Pass-1", "NewPassword", "Second-Pass-2"); code != 200 {
		t.Fatalf("ChangePassword: %d %s", code, body)
	}
	if ok, _ := store.Verify(ctx, lpUsersNS, "alice", "Second-Pass-2"); !ok {
		t.Fatal("the new password does not verify")
	}
	if a := lpUser(t, h, "alice").GetAnnotations(); a[loginprofile.AnnResetRequired] != "" {
		t.Fatalf("a changed password clears PasswordResetRequired: %v", a)
	}
	if code, body := lpCall(h, alice, "Action", "ChangePassword", "OldPassword", "Second-Pass-2", "NewPassword", "First-Pass-1"); code != 400 || !strings.Contains(body, "PasswordPolicyViolation") {
		t.Fatalf("the previous password is remembered (PasswordReusePrevention 2): %d %s", code, body)
	}

	// Only an IAM user changes its own password.
	if code, body := lpCall(h, iam.Claims{Sub: "app/session", AssumedRole: "app"}, "Action", "ChangePassword", "OldPassword", "x", "NewPassword", "Third-Pass-3"); code != 400 || !strings.Contains(body, "InvalidUserType") {
		t.Fatalf("a role session: %d %s", code, body)
	}
	if code, body := lpCall(h, iam.Claims{Sub: "root", Role: "root"}, "Action", "ChangePassword", "OldPassword", "x", "NewPassword", "Third-Pass-3"); code != 400 || !strings.Contains(body, "InvalidUserType") {
		t.Fatalf("the root user: %d %s", code, body)
	}
}

// Without AllowUsersToChangePassword, a user needs iam:ChangePassword on itself; with neither, refused.
func TestChangePassword_NeedsAGrantOrThePolicy(t *testing.T) {
	h, _ := lpHandler(t, true)
	if code, body := lpCall(h, lpAdmin, "Action", "CreateLoginProfile", "UserName", "alice", "Password", "First-Pass-1"); code != 200 {
		t.Fatalf("setup: %d %s", code, body)
	}
	lpAllow = false // alice holds no authority over her own User, and no policy allows users to
	if code, body := lpCall(h, iam.Claims{Sub: "alice"}, "Action", "ChangePassword", "OldPassword", "First-Pass-1", "NewPassword", "Second-Pass-2"); code != 403 || !strings.Contains(body, "not authorized to perform: iam:ChangePassword") {
		t.Fatalf("ChangePassword with no grant: %d %s", code, body)
	}
}

// A profile the console set before the store (a Secret in the console namespace): readable, movable to
// the store by UpdateLoginProfile, and unset by DeleteLoginProfile; ChangePassword cannot prove its old
// password and says so.
func TestLoginProfile_ConsoleProfile(t *testing.T) {
	h, cs := lpHandler(t, true)
	ctx := context.Background()
	if err := h.patchUser(ctx, "alice", map[string]any{"spec": map[string]any{"passwordSecretRef": map[string]any{"name": "iam-pw-alice", "key": "hash"}}}); err != nil {
		t.Fatal(err)
	}
	if code, body := lpCall(h, lpAdmin, "Action", "GetLoginProfile", "UserName", "alice"); code != 200 {
		t.Fatalf("a console profile is a profile: %d %s", code, body)
	}
	if code, body := lpCall(h, iam.Claims{Sub: "alice"}, "Action", "ChangePassword", "OldPassword", "x", "NewPassword", "Second-Pass-2"); code != 409 || !strings.Contains(body, "EntityTemporarilyUnmodifiable") {
		t.Fatalf("ChangePassword on a console profile: %d %s", code, body)
	}
	if code, body := lpCall(h, lpAdmin, "Action", "UpdateLoginProfile", "UserName", "alice", "Password", "Moved-Pass-1"); code != 200 {
		t.Fatalf("UpdateLoginProfile moves it to the store: %d %s", code, body)
	}
	if ok, _ := (loginprofile.Store{CS: cs, NS: lpStoreNS}).Verify(ctx, lpUsersNS, "alice", "Moved-Pass-1"); !ok {
		t.Fatal("the moved password does not verify in the store")
	}
	ref, _, _ := unstructured.NestedStringMap(lpUser(t, h, "alice").Object, "spec", "passwordSecretRef")
	if ref["namespace"] != lpStoreNS {
		t.Fatalf("the User must now point at the store: %v", ref)
	}
}

func TestAccountPasswordPolicy(t *testing.T) {
	h, _ := lpHandler(t, true)
	if code, body := lpCall(h, lpAdmin, "Action", "GetAccountPasswordPolicy"); code != 404 || !strings.Contains(body, "Password Policy with domain name 000000000000 cannot be found") {
		t.Fatalf("no policy yet: %d %s", code, body)
	}
	if code, body := lpCall(h, lpAdmin, "Action", "UpdateAccountPasswordPolicy", "MinimumPasswordLength", "200"); code != 400 || !strings.Contains(body, "ValidationError") {
		t.Fatalf("an out-of-range length: %d %s", code, body)
	}
	if code, body := lpCall(h, lpAdmin, "Action", "UpdateAccountPasswordPolicy", "MinimumPasswordLength", "14", "RequireSymbols", "true",
		"AllowUsersToChangePassword", "true", "MaxPasswordAge", "90", "PasswordReusePrevention", "5"); code != 200 {
		t.Fatalf("UpdateAccountPasswordPolicy: %d %s", code, body)
	}
	code, body := lpCall(h, lpAdmin, "Action", "GetAccountPasswordPolicy")
	for _, want := range []string{"<MinimumPasswordLength>14</MinimumPasswordLength>", "<RequireSymbols>true</RequireSymbols>",
		"<AllowUsersToChangePassword>true</AllowUsersToChangePassword>", "<ExpirePasswords>true</ExpirePasswords>",
		"<MaxPasswordAge>90</MaxPasswordAge>", "<PasswordReusePrevention>5</PasswordReusePrevention>"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("GetAccountPasswordPolicy lacks %s: %d %s", want, code, body)
		}
	}
	// The custom policy now governs new passwords.
	if code, body := lpCall(h, lpAdmin, "Action", "CreateLoginProfile", "UserName", "alice", "Password", "Short-Pass-1"); code != 400 || !strings.Contains(body, "at least 14 characters") {
		t.Fatalf("the custom policy applies: %d %s", code, body)
	}
	if code, _ := lpCall(h, lpAdmin, "Action", "DeleteAccountPasswordPolicy"); code != 200 {
		t.Fatal("DeleteAccountPasswordPolicy")
	}
	if code, body := lpCall(h, lpAdmin, "Action", "DeleteAccountPasswordPolicy"); code != 404 || !strings.Contains(body, "NoSuchEntity") {
		t.Fatalf("deleting an absent policy: %d %s", code, body)
	}
}
