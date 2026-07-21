package main

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// crdGroups is what actually decides a CR-backed user's authority — every group it
// returns becomes an Impersonate-Group header. Getting it wrong is a privilege bug,
// not a cosmetic one, so pin the exact output.
func TestCRDGroups_PrefixesAndAlwaysIncludesUsers(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"prefixes each group", []string{"admins"}, []string{"openinfra:admins", "openinfra:users"}},
		{"multiple", []string{"powerusers", "readers"},
			[]string{"openinfra:powerusers", "openinfra:readers", "openinfra:users"}},
		{"blanks are dropped", []string{"", "  ", "admins"},
			[]string{"openinfra:admins", "openinfra:users"}},
		// No groups must NOT fall back to a default role: a User that forgot its
		// groups gets a session and no authority at all.
		{"no groups fails closed", nil, []string{"openinfra:users"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var u crdUser
			u.Spec.Groups = tc.in
			got := crdGroups(u)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v want %v", got, tc.want)
				}
			}
		})
	}
}

// A group name must never reach the impersonation header unprefixed: "system:masters"
// spelled in a User's spec.groups has to come out as the inert "openinfra:system:masters",
// not as the real cluster-admin group.
func TestCRDGroups_CannotNameABuiltInGroup(t *testing.T) {
	var u crdUser
	u.Spec.Groups = []string{"system:masters", "system:authenticated"}
	for _, g := range crdGroups(u) {
		if g == "system:masters" || g == "system:authenticated" {
			t.Fatalf("built-in group %q escaped the openinfra: prefix: %v", g, crdGroups(u))
		}
	}
}

func TestCRDPasswordHash(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "alice-pw", Namespace: "open-infra-console"},
		Data:       map[string][]byte{"hash": []byte("  $2a$10$abc  "), "other": []byte("x")},
	})
	a := &authStore{cs: cs, ns: "open-infra-console"}

	mk := func(name, key string) crdUser {
		var u crdUser
		u.Spec.PasswordSecretRef.Name = name
		u.Spec.PasswordSecretRef.Key = key
		return u
	}

	if h, ok := a.crdPasswordHash(context.Background(), mk("alice-pw", "")); !ok || h != "$2a$10$abc" {
		t.Fatalf("default key + trim: got %q ok=%v", h, ok)
	}
	if _, ok := a.crdPasswordHash(context.Background(), mk("", "")); ok {
		t.Fatal("a User with no passwordSecretRef must not authenticate")
	}
	if _, ok := a.crdPasswordHash(context.Background(), mk("missing", "")); ok {
		t.Fatal("a missing Secret must not authenticate")
	}
	if _, ok := a.crdPasswordHash(context.Background(), mk("alice-pw", "nope")); ok {
		t.Fatal("a missing key must not authenticate")
	}
}

// The Secret is consulted before the CRDs so the bootstrap root account keeps working
// even when the IAM CRDs are absent — which is exactly the state a fake clientset is in.
func TestVerify_LocalWorksWithoutIAMCRDs(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	users := `{"root":{"hash":"` + string(hash) + `","role":"root"}}`
	cs := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: authSecret, Namespace: "open-infra-console"},
		Data:       map[string][]byte{"users": []byte(users)},
	})
	a := &authStore{cs: cs, ns: "open-infra-console", mode: "local"}

	role, groups, ok := a.verify(context.Background(), "root", "s3cret")
	if !ok || role != "root" {
		t.Fatalf("break-glass root login failed: role=%q ok=%v", role, ok)
	}
	// Secret-backed accounts carry no explicit groups; roleGroups(role) derives them.
	if groups != nil {
		t.Fatalf("local account should not pin groups, got %v", groups)
	}
	if _, _, ok := a.verify(context.Background(), "root", "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
	if _, _, ok := a.verify(context.Background(), "nobody", "s3cret"); ok {
		t.Fatal("unknown user accepted")
	}
}

// identityFor must prefer the claim's explicit groups (a CR user's spec.groups) over
// the role-derived defaults, otherwise kind: User memberships would be silently ignored.
func TestIdentityFromClaims_PrefersExplicitGroups(t *testing.T) {
	c := sessionClaims{Sub: "alice", Role: "readonly", Groups: []string{"openinfra:admins", "openinfra:users"}}
	user, groups, ok := identityFromClaims(c)
	if !ok || user != "openinfra:alice" {
		t.Fatalf("user=%q ok=%v", user, ok)
	}
	if len(groups) != 2 || groups[0] != "openinfra:admins" {
		t.Fatalf("explicit groups ignored: %v", groups)
	}

	// No explicit groups → fall back to the role mapping.
	_, groups, _ = identityFromClaims(sessionClaims{Sub: "root", Role: "root"})
	want := roleGroups("root")
	if len(groups) != len(want) || groups[0] != want[0] {
		t.Fatalf("role fallback broken: %v want %v", groups, want)
	}
}
