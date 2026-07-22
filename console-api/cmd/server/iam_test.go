package main

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestValidName(t *testing.T) {
	ok := []string{"alice", "a", "a-b-c", "user1", "x9"}
	bad := []string{"", "-a", "a-", "A", "a_b", "a.b", "a b", "system:masters"}
	for _, s := range ok {
		if !validName(s) {
			t.Errorf("validName(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validName(s) {
			t.Errorf("validName(%q) = true, want false", s)
		}
	}
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	if validName(string(long)) {
		t.Error("a 64-char name must be rejected (k8s limit is 63)")
	}
}

func TestCleanGroups(t *testing.T) {
	got := cleanGroups([]string{" admins ", "admins", "", "  ", "readers"})
	want := []string{"admins", "readers"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

// The impersonation ceiling is what decides whether a group actually does anything, so the
// helpers that flag out-of-ceiling names must match the impersonator ClusterRole's
// resourceNames exactly. Getting this wrong shows a green UI for a group that silently
// grants nothing.
func TestGroupCeiling(t *testing.T) {
	for _, g := range []string{"admins", "powerusers", "readers", "users"} {
		if !isBuiltinGroup(g) {
			t.Errorf("%q should be in the impersonation ceiling", g)
		}
	}
	for _, g := range []string{"devs", "system:masters", "admin", ""} {
		if isBuiltinGroup(g) {
			t.Errorf("%q must NOT be treated as impersonable", g)
		}
	}
	// A user in a mix of bound and unbound groups: only the unbound ones are flagged.
	ub := unboundGroups([]string{"admins", "devs", "readers", " ops "})
	if len(ub) != 2 || ub[0] != "devs" || ub[1] != "ops" {
		t.Fatalf("unboundGroups = %v, want [devs ops]", ub)
	}
}

func TestIAMErr(t *testing.T) {
	cases := map[string]string{
		`users.iam.openinfra.dev "alice" already exists`: "a resource with that name already exists",
		`users.iam.openinfra.dev "bob" not found`:        "not found",
		`secrets is forbidden: cannot create`:            "the console is not permitted to do that",
		`some other apiserver failure`:                   "the API server rejected the request",
	}
	for in, want := range cases {
		if got := iamErr(errString(in)); got != want {
			t.Errorf("iamErr(%q) = %q, want %q", in, got, want)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// writePasswordSecret must create the Secret the first time and update the hash in place on
// a reset — never leaving a stale hash, and always producing a Secret whose stored value is
// a valid bcrypt of the new password.
func TestWritePasswordSecret(t *testing.T) {
	cs := fake.NewSimpleClientset()
	a := &authStore{cs: cs, ns: "open-infra-console"}
	ctx := context.Background()

	if err := a.writePasswordSecret(ctx, "iam-pw-alice", "alice", "first-password"); err != nil {
		t.Fatal(err)
	}
	sec, err := cs.CoreV1().Secrets("open-infra-console").Get(ctx, "iam-pw-alice", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if sec.Labels["openinfra.dev/iam-user"] != "alice" {
		t.Errorf("secret not labelled with its user: %v", sec.Labels)
	}
	if bcrypt.CompareHashAndPassword(sec.Data[iamPasswordKey], []byte("first-password")) != nil {
		t.Fatal("stored hash does not verify against the original password")
	}

	// Reset: same Secret, new hash.
	if err := a.writePasswordSecret(ctx, "iam-pw-alice", "alice", "second-password"); err != nil {
		t.Fatal(err)
	}
	sec, _ = cs.CoreV1().Secrets("open-infra-console").Get(ctx, "iam-pw-alice", metav1.GetOptions{})
	if bcrypt.CompareHashAndPassword(sec.Data[iamPasswordKey], []byte("second-password")) != nil {
		t.Fatal("hash was not updated on reset")
	}
	if bcrypt.CompareHashAndPassword(sec.Data[iamPasswordKey], []byte("first-password")) == nil {
		t.Fatal("the old password still verifies — the hash was not replaced")
	}
}

// A User created here must round-trip through the sign-in read path: the same bcrypt Secret
// verifies, and crdGroups prefixes exactly as impersonation expects.
func TestCreatedUserIsSignInReady(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "iam-pw-bob", Namespace: "open-infra-console"},
	})
	a := &authStore{cs: cs, ns: "open-infra-console"}
	if err := a.writePasswordSecret(context.Background(), "iam-pw-bob", "bob", "hunter2!!"); err != nil {
		t.Fatal(err)
	}
	var u crdUser
	u.Spec.PasswordSecretRef.Name = "iam-pw-bob"
	u.Spec.Groups = []string{"admins"}
	hash, ok := a.crdPasswordHash(context.Background(), u)
	if !ok || bcrypt.CompareHashAndPassword([]byte(hash), []byte("hunter2!!")) != nil {
		t.Fatal("crdPasswordHash could not read back what writePasswordSecret stored")
	}
	g := crdGroups(u)
	if len(g) != 2 || g[0] != "openinfra:admins" || g[1] != "openinfra:users" {
		t.Fatalf("crdGroups = %v, want [openinfra:admins openinfra:users]", g)
	}
}

// A name clash is the caller's fault (409), not a platform failure (502) — the earlier
// version returned 502 for "already exists", which reads as "the console is broken".
func TestIAMErrStatus(t *testing.T) {
	cases := map[string]int{
		`policies.iam.openinfra.dev "vmops" already exists`: 409,
		`policies.iam.openinfra.dev "x" not found`:          404,
		`clusterroles is forbidden: cannot create`:          403,
		`connection refused`:                                502,
	}
	for in, want := range cases {
		if got := iamErrStatus(errString(in)); got != want {
			t.Errorf("iamErrStatus(%q) = %d, want %d", in, got, want)
		}
	}
}
