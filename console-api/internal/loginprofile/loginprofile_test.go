package loginprofile

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const storeNS = "open-infra-aws-shim"

func newStore(objs ...*corev1.Secret) Store {
	cs := fake.NewSimpleClientset()
	for _, o := range objs {
		_, _ = cs.CoreV1().Secrets(o.Namespace).Create(context.Background(), o, metav1.CreateOptions{})
	}
	return Store{CS: cs, NS: storeNS, Cost: bcrypt.MinCost}
}

func TestSecretName_UniqueAcrossAccounts(t *testing.T) {
	a, b := SecretName("open-infra-console", "alice"), SecretName("tenant-a", "alice")
	if a == b || !strings.HasPrefix(a, SecretPrefix+"alice-") {
		t.Fatalf("names must be per user and namespace: %q %q", a, b)
	}
	if long := SecretName("ns", strings.Repeat("x", 60)); len(long) > 63 {
		t.Fatalf("name too long for a Secret: %d", len(long))
	}
}

func TestWriteVerifyAndReplace(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	if _, err := s.Write(ctx, "open-infra-console", "alice", "Old-Pass-1", 0); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Verify(ctx, "open-infra-console", "alice", "Old-Pass-1"); !ok {
		t.Fatal("the password just set must verify")
	}
	if ok, _ := s.Verify(ctx, "open-infra-console", "alice", "wrong"); ok {
		t.Fatal("a wrong password verified")
	}
	// Another account's alice has no profile.
	if _, err := s.Verify(ctx, "tenant-a", "alice", "Old-Pass-1"); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("another account's user must have no profile, got %v", err)
	}
	if _, err := s.Write(ctx, "open-infra-console", "alice", "New-Pass-2", 2); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Verify(ctx, "open-infra-console", "alice", "Old-Pass-1"); ok {
		t.Fatal("the replaced password still verifies")
	}
	if r, _ := s.Reused(ctx, "open-infra-console", "alice", "Old-Pass-1", 2); !r {
		t.Fatal("the replaced password must count as reused with PasswordReusePrevention 2")
	}
	if r, _ := s.Reused(ctx, "open-infra-console", "alice", "Old-Pass-1", 1); r {
		t.Fatal("with PasswordReusePrevention 1 only the current password is remembered")
	}
}

// A Secret of a profile's name that is not that user's profile is never read as one, nor overwritten.
func TestNotAProfileIsNeitherReadNorOverwritten(t *testing.T) {
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	name := SecretName("open-infra-console", "alice")
	s := newStore(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: storeNS,
		Labels: map[string]string{LabelProfile: "true", LabelUser: "mallory", LabelUserNamespace: "open-infra-console"}},
		Data: map[string][]byte{HashKey: hash}})
	if _, err := s.Verify(ctx, "open-infra-console", "alice", "pw"); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("a Secret labelled for another user must not verify alice, got %v", err)
	}
	if _, err := s.Write(ctx, "open-infra-console", "alice", "Pass-word-1", 0); err == nil {
		t.Fatal("a Secret that is not alice's profile must not be overwritten")
	}
	if err := s.Delete(ctx, "open-infra-console", "alice"); err == nil {
		t.Fatal("a Secret that is not alice's profile must not be deleted")
	}
}

func TestDefaultPolicy(t *testing.T) {
	for pw, ok := range map[string]bool{
		"short1A":       false, // 7 characters
		"alllowercase1": false, // two classes
		"Lower-and-1":   true,
		"UPPER1lower":   true,
		"Abcdefg!":      true,
	} {
		if err := CheckDefault(pw); (err == nil) != ok {
			t.Errorf("default policy, %q: got %v, want ok=%v", pw, err, ok)
		}
	}
	if err := CheckDefault("Acct-Name-1", "acct-name-1"); err == nil {
		t.Error("the account's name must be refused")
	}
}

func TestCustomPolicy(t *testing.T) {
	p := Policy{MinimumPasswordLength: 12, RequireSymbols: true, RequireNumbers: true, RequireUppercaseCharacters: true, RequireLowercaseCharacters: true}
	err := p.Check("short")
	var v *ViolationError
	if !errors.As(err, &v) || !strings.Contains(v.Msg, "at least 12 characters") || !strings.Contains(v.Msg, "uppercase") {
		t.Fatalf("got %v", err)
	}
	if err := p.Check("Long-enough-pass1"); err != nil {
		t.Fatalf("a compliant password was refused: %v", err)
	}
	if (Policy{MinimumPasswordLength: 5}).Validate() == nil || (Policy{MaxPasswordAge: 2000}).Validate() == nil ||
		(Policy{PasswordReusePrevention: 25}).Validate() == nil {
		t.Error("out-of-range policy values must be refused")
	}
}

func TestPolicyStore(t *testing.T) {
	ctx := context.Background()
	s := newStore()
	if _, found, _ := s.GetPolicy(ctx, "000000000000"); found {
		t.Fatal("no policy is set at first")
	}
	if err := s.PutPolicy(ctx, "000000000000", Policy{RequireNumbers: true, AllowUsersToChangePassword: true}); err != nil {
		t.Fatal(err)
	}
	p, found, _ := s.GetPolicy(ctx, "000000000000")
	if !found || !p.RequireNumbers || p.MinimumPasswordLength != 6 || !p.AllowUsersToChangePassword {
		t.Fatalf("got %+v %v", p, found)
	}
	if _, found, _ := s.GetPolicy(ctx, "912345678901"); found {
		t.Fatal("a policy belongs to its own account")
	}
	if _, custom, err := s.CheckFor(ctx, "000000000000", "nonumbers"); !custom || err == nil {
		t.Fatalf("the custom policy must apply: custom=%v err=%v", custom, err)
	}
	if ok, _ := s.DeletePolicy(ctx, "000000000000"); !ok {
		t.Fatal("delete must report the policy it removed")
	}
	if ok, _ := s.DeletePolicy(ctx, "000000000000"); ok {
		t.Fatal("deleting an absent policy reports nothing removed")
	}
}

func TestExpiry(t *testing.T) {
	p := Policy{MaxPasswordAge: 30}
	now := time.Now()
	if !p.Expired(now.Add(-31*24*time.Hour), now) || p.Expired(now.Add(-29*24*time.Hour), now) {
		t.Fatal("MaxPasswordAge 30 expires a password after 30 days")
	}
	if (Policy{}).Expired(now.Add(-1000*24*time.Hour), now) {
		t.Fatal("no MaxPasswordAge: passwords never expire")
	}
}
