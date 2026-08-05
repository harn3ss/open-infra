package iam

import (
	"context"
	"errors"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestRoleGroups(t *testing.T) {
	cases := map[string][]string{
		"root":      {"openinfra:admins", "openinfra:users"},
		"admin":     {"openinfra:admins", "openinfra:users"},
		"ADMIN":     {"openinfra:admins", "openinfra:users"}, // case-insensitive
		"poweruser": {"openinfra:powerusers", "openinfra:users"},
		"readonly":  {"openinfra:readers", "openinfra:users"},
		"":          {"openinfra:readers", "openinfra:users"}, // unknown → least privilege
		"nonsense":  {"openinfra:readers", "openinfra:users"},
	}
	for role, want := range cases {
		got := RoleGroups(role)
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("RoleGroups(%q) = %v, want %v", role, got, want)
		}
	}
}

func TestIdentity(t *testing.T) {
	t.Run("explicit groups win over role", func(t *testing.T) {
		user, groups, ok := Identity(Claims{Sub: "alice", Role: "readonly",
			Groups: []string{"openinfra:admins", "openinfra:users"}})
		if !ok || user != "openinfra:alice" || groups[0] != "openinfra:admins" {
			t.Fatalf("got user=%q groups=%v ok=%v", user, groups, ok)
		}
	})
	t.Run("role fallback when no explicit groups", func(t *testing.T) {
		_, groups, ok := Identity(Claims{Sub: "svc", Role: "poweruser"})
		if !ok || groups[0] != "openinfra:powerusers" {
			t.Fatalf("got groups=%v ok=%v", groups, ok)
		}
	})
	t.Run("empty subject is not a valid identity", func(t *testing.T) {
		if _, _, ok := Identity(Claims{Role: "admin"}); ok {
			t.Fatal("empty subject must not resolve to an identity")
		}
	})
	t.Run("subject but no role/groups → least privilege, still valid", func(t *testing.T) {
		user, groups, ok := Identity(Claims{Sub: "nobody"})
		if !ok || user != "openinfra:nobody" || groups[0] != "openinfra:readers" {
			t.Fatalf("got user=%q groups=%v ok=%v", user, groups, ok)
		}
	})
}

// sarReactor makes a fake clientset answer SubjectAccessReview creates with a fixed verdict/error.
func sarReactor(allowed, denied bool, err error) ktesting.ReactionFunc {
	return func(ktesting.Action) (bool, runtime.Object, error) {
		if err != nil {
			return true, nil, err
		}
		return true, &authzv1.SubjectAccessReview{
			Status: authzv1.SubjectAccessReviewStatus{Allowed: allowed, Denied: denied},
		}, nil
	}
}

func TestCanDo(t *testing.T) {
	claims := Claims{Sub: "alice", Groups: []string{"openinfra:powerusers", "openinfra:users"}}

	t.Run("allowed", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("create", "subjectaccessreviews", sarReactor(true, false, nil))
		ok, _ := CanDo(context.Background(), cs, claims, "update", "openinfra.dev", "applications", "default", "x")
		if !ok {
			t.Fatal("expected allowed")
		}
	})

	// "Prove the no": every denial path must fail CLOSED. These are the tests that earn the trust —
	// a broken CanDo that returned true on error would be silently, catastrophically open.
	t.Run("denied is not allowed", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("create", "subjectaccessreviews", sarReactor(false, true, nil))
		if ok, _ := CanDo(context.Background(), cs, claims, "delete", "openinfra.dev", "policies", "", ""); ok {
			t.Fatal("explicit Denied must not be allowed")
		}
	})
	t.Run("not-allowed is not allowed", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("create", "subjectaccessreviews", sarReactor(false, false, nil))
		if ok, _ := CanDo(context.Background(), cs, claims, "get", "openinfra.dev", "secrets", "", ""); ok {
			t.Fatal("Allowed=false must not be allowed")
		}
	})
	t.Run("API error fails closed", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("create", "subjectaccessreviews", sarReactor(false, false, errors.New("apiserver down")))
		if ok, _ := CanDo(context.Background(), cs, claims, "list", "openinfra.dev", "applications", "", ""); ok {
			t.Fatal("an authorization-check error must fail closed (deny)")
		}
	})
	t.Run("no identity fails closed without calling the API", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("create", "subjectaccessreviews", sarReactor(true, false, nil)) // would allow if reached
		if ok, reason := CanDo(context.Background(), cs, Claims{}, "get", "openinfra.dev", "applications", "", ""); ok || reason != "no identity" {
			t.Fatalf("empty claims must deny with 'no identity', got ok=%v reason=%q", ok, reason)
		}
	})
}
