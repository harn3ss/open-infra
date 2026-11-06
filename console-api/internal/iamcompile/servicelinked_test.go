package iamcompile

import (
	"context"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/console-api/internal/controlplaneauthz"
	"github.com/harn3ss/open-infra/console-api/internal/iamauthz"
	authzv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

// A service-linked role is bound in every member account's home and nowhere else, its corpus grant
// admits its ServiceAccounts there alone, and a role that is not named as one is never bound.
func TestServiceLinkedRolesBindInMemberHomes(t *testing.T) {
	shim := rbacv1.Subject{Kind: "ServiceAccount", Namespace: "open-infra-aws-shim", Name: "aws-shim"}
	in := Input{
		Home: iamauthz.DefaultHomeNamespace,
		NamespaceAccounts: map[string]string{
			"shop": "111111111111", "shop-extra": "111111111111", "lab": "222222222222",
			"ops": iamauthz.ManagementAccount,
		},
		Namespaces: []string{"shop", "shop-extra", "lab", "ops", "kube-system"},
		Homes:      map[string]bool{"shop": true, "lab": true, "ops": true},
		ServiceLinkedRoles: []ServiceLinkedRole{
			{Name: ServiceLinkedRolePrefix + "aws-shim", Principals: []rbacv1.Subject{shim},
				Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "create"}}}},
			{Name: "cluster-admin", Principals: []rbacv1.Subject{shim},
				Rules: []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}},
		},
	}
	out := Compile(in)
	got := map[string]bool{}
	for _, rb := range out.RoleBindings {
		if rb.Labels[ServiceLinkedRoleLabel] != "true" {
			continue
		}
		got[rb.Namespace+"/"+rb.Name] = true
		if rb.Labels[GeneratedByLabel] != GeneratedBy || rb.RoleRef.Kind != "ClusterRole" || rb.RoleRef.Name != ServiceLinkedRolePrefix+"aws-shim" {
			t.Fatalf("binding %s/%s: labels %v roleRef %+v", rb.Namespace, rb.Name, rb.Labels, rb.RoleRef)
		}
		if rb.Labels[AccountIDLabel] != in.NamespaceAccounts[rb.Namespace] {
			t.Fatalf("binding %s/%s carries account %q", rb.Namespace, rb.Name, rb.Labels[AccountIDLabel])
		}
	}
	want := map[string]bool{"shop/" + ServiceLinkedRolePrefix + "aws-shim": true, "lab/" + ServiceLinkedRolePrefix + "aws-shim": true}
	if len(got) != len(want) || !got["shop/"+ServiceLinkedRolePrefix+"aws-shim"] || !got["lab/"+ServiceLinkedRolePrefix+"aws-shim"] {
		t.Fatalf("service-linked bindings %v, want %v (member homes only; never the management account's, a non-home namespace, or a role not named as one)", got, want)
	}
	if out.ServiceLinked != 2 {
		t.Fatalf("ServiceLinked = %d, want 2", out.ServiceLinked)
	}

	raw, err := MarshalCorpus(MergeGrants(out.Corpus))
	if err != nil {
		t.Fatal(err)
	}
	docs, err := ParseCorpus(raw)
	if err != nil {
		t.Fatal(err)
	}
	chk := controlplaneauthz.New(func(context.Context) ([]controlplaneauthz.PolicyDoc, error) { return docs, nil }, time.Minute)
	ask := func(user, verb, ns string) bool {
		return chk.Evaluate(context.Background(), authzv1.SubjectAccessReviewSpec{
			User: user, Groups: []string{"system:serviceaccounts"},
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: verb, Resource: "configmaps", Namespace: ns},
		}).Allowed
	}
	const sa = "system:serviceaccount:open-infra-aws-shim:aws-shim"
	for _, c := range []struct {
		user, verb, ns string
		want           bool
	}{
		{sa, "create", "shop", true},
		{sa, "get", "lab", true},
		{sa, "delete", "shop", false},       // not in the role
		{sa, "create", "shop-extra", false}, // a member namespace that is not the home
		{sa, "create", "ops", false},        // the management account's
		{sa, "create", "kube-system", false},
		{"system:serviceaccount:kube-system:other", "create", "shop", false},
	} {
		if got := ask(c.user, c.verb, c.ns); got != c.want {
			t.Errorf("%s %s configmaps in %s: allowed=%v, want %v", c.user, c.verb, c.ns, got, c.want)
		}
	}

	// No member account: nothing is bound and the corpus carries no service-linked grant.
	in.NamespaceAccounts = map[string]string{"ops": iamauthz.ManagementAccount}
	if out := Compile(in); out.ServiceLinked != 0 {
		t.Fatalf("with no member account, %d service-linked bindings", out.ServiceLinked)
	}
}

func TestParseServicePrincipals(t *testing.T) {
	got := ParseServicePrincipals(" open-infra-aws-shim/aws-shim, crossplane-system/openinfra-statemachine,bad,/x,ns/,Upper/x,open-infra-aws-shim/aws-shim,a/b/c")
	if len(got) != 2 || got[0].Namespace != "crossplane-system" || got[1].Name != "aws-shim" {
		t.Fatalf("ParseServicePrincipals = %+v", got)
	}
	for _, s := range got {
		if s.Kind != rbacv1.ServiceAccountKind {
			t.Fatalf("kind %q", s.Kind)
		}
	}
}
