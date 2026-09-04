package controlplaneauthz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/harn3ss/open-infra/policyengine"
	authzv1 "k8s.io/api/authorization/v1"
)

func fixed(docs []PolicyDoc, err error) Loader {
	return func(context.Context) ([]PolicyDoc, error) { return docs, err }
}

func resReq(user string, groups []string, verb, group, resource, ns, name string) authzv1.SubjectAccessReviewSpec {
	return authzv1.SubjectAccessReviewSpec{
		User:   user,
		Groups: groups,
		ResourceAttributes: &authzv1.ResourceAttributes{
			Verb: verb, Group: group, Resource: resource, Namespace: ns, Name: name,
		},
	}
}

// A group grant allows its verbs on a resource type; an explicit Deny overrides (which RBAC cannot
// express); a principal no statement names is default-denied.
func TestEvaluate_GroupGrantWithForbid(t *testing.T) {
	docs := []PolicyDoc{{
		AppliesTo: []string{"Group::platform-admins"},
		Statements: []policyengine.Statement{
			{Effect: policyengine.Allow, Actions: []string{"get", "list", "create", "update", "delete"},
				Resources: []string{"databases.openinfra.dev::*"}},
			{Effect: policyengine.Deny, Actions: []string{"delete"},
				Resources: []string{"databases.openinfra.dev::prod/*"}},
		},
	}}
	c := New(fixed(docs, nil), time.Minute)
	ctx := context.Background()
	admins := []string{"openinfra:platform-admins"}

	if d := c.Evaluate(ctx, resReq("alice", admins, "create", "openinfra.dev", "databases", "team-a", "db1")); !d.Allowed {
		t.Errorf("create db in team-a should be allowed: %s", d.Reason)
	}
	if d := c.Evaluate(ctx, resReq("alice", admins, "delete", "openinfra.dev", "databases", "prod", "db1")); d.Allowed {
		t.Errorf("delete of a prod db must be denied by the forbid, got allowed")
	}
	// A verb the grant does not include → default deny within the allow-list.
	if d := c.Evaluate(ctx, resReq("alice", admins, "escalate", "openinfra.dev", "databases", "team-a", "db1")); d.Allowed {
		t.Errorf("an ungranted verb must be denied, got allowed")
	}
	// A principal no statement names → default deny (Cedar is the sole authority here).
	if d := c.Evaluate(ctx, resReq("mallory", []string{"openinfra:interns"}, "get", "openinfra.dev", "databases", "team-a", "db1")); d.Allowed {
		t.Errorf("an ungoverned principal must be denied under replacement semantics, got allowed")
	}
}

// A ServiceAccount principal is matched from the API server's "system:serviceaccount:ns:name" user.
func TestEvaluate_ServiceAccountPrincipal(t *testing.T) {
	docs := []PolicyDoc{{
		AppliesTo:  []string{"ServiceAccount::open-infra-console/console-api"},
		Statements: []policyengine.Statement{{Effect: policyengine.Allow, Actions: []string{"*"}, Resources: []string{"*"}}},
	}}
	c := New(fixed(docs, nil), time.Minute)
	spec := resReq("system:serviceaccount:open-infra-console:console-api", nil, "list", "openinfra.dev", "applications", "team-a", "")
	if d := c.Evaluate(context.Background(), spec); !d.Allowed {
		t.Errorf("the console-api SA should be granted: %s", d.Reason)
	}
	// A different SA is not matched.
	other := resReq("system:serviceaccount:other:sa", nil, "list", "openinfra.dev", "applications", "team-a", "")
	if d := c.Evaluate(context.Background(), other); d.Allowed {
		t.Errorf("a different SA must not inherit the grant, got allowed")
	}
}

// A non-resource URL (health, metrics) maps to resource type NonResourceURL by path.
func TestEvaluate_NonResourceURL(t *testing.T) {
	docs := []PolicyDoc{{
		AppliesTo:  []string{"Group::system:monitoring"},
		Statements: []policyengine.Statement{{Effect: policyengine.Allow, Actions: []string{"get"}, Resources: []string{"NonResourceURL::/metrics"}}},
	}}
	c := New(fixed(docs, nil), time.Minute)
	spec := authzv1.SubjectAccessReviewSpec{
		User: "prometheus", Groups: []string{"system:monitoring"},
		NonResourceAttributes: &authzv1.NonResourceAttributes{Verb: "get", Path: "/metrics"},
	}
	if d := c.Evaluate(context.Background(), spec); !d.Allowed {
		t.Errorf("GET /metrics should be allowed: %s", d.Reason)
	}
	spec.NonResourceAttributes.Path = "/healthz"
	if d := c.Evaluate(context.Background(), spec); d.Allowed {
		t.Errorf("GET /healthz is not granted, must be denied, got allowed")
	}
}

// Fail-closed: a cold-start load error denies; a nil checker denies with a clear reason.
func TestEvaluate_FailClosed(t *testing.T) {
	c := New(fixed(nil, errors.New("apiserver down")), time.Minute)
	if d := c.Evaluate(context.Background(), resReq("alice", nil, "get", "", "pods", "default", "x")); d.Allowed {
		t.Errorf("a load error must fail closed, got allowed")
	}
	var nilc *Checker
	if d := nilc.Evaluate(context.Background(), resReq("alice", nil, "get", "", "pods", "default", "x")); d.Allowed {
		t.Errorf("a nil checker must deny, got allowed")
	}
}
