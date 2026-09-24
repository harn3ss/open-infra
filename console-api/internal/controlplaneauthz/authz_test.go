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

// A subresource is a distinct resource: a grant on "<resource>/<subresource>" (the corpus/RBAC form)
// authorizes the subresource request and ONLY it — the base resource is not granted (no widening), and
// a subresource request is not silently served by a base-resource grant (no collapse). This is the
// exact shape that let the scheduler's pods/binding + pods/status through once the evaluator keyed the
// subresource into the resource type.
func TestEvaluate_SubresourceIsDistinct(t *testing.T) {
	sub := func(user, verb, group, resource, subresource, ns, name string) authzv1.SubjectAccessReviewSpec {
		return authzv1.SubjectAccessReviewSpec{
			User: user,
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb: verb, Group: group, Resource: resource, Subresource: subresource, Namespace: ns, Name: name,
			},
		}
	}
	docs := []PolicyDoc{{
		AppliesTo: []string{"User::system:kube-scheduler"},
		Statements: []policyengine.Statement{
			{Effect: policyengine.Allow, Actions: []string{"create"}, Resources: []string{"pods/binding::*"}},
			{Effect: policyengine.Allow, Actions: []string{"patch", "update"}, Resources: []string{"pods/status::*"}},
			{Effect: policyengine.Allow, Actions: []string{"get", "list", "watch", "delete"}, Resources: []string{"pods::*"}},
			// A grant on a subresource type in a NAMED group, matching the corpus format.
			{Effect: policyengine.Allow, Actions: []string{"update"}, Resources: []string{"daemonsets/status.apps::*"}},
		},
	}}
	c := New(fixed(docs, nil), time.Minute)
	ctx := context.Background()
	const sched = "system:kube-scheduler"

	// The subresource grants now match (previously collapsed to the base type and were denied).
	if d := c.Evaluate(ctx, sub(sched, "create", "", "pods", "binding", "crossplane-system", "job-x")); !d.Allowed {
		t.Errorf("create pods/binding should be allowed by the pods/binding grant: %s", d.Reason)
	}
	if d := c.Evaluate(ctx, sub(sched, "patch", "", "pods", "status", "crossplane-system", "job-x")); !d.Allowed {
		t.Errorf("patch pods/status should be allowed by the pods/status grant: %s", d.Reason)
	}
	if d := c.Evaluate(ctx, sub(sched, "update", "apps", "daemonsets", "status", "kubevirt", "virt-handler")); !d.Allowed {
		t.Errorf("update daemonsets/status.apps should be allowed: %s", d.Reason)
	}
	// No widening: the pods/binding + pods/status grants do NOT confer create/patch on the pods object.
	if d := c.Evaluate(ctx, sub(sched, "create", "", "pods", "", "crossplane-system", "job-x")); d.Allowed {
		t.Errorf("create on the base pods object must NOT be granted by a subresource grant, got allowed")
	}
	if d := c.Evaluate(ctx, sub(sched, "patch", "", "pods", "", "crossplane-system", "job-x")); d.Allowed {
		t.Errorf("patch on the base pods object must NOT be granted by pods/status, got allowed")
	}
	// No collapse: a base grant (delete pods) does not authorize a subresource request.
	if d := c.Evaluate(ctx, sub(sched, "delete", "", "pods", "binding", "crossplane-system", "job-x")); d.Allowed {
		t.Errorf("delete pods/binding must not be served by the base pods delete grant, got allowed")
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
