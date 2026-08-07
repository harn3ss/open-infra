package probe

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtlruntime"
)

// Field-level authorization: the executor consults the shared boundary BEFORE running
// a field's resolver. These prove the "no" (a denial rejects the field and the resolver never runs) as
// well as the "yes", and that the check is delegated to the injected Authorizer — not a bespoke rule.

// countingStore records whether the data source was ever touched.
type countingStore struct{ calls int }

func (c *countingStore) Execute(context.Context, runtime.Operation) (any, error) {
	c.calls++
	return map[string]any{"id": "1"}, nil
}

// fakeAuthz is a stand-in for the SAR authorizer (unit-testing the executor's delegation, not k8s).
type fakeAuthz struct {
	allow bool
	last  authz.Requirement
	calls int
}

func (f *fakeAuthz) Authorize(_ context.Context, _ authz.Identity, need authz.Requirement) error {
	f.calls++
	f.last = need
	if f.allow {
		return nil
	}
	return authz.ErrDenied
}

func fieldAuthEngine(t *testing.T, a authz.Authorizer, store *countingStore) *graphql.Engine {
	t.Helper()
	r := resolver.Resolver{
		Runtime: vtlruntime.New(engine(), mustCorpus("getitem.request.vtl"), "$util.toJson($ctx.result)"),
		Source:  store,
		Auth:    authz.Requirement{Group: "openinfra.dev", Resource: "graphqlapis", Verb: "get"},
	}
	return graphql.New(map[string]resolver.Resolver{"Query.getTodo": r}, graphql.WithAuthorizer(a))
}

// DENY (prove the "no"): the field is Unauthorized, data is null, and the resolver's data source is
// NEVER called.
func TestFieldAuth_DenyRejectsBeforeResolver(t *testing.T) {
	store := &countingStore{}
	deny := &fakeAuthz{allow: false}
	e := fieldAuthEngine(t, deny, store)

	res := e.Execute(context.Background(), `query { getTodo(id:"1") { id } }`, nil)
	if len(res.Errors) != 1 || res.Errors[0].ErrorType != "Unauthorized" {
		t.Fatalf("expected one Unauthorized error, got %+v", res.Errors)
	}
	if res.Data["getTodo"] != nil {
		t.Fatalf("a denied field must be null, got %v", res.Data["getTodo"])
	}
	if store.calls != 0 {
		t.Fatalf("a denied resolver must not run — data source called %d times", store.calls)
	}
	// The requirement was delegated to the boundary, not evaluated locally.
	if deny.calls != 1 || deny.last.Resource != "graphqlapis" || deny.last.Verb != "get" {
		t.Fatalf("executor must delegate the exact Requirement to the Authorizer, got %+v (calls=%d)", deny.last, deny.calls)
	}
}

// ALLOW: the same field, permitted, runs its resolver.
func TestFieldAuth_AllowRunsResolver(t *testing.T) {
	store := &countingStore{}
	e := fieldAuthEngine(t, &fakeAuthz{allow: true}, store)
	res := e.Execute(context.Background(), `query { getTodo(id:"1") { id } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("allowed field errored: %+v", res.Errors)
	}
	if store.calls != 1 {
		t.Fatalf("an allowed resolver must run its data source once, got %d", store.calls)
	}
}

// A public field (zero Requirement) runs without consulting the authorizer at all.
func TestFieldAuth_PublicFieldSkipsAuthorizer(t *testing.T) {
	store := &countingStore{}
	a := &fakeAuthz{allow: false} // would deny if consulted
	r := resolver.Resolver{
		Runtime: vtlruntime.New(engine(), mustCorpus("getitem.request.vtl"), "$util.toJson($ctx.result)"),
		Source:  store, // no Auth → public
	}
	e := graphql.New(map[string]resolver.Resolver{"Query.getTodo": r}, graphql.WithAuthorizer(a))
	res := e.Execute(context.Background(), `query { getTodo(id:"1") { id } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("public field errored: %+v", res.Errors)
	}
	if a.calls != 0 {
		t.Fatalf("a public field must not consult the authorizer, got %d calls", a.calls)
	}
}

// The caller's identity flows to $ctx.identity for mapping templates (mirrors AppSync).
func TestFieldAuth_IdentityInContext(t *testing.T) {
	store := &countingStore{}
	r := resolver.Resolver{
		Runtime: vtlruntime.New(engine(), mustCorpus("getitem.request.vtl"), `{"who":$util.toJson($ctx.identity.username)}`),
		Source:  store,
	}
	e := graphql.New(map[string]resolver.Resolver{"Query.getTodo": r})
	ctx := authz.NewContext(context.Background(), authz.Identity{Username: "alice", Groups: []string{"admins"}})
	res := e.Execute(ctx, `query { getTodo(id:"1") { who } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %+v", res.Errors)
	}
	got := res.Data["getTodo"].(map[string]any)["who"]
	if got != "alice" {
		t.Fatalf("$ctx.identity.username not exposed, got %v", got)
	}
}
