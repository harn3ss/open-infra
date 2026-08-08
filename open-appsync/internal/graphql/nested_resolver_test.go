package graphql

import (
	"context"
	"fmt"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// fnRuntime is a resolver runtime whose response is a function of the $ctx (so a test can read
// $ctx.source and drive errors) — enough to exercise per-nested-field resolvers without VTL.
type fnRuntime struct {
	fn func(ctx map[string]any) (any, error)
}

func (fnRuntime) RenderRequest(map[string]any) (runtime.Operation, error) {
	return runtime.Operation{}, nil
}
func (f fnRuntime) RenderResponse(ctx map[string]any) (any, error) { return f.fn(ctx) }

type denyAll struct{}

func (denyAll) Authorize(context.Context, authz.Identity, authz.Requirement) error {
	return fmt.Errorf("forbidden")
}

func nestedSchema(t *testing.T) *Schema {
	t.Helper()
	s, err := ParseSchema(nestedSDL)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The root getPost returns an author with only an id — the `name` must come from a per-field resolver.
func rootPostResolver() resolver.Resolver {
	post := map[string]any{"id": "p1", "title": "Hi", "author": map[string]any{"id": "a1"}}
	return resolver.Resolver{Runtime: stubRuntime{}, Source: stubStore{result: post}}
}

// TestNestedResolver_RunsWithSource: a Post.author resolver runs, sees $ctx.source (the Post), and its
// result replaces the structural value; nested __typename still resolves.
func TestNestedResolver_RunsWithSource(t *testing.T) {
	authorRes := resolver.Resolver{Runtime: fnRuntime{fn: func(ctx map[string]any) (any, error) {
		src := ctx["source"].(map[string]any)
		return map[string]any{"id": "a1", "name": "Ada-of-" + src["title"].(string)}, nil
	}}, Source: stubStore{}}
	e := New(map[string]resolver.Resolver{
		"Query.getPost": rootPostResolver(),
		"Post.author":   authorRes,
	}, WithSchema(nestedSchema(t)))

	res := e.Execute(context.Background(), `{ getPost(id:"p1") { title author { id name __typename } } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errored: %+v", res.Errors)
	}
	author := res.Data["getPost"].(map[string]any)["author"].(map[string]any)
	if author["name"] != "Ada-of-Hi" { // proves the nested resolver ran AND saw $ctx.source
		t.Errorf("author.name = %v, want Ada-of-Hi", author["name"])
	}
	if author["__typename"] != "Author" {
		t.Errorf("author.__typename = %v, want Author", author["__typename"])
	}
}

// TestNestedResolver_StructuralFallback: with no Post.author resolver, the nested value is read
// structurally from the parent result (the pre-existing behavior — a selected field the parent didn't
// produce is null).
func TestNestedResolver_StructuralFallback(t *testing.T) {
	e := New(map[string]resolver.Resolver{"Query.getPost": rootPostResolver()}, WithSchema(nestedSchema(t)))
	res := e.Execute(context.Background(), `{ getPost(id:"p1") { author { id name } } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errored: %+v", res.Errors)
	}
	author := res.Data["getPost"].(map[string]any)["author"].(map[string]any)
	if author["id"] != "a1" || author["name"] != nil {
		t.Errorf("structural author = %v, want {id:a1, name:nil}", author)
	}
}

// TestNestedResolver_ErrorPath: a nested resolver error nulls the field and reports the path.
func TestNestedResolver_ErrorPath(t *testing.T) {
	boom := resolver.Resolver{Runtime: fnRuntime{fn: func(map[string]any) (any, error) {
		return nil, fmt.Errorf("author lookup failed")
	}}, Source: stubStore{}}
	e := New(map[string]resolver.Resolver{
		"Query.getPost": rootPostResolver(),
		"Post.author":   boom,
	}, WithSchema(nestedSchema(t)))
	res := e.Execute(context.Background(), `{ getPost(id:"p1") { author { name } } }`, nil)
	if res.Data["getPost"].(map[string]any)["author"] != nil {
		t.Error("errored nested field should be null")
	}
	if len(res.Errors) == 0 {
		t.Fatal("expected an error")
	}
	p := res.Errors[0].Path
	if len(p) != 2 || p[0] != "getPost" || p[1] != "author" {
		t.Errorf("error path = %v, want [getPost author]", p)
	}
}

// TestNestedResolver_AuthEnforced: a nested resolver's Auth requirement is checked before it runs.
func TestNestedResolver_AuthEnforced(t *testing.T) {
	authorRes := resolver.Resolver{
		Runtime: fnRuntime{fn: func(map[string]any) (any, error) { return map[string]any{"name": "secret"}, nil }},
		Source:  stubStore{},
		Auth:    authz.Requirement{Verb: "get", Resource: "authors"},
	}
	e := New(map[string]resolver.Resolver{
		"Query.getPost": rootPostResolver(),
		"Post.author":   authorRes,
	}, WithSchema(nestedSchema(t)), WithAuthorizer(denyAll{}))

	res := e.Execute(context.Background(), `{ getPost(id:"p1") { author { name } } }`, nil)
	if res.Data["getPost"].(map[string]any)["author"] != nil {
		t.Error("denied nested field should be null")
	}
	if len(res.Errors) == 0 || res.Errors[0].ErrorType != "Unauthorized" {
		t.Fatalf("expected Unauthorized, got %+v", res.Errors)
	}
}
