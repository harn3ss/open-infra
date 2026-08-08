package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

// @skip/@include execution. The spec pins the semantics (skip drops on if:true, include drops on
// if:false), so there is a single right answer. Driven through the executor via the introspection path
// (no resolvers needed) plus a data query, at the field, fragment-spread, and inline-fragment locations.

func directiveEngine(t *testing.T) *Engine {
	t.Helper()
	post := map[string]any{"id": "p1", "title": "Hi", "author": map[string]any{"id": "a1", "name": "Ada"}}
	resolvers := map[string]resolver.Resolver{
		"Query.getPost": {Runtime: stubRuntime{}, Source: stubStore{result: post}},
	}
	schema, err := ParseSchema(nestedSDL)
	if err != nil {
		t.Fatal(err)
	}
	return New(resolvers, WithSchema(schema))
}

func TestDirectives_SkipIncludeOnField(t *testing.T) {
	e := directiveEngine(t)
	has := func(q string, vars map[string]any) map[string]any {
		res := e.Execute(context.Background(), q, vars)
		if len(res.Errors) != 0 {
			t.Fatalf("query errored: %+v", res.Errors)
		}
		return res.Data["getPost"].(map[string]any)
	}

	// @skip(if: true) drops the field; @skip(if: false) keeps it.
	if m := has(`{ getPost(id:"p1") { id title @skip(if: true) } }`, nil); mapHas(m, "title") {
		t.Error("@skip(if:true) should drop title")
	}
	if m := has(`{ getPost(id:"p1") { id title @skip(if: false) } }`, nil); !mapHas(m, "title") {
		t.Error("@skip(if:false) should keep title")
	}
	// @include(if: false) drops; @include(if: true) keeps.
	if m := has(`{ getPost(id:"p1") { id title @include(if: false) } }`, nil); mapHas(m, "title") {
		t.Error("@include(if:false) should drop title")
	}
	if m := has(`{ getPost(id:"p1") { id title @include(if: true) } }`, nil); !mapHas(m, "title") {
		t.Error("@include(if:true) should keep title")
	}
	// Variable-driven if.
	q := `query($show: Boolean!) { getPost(id:"p1") { id title @include(if: $show) } }`
	if m := has(q, map[string]any{"show": false}); mapHas(m, "title") {
		t.Error("@include(if:$show=false) should drop title")
	}
	if m := has(q, map[string]any{"show": true}); !mapHas(m, "title") {
		t.Error("@include(if:$show=true) should keep title")
	}
}

func TestDirectives_OnFragmentSpreadAndInline(t *testing.T) {
	e := directiveEngine(t)
	// Skip a whole fragment spread.
	q := `{ getPost(id:"p1") { id ...F @skip(if: true) } }
	      fragment F on Post { title author { name } }`
	res := e.Execute(context.Background(), q, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errored: %+v", res.Errors)
	}
	m := res.Data["getPost"].(map[string]any)
	if mapHas(m, "title") || mapHas(m, "author") {
		t.Errorf("@skip on a spread should drop its fields: %v", m)
	}
	// Include an inline fragment conditionally.
	q = `query($show: Boolean!) { getPost(id:"p1") { id ... on Post @include(if: $show) { title } } }`
	if m := mustData(t, e, q, map[string]any{"show": false}); mapHas(m, "title") {
		t.Error("@include(if:false) on inline fragment should drop its fields")
	}
	if m := mustData(t, e, q, map[string]any{"show": true}); !mapHas(m, "title") {
		t.Error("@include(if:true) on inline fragment should keep its fields")
	}
}

func TestDirectives_BadIfErrors(t *testing.T) {
	e := directiveEngine(t)
	// Missing `if`.
	if res := e.Execute(context.Background(), `{ getPost(id:"p1") { id @skip } }`, nil); len(res.Errors) == 0 {
		t.Error("@skip without if should error")
	}
	// Non-boolean `if`.
	if res := e.Execute(context.Background(), `{ getPost(id:"p1") { id @skip(if: "yes") } }`, nil); len(res.Errors) == 0 {
		t.Error("@skip with a non-boolean if should error")
	}
}

func mustData(t *testing.T, e *Engine, q string, vars map[string]any) map[string]any {
	t.Helper()
	res := e.Execute(context.Background(), q, vars)
	if len(res.Errors) != 0 {
		t.Fatalf("query errored: %+v", res.Errors)
	}
	return res.Data["getPost"].(map[string]any)
}

func mapHas(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}
