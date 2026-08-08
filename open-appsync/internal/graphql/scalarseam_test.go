package graphql

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

// The neutral scalar-validation seam: the core consults a registered validator for a custom scalar but
// knows nothing about it. Proven with a NON-AWS scalar so the neutrality is unmistakable.
func TestScalarSeam_CustomValidator(t *testing.T) {
	schema, err := ParseSchema(`
		scalar Slug
		type Query { bySlug(s: Slug!): String }
	`)
	if err != nil {
		t.Fatal(err)
	}
	validators := map[string]ScalarValidator{
		"Slug": func(v any) (any, error) {
			s, ok := v.(string)
			if !ok || !isSlug(s) {
				return nil, fmt.Errorf("must be a lowercase slug")
			}
			return s, nil
		},
	}
	resolvers := map[string]resolver.Resolver{
		"Query.bySlug": {Runtime: stubRuntime{}, Source: stubStore{result: "ok"}},
	}
	e := New(resolvers, WithSchema(schema), WithScalarValidators(validators))

	// Malformed literal for the declared scalar → rejected with ValidationError.
	res := e.Execute(context.Background(), `query($s: Slug!){ bySlug(s: $s) }`, map[string]any{"s": "Not A Slug"})
	if len(res.Errors) == 0 || res.Errors[0].ErrorType != "ValidationError" {
		t.Fatalf("malformed custom scalar should be a ValidationError, got %+v", res.Errors)
	}
	if !strings.Contains(res.Errors[0].Message, "Slug") {
		t.Errorf("error should name the scalar: %q", res.Errors[0].Message)
	}

	// Valid value → coercion passes (no ValidationError; the stub resolver serves it).
	res = e.Execute(context.Background(), `query($s: Slug!){ bySlug(s: $s) }`, map[string]any{"s": "a-slug"})
	for _, ge := range res.Errors {
		if ge.ErrorType == "ValidationError" {
			t.Fatalf("valid slug should not be a ValidationError: %+v", res.Errors)
		}
	}
}

// Without a registered validator, a declared custom scalar passes through unvalidated (opt-in per scalar).
func TestScalarSeam_UnregisteredPassesThrough(t *testing.T) {
	schema, err := ParseSchema(`scalar Slug
		type Query { bySlug(s: Slug!): String }`)
	if err != nil {
		t.Fatal(err)
	}
	resolvers := map[string]resolver.Resolver{
		"Query.bySlug": {Runtime: stubRuntime{}, Source: stubStore{result: "ok"}},
	}
	e := New(resolvers, WithSchema(schema)) // no validators registered
	res := e.Execute(context.Background(), `query($s: Slug!){ bySlug(s: $s) }`, map[string]any{"s": "Anything Goes"})
	for _, ge := range res.Errors {
		if ge.ErrorType == "ValidationError" {
			t.Fatalf("unregistered custom scalar should pass through, got %+v", res.Errors)
		}
	}
}

func isSlug(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r == '-') {
			return false
		}
	}
	return true
}
