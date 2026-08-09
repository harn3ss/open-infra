package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

const apiKeySDL = `
type Query {
  pub: String
  keyed: String @aws_api_key
  mixed: String @aws_api_key @aws_iam
  iamOnly: String @aws_iam
}
`

// @aws_api_key is ENFORCED: a field gated by it (and no not-yet-enforced mode) requires the request to
// be api-key-authenticated. A field that also lists an advisory mode stays advisory (never over-denied);
// an advisory-only field and a public field are unrestricted.
func TestAPIKeyAuth_FieldGate(t *testing.T) {
	schema, err := ParseSchema(apiKeySDL)
	if err != nil {
		t.Fatal(err)
	}
	mk := func() resolver.Resolver {
		return resolver.Resolver{Runtime: stubRuntime{}, Source: stubStore{result: "ok"}}
	}
	e := New(map[string]resolver.Resolver{
		"Query.pub":     mk(),
		"Query.keyed":   mk(),
		"Query.mixed":   mk(),
		"Query.iamOnly": mk(),
	}, WithSchema(schema))

	withMode := func(mode string) context.Context {
		return authz.WithMode(authz.NewContext(context.Background(), authz.Identity{Username: "u"}), mode)
	}
	anon := context.Background()
	apiKey := withMode(authz.ModeAPIKey)
	iam := withMode(authz.ModeIAM)

	unauthorized := func(ctx context.Context, q string) bool {
		res := e.Execute(ctx, q, nil)
		for _, ge := range res.Errors {
			if ge.ErrorType == "Unauthorized" {
				return true
			}
		}
		return false
	}

	// pub: public → always allowed.
	if unauthorized(anon, `{ pub }`) {
		t.Error("public field must not be denied")
	}
	// keyed (@aws_api_key): only api-key mode passes.
	if !unauthorized(anon, `{ keyed }`) || !unauthorized(iam, `{ keyed }`) {
		t.Error("@aws_api_key field must deny anon and iam-mode requests")
	}
	if unauthorized(apiKey, `{ keyed }`) {
		t.Error("@aws_api_key field must allow an api-key request")
	}
	// iamOnly (@aws_iam): only iam mode passes (now enforced).
	if !unauthorized(anon, `{ iamOnly }`) || !unauthorized(apiKey, `{ iamOnly }`) {
		t.Error("@aws_iam field must deny anon and api-key-mode requests")
	}
	if unauthorized(iam, `{ iamOnly }`) {
		t.Error("@aws_iam field must allow an iam request")
	}
	// mixed (@aws_api_key @aws_iam): both modes enforced → either passes, anon denied.
	if !unauthorized(anon, `{ mixed }`) {
		t.Error("a field requiring api-key OR iam must deny an anonymous request")
	}
	if unauthorized(apiKey, `{ mixed }`) || unauthorized(iam, `{ mixed }`) {
		t.Error("a field requiring api-key OR iam must allow either mode")
	}
}

// A valid api-key request impersonates the key's mapped identity, which then flows into the field's SAR
// auth (one policy world): a deny authorizer still denies even with a valid api-key mode.
func TestAPIKeyAuth_IdentityFlowsIntoSAR(t *testing.T) {
	schema, err := ParseSchema(`type Query { keyed: String @aws_api_key }`)
	if err != nil {
		t.Fatal(err)
	}
	r := resolver.Resolver{
		Runtime: stubRuntime{},
		Source:  stubStore{result: "ok"},
		Auth:    authz.Requirement{Verb: "get", Resource: "graphqlapis"}, // SAR requirement on the field
	}
	e := New(map[string]resolver.Resolver{"Query.keyed": r}, WithSchema(schema), WithAuthorizer(denyAll{}))
	ctx := authz.WithMode(authz.NewContext(context.Background(), authz.Identity{Username: "system:serviceaccount:demo:reader"}), authz.ModeAPIKey)
	res := e.Execute(ctx, `{ keyed }`, nil)
	if len(res.Errors) == 0 || res.Errors[0].ErrorType != "Unauthorized" {
		t.Fatalf("api-key mode passes the mode gate but SAR must still deny, got %+v", res.Errors)
	}
}
