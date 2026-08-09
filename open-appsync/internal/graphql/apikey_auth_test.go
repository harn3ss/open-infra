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

	anon := context.Background()
	keyed := authz.WithMode(authz.NewContext(context.Background(), authz.Identity{Username: "system:serviceaccount:demo:reader"}), authz.ModeAPIKey)

	unauthorized := func(ctx context.Context, q string) bool {
		res := e.Execute(ctx, q, nil)
		for _, ge := range res.Errors {
			if ge.ErrorType == "Unauthorized" {
				return true
			}
		}
		return false
	}

	// keyed: requires api-key mode.
	if !unauthorized(anon, `{ keyed }`) {
		t.Error("@aws_api_key field must deny an anonymous (non-api-key) request")
	}
	if unauthorized(keyed, `{ keyed }`) {
		t.Error("@aws_api_key field must allow an api-key-authenticated request")
	}
	// mixed (@aws_api_key @aws_iam): iam not enforced yet → stays advisory → not gated.
	if unauthorized(anon, `{ mixed }`) {
		t.Error("a field mixing in a not-yet-enforced mode must stay advisory (not denied)")
	}
	// iamOnly + pub: advisory / public → allowed.
	if unauthorized(anon, `{ iamOnly }`) {
		t.Error("@aws_iam-only field is advisory, must not be denied")
	}
	if unauthorized(anon, `{ pub }`) {
		t.Error("public field must not be denied")
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
