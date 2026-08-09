package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

// @aws_lambda is now ENFORCED (the fifth and last AWS auth mode to graduate). A @aws_lambda field
// requires a request the aws-shim authenticated via the API's Lambda authorizer (conveyed as
// X-OpenInfra-Auth-Mode: aws_lambda + the mapped identity). The engine trusts the shim-set mode
// exactly as it does for iam/oidc; the mapped identity then flows into the field's SAR check.
func TestLambdaAuth_FieldGate(t *testing.T) {
	schema, err := ParseSchema(`
type Query {
  pub: String
  viaLambda: String @aws_lambda
  lambdaOrIam: String @aws_lambda @aws_iam
}
`)
	if err != nil {
		t.Fatal(err)
	}
	mk := func() resolver.Resolver {
		return resolver.Resolver{Runtime: stubRuntime{}, Source: stubStore{result: "ok"}}
	}
	e := New(map[string]resolver.Resolver{
		"Query.pub":         mk(),
		"Query.viaLambda":   mk(),
		"Query.lambdaOrIam": mk(),
	}, WithSchema(schema))

	withMode := func(mode string) context.Context {
		return authz.WithMode(authz.NewContext(context.Background(), authz.Identity{Username: "u"}), mode)
	}
	anon := context.Background()
	lambda := withMode(authz.ModeLambda)
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

	if unauthorized(anon, `{ pub }`) {
		t.Error("public field must not be denied")
	}
	// viaLambda (@aws_lambda): only lambda mode passes — anon and iam are denied (no longer advisory).
	if !unauthorized(anon, `{ viaLambda }`) || !unauthorized(iam, `{ viaLambda }`) {
		t.Error("@aws_lambda field must deny anon and iam-mode requests now that it is enforced")
	}
	if unauthorized(lambda, `{ viaLambda }`) {
		t.Error("@aws_lambda field must allow a lambda-authenticated request")
	}
	// lambdaOrIam: both modes enforced → either passes, anon denied.
	if !unauthorized(anon, `{ lambdaOrIam }`) {
		t.Error("a field requiring lambda OR iam must deny an anonymous request")
	}
	if unauthorized(lambda, `{ lambdaOrIam }`) || unauthorized(iam, `{ lambdaOrIam }`) {
		t.Error("a field requiring lambda OR iam must allow either mode")
	}
}
