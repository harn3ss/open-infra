package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

const oidcSDL = `
type Query {
  viaOidc: String @aws_oidc
  cognitoAny: String @aws_cognito_user_pools
  adminOnly: String @aws_cognito_user_pools(cognito_groups: ["Admin", "Ops"])
}
`

func oidcEngine(t *testing.T) *Engine {
	t.Helper()
	schema, err := ParseSchema(oidcSDL)
	if err != nil {
		t.Fatal(err)
	}
	mk := func() resolver.Resolver {
		return resolver.Resolver{Runtime: stubRuntime{}, Source: stubStore{result: "ok"}}
	}
	return New(map[string]resolver.Resolver{
		"Query.viaOidc":    mk(),
		"Query.cognitoAny": mk(),
		"Query.adminOnly":  mk(),
	}, WithSchema(schema))
}

// ctxWith builds a request context with an auth mode + caller groups (as the shim would forward them).
func ctxWith(mode string, groups ...string) context.Context {
	return authz.WithMode(authz.NewContext(context.Background(), authz.Identity{Username: "u", Groups: groups}), mode)
}

func TestOIDCAuth_ModeAndGroupGate(t *testing.T) {
	e := oidcEngine(t)
	unauthorized := func(ctx context.Context, q string) bool {
		res := e.Execute(ctx, q, nil)
		for _, ge := range res.Errors {
			if ge.ErrorType == "Unauthorized" {
				return true
			}
		}
		return false
	}

	// @aws_oidc: requires oidc mode; api-key/iam/anon denied.
	if unauthorized(ctxWith(authz.ModeOIDC), `{ viaOidc }`) {
		t.Error("@aws_oidc must allow an oidc-mode request")
	}
	if !unauthorized(context.Background(), `{ viaOidc }`) || !unauthorized(ctxWith(authz.ModeAPIKey), `{ viaOidc }`) {
		t.Error("@aws_oidc must deny anon and non-oidc modes")
	}

	// @aws_cognito_user_pools (no groups): any cognito-mode caller passes.
	if unauthorized(ctxWith(authz.ModeCognito), `{ cognitoAny }`) {
		t.Error("@aws_cognito_user_pools (no groups) must allow a cognito-mode request")
	}
	if !unauthorized(ctxWith(authz.ModeOIDC), `{ cognitoAny }`) {
		t.Error("a cognito field must deny an oidc-mode request (mode mismatch)")
	}

	// @aws_cognito_user_pools(cognito_groups: [Admin,Ops]): group intersection required.
	if unauthorized(ctxWith(authz.ModeCognito, "Ops"), `{ adminOnly }`) {
		t.Error("cognito_groups field must allow a caller in a required group")
	}
	if !unauthorized(ctxWith(authz.ModeCognito, "Users"), `{ adminOnly }`) {
		t.Error("cognito_groups field must deny a caller lacking every required group")
	}
}

// FAIL-CLOSED: a cognito-mode caller with NO groups (missing/unparseable) must be denied on a
// group-restricted field — never allowed by skipping the check. This is the dangerous edge.
func TestOIDCAuth_EmptyGroupsFailsClosed(t *testing.T) {
	e := oidcEngine(t)
	res := e.Execute(ctxWith(authz.ModeCognito /* no groups */), `{ adminOnly }`, nil)
	if len(res.Errors) == 0 || res.Errors[0].ErrorType != "Unauthorized" {
		t.Fatalf("cognito_groups field with an empty-groups caller must DENY (fail closed), got %+v", res.Errors)
	}
	// Sanity: the same caller passes a cognito field that has no group restriction.
	if res := e.Execute(ctxWith(authz.ModeCognito), `{ cognitoAny }`, nil); len(res.Errors) != 0 {
		t.Fatalf("no-group cognito field should allow an empty-groups cognito caller, got %+v", res.Errors)
	}
}
