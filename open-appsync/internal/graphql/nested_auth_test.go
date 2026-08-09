package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

// REGRESSION (critical): a nested field's auth directive must be enforced even when the field has NO
// resolver of its own and is read structurally from the parent result. A sensitive scalar like
// `secret @aws_iam` is exactly this case; before the fix it was silently returned to anyone.
func TestNestedFieldAuth_ResolverlessScalarGated(t *testing.T) {
	schema, err := ParseSchema(`
		type Query { me: User }
		type User { id: ID publicName: String secret: String @aws_iam }
	`)
	if err != nil {
		t.Fatal(err)
	}
	// Only Query.me has a resolver; it returns the whole User incl. secret. User.secret has NO resolver.
	me := resolver.Resolver{Runtime: stubRuntime{}, Source: stubStore{result: map[string]any{
		"id": "1", "publicName": "Alice", "secret": "TOPSECRET",
	}}}
	e := New(map[string]resolver.Resolver{"Query.me": me}, WithSchema(schema))

	// Anonymous caller: id + publicName come back; secret is DENIED (null + Unauthorized at [me secret]).
	res := e.Execute(context.Background(), `{ me { id publicName secret } }`, nil)
	user := res.Data["me"].(map[string]any)
	if user["id"] != "1" || user["publicName"] != "Alice" {
		t.Fatalf("public fields should resolve: %v", user)
	}
	if user["secret"] != nil {
		t.Errorf("secret @aws_iam must NOT be returned to an anonymous caller, got %v", user["secret"])
	}
	found := false
	for _, ge := range res.Errors {
		if ge.ErrorType == "Unauthorized" && len(ge.Path) == 2 && ge.Path[0] == "me" && ge.Path[1] == "secret" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Unauthorized at [me secret], got %+v", res.Errors)
	}

	// An iam-mode request gets the secret.
	iam := authz.WithMode(authz.NewContext(context.Background(), authz.Identity{Username: "u"}), authz.ModeIAM)
	res = e.Execute(iam, `{ me { secret } }`, nil)
	if len(res.Errors) != 0 || res.Data["me"].(map[string]any)["secret"] != "TOPSECRET" {
		t.Errorf("iam-mode caller should get secret, got data=%v errs=%+v", res.Data, res.Errors)
	}
}

// REGRESSION (high): legacy @aws_auth(cognito_groups:) must be ENFORCED (normalized to the cognito mode),
// not silently advisory — and it must not downgrade a sibling enforceable rule.
func TestAwsAuthLegacy_Enforced(t *testing.T) {
	schema, err := ParseSchema(`
		type Query { adminData: String @aws_auth(cognito_groups: ["Admins"]) }
	`)
	if err != nil {
		t.Fatal(err)
	}
	e := New(map[string]resolver.Resolver{
		"Query.adminData": {Runtime: stubRuntime{}, Source: stubStore{result: "ok"}},
	}, WithSchema(schema))
	unauthorized := func(ctx context.Context) bool {
		for _, ge := range e.Execute(ctx, `{ adminData }`, nil).Errors {
			if ge.ErrorType == "Unauthorized" {
				return true
			}
		}
		return false
	}
	// Anonymous → denied (before the fix @aws_auth tripped the advisory short-circuit → public).
	if !unauthorized(context.Background()) {
		t.Error("@aws_auth field must deny an anonymous caller (it is enforced, not advisory)")
	}
	// Cognito caller NOT in Admins → denied.
	notAdmin := authz.WithMode(authz.NewContext(context.Background(), authz.Identity{Username: "u", Groups: []string{"Users"}}), authz.ModeCognito)
	if !unauthorized(notAdmin) {
		t.Error("@aws_auth field must deny a cognito caller lacking the Admins group")
	}
	// Cognito caller in Admins → allowed.
	admin := authz.WithMode(authz.NewContext(context.Background(), authz.Identity{Username: "u", Groups: []string{"Admins"}}), authz.ModeCognito)
	if unauthorized(admin) {
		t.Error("@aws_auth field must allow a cognito caller in the Admins group")
	}
	// The directive normalizes to the cognito mode (advisory list no longer contains aws_auth).
	for _, d := range schema.AdvisoryAuthDirectives() {
		if d == "aws_auth" {
			t.Errorf("aws_auth must not be reported advisory (it is enforced as cognito): %v", schema.AdvisoryAuthDirectives())
		}
	}
}
