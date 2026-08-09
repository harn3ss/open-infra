package graphql

import (
	"context"
	"strings"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

const authSDL = `
type Query {
  pub: String @aws_api_key
  secret: String @aws_iam
  admin: String @aws_cognito_user_pools(cognito_groups: ["Admin", "Ops"])
  viaOidc: String @aws_oidc
  viaLambda: String @aws_lambda
}
type Ledger @aws_iam { id: ID! }
`

// AppSync auth directives parse (an imported schema doesn't choke), are captured on fields + types, and
// DeclaredAuthDirectives reports the distinct set — the model the future SAR enforcement will read.
func TestAuthDirectives_ParsedAndCaptured(t *testing.T) {
	s, err := ParseSchema(authSDL)
	if err != nil {
		t.Fatal(err)
	}
	got := s.DeclaredAuthDirectives()
	want := []string{"aws_api_key", "aws_cognito_user_pools", "aws_iam", "aws_lambda", "aws_oidc"}
	if !equalStrings(got, want) {
		t.Errorf("DeclaredAuthDirectives = %v, want %v", got, want)
	}

	// Field-level capture, including cognito groups.
	q := s.types["Query"]
	byField := map[string][]appliedAuth{}
	for _, f := range q.fields {
		byField[f.name] = f.authDirectives
	}
	if len(byField["secret"]) != 1 || byField["secret"][0].name != "aws_iam" {
		t.Errorf("secret auth = %+v, want [aws_iam]", byField["secret"])
	}
	admin := byField["admin"]
	if len(admin) != 1 || admin[0].name != "aws_cognito_user_pools" || !equalStrings(admin[0].cognitoGroups, []string{"Admin", "Ops"}) {
		t.Errorf("admin auth = %+v, want aws_cognito_user_pools(Admin,Ops)", admin)
	}

	// Type-level capture.
	ledger := s.types["Ledger"]
	if len(ledger.authDirectives) != 1 || ledger.authDirectives[0].name != "aws_iam" {
		t.Errorf("Ledger auth = %+v, want [aws_iam]", ledger.authDirectives)
	}
}

// The five auth directives are reported in introspection as directive definitions, each LOUDLY labeled
// advisory / not-enforced, with the right locations (OBJECT, FIELD_DEFINITION) and cognito's arg.
func TestAuthDirectives_ReportedAdvisoryInIntrospection(t *testing.T) {
	s, err := ParseSchema(authSDL)
	if err != nil {
		t.Fatal(err)
	}
	e := New(map[string]resolver.Resolver{}, WithSchema(s))
	res := e.Execute(context.Background(),
		`{ __schema { directives { name description locations args { name } } } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errored: %+v", res.Errors)
	}
	dirs := map[string]map[string]any{}
	for _, d := range res.Data["__schema"].(map[string]any)["directives"].([]any) {
		dm := d.(map[string]any)
		dirs[dm["name"].(string)] = dm
	}
	for _, name := range []string{"aws_api_key", "aws_iam", "aws_oidc", "aws_lambda", "aws_cognito_user_pools"} {
		d, ok := dirs[name]
		if !ok {
			t.Errorf("auth directive %q missing from introspection", name)
			continue
		}
		desc, _ := d["description"].(string)
		if !strings.Contains(desc, "NOT enforce") && !strings.Contains(desc, "advisory") {
			t.Errorf("%q description must loudly say not-enforced/advisory, got %q", name, desc)
		}
		locs := map[string]bool{}
		for _, l := range d["locations"].([]any) {
			locs[l.(string)] = true
		}
		if !locs["OBJECT"] || !locs["FIELD_DEFINITION"] {
			t.Errorf("%q locations = %v, want OBJECT + FIELD_DEFINITION", name, d["locations"])
		}
	}
	// cognito carries its cognito_groups arg.
	cognito := dirs["aws_cognito_user_pools"]
	hasGroups := false
	for _, a := range cognito["args"].([]any) {
		if a.(map[string]any)["name"] == "cognito_groups" {
			hasGroups = true
		}
	}
	if !hasGroups {
		t.Error("aws_cognito_user_pools should report a cognito_groups arg")
	}
}
