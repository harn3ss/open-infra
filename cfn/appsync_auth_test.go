package cfn

import (
	"strings"
	"testing"
)

// Every root operation field must carry an auth directive (on itself or its type); a field with none
// would be public on open-appsync where AWS applies the API's default mode.
func TestAppSync_RootFieldsWithoutAuth(t *testing.T) {
	cases := []struct {
		sdl  string
		want string // comma-joined missing fields
		ok   bool
	}{
		{"type Query @aws_api_key { a: Int b(x: Int): Int }", "", true},
		{"type Query { a: Int @aws_iam\n b: Int }", "Query.b", true},
		{"type Query {\n  a(\n    x: Int\n  ): Int\n  @aws_cognito_user_pools\n}", "", true},
		{"type Mutation { put(v: String): String } type Query { get: String @aws_api_key }", "Mutation.put", true},
		{`schema { query: Root } type Root { x: Int } type Query { y: Int }`, "Root.x", true},
		{`"""a description with { braces } and @aws_iam""" type Query { x: Int }`, "Query.x", true},
		{"# @aws_iam in a comment\ntype Query { x: Int }", "Query.x", true},
		{"type Query { x(a: Int: Int }", "", false},
		{"type Thing { x: Int }", "", true}, // not a root type
	}
	for _, c := range cases {
		got, ok := rootFieldsWithoutAuth(c.sdl)
		if ok != c.ok || strings.Join(got, ",") != c.want {
			t.Errorf("%q: got %v ok=%v, want %q ok=%v", c.sdl, got, ok, c.want, c.ok)
		}
	}
}

// A GraphQLApi whose schema relies on the default AuthenticationType is refused; PRIVATE visibility and
// a merged API are refused; IntrospectionConfig DISABLED and QueryDepthLimit map onto the API's limits.
func TestTranslate_AppSync_AuthAndVisibility(t *testing.T) {
	base := appsyncStack()
	open := strings.Replace(base, "type Query @aws_api_key {", "type Query {", 1)
	if _, fs := translateIn(t, open, "Api", nil); !strings.Contains(findingsText(fs), "Query.getTodo carry no auth directive") {
		t.Errorf("an unprotected root field must refuse, got %q", findingsText(fs))
	}
	priv := strings.Replace(base, "AuthenticationType: API_KEY", "AuthenticationType: API_KEY\n      Visibility: PRIVATE", 1)
	if _, fs := translateIn(t, priv, "Api", nil); !strings.Contains(findingsText(fs), "Visibility PRIVATE") {
		t.Errorf("PRIVATE must refuse, got %q", findingsText(fs))
	}
	lim := strings.Replace(base, "AuthenticationType: API_KEY", "AuthenticationType: API_KEY\n      IntrospectionConfig: DISABLED\n      QueryDepthLimit: 5", 1)
	m, fs := translateIn(t, lim, "Api", nil)
	if len(fs) != 0 {
		t.Fatalf("findings: %s", findingsText(fs))
	}
	l, _ := m.Spec["limits"].(map[string]any)
	if l["introspection"] != "disabled" || l["maxDepth"] != 5 {
		t.Errorf("limits = %#v", l)
	}
}
