package graphql

import (
	"context"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

// sampleSDL exercises every wrapper combination + each named-type kind introspection must report.
const sampleSDL = `
"A unit of work."
type Todo {
  id: ID!
  name: String!
  description: String
  priority: Priority!
  tags: [String!]
  createdAt: AWSDateTime
}

scalar AWSDateTime

"How urgent a todo is."
enum Priority { LOW MEDIUM HIGH }

input CreateTodoInput {
  name: String!
  description: String
  priority: Priority = LOW
  tags: [String!]
}

type Query {
  getTodo(id: ID!): Todo
  listTodos: [Todo!]!
}

type Mutation {
  createTodo(input: CreateTodoInput!): Todo
}

type Subscription {
  onCreateTodo: Todo
}
`

func mustParse(t *testing.T) *Schema {
	t.Helper()
	s, err := ParseSchema(sampleSDL)
	if err != nil {
		t.Fatalf("ParseSchema: %v", err)
	}
	return s
}

func TestParseSchema_RootTypesAndKinds(t *testing.T) {
	s := mustParse(t)
	if s.queryType != "Query" || s.mutationType != "Mutation" || s.subscriptionType != "Subscription" {
		t.Fatalf("root types wrong: q=%q m=%q s=%q", s.queryType, s.mutationType, s.subscriptionType)
	}
	want := map[string]string{
		"Todo": kindObject, "Priority": kindEnum, "CreateTodoInput": kindInputObject,
		"AWSDateTime": kindScalar, "String": kindScalar, "ID": kindScalar,
		"Query": kindObject, "Mutation": kindObject, "Subscription": kindObject,
	}
	for name, kind := range want {
		nt, ok := s.types[name]
		if !ok {
			t.Fatalf("type %q missing from the map", name)
		}
		if nt.kind != kind {
			t.Errorf("type %q kind = %q, want %q", name, nt.kind, kind)
		}
	}
}

// TestParseSchema_WrappedTypeRefs is the load-bearing case: the four shapes of a type reference must be
// modeled distinctly (Post vs Post! vs [Post] vs [Post!]!), because introspection reports them exactly.
func TestParseSchema_WrappedTypeRefs(t *testing.T) {
	s := mustParse(t)
	todo := s.types["Todo"]
	fieldType := func(nt *namedType, field string) typeRef {
		for _, f := range nt.fields {
			if f.name == field {
				return f.typ
			}
		}
		t.Fatalf("field %q not found", field)
		return typeRef{}
	}

	// id: ID!  → NON_NULL(ID)
	if tr := fieldType(todo, "id"); tr.kind != kindNonNull || tr.elem.name != "ID" {
		t.Errorf("id type = %+v, want NON_NULL(ID)", tr)
	}
	// description: String → named, nullable
	if tr := fieldType(todo, "description"); tr.kind != "" || tr.name != "String" {
		t.Errorf("description type = %+v, want String", tr)
	}
	// tags: [String!] → LIST(NON_NULL(String))
	tags := fieldType(todo, "tags")
	if tags.kind != kindList || tags.elem.kind != kindNonNull || tags.elem.elem.name != "String" {
		t.Errorf("tags type = %+v, want [String!]", tags)
	}
	// Query.listTodos: [Todo!]! → NON_NULL(LIST(NON_NULL(Todo)))
	lt := fieldType(s.types["Query"], "listTodos")
	if lt.kind != kindNonNull || lt.elem.kind != kindList || lt.elem.elem.kind != kindNonNull || lt.elem.elem.elem.name != "Todo" {
		t.Errorf("listTodos type = %+v, want [Todo!]!", lt)
	}
}

func TestParseSchema_EnumInputAndDefaults(t *testing.T) {
	s := mustParse(t)
	pr := s.types["Priority"]
	if len(pr.enumValues) != 3 || pr.enumValues[0].name != "LOW" || pr.enumValues[2].name != "HIGH" {
		t.Errorf("Priority enum values = %+v", pr.enumValues)
	}
	if pr.description != "How urgent a todo is." {
		t.Errorf("Priority description = %q", pr.description)
	}
	in := s.types["CreateTodoInput"]
	var priority *inputValueDef
	for i := range in.inputFields {
		if in.inputFields[i].name == "priority" {
			priority = &in.inputFields[i]
		}
	}
	if priority == nil {
		t.Fatal("CreateTodoInput.priority missing")
	}
	if priority.defaultValue != "LOW" { // an enum default → unquoted (distinct from a "LOW" string)
		t.Errorf("priority defaultValue = %q, want LOW", priority.defaultValue)
	}
	if priority.typ.name != "Priority" {
		t.Errorf("priority type = %+v, want Priority", priority.typ)
	}
}

// TestIntrospect_TypeWrappersRoundTrip drives __type through the executor and checks the wrappers come
// back out in the exact spec shape (kind/name/ofType), including deep nesting.
func TestIntrospect_TypeWrappersRoundTrip(t *testing.T) {
	e := New(map[string]resolver.Resolver{}, WithSchema(mustParse(t)))
	q := `{ __type(name: "Query") { name kind fields { name type { kind name ofType { kind name ofType { kind name } } } } } }`
	res := e.Execute(context.Background(), q, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("introspection errored: %+v", res.Errors)
	}
	typ, _ := res.Data["__type"].(map[string]any)
	if typ["name"] != "Query" || typ["kind"] != kindObject {
		t.Fatalf("__type(Query) = %+v", typ)
	}
	fields, _ := typ["fields"].([]any)
	got := map[string]map[string]any{}
	for _, f := range fields {
		fm := f.(map[string]any)
		got[fm["name"].(string)] = fm["type"].(map[string]any)
	}
	// listTodos: [Todo!]! → NON_NULL → LIST → NON_NULL(Todo). Our query only unwraps 2 ofType levels.
	lt := got["listTodos"]
	if lt["kind"] != kindNonNull || lt["name"] != nil {
		t.Errorf("listTodos outer = %+v, want NON_NULL", lt)
	}
	inner := lt["ofType"].(map[string]any)
	if inner["kind"] != kindList {
		t.Errorf("listTodos ofType = %+v, want LIST", inner)
	}
	innermost := inner["ofType"].(map[string]any)
	if innermost["kind"] != kindNonNull {
		t.Errorf("listTodos LIST.ofType = %+v, want NON_NULL", innermost)
	}
}

func TestIntrospect_ToggleGates(t *testing.T) {
	schema := mustParse(t)
	q := `{ __schema { queryType { name } } }`

	// disabled → refuse for everyone
	e := New(map[string]resolver.Resolver{}, WithSchema(schema), WithLimits(Limits{Introspection: IntrospectionDisabled}))
	if res := e.Execute(context.Background(), q, nil); len(res.Errors) == 0 {
		t.Error("disabled introspection should error")
	} else if res.Errors[0].ErrorType != "IntrospectionDisabled" {
		t.Errorf("errorType = %q, want IntrospectionDisabled", res.Errors[0].ErrorType)
	}

	// authenticated-only → refuse anonymous, allow a named caller
	e = New(map[string]resolver.Resolver{}, WithSchema(schema), WithLimits(Limits{Introspection: IntrospectionAuthenticated}))
	if res := e.Execute(context.Background(), q, nil); len(res.Errors) == 0 {
		t.Error("authenticated-only introspection should refuse an anonymous caller")
	}
	authed := authz.NewContext(context.Background(), authz.Identity{Username: "alice"})
	if res := e.Execute(authed, q, nil); len(res.Errors) != 0 {
		t.Errorf("authenticated-only should allow a named caller, got %+v", res.Errors)
	}

	// no schema → unavailable
	e = New(map[string]resolver.Resolver{})
	if res := e.Execute(context.Background(), q, nil); len(res.Errors) == 0 || res.Errors[0].ErrorType != "IntrospectionUnavailable" {
		t.Errorf("no-schema introspection should be unavailable, got %+v", res.Errors)
	}
}

// TestIntrospect_UnknownTypeIsNull: __type(name:) for a missing type resolves to null, per spec.
func TestIntrospect_UnknownTypeIsNull(t *testing.T) {
	e := New(map[string]resolver.Resolver{}, WithSchema(mustParse(t)))
	res := e.Execute(context.Background(), `{ __type(name: "Nope") { name } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("errors: %+v", res.Errors)
	}
	if v, ok := res.Data["__type"]; !ok || v != nil {
		t.Errorf("__type(Nope) = %v, want nil", v)
	}
}
