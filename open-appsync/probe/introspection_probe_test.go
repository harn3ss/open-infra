package probe

// The introspection honesty gates (a DIFFERENT flavor from the runtime fidelity goldens). Introspection
// is standard GraphQL — AWS has no dialect here — so a byte-match-AWS golden proves little. The real
// bar is OPERABILITY:
//
//	Gate #1 (this file, TestIntrospection_CanonicalQueryShape): fire the standard introspection query
//	  and validate the response against the shape the GraphQL spec mandates. Deterministic, no network.
//	Gate #2 (TestIntrospection_RealToolConsumes): feed the emitted result to real GraphQL tooling
//	  (graphql-js buildClientSchema + graphql-codegen) and assert the ecosystem builds a client schema
//	  and TypeScript types from it. THIS is the proof that matters — a real tool consumes it or it fails.
//
// Honest scope note: the verbatim canonical introspection query graphql-js emits uses FRAGMENTS, which
// this engine's parser does not accept yet (fragments are their own rung). So gate #1 fires a
// fragment-free but semantically identical introspection query, and gate #2 consumes the RESULT (what
// codegen/Apollo ultimately do via buildClientSchema). Pointing a tool at the LIVE endpoint to
// auto-introspect waits on fragment support — a separate item, not part of introspection's graduation.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/graphql"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

const introspectionSDL = `
"A unit of work to track."
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

// typeRefSelection is the 7-deep ofType chain the standard introspection query uses to unwrap any
// combination of LIST/NON_NULL wrappers (fragment `TypeRef` from graphql-js, inlined).
const typeRefSelection = `kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } }`

// canonicalIntrospectionQuery is graphql-js's getIntrospectionQuery() with its fragments inlined.
var canonicalIntrospectionQuery = `{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args { name description type { ` + typeRefSelection + ` } defaultValue }
        type { ` + typeRefSelection + ` }
        isDeprecated
        deprecationReason
      }
      inputFields { name description type { ` + typeRefSelection + ` } defaultValue }
      interfaces { ` + typeRefSelection + ` }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
      possibleTypes { ` + typeRefSelection + ` }
    }
    directives { name description locations args { name description type { ` + typeRefSelection + ` } defaultValue } }
  }
}`

func introspectionEngine(t *testing.T) *graphql.Engine {
	t.Helper()
	schema, err := graphql.ParseSchema(introspectionSDL)
	if err != nil {
		t.Fatalf("ParseSchema: %v", err)
	}
	return graphql.New(map[string]resolver.Resolver{}, graphql.WithSchema(schema))
}

// TestIntrospection_CanonicalQueryShape is gate #1: the standard introspection query returns the
// spec-mandated shape. It also writes the result to testdata for gate #2 to consume.
func TestIntrospection_CanonicalQueryShape(t *testing.T) {
	e := introspectionEngine(t)
	res := e.Execute(context.Background(), canonicalIntrospectionQuery, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("introspection returned errors: %+v", res.Errors)
	}

	schema, ok := res.Data["__schema"].(map[string]any)
	if !ok {
		t.Fatal("no __schema in response")
	}
	if qt, _ := schema["queryType"].(map[string]any); qt["name"] != "Query" {
		t.Errorf("queryType.name = %v, want Query", qt["name"])
	}
	if mt, _ := schema["mutationType"].(map[string]any); mt["name"] != "Mutation" {
		t.Errorf("mutationType.name = %v, want Mutation", mt["name"])
	}
	if st, _ := schema["subscriptionType"].(map[string]any); st["name"] != "Subscription" {
		t.Errorf("subscriptionType.name = %v, want Subscription", st["name"])
	}

	// Index the types list by name; assert each expected kind is present.
	types := map[string]map[string]any{}
	for _, ti := range schema["types"].([]any) {
		tm := ti.(map[string]any)
		types[tm["name"].(string)] = tm
	}
	wantKinds := map[string]string{
		"Todo": "OBJECT", "Priority": "ENUM", "CreateTodoInput": "INPUT_OBJECT",
		"AWSDateTime": "SCALAR", "Query": "OBJECT", "Mutation": "OBJECT", "Subscription": "OBJECT",
		"String": "SCALAR", "ID": "SCALAR", "Boolean": "SCALAR", "Int": "SCALAR", "Float": "SCALAR",
	}
	for name, kind := range wantKinds {
		tm, ok := types[name]
		if !ok {
			t.Errorf("type %q missing from __schema.types", name)
			continue
		}
		if tm["kind"] != kind {
			t.Errorf("type %q kind = %v, want %v", name, tm["kind"], kind)
		}
	}

	// Todo.id must be NON_NULL(ID) — the wrapper reported exactly.
	assertWrappers(t, fieldType(t, types["Todo"], "id"), []string{"NON_NULL", "ID"})
	// Query.listTodos must be NON_NULL(LIST(NON_NULL(Todo))).
	assertWrappers(t, fieldType(t, types["Query"], "listTodos"), []string{"NON_NULL", "LIST", "NON_NULL", "Todo"})
	// Todo.tags must be LIST(NON_NULL(String)).
	assertWrappers(t, fieldType(t, types["Todo"], "tags"), []string{"LIST", "NON_NULL", "String"})

	// Enum values present and ordered.
	prVals := types["Priority"]["enumValues"].([]any)
	if len(prVals) != 3 || prVals[0].(map[string]any)["name"] != "LOW" {
		t.Errorf("Priority.enumValues = %+v", prVals)
	}
	// Input default value reported as an (unquoted) enum literal.
	var gotDefault any
	for _, iv := range types["CreateTodoInput"]["inputFields"].([]any) {
		m := iv.(map[string]any)
		if m["name"] == "priority" {
			gotDefault = m["defaultValue"]
		}
	}
	if gotDefault != "LOW" {
		t.Errorf("CreateTodoInput.priority defaultValue = %v, want LOW", gotDefault)
	}

	// Standard directives reported (skip/include/deprecated).
	dirNames := map[string]bool{}
	for _, d := range schema["directives"].([]any) {
		dirNames[d.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"skip", "include", "deprecated"} {
		if !dirNames[want] {
			t.Errorf("standard directive %q missing from __schema.directives", want)
		}
	}

	// Emit the result for gate #2 (buildClientSchema / codegen consume this).
	writeIntrospectionResult(t, res.Data)
}

// fieldType returns a type's field's `type` object by field name.
func fieldType(t *testing.T, typ map[string]any, field string) map[string]any {
	t.Helper()
	for _, f := range typ["fields"].([]any) {
		fm := f.(map[string]any)
		if fm["name"] == field {
			return fm["type"].(map[string]any)
		}
	}
	t.Fatalf("field %q not found on type", field)
	return nil
}

// assertWrappers walks the kind/name/ofType chain and checks it equals the expected sequence, where a
// wrapper element is a kind (LIST/NON_NULL) and the terminal element is a named type.
func assertWrappers(t *testing.T, typ map[string]any, want []string) {
	t.Helper()
	cur := typ
	for i, w := range want {
		if i == len(want)-1 { // terminal: a named type
			if cur["name"] != w {
				t.Errorf("wrapper[%d] name = %v, want %v", i, cur["name"], w)
			}
			return
		}
		if cur["kind"] != w {
			t.Errorf("wrapper[%d] kind = %v, want %v", i, cur["kind"], w)
			return
		}
		next, ok := cur["ofType"].(map[string]any)
		if !ok {
			t.Errorf("wrapper[%d] (%s) has no ofType", i, w)
			return
		}
		cur = next
	}
}

func introspectionResultPath() string {
	return filepath.Join("introspection", "introspection.json")
}

func writeIntrospectionResult(t *testing.T, data map[string]any) {
	t.Helper()
	if err := os.MkdirAll("introspection", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// buildClientSchema wants the IntrospectionQuery result: {"__schema": {...}} (the contents of `data`).
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(introspectionResultPath(), b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestIntrospection_RealToolConsumes is gate #2: real GraphQL tooling builds a client schema + TS types
// from our introspection result. It shells out to Node (probe/introspection/consume.mjs). It SKIPS
// (never silently passes) when Node or the tool's node_modules aren't present — see that dir's README
// for the one-time `npm install`. The graduation evidence is this test PASSING, not skipping.
func TestIntrospection_RealToolConsumes(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping the real-tool introspection gate")
	}
	if _, err := os.Stat(filepath.Join("introspection", "node_modules", "graphql")); err != nil {
		t.Skip("probe/introspection/node_modules absent; run `npm install` there to enable the real-tool gate")
	}
	// Ensure the result file exists (gate #1 writes it; regenerate here so this test can run alone).
	e := introspectionEngine(t)
	writeIntrospectionResult(t, e.Execute(context.Background(), canonicalIntrospectionQuery, nil).Data)

	cmd := exec.Command(node, "consume.mjs", "introspection.json")
	cmd.Dir = "introspection"
	out, err := cmd.CombinedOutput()
	t.Logf("consume.mjs output:\n%s", out)
	if err != nil {
		t.Fatalf("real-tool gate FAILED: %v", err)
	}
}
