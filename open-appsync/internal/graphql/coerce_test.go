package graphql

import (
	"context"
	"reflect"
	"testing"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

func named(n string) typeRef              { return typeRef{name: n} }
func nonNull(t typeRef) typeRef           { return typeRef{kind: kindNonNull, elem: &t} }
func listOf(t typeRef) typeRef            { return typeRef{kind: kindList, elem: &t} }
func def(n string, t typeRef) variableDef { return variableDef{name: n, typ: t} }

// coerceOne runs one variable definition through coerceVariables against the sample schema.
func coerceOne(t *testing.T, d variableDef, vars map[string]any) (any, *GqlError) {
	t.Helper()
	out, err := (coercer{schema: mustParse(t)}).variables([]variableDef{d}, vars)
	if err != nil {
		return nil, err
	}
	return out[d.name], nil
}

func TestCoerce_ScalarsAcceptedAndRejected(t *testing.T) {
	// Right types accepted.
	if v, err := coerceOne(t, def("s", named("String")), map[string]any{"s": "hi"}); err != nil || v != "hi" {
		t.Errorf("String accept: v=%v err=%v", v, err)
	}
	if v, err := coerceOne(t, def("n", named("Int")), map[string]any{"n": float64(5)}); err != nil || v != float64(5) {
		t.Errorf("Int accept: v=%v err=%v", v, err)
	}
	if v, err := coerceOne(t, def("f", named("Float")), map[string]any{"f": float64(1.5)}); err != nil || v != 1.5 {
		t.Errorf("Float accept: v=%v err=%v", v, err)
	}
	if v, err := coerceOne(t, def("b", named("Boolean")), map[string]any{"b": true}); err != nil || v != true {
		t.Errorf("Boolean accept: v=%v err=%v", v, err)
	}
	// ID accepts an Int, serialized to a String.
	if v, err := coerceOne(t, def("id", named("ID")), map[string]any{"id": float64(42)}); err != nil || v != "42" {
		t.Errorf("ID(Int) accept: v=%v err=%v", v, err)
	}

	// Wrong types rejected.
	for _, tc := range []struct {
		name string
		d    variableDef
		vars map[string]any
	}{
		{"Int<-string", def("n", named("Int")), map[string]any{"n": "x"}},
		{"Int<-float", def("n", named("Int")), map[string]any{"n": 1.5}},
		{"String<-number", def("s", named("String")), map[string]any{"s": float64(3)}},
		{"Boolean<-string", def("b", named("Boolean")), map[string]any{"b": "true"}},
	} {
		if _, err := coerceOne(t, tc.d, tc.vars); err == nil {
			t.Errorf("%s: expected a coercion error", tc.name)
		} else if err.ErrorType != "ValidationError" {
			t.Errorf("%s: errorType=%q want ValidationError", tc.name, err.ErrorType)
		}
	}
}

func TestCoerce_NonNullAndDefaults(t *testing.T) {
	// Missing required → error.
	if _, err := coerceOne(t, def("id", nonNull(named("ID"))), map[string]any{}); err == nil {
		t.Error("missing required var should error")
	}
	// Provided null for NON_NULL → error.
	if _, err := coerceOne(t, def("id", nonNull(named("ID"))), map[string]any{"id": nil}); err == nil {
		t.Error("null for NON_NULL should error")
	}
	// Default applied when absent.
	d := variableDef{name: "n", typ: named("Int"), hasDefault: true, defaultValue: valueNode{kind: "scalar", val: float64(7)}}
	if v, err := coerceOne(t, d, map[string]any{}); err != nil || v != float64(7) {
		t.Errorf("default apply: v=%v err=%v", v, err)
	}
	// Bad default rejected.
	bad := variableDef{name: "n", typ: named("Int"), hasDefault: true, defaultValue: valueNode{kind: "scalar", val: "nope"}}
	if _, err := coerceOne(t, bad, map[string]any{}); err == nil {
		t.Error("bad default should be rejected")
	}
}

func TestCoerce_ListsAndEnums(t *testing.T) {
	// [String!] accepts a list.
	if v, err := coerceOne(t, def("t", listOf(nonNull(named("String")))), map[string]any{"t": []any{"a", "b"}}); err != nil || !reflect.DeepEqual(v, []any{"a", "b"}) {
		t.Errorf("list accept: v=%v err=%v", v, err)
	}
	// A single value coerces to a one-element list (spec list input coercion).
	if v, err := coerceOne(t, def("t", listOf(named("String"))), map[string]any{"t": "solo"}); err != nil || !reflect.DeepEqual(v, []any{"solo"}) {
		t.Errorf("single→list: v=%v err=%v", v, err)
	}
	// A null element in [String!] is rejected.
	if _, err := coerceOne(t, def("t", listOf(nonNull(named("String")))), map[string]any{"t": []any{"a", nil}}); err == nil {
		t.Error("null element in [String!] should error")
	}
	// Enum: valid value accepted, off-list rejected.
	if v, err := coerceOne(t, def("p", named("Priority")), map[string]any{"p": "HIGH"}); err != nil || v != "HIGH" {
		t.Errorf("enum accept: v=%v err=%v", v, err)
	}
	if _, err := coerceOne(t, def("p", named("Priority")), map[string]any{"p": "URGENT"}); err == nil {
		t.Error("off-list enum value should error")
	}
}

func TestCoerce_InputObject(t *testing.T) {
	in := named("CreateTodoInput")
	// Valid input object; the enum default (priority = LOW) is applied for the absent field.
	v, err := coerceOne(t, def("in", in), map[string]any{"in": map[string]any{"name": "Ada"}})
	if err != nil {
		t.Fatalf("valid input errored: %v", err)
	}
	m := v.(map[string]any)
	if m["name"] != "Ada" || m["priority"] != "LOW" {
		t.Errorf("input coercion + default = %v", m)
	}
	// Unknown field rejected.
	if _, err := coerceOne(t, def("in", in), map[string]any{"in": map[string]any{"name": "A", "bogus": 1}}); err == nil {
		t.Error("unknown input field should error")
	}
	// Missing required field (name is String!) rejected.
	if _, err := coerceOne(t, def("in", in), map[string]any{"in": map[string]any{"description": "x"}}); err == nil {
		t.Error("missing required input field should error")
	}
	// Wrong nested type rejected (tags is [String!]; give a [number]).
	if _, err := coerceOne(t, def("in", in), map[string]any{"in": map[string]any{"name": "A", "tags": []any{float64(1)}}}); err == nil {
		t.Error("wrong nested element type should error")
	}
}

// TestCoerce_WiredIntoExecute proves coercion runs before dispatch: a missing required variable fails
// the whole operation with a ValidationError, and no resolver runs.
func TestCoerce_WiredIntoExecute(t *testing.T) {
	e := New(map[string]resolver.Resolver{}, WithSchema(mustParse(t)))
	res := e.Execute(context.Background(), `query($id: ID!) { getTodo(id: $id) { id } }`, map[string]any{})
	if len(res.Errors) == 0 || res.Errors[0].ErrorType != "ValidationError" {
		t.Fatalf("expected a ValidationError for the missing required var, got %+v", res.Errors)
	}
}
