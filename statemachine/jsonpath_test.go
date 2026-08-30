package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func mustJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("bad test JSON %q: %v", s, err)
	}
	return v
}

func TestGetPath(t *testing.T) {
	data := mustJSON(t, `{"a":{"b":[10,20,{"c":"deep"}]},"n":5}`)
	ctx := map[string]any{"Execution": map[string]any{"Name": "run-1"}}
	cases := []struct {
		path  string
		want  any
		found bool
	}{
		{"$", data, true},
		{"$.n", float64(5), true},
		{"$.a.b[0]", float64(10), true},
		{"$.a.b[2].c", "deep", true},
		{"$.a.missing", nil, false},
		{"$.a.b[9]", nil, false},
		{"$$.Execution.Name", "run-1", true},
	}
	for _, c := range cases {
		got, found, err := getPath(data, ctx, c.path)
		if err != nil {
			t.Fatalf("getPath(%q): %v", c.path, err)
		}
		if found != c.found {
			t.Fatalf("getPath(%q) found=%v want %v", c.path, found, c.found)
		}
		if found && !reflect.DeepEqual(got, c.want) {
			t.Fatalf("getPath(%q)=%v want %v", c.path, got, c.want)
		}
	}
}

func TestApplyResultPath(t *testing.T) {
	data := mustJSON(t, `{"n":2}`)
	// default "$" replaces
	got, _ := applyResultPath(data, "R", "$")
	if got != "R" {
		t.Fatalf(`ResultPath "$" = %v want "R"`, got)
	}
	// null discards
	got, _ = applyResultPath(data, "R", "")
	if !reflect.DeepEqual(got, data) {
		t.Fatalf("ResultPath null = %v want passthrough", got)
	}
	// nested insert
	got, _ = applyResultPath(data, float64(4), "$.out.value")
	want := mustJSON(t, `{"n":2,"out":{"value":4}}`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResultPath nested = %v want %v", got, want)
	}
}

func TestResolveParameters(t *testing.T) {
	input := mustJSON(t, `{"x":42,"name":"bob"}`)
	ctx := map[string]any{"Execution": map[string]any{"Name": "run-1"}}
	raw := json.RawMessage(`{"val.$":"$.x","who.$":"$$.Execution.Name","lit":1,"nested":{"deep.$":"$.name"}}`)
	got, err := resolveParameters(raw, input, ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := mustJSON(t, `{"val":42,"who":"run-1","lit":1,"nested":{"deep":"bob"}}`)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveParameters = %v want %v", got, want)
	}
}

func TestResolveParametersMissingPathErrors(t *testing.T) {
	_, err := resolveParameters(json.RawMessage(`{"v.$":"$.nope"}`), mustJSON(t, `{}`), nil)
	if err == nil {
		t.Fatal("expected error for unmatched Parameters path")
	}
}
