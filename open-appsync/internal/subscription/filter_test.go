package subscription

import "testing"

// Filter matching is the genuinely hard part of the subscription rung, so it carries
// the weight of the unit tests. AppSync semantics: conditions AND within a filter, filters OR within a
// group, an empty group matches everything.

func ev(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func TestFilter_EmptyGroupMatchesAll(t *testing.T) {
	if !(FilterGroup{}).Match(ev("x", "y")) {
		t.Fatal("an empty filter group must receive all events")
	}
}

func TestFilter_Operators(t *testing.T) {
	cases := []struct {
		name  string
		cond  Condition
		event map[string]any
		want  bool
	}{
		{"eq hit", Condition{"owner", "eq", "ada"}, ev("owner", "ada"), true},
		{"eq miss", Condition{"owner", "eq", "ada"}, ev("owner", "bob"), false},
		{"eq numeric", Condition{"age", "eq", float64(36)}, ev("age", float64(36)), true},
		{"ne hit", Condition{"owner", "ne", "ada"}, ev("owner", "bob"), true},
		{"ne on missing field", Condition{"owner", "ne", "ada"}, ev(), true},
		{"in hit", Condition{"role", "in", []any{"admin", "editor"}}, ev("role", "editor"), true},
		{"in miss", Condition{"role", "in", []any{"admin"}}, ev("role", "viewer"), false},
		{"contains string", Condition{"title", "contains", "graph"}, ev("title", "graphql api"), true},
		{"contains list", Condition{"tags", "contains", "x"}, ev("tags", []any{"a", "x"}), true},
		{"beginsWith", Condition{"id", "beginsWith", "todo#"}, ev("id", "todo#123"), true},
		{"gt", Condition{"age", "gt", float64(30)}, ev("age", float64(36)), true},
		{"le boundary", Condition{"age", "le", float64(36)}, ev("age", float64(36)), true},
		{"between", Condition{"age", "between", []any{float64(30), float64(40)}}, ev("age", float64(36)), true},
		{"between out", Condition{"age", "between", []any{float64(30), float64(35)}}, ev("age", float64(36)), false},
		{"dotted field", Condition{"author.id", "eq", "u1"}, ev("author", ev("id", "u1")), true},
		{"unknown op fails closed", Condition{"x", "regex", ".*"}, ev("x", "y"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FilterGroup{Filters: []Filter{{Conditions: []Condition{tc.cond}}}}.Match(tc.event)
			if got != tc.want {
				t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestFilter_AndWithinFilter(t *testing.T) {
	g := FilterGroup{Filters: []Filter{{Conditions: []Condition{
		{"owner", "eq", "ada"}, {"age", "gt", float64(18)},
	}}}}
	if !g.Match(ev("owner", "ada", "age", float64(36))) {
		t.Fatal("all conditions hold → match")
	}
	if g.Match(ev("owner", "ada", "age", float64(10))) {
		t.Fatal("one condition fails → no match (AND)")
	}
}

func TestFilter_OrAcrossFilters(t *testing.T) {
	g := FilterGroup{Filters: []Filter{
		{Conditions: []Condition{{"owner", "eq", "ada"}}},
		{Conditions: []Condition{{"role", "eq", "admin"}}},
	}}
	if !g.Match(ev("owner", "bob", "role", "admin")) {
		t.Fatal("second filter matches → deliver (OR)")
	}
	if g.Match(ev("owner", "bob", "role", "viewer")) {
		t.Fatal("neither filter matches → no delivery")
	}
}
