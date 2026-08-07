// Package subscription is open-appsync's subscription rung. Subscriptions invert the
// resolver lifecycle — setup-then-push, not request→response — so they are their own lifecycle, not a
// unit/pipeline resolver, and their event source is a PUSH source (a stream of mutation events that
// call you), NOT a datasource.Store (that call-vs-stream split). This file is the genuinely hard part:
// enhanced subscription FILTER matching. The WebSocket transport is the easy half; the
// durable bus (JetStream) is behind a port (bus.go); the temporal graduation bar (a node-kill chaos
// run) is external and the label stays experimental until it is green.
package subscription

import (
	"strings"
)

// Condition is one field constraint, mirroring AppSync's enhanced-filter operators.
type Condition struct {
	Field    string `json:"field"`    // event field, dotted for nested (e.g. "author.id")
	Operator string `json:"operator"` // eq|ne|lt|le|gt|ge|in|notIn|contains|notContains|beginsWith|between
	Value    any    `json:"value"`
}

// Filter is a set of conditions that ALL must hold (AND).
type Filter struct {
	Conditions []Condition `json:"conditions"`
}

// FilterGroup is a set of filters, ANY of which delivering (OR). An empty group matches everything
// (an unfiltered subscription). This is exactly AppSync's filterGroup semantics.
type FilterGroup struct {
	Filters []Filter `json:"filters"`
}

// Match reports whether an event should be delivered to a subscriber with this filter group.
func (g FilterGroup) Match(event map[string]any) bool {
	if len(g.Filters) == 0 {
		return true // no filter → receive all events for the field
	}
	for _, f := range g.Filters {
		if f.match(event) {
			return true // OR across filters
		}
	}
	return false
}

func (f Filter) match(event map[string]any) bool {
	for _, c := range f.Conditions {
		if !c.match(event) {
			return false // AND across conditions
		}
	}
	return true
}

func (c Condition) match(event map[string]any) bool {
	actual, ok := lookup(event, c.Field)
	switch c.Operator {
	case "eq":
		return ok && equal(actual, c.Value)
	case "ne":
		return !equal(actual, c.Value)
	case "in":
		return ok && inList(actual, c.Value)
	case "notIn":
		return !inList(actual, c.Value)
	case "contains":
		return ok && contains(actual, c.Value)
	case "notContains":
		return !contains(actual, c.Value)
	case "beginsWith":
		a, aok := actual.(string)
		v, vok := c.Value.(string)
		return aok && vok && strings.HasPrefix(a, v)
	case "lt", "le", "gt", "ge":
		return ok && compareOK(actual, c.Value, c.Operator)
	case "between":
		bounds, bok := c.Value.([]any)
		return ok && bok && len(bounds) == 2 &&
			compareOK(actual, bounds[0], "ge") && compareOK(actual, bounds[1], "le")
	default:
		return false // unknown operator never matches (fail closed)
	}
}

// lookup resolves a dotted field path in the event.
func lookup(event map[string]any, field string) (any, bool) {
	var cur any = event
	for _, seg := range strings.Split(field, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func equal(a, b any) bool {
	if af, aok := toFloat(a); aok {
		if bf, bok := toFloat(b); bok {
			return af == bf
		}
	}
	return a == b
}

func inList(a, list any) bool {
	items, ok := list.([]any)
	if !ok {
		return false
	}
	for _, it := range items {
		if equal(a, it) {
			return true
		}
	}
	return false
}

func contains(a, v any) bool {
	switch av := a.(type) {
	case string:
		vs, ok := v.(string)
		return ok && strings.Contains(av, vs)
	case []any:
		for _, it := range av {
			if equal(it, v) {
				return true
			}
		}
	}
	return false
}

func compareOK(a, b any, op string) bool {
	af, aok := toFloat(a)
	bf, bok := toFloat(b)
	if !aok || !bok {
		return false
	}
	switch op {
	case "lt":
		return af < bf
	case "le":
		return af <= bf
	case "gt":
		return af > bf
	case "ge":
		return af >= bf
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}
