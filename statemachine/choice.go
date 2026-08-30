// Choice-state rule evaluation — a faithful subset of ASL's comparison operators.
//
// Supported: String/Numeric/Timestamp {Equals,LessThan,GreaterThan,LessThanEquals,
// GreaterThanEquals}, BooleanEquals, IsPresent, IsNull, IsString, IsNumeric,
// IsBoolean, IsTimestamp, the And/Or/Not compositions, and every "<Op>Path" variant
// (the operand is itself a reference path). Data-test operators are evaluated
// map-generically so the set stays compact.
package main

import (
	"encoding/json"
	"strings"
	"time"
)

// ChoiceRule is one rule in a Choice state's Choices (or a nested rule inside
// And/Or/Not, in which case Next is empty).
type ChoiceRule struct {
	raw map[string]json.RawMessage
}

func (c *ChoiceRule) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &c.raw)
}

// Next is the target state when this (top-level) rule matches.
func (c ChoiceRule) Next() string {
	var s string
	if r, ok := c.raw["Next"]; ok {
		_ = json.Unmarshal(r, &s)
	}
	return s
}

func (c ChoiceRule) variable() (string, bool) {
	r, ok := c.raw["Variable"]
	if !ok {
		return "", false
	}
	var s string
	_ = json.Unmarshal(r, &s)
	return s, true
}

// eval reports whether the rule matches the given data.
func (c ChoiceRule) eval(data any, ctx map[string]any) (bool, error) {
	// Boolean compositions.
	if r, ok := c.raw["And"]; ok {
		var rules []ChoiceRule
		if err := json.Unmarshal(r, &rules); err != nil {
			return false, perr("And is not a list of rules: %v", err)
		}
		for _, sub := range rules {
			m, err := sub.eval(data, ctx)
			if err != nil {
				return false, err
			}
			if !m {
				return false, nil
			}
		}
		return true, nil
	}
	if r, ok := c.raw["Or"]; ok {
		var rules []ChoiceRule
		if err := json.Unmarshal(r, &rules); err != nil {
			return false, perr("Or is not a list of rules: %v", err)
		}
		for _, sub := range rules {
			m, err := sub.eval(data, ctx)
			if err != nil {
				return false, err
			}
			if m {
				return true, nil
			}
		}
		return false, nil
	}
	if r, ok := c.raw["Not"]; ok {
		var sub ChoiceRule
		if err := json.Unmarshal(r, &sub); err != nil {
			return false, perr("Not is not a rule: %v", err)
		}
		m, err := sub.eval(data, ctx)
		return !m, err
	}

	// Data-test operator.
	varPath, ok := c.variable()
	if !ok {
		return false, perr("choice rule has no Variable and no And/Or/Not")
	}
	value, found, err := getPath(data, ctx, varPath)
	if err != nil {
		return false, err
	}

	for key, rawOperand := range c.raw {
		if key == "Variable" || key == "Next" {
			continue
		}
		return c.applyOp(key, value, found, rawOperand, data, ctx)
	}
	return false, perr("choice rule for %q has no comparison operator", varPath)
}

func (c ChoiceRule) applyOp(op string, value any, found bool, rawOperand json.RawMessage, data any, ctx map[string]any) (bool, error) {
	// Presence / type predicates take a boolean operand and don't need the value present.
	switch op {
	case "IsPresent":
		return found == boolOperand(rawOperand), nil
	case "IsNull":
		return (found && value == nil) == boolOperand(rawOperand), nil
	case "IsString":
		_, is := value.(string)
		return (found && is) == boolOperand(rawOperand), nil
	case "IsNumeric":
		_, is := value.(float64)
		return (found && is) == boolOperand(rawOperand), nil
	case "IsBoolean":
		_, is := value.(bool)
		return (found && is) == boolOperand(rawOperand), nil
	case "IsTimestamp":
		s, is := value.(string)
		ok := false
		if is {
			_, e := time.Parse(time.RFC3339, s)
			ok = e == nil
		}
		return (found && ok) == boolOperand(rawOperand), nil
	}

	// A missing variable never matches a value comparison.
	if !found {
		return false, nil
	}

	// "<Op>Path" variants resolve the operand from a reference path.
	base := op
	if strings.HasSuffix(op, "Path") {
		base = strings.TrimSuffix(op, "Path")
		var p string
		if err := json.Unmarshal(rawOperand, &p); err != nil {
			return false, perr("%s expects a path string", op)
		}
		v, ok, err := getPath(data, ctx, p)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		rawOperand = nil // signal: use resolved operand `v`
		return compareResolved(base, value, v)
	}

	var operand any
	if err := json.Unmarshal(rawOperand, &operand); err != nil {
		return false, perr("%s has an invalid operand: %v", op, err)
	}
	return compareResolved(base, value, operand)
}

func compareResolved(base string, value, operand any) (bool, error) {
	switch {
	case strings.HasPrefix(base, "String"):
		l, lok := value.(string)
		r, rok := operand.(string)
		if !lok || !rok {
			return false, nil
		}
		return cmpOrder(base, "String", strings.Compare(l, r)), nil
	case strings.HasPrefix(base, "Numeric"):
		l, lok := toFloat(value)
		r, rok := toFloat(operand)
		if !lok || !rok {
			return false, nil
		}
		return cmpOrder(base, "Numeric", cmpFloat(l, r)), nil
	case strings.HasPrefix(base, "Boolean"):
		l, lok := value.(bool)
		r, rok := operand.(bool)
		if !lok || !rok {
			return false, nil
		}
		return l == r, nil
	case strings.HasPrefix(base, "Timestamp"):
		l, lok := parseTime(value)
		r, rok := parseTime(operand)
		if !lok || !rok {
			return false, nil
		}
		return cmpOrder(base, "Timestamp", cmpFloat(float64(l.UnixNano()), float64(r.UnixNano()))), nil
	}
	return false, perr("unsupported choice operator %q", base)
}

// cmpOrder maps a -1/0/1 comparison to the operator's boolean.
func cmpOrder(base, prefix string, c int) bool {
	switch strings.TrimPrefix(base, prefix) {
	case "Equals":
		return c == 0
	case "LessThan":
		return c < 0
	case "GreaterThan":
		return c > 0
	case "LessThanEquals":
		return c <= 0
	case "GreaterThanEquals":
		return c >= 0
	}
	return false
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func toFloat(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func parseTime(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

func boolOperand(raw json.RawMessage) bool {
	var b bool
	_ = json.Unmarshal(raw, &b)
	return b
}
