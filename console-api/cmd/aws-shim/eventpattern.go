// EventBridge event-pattern matching for the aws-shim (polyhedron#163).
//
// An EventPattern is not a string comparison — it is a matching language: exact-match by default, arrays
// as OR-lists, nested objects for nested fields, and content filters (prefix, suffix, anything-but,
// numeric, exists, cidr, equals-ignore-case, wildcard). Matching too loosely delivers events a subscriber
// filtered out; too strictly makes events silently vanish. So the pattern is VALIDATED at PutRule
// (unknown operators are refused, never accepted-and-approximated) and TestEventPattern uses the SAME
// matcher the router uses — it can never give a different answer.
package main

import (
	"net"
	"strings"
)

var knownPatternOps = map[string]bool{
	"prefix": true, "suffix": true, "anything-but": true, "exists": true,
	"numeric": true, "cidr": true, "equals-ignore-case": true, "wildcard": true,
}

// validatePattern walks a decoded EventPattern and returns an error for any shape or operator we do not
// implement — so PutRule refuses it rather than the router silently approximating it.
func validatePattern(pattern map[string]any) error {
	for _, pv := range pattern {
		switch v := pv.(type) {
		case []any:
			for _, m := range v {
				switch mv := m.(type) {
				case string, float64, bool, nil:
					// exact scalar match
				case map[string]any:
					for op := range mv {
						if !knownPatternOps[op] {
							return &patternError{"unsupported event-pattern operator: " + op}
						}
					}
				default:
					return &patternError{"event-pattern match values must be scalars or content-filter objects"}
				}
			}
		case map[string]any:
			if err := validatePattern(v); err != nil {
				return err
			}
		default:
			return &patternError{"event-pattern fields must map to an array or a nested object"}
		}
	}
	return nil
}

type patternError struct{ msg string }

func (e *patternError) Error() string { return e.msg }

// matchPattern reports whether an event matches an EventPattern.
func matchPattern(pattern, event map[string]any) bool {
	for key, pv := range pattern {
		ev, present := event[key]
		switch v := pv.(type) {
		case []any:
			if !matchList(v, ev, present) {
				return false
			}
		case map[string]any:
			evMap, ok := ev.(map[string]any)
			if !present || !ok || !matchPattern(v, evMap) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func matchList(matchers []any, ev any, present bool) bool {
	for _, m := range matchers {
		if matchOne(m, ev, present) {
			return true
		}
	}
	return false
}

func matchOne(m, ev any, present bool) bool {
	switch mv := m.(type) {
	case map[string]any:
		return matchFilter(mv, ev, present)
	default:
		return present && scalarEqual(m, ev)
	}
}

func matchFilter(filter map[string]any, ev any, present bool) bool {
	for op, val := range filter {
		switch op {
		case "exists":
			want, _ := val.(bool)
			return want == present
		case "prefix":
			s, ok := stringOf(ev)
			p, _ := val.(string)
			return present && ok && strings.HasPrefix(s, p)
		case "suffix":
			s, ok := stringOf(ev)
			p, _ := val.(string)
			return present && ok && strings.HasSuffix(s, p)
		case "equals-ignore-case":
			s, ok := stringOf(ev)
			p, _ := val.(string)
			return present && ok && strings.EqualFold(s, p)
		case "anything-but":
			if !present {
				return true
			}
			return !anythingButMatches(val, ev)
		case "numeric":
			return present && numericMatches(val, ev)
		case "cidr":
			s, ok := stringOf(ev)
			p, _ := val.(string)
			return present && ok && cidrContains(p, s)
		case "wildcard":
			s, ok := stringOf(ev)
			p, _ := val.(string)
			return present && ok && wildcardMatch(p, s)
		}
	}
	return false
}

// anythingButMatches reports whether ev equals the excluded value (or is in the excluded list).
func anythingButMatches(val, ev any) bool {
	switch v := val.(type) {
	case []any:
		for _, x := range v {
			if scalarEqual(x, ev) {
				return true
			}
		}
		return false
	default:
		return scalarEqual(val, ev)
	}
}

// numericMatches evaluates ["op", n, "op", n, ...] against a numeric event value (all conditions AND).
func numericMatches(val, ev any) bool {
	conds, ok := val.([]any)
	if !ok || len(conds)%2 != 0 {
		return false
	}
	n, ok := ev.(float64)
	if !ok {
		return false
	}
	for i := 0; i < len(conds); i += 2 {
		op, _ := conds[i].(string)
		bound, ok := conds[i+1].(float64)
		if !ok {
			return false
		}
		switch op {
		case "=":
			if n != bound {
				return false
			}
		case "!=":
			if n == bound {
				return false
			}
		case "<":
			if !(n < bound) {
				return false
			}
		case "<=":
			if !(n <= bound) {
				return false
			}
		case ">":
			if !(n > bound) {
				return false
			}
		case ">=":
			if !(n >= bound) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func cidrContains(cidr, ip string) bool {
	_, netw, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	parsed := net.ParseIP(ip)
	return parsed != nil && netw.Contains(parsed)
}

// wildcardMatch supports '*' (any run of characters) as the sole metacharacter.
func wildcardMatch(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

func scalarEqual(a, b any) bool {
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case float64:
		bv, ok := b.(float64)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case nil:
		return b == nil
	}
	return false
}

func stringOf(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}
