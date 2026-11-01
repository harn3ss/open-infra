// Package snsfilter is SNS subscription filter policies: which published messages a subscription
// receives, decided by the message's attributes (FilterPolicyScope MessageAttributes, the default) or by
// its JSON body (MessageBody).
//
// A policy is a JSON object. Each key names a message attribute (or, for the body, a key of the message,
// nested objects naming nested keys) and holds a list of conditions: the message matches when every key
// matches (AND), and a key matches when any of its conditions does (OR). "$or" holds a list of policies of
// which one must match. A condition is a string or number (equal), true/false or null (body only), or an
// operator: prefix, suffix, equals-ignore-case, anything-but (a value, a list, or a prefix/suffix), numeric
// (a comparison or a range), exists, and cidr. A String.Array attribute, or an array in the body, matches
// when any element does; a Binary attribute matches nothing. Anything else is refused by Parse — a policy
// is never accepted and then applied differently than SNS applies it.
package snsfilter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Scopes.
const (
	ScopeAttributes = "MessageAttributes"
	ScopeBody       = "MessageBody"
)

// Limits SNS sets on a policy.
const (
	maxKeys         = 5
	maxCombinations = 150
	maxSize         = 256 * 1024
)

// Attr is a message attribute as published: its DataType (String, String.Array, Number, Binary, or one of
// those with a custom ".suffix") and its string value.
type Attr struct {
	Type  string
	Value string
}

// Policy is a parsed filter policy.
type Policy struct {
	scope string
	root  object
}

type object struct {
	keys map[string]any // key -> []cond (a leaf) or object (nested, body only)
	ors  [][]object     // each "$or": one of its policies must match
}

type cond struct {
	op    string // "eq", "prefix", "suffix", "eqic", "anything-but", "anything-but-prefix", "anything-but-suffix", "numeric", "exists", "cidr"
	value any    // string, float64, bool, nil (eq); string (prefix/suffix/eqic); []any of string/float64 (anything-but)
	num   []numCmp
	exist bool
	cidr  netip.Prefix
}

type numCmp struct {
	op string
	n  float64
}

// Parse reads a filter policy for scope ("" = MessageAttributes).
func Parse(doc, scope string) (*Policy, error) {
	if scope == "" {
		scope = ScopeAttributes
	}
	if scope != ScopeAttributes && scope != ScopeBody {
		return nil, fmt.Errorf("FilterPolicyScope must be %s or %s", ScopeAttributes, ScopeBody)
	}
	if len(doc) > maxSize {
		return nil, errors.New("the filter policy is larger than 256 KB")
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(doc)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("the filter policy is not valid JSON")
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, errors.New("the filter policy must be a non-empty JSON object")
	}
	p := &Policy{scope: scope}
	root, err := parseObject(m, scope == ScopeBody, 0)
	if err != nil {
		return nil, err
	}
	p.root = root
	if n := root.leafKeys(); n > maxKeys && scope == ScopeAttributes {
		return nil, fmt.Errorf("the filter policy names %d attributes; SNS allows at most %d", n, maxKeys)
	}
	if c := root.combinations(); c > maxCombinations {
		return nil, fmt.Errorf("the filter policy has %d combinations of values; SNS allows at most %d", c, maxCombinations)
	}
	return p, nil
}

func parseObject(m map[string]any, nested bool, depth int) (object, error) {
	if depth > 16 {
		return object{}, errors.New("the filter policy is nested too deeply")
	}
	o := object{keys: map[string]any{}}
	for _, k := range sortedKeys(m) {
		v := m[k]
		if k == "$or" {
			list, ok := v.([]any)
			if !ok || len(list) < 2 {
				return o, errors.New(`"$or" must list at least two policies`)
			}
			var branch []object
			for _, e := range list {
				em, ok := e.(map[string]any)
				if !ok || len(em) == 0 {
					return o, errors.New(`each "$or" entry must be a non-empty object`)
				}
				sub, err := parseObject(em, nested, depth+1)
				if err != nil {
					return o, err
				}
				branch = append(branch, sub)
			}
			o.ors = append(o.ors, branch)
			continue
		}
		switch t := v.(type) {
		case []any:
			if len(t) == 0 {
				return o, fmt.Errorf("the conditions for %q must not be empty", k)
			}
			conds := make([]cond, 0, len(t))
			for _, e := range t {
				c, err := parseCond(e, nested)
				if err != nil {
					return o, fmt.Errorf("%q: %w", k, err)
				}
				conds = append(conds, c)
			}
			o.keys[k] = conds
		case map[string]any:
			if !nested {
				return o, fmt.Errorf("%q: a nested key is for FilterPolicyScope MessageBody; message attributes are flat", k)
			}
			sub, err := parseObject(t, nested, depth+1)
			if err != nil {
				return o, err
			}
			o.keys[k] = sub
		default:
			return o, fmt.Errorf("%q must hold a list of conditions", k)
		}
	}
	return o, nil
}

func number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func parseCond(e any, body bool) (cond, error) {
	switch t := e.(type) {
	case string:
		return cond{op: "eq", value: t}, nil
	case json.Number:
		f, ok := number(t)
		if !ok {
			return cond{}, errors.New("a number condition must be a finite number")
		}
		return cond{op: "eq", value: f}, nil
	case bool:
		if !body {
			return cond{}, errors.New("a boolean condition is for FilterPolicyScope MessageBody")
		}
		return cond{op: "eq", value: t}, nil
	case nil:
		if !body {
			return cond{}, errors.New("a null condition is for FilterPolicyScope MessageBody")
		}
		return cond{op: "eq", value: nil}, nil
	case map[string]any:
		if len(t) != 1 {
			return cond{}, errors.New("an operator condition holds exactly one operator")
		}
		for op, arg := range t {
			return parseOp(op, arg)
		}
	}
	return cond{}, errors.New("a condition must be a string, a number or an operator")
}

func parseOp(op string, arg any) (cond, error) {
	str := func() (string, error) {
		s, ok := arg.(string)
		if !ok {
			return "", fmt.Errorf("%s takes a string", op)
		}
		return s, nil
	}
	switch op {
	case "prefix", "suffix":
		s, err := str()
		return cond{op: op, value: s}, err
	case "equals-ignore-case":
		s, err := str()
		return cond{op: "eqic", value: s}, err
	case "exists":
		b, ok := arg.(bool)
		if !ok {
			return cond{}, errors.New("exists takes true or false")
		}
		return cond{op: "exists", exist: b}, nil
	case "cidr":
		s, err := str()
		if err != nil {
			return cond{}, err
		}
		pfx, perr := netip.ParsePrefix(s)
		if perr != nil {
			return cond{}, fmt.Errorf("cidr %q is not an IP prefix", s)
		}
		return cond{op: "cidr", cidr: pfx.Masked()}, nil
	case "numeric":
		list, ok := arg.([]any)
		if !ok || (len(list) != 2 && len(list) != 4) {
			return cond{}, errors.New(`numeric takes one comparison or a range, e.g. [">", 0, "<=", 5]`)
		}
		var cmps []numCmp
		for i := 0; i < len(list); i += 2 {
			o, ok := list[i].(string)
			n, nok := number(list[i+1])
			if !ok || !nok || !containsStr([]string{"=", "<", "<=", ">", ">="}, o) {
				return cond{}, errors.New(`numeric comparisons are "=", "<", "<=", ">", ">=" followed by a number`)
			}
			cmps = append(cmps, numCmp{o, n})
		}
		if len(cmps) == 2 && (!strings.HasPrefix(cmps[0].op, ">") || !strings.HasPrefix(cmps[1].op, "<") || cmps[0].n >= cmps[1].n) {
			return cond{}, errors.New(`a numeric range is a lower bound (">" or ">=") then a higher upper bound ("<" or "<=")`)
		}
		return cond{op: "numeric", num: cmps}, nil
	case "anything-but":
		switch t := arg.(type) {
		case string, json.Number:
			arg = []any{t}
		case map[string]any:
			if len(t) != 1 {
				return cond{}, errors.New("anything-but takes a value, a list, or one prefix/suffix")
			}
			for k, v := range t {
				s, ok := v.(string)
				if !ok || (k != "prefix" && k != "suffix") {
					return cond{}, errors.New("anything-but takes a value, a list, or one prefix/suffix")
				}
				return cond{op: "anything-but-" + k, value: s}, nil
			}
		}
		list, ok := arg.([]any)
		if !ok || len(list) == 0 {
			return cond{}, errors.New("anything-but takes a value, a list, or one prefix/suffix")
		}
		vals := make([]any, 0, len(list))
		for _, e := range list {
			switch x := e.(type) {
			case string:
				vals = append(vals, x)
			case json.Number:
				f, ok := number(x)
				if !ok {
					return cond{}, errors.New("anything-but lists strings or numbers")
				}
				vals = append(vals, f)
			default:
				return cond{}, errors.New("anything-but lists strings or numbers")
			}
		}
		return cond{op: "anything-but", value: vals}, nil
	}
	return cond{}, fmt.Errorf("the operator %q is not one SNS filter policies have here", op)
}

func (o object) leafKeys() int {
	n := 0
	for _, v := range o.keys {
		if sub, ok := v.(object); ok {
			n += sub.leafKeys()
		} else {
			n++
		}
	}
	for _, branch := range o.ors {
		most := 0
		for _, b := range branch {
			if k := b.leafKeys(); k > most {
				most = k
			}
		}
		n += most
	}
	return n
}

func (o object) combinations() int {
	c := 1
	for _, v := range o.keys {
		switch t := v.(type) {
		case object:
			c *= t.combinations()
		case []cond:
			c *= len(t)
		}
	}
	for _, branch := range o.ors {
		s := 0
		for _, b := range branch {
			s += b.combinations()
		}
		c *= s
	}
	return c
}

// Scope is the policy's scope.
func (p *Policy) Scope() string { return p.scope }

// MatchAttributes reports whether a message with these attributes passes the policy (attributes scope).
func (p *Policy) MatchAttributes(attrs map[string]Attr) bool {
	return p.root.match(func(k string) ([]value, bool) {
		a, ok := attrs[k]
		if !ok {
			return nil, false
		}
		return attrValues(a), true
	})
}

// MatchBody reports whether a message body passes the policy (body scope). A body that is not a JSON
// object matches nothing.
func (p *Policy) MatchBody(body string) bool {
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	return p.root.matchBody(m)
}

// value is one value a condition is tested on: its kind and what it holds.
type value struct {
	kind string // "string", "number", "bool", "null", "binary"
	s    string
	n    float64
	b    bool
}

func attrValues(a Attr) []value {
	base := a.Type
	if i := strings.Index(base, "."); i >= 0 && !strings.HasPrefix(base, "String.Array") {
		base = base[:i]
	}
	switch {
	case strings.HasPrefix(a.Type, "String.Array"):
		dec := json.NewDecoder(strings.NewReader(a.Value))
		dec.UseNumber()
		var list []any
		if dec.Decode(&list) != nil {
			return nil
		}
		var out []value
		for _, e := range list {
			out = append(out, jsonValue(e)...)
		}
		return out
	case base == "Number":
		f, err := strconv.ParseFloat(strings.TrimSpace(a.Value), 64)
		if err != nil {
			return nil
		}
		return []value{{kind: "number", n: f}}
	case base == "Binary":
		return []value{{kind: "binary"}}
	}
	return []value{{kind: "string", s: a.Value}}
}

func jsonValue(e any) []value {
	switch x := e.(type) {
	case string:
		return []value{{kind: "string", s: x}}
	case json.Number:
		if f, ok := number(x); ok {
			return []value{{kind: "number", n: f}}
		}
	case bool:
		return []value{{kind: "bool", b: x}}
	case nil:
		return []value{{kind: "null"}}
	case []any:
		var out []value
		for _, y := range x {
			out = append(out, jsonValue(y)...)
		}
		return out
	}
	return nil // an object is not a value a leaf condition tests
}

// match evaluates a flat (attributes) object; lookup returns a key's values and whether it is present.
func (o object) match(lookup func(string) ([]value, bool)) bool {
	for k, v := range o.keys {
		conds, _ := v.([]cond)
		vals, present := lookup(k)
		if !anyCond(conds, vals, present) {
			return false
		}
	}
	for _, branch := range o.ors {
		ok := false
		for _, b := range branch {
			if b.match(lookup) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (o object) matchBody(m map[string]any) bool {
	for k, v := range o.keys {
		got, present := m[k]
		switch t := v.(type) {
		case object:
			if !present {
				return false
			}
			if !matchNested(t, got) {
				return false
			}
		case []cond:
			if !anyCond(t, jsonValue(got), present) {
				return false
			}
		}
	}
	for _, branch := range o.ors {
		ok := false
		for _, b := range branch {
			if b.matchBody(m) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// matchNested matches a nested policy object against a body value: an object, or an array of objects (any).
func matchNested(o object, v any) bool {
	switch t := v.(type) {
	case map[string]any:
		return o.matchBody(t)
	case []any:
		for _, e := range t {
			if mm, ok := e.(map[string]any); ok && o.matchBody(mm) {
				return true
			}
		}
	}
	return false
}

func anyCond(conds []cond, vals []value, present bool) bool {
	for _, c := range conds {
		if c.op == "exists" {
			if c.exist == present {
				return true
			}
			continue
		}
		if !present {
			continue
		}
		if c.op == "anything-but" || c.op == "anything-but-prefix" || c.op == "anything-but-suffix" {
			if len(vals) > 0 && allNot(c, vals) {
				return true
			}
			continue
		}
		for _, v := range vals {
			if c.matches(v) {
				return true
			}
		}
	}
	return false
}

// allNot: anything-but holds when no value is one of those excluded (an attribute's values all differ).
func allNot(c cond, vals []value) bool {
	for _, v := range vals {
		switch c.op {
		case "anything-but-prefix":
			if v.kind != "string" || strings.HasPrefix(v.s, c.value.(string)) {
				return false
			}
		case "anything-but-suffix":
			if v.kind != "string" || strings.HasSuffix(v.s, c.value.(string)) {
				return false
			}
		default:
			for _, x := range c.value.([]any) {
				if (cond{op: "eq", value: x}).matches(v) {
					return false
				}
			}
			if v.kind == "binary" {
				return false
			}
		}
	}
	return true
}

func (c cond) matches(v value) bool {
	switch c.op {
	case "eq":
		switch x := c.value.(type) {
		case string:
			return v.kind == "string" && v.s == x
		case float64:
			return v.kind == "number" && v.n == x
		case bool:
			return v.kind == "bool" && v.b == x
		case nil:
			return v.kind == "null"
		}
	case "prefix":
		return v.kind == "string" && strings.HasPrefix(v.s, c.value.(string))
	case "suffix":
		return v.kind == "string" && strings.HasSuffix(v.s, c.value.(string))
	case "eqic":
		return v.kind == "string" && strings.EqualFold(v.s, c.value.(string))
	case "numeric":
		if v.kind != "number" {
			return false
		}
		for _, n := range c.num {
			if !compare(v.n, n) {
				return false
			}
		}
		return true
	case "cidr":
		if v.kind != "string" {
			return false
		}
		ip, err := netip.ParseAddr(v.s)
		return err == nil && c.cidr.Contains(ip.Unmap())
	}
	return false
}

func compare(x float64, c numCmp) bool {
	switch c.op {
	case "=":
		return x == c.n
	case "<":
		return x < c.n
	case "<=":
		return x <= c.n
	case ">":
		return x > c.n
	case ">=":
		return x >= c.n
	}
	return false
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
