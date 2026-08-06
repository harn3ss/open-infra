// Package graphql is a focused GraphQL query parser + executor for open-appsync (handoff §3.1 piece
// 1 + the execution half of piece 4). It parses an incoming operation, runs the VTL resolver bound
// to each top-level field (Query.<field> / Mutation.<field>), and projects the query's selection set
// onto the resolver's result — turning "a resolver runs" into "a real GraphQL query runs."
//
// Scoped to the slice-1 subset: one operation per document; top-level resolver fields; arguments
// (scalars / $variables / object & list literals); nested selection sets projected structurally from
// the resolver result. Fragments, directives, aliases-on-everything, and per-nested-field resolvers
// are later rungs. Stdlib only — no GraphQL dependency.
package graphql

import (
	"fmt"
	"strconv"
	"strings"
)

// operation is a parsed GraphQL operation.
type operation struct {
	opType     string // "query" | "mutation"
	selections []selection
}

type selection struct {
	alias      string
	name       string
	args       map[string]valueNode
	selections []selection
}

// valueNode is a GraphQL argument value: literal, $variable, list, or object.
type valueNode struct {
	kind string // "scalar" | "var" | "list" | "object"
	val  any    // scalar Go value; var name (string); []valueNode; map[string]valueNode
}

// --- lexer ---

type gtok struct {
	kind string // name int float str punct eof
	val  string
}

func tokenize(s string) ([]gtok, error) {
	var toks []gtok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '"':
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					b.WriteByte(s[j+1])
					j += 2
					continue
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("graphql: unterminated string")
			}
			toks = append(toks, gtok{"str", b.String()})
			i = j + 1
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			isFloat := false
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.' || s[j] == 'e' || s[j] == 'E' || s[j] == '-' || s[j] == '+') {
				if s[j] == '.' || s[j] == 'e' || s[j] == 'E' {
					isFloat = true
				}
				j++
			}
			kind := "int"
			if isFloat {
				kind = "float"
			}
			toks = append(toks, gtok{kind, s[i:j]})
			i = j
		case isNameStart(c):
			j := i + 1
			for j < len(s) && isNamePart(s[j]) {
				j++
			}
			toks = append(toks, gtok{"name", s[i:j]})
			i = j
		case strings.IndexByte("{}()[]:$!=", c) >= 0:
			toks = append(toks, gtok{"punct", string(c)})
			i++
		default:
			return nil, fmt.Errorf("graphql: unexpected char %q", string(c))
		}
	}
	return append(toks, gtok{"eof", ""}), nil
}

func isNameStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}
func isNamePart(c byte) bool { return isNameStart(c) || c >= '0' && c <= '9' }

// --- parser ---

type gparser struct {
	toks []gtok
	i    int
}

func parseQuery(s string) (*operation, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	p := &gparser{toks: toks}
	op := &operation{opType: "query"}

	// Optional: operation type + name + variable definitions.
	if p.peek().kind == "name" && (p.peek().val == "query" || p.peek().val == "mutation" || p.peek().val == "subscription") {
		op.opType = p.next().val
		if op.opType == "subscription" {
			return nil, fmt.Errorf("graphql: subscriptions are a later rung, not in slice 1")
		}
		if p.peek().kind == "name" { // operation name
			p.next()
		}
		if p.isPunct("(") { // variable definitions — parsed and ignored (values come at execution)
			if err := p.skipBalanced("(", ")"); err != nil {
				return nil, err
			}
		}
	}
	if !p.isPunct("{") {
		return nil, fmt.Errorf("graphql: expected a selection set '{'")
	}
	sels, err := p.parseSelectionSet()
	if err != nil {
		return nil, err
	}
	op.selections = sels
	return op, nil
}

func (p *gparser) parseSelectionSet() ([]selection, error) {
	if !p.accept("punct", "{") {
		return nil, fmt.Errorf("graphql: expected '{'")
	}
	var sels []selection
	for !p.isPunct("}") {
		if p.peek().kind == "eof" {
			return nil, fmt.Errorf("graphql: unterminated selection set")
		}
		s, err := p.parseField()
		if err != nil {
			return nil, err
		}
		sels = append(sels, s)
	}
	p.next() // }
	return sels, nil
}

func (p *gparser) parseField() (selection, error) {
	if p.peek().kind != "name" {
		return selection{}, fmt.Errorf("graphql: expected a field name, got %q", p.peek().val)
	}
	name := p.next().val
	sel := selection{name: name}
	if p.accept("punct", ":") { // alias: name
		if p.peek().kind != "name" {
			return selection{}, fmt.Errorf("graphql: expected field name after alias")
		}
		sel.alias = name
		sel.name = p.next().val
	}
	if p.isPunct("(") {
		args, err := p.parseArgs()
		if err != nil {
			return selection{}, err
		}
		sel.args = args
	}
	if p.isPunct("{") {
		sub, err := p.parseSelectionSet()
		if err != nil {
			return selection{}, err
		}
		sel.selections = sub
	}
	return sel, nil
}

func (p *gparser) parseArgs() (map[string]valueNode, error) {
	p.next() // (
	args := map[string]valueNode{}
	for !p.isPunct(")") {
		if p.peek().kind != "name" {
			return nil, fmt.Errorf("graphql: expected argument name")
		}
		name := p.next().val
		if !p.accept("punct", ":") {
			return nil, fmt.Errorf("graphql: expected ':' after argument name")
		}
		v, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		args[name] = v
	}
	p.next() // )
	return args, nil
}

func (p *gparser) parseValue() (valueNode, error) {
	t := p.peek()
	switch {
	case t.kind == "str":
		p.next()
		return valueNode{kind: "scalar", val: t.val}, nil
	case t.kind == "int":
		p.next()
		f, _ := strconv.ParseFloat(t.val, 64)
		return valueNode{kind: "scalar", val: f}, nil
	case t.kind == "float":
		p.next()
		f, _ := strconv.ParseFloat(t.val, 64)
		return valueNode{kind: "scalar", val: f}, nil
	case t.kind == "name":
		p.next()
		switch t.val {
		case "true":
			return valueNode{kind: "scalar", val: true}, nil
		case "false":
			return valueNode{kind: "scalar", val: false}, nil
		case "null":
			return valueNode{kind: "scalar", val: nil}, nil
		}
		return valueNode{kind: "scalar", val: t.val}, nil // enum value → its name
	case p.isPunct("$"):
		p.next()
		if p.peek().kind != "name" {
			return valueNode{}, fmt.Errorf("graphql: expected variable name after '$'")
		}
		return valueNode{kind: "var", val: p.next().val}, nil
	case p.isPunct("["):
		p.next()
		var list []valueNode
		for !p.isPunct("]") {
			v, err := p.parseValue()
			if err != nil {
				return valueNode{}, err
			}
			list = append(list, v)
		}
		p.next()
		return valueNode{kind: "list", val: list}, nil
	case p.isPunct("{"):
		p.next()
		obj := map[string]valueNode{}
		for !p.isPunct("}") {
			if p.peek().kind != "name" {
				return valueNode{}, fmt.Errorf("graphql: expected object field name")
			}
			k := p.next().val
			if !p.accept("punct", ":") {
				return valueNode{}, fmt.Errorf("graphql: expected ':' in object value")
			}
			v, err := p.parseValue()
			if err != nil {
				return valueNode{}, err
			}
			obj[k] = v
		}
		p.next()
		return valueNode{kind: "object", val: obj}, nil
	}
	return valueNode{}, fmt.Errorf("graphql: unexpected value token %q", t.val)
}

// --- parser helpers ---

func (p *gparser) peek() gtok { return p.toks[p.i] }
func (p *gparser) next() gtok { t := p.toks[p.i]; p.i++; return t }
func (p *gparser) isPunct(v string) bool {
	return p.peek().kind == "punct" && p.peek().val == v
}
func (p *gparser) accept(kind, val string) bool {
	if p.peek().kind == kind && p.peek().val == val {
		p.i++
		return true
	}
	return false
}
func (p *gparser) skipBalanced(open, close string) error {
	if !p.accept("punct", open) {
		return fmt.Errorf("graphql: expected %q", open)
	}
	depth := 1
	for depth > 0 {
		t := p.next()
		if t.kind == "eof" {
			return fmt.Errorf("graphql: unbalanced %q", open)
		}
		if t.kind == "punct" && t.val == open {
			depth++
		} else if t.kind == "punct" && t.val == close {
			depth--
		}
	}
	return nil
}
