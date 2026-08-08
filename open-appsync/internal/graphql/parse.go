// Package graphql is a focused GraphQL query parser + executor for open-appsync (schema intake + the
// execution half). It parses an incoming operation, runs the VTL resolver bound
// to each top-level field (Query.<field> / Mutation.<field>), and projects the query's selection set
// onto the resolver's result — turning "a resolver runs" into "a real GraphQL query runs."
//
// Scope: one operation per document (plus any number of fragment definitions); top-level resolver
// fields; arguments (scalars / $variables / object & list literals); nested selection sets projected
// structurally from the resolver result; named + inline fragments (expanded to fields before execution).
// Directives (@skip/@include execution), aliases-on-everything, per-nested-field resolvers, and
// polymorphic fragment type-condition dispatch (interfaces/unions) are later rungs. Stdlib only — no
// GraphQL dependency.
package graphql

import (
	"fmt"
	"strconv"
	"strings"
)

// operation is a parsed GraphQL operation plus any fragment definitions in the same document.
type operation struct {
	opType     string // "query" | "mutation" | "subscription"
	selections []selection
	fragments  map[string]fragmentDef // named fragments in the document, by name
	varDefs    []variableDef          // operation variable definitions ($name: Type = default)
}

// variableDef is one operation variable definition: `$name: Type = default`. The type is a wrapped
// typeRef so coercion can enforce nullability/list structure; the default (if any) is an unevaluated
// value literal.
type variableDef struct {
	name         string
	typ          typeRef
	defaultValue valueNode
	hasDefault   bool
}

// fragmentDef is a `fragment Name on Type { … }` definition.
type fragmentDef struct {
	name          string
	typeCondition string
	selections    []selection
}

// selection is one entry in a selection set: a field, a fragment spread (`...Name`), or an inline
// fragment (`... on Type { … }` / `... { … }`). The three are distinguished by which fields are set:
// a field has `name`; a spread has `fragmentSpread`; an inline fragment has `inline` true. Spreads and
// inline fragments are expanded away by flattenSelections before execution, so the executor and
// project() only ever see fields.
type selection struct {
	alias      string
	name       string
	args       map[string]valueNode
	selections []selection

	fragmentSpread string // non-empty → this selection is `...<fragmentSpread>`
	inline         bool   // true → this selection is an inline fragment
	typeCondition  string // inline fragment's `on Type` (may be "" for an untyped `... { }`)
}

// valueNode is a GraphQL argument value: literal, enum, $variable, list, or object.
type valueNode struct {
	kind string // "scalar" | "enum" | "var" | "list" | "object"
	val  any    // scalar Go value; enum name (string); var name (string); []valueNode; map[string]valueNode
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
		case c == '"' && i+2 < len(s) && s[i+1] == '"' && s[i+2] == '"':
			// Block string ("""…"""): SDL descriptions use these. We keep the raw inner text (no
			// dedent/normalization — descriptions are carried verbatim into introspection).
			j := i + 3
			var b strings.Builder
			for j+2 < len(s) && !(s[j] == '"' && s[j+1] == '"' && s[j+2] == '"') {
				b.WriteByte(s[j])
				j++
			}
			if j+2 >= len(s) {
				return nil, fmt.Errorf("graphql: unterminated block string")
			}
			toks = append(toks, gtok{"str", strings.TrimSpace(b.String())})
			i = j + 3
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
		case c == '.': // the only multi-char punct: `...` (fragment spread / inline fragment)
			if i+2 < len(s) && s[i+1] == '.' && s[i+2] == '.' {
				toks = append(toks, gtok{"punct", "..."})
				i += 3
			} else {
				return nil, fmt.Errorf("graphql: unexpected char %q", ".")
			}
		case strings.IndexByte("{}()[]:$!=@|&", c) >= 0: // SDL adds @ (directives), | (unions), & (implements)
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
	op := &operation{opType: "query", fragments: map[string]fragmentDef{}}

	// A document is a list of definitions: one operation (this slice supports one) plus any number of
	// fragment definitions, in any order (the canonical introspection query puts fragments after the op).
	gotOp := false
	for p.peek().kind != "eof" {
		t := p.peek()
		switch {
		case t.kind == "name" && t.val == "fragment":
			fd, err := p.parseFragmentDef()
			if err != nil {
				return nil, err
			}
			op.fragments[fd.name] = fd
		case (t.kind == "name" && (t.val == "query" || t.val == "mutation" || t.val == "subscription")) || (t.kind == "punct" && t.val == "{"):
			if gotOp {
				return nil, fmt.Errorf("graphql: only one operation per document is supported")
			}
			if err := p.parseOperationInto(op); err != nil {
				return nil, err
			}
			gotOp = true
		default:
			return nil, fmt.Errorf("graphql: expected an operation or a fragment definition, got %q", t.val)
		}
	}
	if !gotOp {
		return nil, fmt.Errorf("graphql: document has no operation")
	}
	return op, nil
}

// parseOperationInto parses one operation (optional type/name/variable-definitions + selection set).
func (p *gparser) parseOperationInto(op *operation) error {
	if p.peek().kind == "name" && (p.peek().val == "query" || p.peek().val == "mutation" || p.peek().val == "subscription") {
		op.opType = p.next().val
		// subscription operations parse like any other (a root selection set); they are routed to the
		// subscription lifecycle by the WebSocket handler, not run through the request/response executor.
		if p.peek().kind == "name" { // operation name
			p.next()
		}
		if p.isPunct("(") { // variable definitions ($name: Type = default) — parsed and coerced at execution
			defs, err := p.parseVarDefs()
			if err != nil {
				return err
			}
			op.varDefs = defs
		}
	}
	if !p.isPunct("{") {
		return fmt.Errorf("graphql: expected a selection set '{'")
	}
	sels, err := p.parseSelectionSet()
	if err != nil {
		return err
	}
	op.selections = sels
	return nil
}

// parseVarDefs parses an operation's `( $name: Type = default, … )` variable definition block.
func (p *gparser) parseVarDefs() ([]variableDef, error) {
	p.next() // (
	var defs []variableDef
	for !p.isPunct(")") {
		if p.peek().kind == "eof" {
			return nil, fmt.Errorf("graphql: unterminated variable definitions")
		}
		if !p.accept("punct", "$") {
			return nil, fmt.Errorf("graphql: expected a variable ($name) in the variable definitions")
		}
		name, err := p.expectName()
		if err != nil {
			return nil, err
		}
		if !p.accept("punct", ":") {
			return nil, fmt.Errorf("graphql: expected ':' after variable $%s", name)
		}
		tr, err := p.parseTypeRef()
		if err != nil {
			return nil, err
		}
		d := variableDef{name: name, typ: tr}
		if p.accept("punct", "=") {
			dv, err := p.parseValue()
			if err != nil {
				return nil, err
			}
			d.defaultValue = dv
			d.hasDefault = true
		}
		defs = append(defs, d)
	}
	p.next() // )
	return defs, nil
}

// literalString serializes a value literal to its canonical GraphQL form — enum values unquoted, strings
// quoted — for introspection's defaultValue reporting (which is a String of the GraphQL literal).
func literalString(v valueNode) string {
	switch v.kind {
	case "enum":
		return v.val.(string)
	case "var":
		return "$" + v.val.(string)
	case "list":
		parts := []string{}
		for _, e := range v.val.([]valueNode) {
			parts = append(parts, literalString(e))
		}
		return "[" + join(parts, ", ") + "]"
	case "object":
		parts := []string{}
		for k, e := range v.val.(map[string]valueNode) {
			parts = append(parts, k+": "+literalString(e))
		}
		return "{" + join(parts, ", ") + "}"
	default: // scalar
		switch x := v.val.(type) {
		case nil:
			return "null"
		case string:
			return strconv.Quote(x)
		case bool:
			if x {
				return "true"
			}
			return "false"
		case float64:
			return strconv.FormatFloat(x, 'g', -1, 64)
		default:
			return fmt.Sprintf("%v", x)
		}
	}
}

// expectName consumes and returns a name token, erroring otherwise.
func (p *gparser) expectName() (string, error) {
	if p.peek().kind != "name" {
		return "", fmt.Errorf("graphql: expected a name, got %q", p.peek().val)
	}
	return p.next().val, nil
}

// parseTypeRef parses a (possibly wrapped) type reference: Name, [Inner], and a trailing ! on either —
// shared by the SDL parser and the operation variable-definition parser.
func (p *gparser) parseTypeRef() (typeRef, error) {
	var tr typeRef
	if p.accept("punct", "[") {
		inner, err := p.parseTypeRef()
		if err != nil {
			return typeRef{}, err
		}
		if !p.accept("punct", "]") {
			return typeRef{}, fmt.Errorf("graphql: expected ']' closing a list type")
		}
		tr = typeRef{kind: kindList, elem: &inner}
	} else {
		name, err := p.expectName()
		if err != nil {
			return typeRef{}, err
		}
		tr = typeRef{name: name}
	}
	if p.accept("punct", "!") {
		inner := tr
		tr = typeRef{kind: kindNonNull, elem: &inner}
	}
	return tr, nil
}

// parseFragmentDef parses `fragment Name on Type { … }`.
func (p *gparser) parseFragmentDef() (fragmentDef, error) {
	p.next() // fragment
	if p.peek().kind != "name" || p.peek().val == "on" {
		return fragmentDef{}, fmt.Errorf("graphql: expected a fragment name after `fragment`")
	}
	fd := fragmentDef{name: p.next().val}
	if !(p.peek().kind == "name" && p.peek().val == "on") {
		return fragmentDef{}, fmt.Errorf("graphql: expected `on Type` in fragment %q", fd.name)
	}
	p.next() // on
	if p.peek().kind != "name" {
		return fragmentDef{}, fmt.Errorf("graphql: expected a type condition in fragment %q", fd.name)
	}
	fd.typeCondition = p.next().val
	sels, err := p.parseSelectionSet()
	if err != nil {
		return fragmentDef{}, err
	}
	fd.selections = sels
	return fd, nil
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
		var (
			s   selection
			err error
		)
		if p.isPunct("...") {
			s, err = p.parseFragmentSelection()
		} else {
			s, err = p.parseField()
		}
		if err != nil {
			return nil, err
		}
		sels = append(sels, s)
	}
	p.next() // }
	return sels, nil
}

// parseFragmentSelection parses either a fragment spread (`...Name`) or an inline fragment
// (`... on Type { … }` or an untyped `... { … }`), having already peeked the `...`.
func (p *gparser) parseFragmentSelection() (selection, error) {
	p.next() // ...
	if p.peek().kind == "name" && p.peek().val == "on" {
		p.next() // on
		if p.peek().kind != "name" {
			return selection{}, fmt.Errorf("graphql: expected a type after `... on`")
		}
		cond := p.next().val
		sels, err := p.parseSelectionSet()
		if err != nil {
			return selection{}, err
		}
		return selection{inline: true, typeCondition: cond, selections: sels}, nil
	}
	if p.isPunct("{") { // untyped inline fragment: ... { … }
		sels, err := p.parseSelectionSet()
		if err != nil {
			return selection{}, err
		}
		return selection{inline: true, selections: sels}, nil
	}
	if p.peek().kind == "name" { // fragment spread: ...Name
		return selection{fragmentSpread: p.next().val}, nil
	}
	return selection{}, fmt.Errorf("graphql: expected a fragment name, `on`, or `{` after `...`")
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
		return valueNode{kind: "enum", val: t.val}, nil // a bare name is an enum value
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

// flattenSelections expands fragment spreads and inline fragments into a flat list of field selections,
// recursively (so nested selection sets come out fragment-free too — the executor and project() then
// never see a fragment). It detects unknown fragments and fragment cycles (a fragment that transitively
// spreads itself, which would otherwise recurse forever). When schema is non-nil, it also validates that
// each `on Type` condition names a real type. Field collection is unconditional with respect to the type
// condition: precise polymorphic dispatch (applying `on Type` only to matching runtime objects) waits on
// interface/union runtime typing — a later rung — and does not affect well-formed queries against a
// matching shape (including the introspection query).
func flattenSelections(sels []selection, frags map[string]fragmentDef, schema *Schema, open map[string]bool) ([]selection, error) {
	var out []selection
	for _, sel := range sels {
		switch {
		case sel.fragmentSpread != "":
			name := sel.fragmentSpread
			frag, ok := frags[name]
			if !ok {
				return nil, fmt.Errorf("graphql: unknown fragment %q", name)
			}
			if open[name] {
				return nil, fmt.Errorf("graphql: fragment cycle detected at %q", name)
			}
			if err := checkTypeCondition(schema, frag.typeCondition); err != nil {
				return nil, err
			}
			open[name] = true
			exp, err := flattenSelections(frag.selections, frags, schema, open)
			delete(open, name)
			if err != nil {
				return nil, err
			}
			out = append(out, exp...)
		case sel.inline:
			if err := checkTypeCondition(schema, sel.typeCondition); err != nil {
				return nil, err
			}
			exp, err := flattenSelections(sel.selections, frags, schema, open)
			if err != nil {
				return nil, err
			}
			out = append(out, exp...)
		default: // a field: flatten its own sub-selections
			f := sel
			sub, err := flattenSelections(sel.selections, frags, schema, open)
			if err != nil {
				return nil, err
			}
			f.selections = sub
			out = append(out, f)
		}
	}
	return out, nil
}

// checkTypeCondition errors if a fragment/inline type condition names a type absent from the schema. A
// nil schema or empty condition (untyped inline fragment) is a no-op.
func checkTypeCondition(schema *Schema, cond string) error {
	if schema == nil || cond == "" {
		return nil
	}
	if strings.HasPrefix(cond, "__") {
		// Introspection meta-types (__Type, __Schema, __InputValue, …) are implicitly part of every
		// schema per spec — the canonical wire introspection query's fragments are `on __Type` etc. — so
		// a condition on one is always valid even though we don't list them in the user type map.
		return nil
	}
	if _, ok := schema.types[cond]; !ok {
		return fmt.Errorf("graphql: fragment type condition %q is not a type in the schema", cond)
	}
	return nil
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
