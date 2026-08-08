package graphql

// This file is the in-memory schema TYPE SYSTEM and the introspection reader over it.
//
// The engine's execution half (execute.go) keys resolvers by "<RootType>.<field>" strings and never
// needed the schema's types in memory. Introspection does: a GraphQL client (graphql-codegen, Apollo,
// GraphiQL) discovers the API by querying __schema / __type, and the ONE shape it expects is the
// GraphQL spec's introspection schema. So we parse the API's SDL into a name→type map where a field's
// return type is a *reference* into that same map carrying its wrappers (Post, Post!, [Post], [Post!]!
// are four different types), and then answer __schema / __type by reading that map back out in the
// mandated shape — no creativity, one right answer to match.
//
// Scope tonight is the type graph + introspection ONLY. Nested __typename, fragments, directives
// (@skip/@include execution), variable coercion, and custom-scalar validation all lean on this graph
// but each graduates on its own evidence; none is promoted by proximity.

import (
	"fmt"
	"sort"
)

// __TypeKind enum values (GraphQL spec §3.4.1).
const (
	kindScalar      = "SCALAR"
	kindObject      = "OBJECT"
	kindInterface   = "INTERFACE"
	kindUnion       = "UNION"
	kindEnum        = "ENUM"
	kindInputObject = "INPUT_OBJECT"
	kindList        = "LIST"
	kindNonNull     = "NON_NULL"
)

// typeRef is a possibly-wrapped reference to a named type — the load-bearing detail. A field's return
// type is NOT a string: `Post`, `Post!`, `[Post]`, `[Post!]!` are four distinct types, and introspection
// must report the wrappers exactly (and the executor will later need them to know if a null is legal).
// Exactly one shape is set: a plain named ref (kind==""), or a LIST/NON_NULL wrapper around an elem.
type typeRef struct {
	kind string   // "" (named), kindList, or kindNonNull
	name string   // set when kind == ""
	elem *typeRef // set when kind == kindList or kindNonNull
}

type fieldDef struct {
	name               string
	description        string
	args               []inputValueDef
	typ                typeRef
	deprecated         bool
	deprecationReason  string
	subscribeMutations []string // @aws_subscribe(mutations:) — set on Subscription-type fields
}

type inputValueDef struct {
	name         string
	description  string
	typ          typeRef
	defaultValue string    // GraphQL literal as a string (for introspection), e.g. `LOW`, `"x"`; "" if none
	defaultVal   valueNode // the parsed default (for input coercion)
	hasDefault   bool
}

type enumValueDef struct {
	name              string
	description       string
	deprecated        bool
	deprecationReason string
}

// namedType is one entry in the type map: every `type`/`scalar`/`enum`/`input`/`interface`/`union` in
// the SDL becomes one of these. The graph is these plus the typeRefs that point between them.
type namedType struct {
	kind          string // SCALAR | OBJECT | INTERFACE | UNION | ENUM | INPUT_OBJECT
	name          string
	description   string
	fields        []fieldDef      // OBJECT, INTERFACE
	inputFields   []inputValueDef // INPUT_OBJECT
	enumValues    []enumValueDef  // ENUM
	interfaces    []string        // OBJECT: implemented interface names
	possibleTypes []string        // UNION members / INTERFACE implementors
}

// Schema is the parsed type system: the name→type map plus the three root operation type names. It also
// memoizes the introspection __Type objects so repeated introspection queries reuse one graph.
type Schema struct {
	types            map[string]*namedType
	queryType        string
	mutationType     string
	subscriptionType string

	typeObjs  map[string]map[string]any // memoized __Type per name (shared pointers = cycle-safe graph)
	schemaObj map[string]any            // memoized __schema
}

// builtinScalars are always present even if the SDL never declares them (GraphQL spec §3.5.7). Custom
// AppSync scalars (AWSDateTime, AWSJSON, …) are only present when the SDL declares them.
var builtinScalars = []string{"Int", "Float", "String", "Boolean", "ID"}

// ParseSchema parses GraphQL SDL into a Schema. It fails loud on malformed SDL (the engine refuses to
// serve a half-parsed type graph). An empty/whitespace SDL yields a schema with only the built-in
// scalars and no root types — introspection then reports an (almost) empty API rather than crashing.
func ParseSchema(sdl string) (*Schema, error) {
	toks, err := tokenize(sdl)
	if err != nil {
		return nil, fmt.Errorf("graphql: tokenize SDL: %w", err)
	}
	p := &sdlParser{gparser: gparser{toks: toks}}
	s := &Schema{types: map[string]*namedType{}}

	// Built-in scalars first, so an SDL that redeclares one (harmless) just overwrites with the same.
	for _, name := range builtinScalars {
		s.types[name] = &namedType{kind: kindScalar, name: name}
	}

	var schemaBlock map[string]string // set if an explicit `schema { query: … }` appears
	for p.peek().kind != "eof" {
		desc := p.maybeDescription()
		kw := p.peek()
		if kw.kind != "name" {
			return nil, fmt.Errorf("graphql: SDL: expected a definition, got %q", kw.val)
		}
		switch kw.val {
		case "schema":
			blk, err := p.parseSchemaBlock()
			if err != nil {
				return nil, err
			}
			schemaBlock = blk
		case "type", "interface":
			nt, err := p.parseObjectLike(desc, kw.val)
			if err != nil {
				return nil, err
			}
			s.types[nt.name] = nt
		case "input":
			nt, err := p.parseInput(desc)
			if err != nil {
				return nil, err
			}
			s.types[nt.name] = nt
		case "enum":
			nt, err := p.parseEnum(desc)
			if err != nil {
				return nil, err
			}
			s.types[nt.name] = nt
		case "union":
			nt, err := p.parseUnion(desc)
			if err != nil {
				return nil, err
			}
			s.types[nt.name] = nt
		case "scalar":
			p.next() // scalar
			name, err := p.expectName()
			if err != nil {
				return nil, err
			}
			p.parseDirectives()
			s.types[name] = &namedType{kind: kindScalar, name: name, description: desc}
		case "directive":
			// A `directive @x on …` definition: parsed-and-skipped tonight (we report the standard
			// directives from introspection; honoring custom ones is a later rung).
			if err := p.skipDirectiveDefinition(); err != nil {
				return nil, err
			}
		case "extend":
			return nil, fmt.Errorf("graphql: SDL: `extend` is not supported yet")
		default:
			return nil, fmt.Errorf("graphql: SDL: unknown definition keyword %q", kw.val)
		}
	}

	// Resolve root operation types: an explicit `schema {}` block wins; otherwise the spec default names.
	s.queryType = rootName(schemaBlock, "query", "Query", s.types)
	s.mutationType = rootName(schemaBlock, "mutation", "Mutation", s.types)
	s.subscriptionType = rootName(schemaBlock, "subscription", "Subscription", s.types)

	// Derive interface possibleTypes (implementors) so introspection can report them.
	for _, nt := range s.types {
		if nt.kind != kindObject {
			continue
		}
		for _, iface := range nt.interfaces {
			if it := s.types[iface]; it != nil {
				it.possibleTypes = append(it.possibleTypes, nt.name)
			}
		}
	}

	s.buildIntrospection()
	return s, nil
}

// rootName picks a root operation type: the explicit schema-block mapping if present, else the
// conventional default name when a type by that name exists, else "" (no such root operation).
func rootName(block map[string]string, op, def string, types map[string]*namedType) string {
	if block != nil {
		return block[op] // explicit (may be "")
	}
	if _, ok := types[def]; ok {
		return def
	}
	return ""
}

// --- SDL parser (rides the shared lexer/gparser from parse.go) ---

type sdlParser struct{ gparser }

// expectName and parseTypeRef are inherited from the embedded gparser (shared with the operation parser).

// maybeDescription consumes a leading string token used as a description, returning "" if none.
func (p *sdlParser) maybeDescription() string {
	if p.peek().kind == "str" {
		return p.next().val
	}
	return ""
}

func (p *sdlParser) parseSchemaBlock() (map[string]string, error) {
	p.next() // schema
	p.parseDirectives()
	if !p.accept("punct", "{") {
		return nil, fmt.Errorf("graphql: SDL: expected '{' after `schema`")
	}
	block := map[string]string{}
	for !p.isPunct("}") {
		if p.peek().kind == "eof" {
			return nil, fmt.Errorf("graphql: SDL: unterminated schema block")
		}
		op, err := p.expectName()
		if err != nil {
			return nil, err
		}
		if !p.accept("punct", ":") {
			return nil, fmt.Errorf("graphql: SDL: expected ':' in schema block")
		}
		t, err := p.expectName()
		if err != nil {
			return nil, err
		}
		block[op] = t
	}
	p.next() // }
	return block, nil
}

// parseObjectLike parses `type`/`interface Name implements A & B { fields }`.
func (p *sdlParser) parseObjectLike(desc, keyword string) (*namedType, error) {
	p.next() // type | interface
	name, err := p.expectName()
	if err != nil {
		return nil, err
	}
	nt := &namedType{name: name, description: desc, kind: kindObject}
	if keyword == "interface" {
		nt.kind = kindInterface
	}
	if p.peek().kind == "name" && p.peek().val == "implements" {
		p.next()
		p.accept("punct", "&") // an optional leading & is legal
		for {
			iface, err := p.expectName()
			if err != nil {
				return nil, err
			}
			nt.interfaces = append(nt.interfaces, iface)
			if !p.accept("punct", "&") {
				break
			}
		}
	}
	p.parseDirectives()
	if !p.accept("punct", "{") {
		return nil, fmt.Errorf("graphql: SDL: expected '{' in %s %s", keyword, name)
	}
	for !p.isPunct("}") {
		if p.peek().kind == "eof" {
			return nil, fmt.Errorf("graphql: SDL: unterminated %s %s", keyword, name)
		}
		f, err := p.parseFieldDef()
		if err != nil {
			return nil, err
		}
		nt.fields = append(nt.fields, f)
	}
	p.next() // }
	return nt, nil
}

func (p *sdlParser) parseFieldDef() (fieldDef, error) {
	desc := p.maybeDescription()
	name, err := p.expectName()
	if err != nil {
		return fieldDef{}, err
	}
	f := fieldDef{name: name, description: desc}
	if p.isPunct("(") {
		args, err := p.parseArgDefs()
		if err != nil {
			return fieldDef{}, err
		}
		f.args = args
	}
	if !p.accept("punct", ":") {
		return fieldDef{}, fmt.Errorf("graphql: SDL: expected ':' after field %q", name)
	}
	tr, err := p.parseTypeRef()
	if err != nil {
		return fieldDef{}, err
	}
	f.typ = tr
	di := p.parseDirectives()
	f.deprecated, f.deprecationReason, f.subscribeMutations = di.deprecated, di.reason, di.subscribeMutations
	return f, nil
}

func (p *sdlParser) parseArgDefs() ([]inputValueDef, error) {
	p.next() // (
	var args []inputValueDef
	for !p.isPunct(")") {
		if p.peek().kind == "eof" {
			return nil, fmt.Errorf("graphql: SDL: unterminated argument list")
		}
		iv, err := p.parseInputValueDef()
		if err != nil {
			return nil, err
		}
		args = append(args, iv)
	}
	p.next() // )
	return args, nil
}

func (p *sdlParser) parseInputValueDef() (inputValueDef, error) {
	desc := p.maybeDescription()
	name, err := p.expectName()
	if err != nil {
		return inputValueDef{}, err
	}
	if !p.accept("punct", ":") {
		return inputValueDef{}, fmt.Errorf("graphql: SDL: expected ':' after %q", name)
	}
	tr, err := p.parseTypeRef()
	if err != nil {
		return inputValueDef{}, err
	}
	iv := inputValueDef{name: name, description: desc, typ: tr}
	if p.accept("punct", "=") {
		dv, err := p.parseValue()
		if err != nil {
			return inputValueDef{}, err
		}
		iv.defaultVal = dv
		iv.hasDefault = true
		iv.defaultValue = literalString(dv) // canonical literal for introspection
	}
	p.parseDirectives()
	return iv, nil
}

func (p *sdlParser) parseInput(desc string) (*namedType, error) {
	p.next() // input
	name, err := p.expectName()
	if err != nil {
		return nil, err
	}
	nt := &namedType{name: name, description: desc, kind: kindInputObject}
	p.parseDirectives()
	if !p.accept("punct", "{") {
		return nil, fmt.Errorf("graphql: SDL: expected '{' in input %s", name)
	}
	for !p.isPunct("}") {
		if p.peek().kind == "eof" {
			return nil, fmt.Errorf("graphql: SDL: unterminated input %s", name)
		}
		iv, err := p.parseInputValueDef()
		if err != nil {
			return nil, err
		}
		nt.inputFields = append(nt.inputFields, iv)
	}
	p.next() // }
	return nt, nil
}

func (p *sdlParser) parseEnum(desc string) (*namedType, error) {
	p.next() // enum
	name, err := p.expectName()
	if err != nil {
		return nil, err
	}
	nt := &namedType{name: name, description: desc, kind: kindEnum}
	p.parseDirectives()
	if !p.accept("punct", "{") {
		return nil, fmt.Errorf("graphql: SDL: expected '{' in enum %s", name)
	}
	for !p.isPunct("}") {
		if p.peek().kind == "eof" {
			return nil, fmt.Errorf("graphql: SDL: unterminated enum %s", name)
		}
		vdesc := p.maybeDescription()
		v, err := p.expectName()
		if err != nil {
			return nil, err
		}
		di := p.parseDirectives()
		nt.enumValues = append(nt.enumValues, enumValueDef{name: v, description: vdesc, deprecated: di.deprecated, deprecationReason: di.reason})
	}
	p.next() // }
	return nt, nil
}

func (p *sdlParser) parseUnion(desc string) (*namedType, error) {
	p.next() // union
	name, err := p.expectName()
	if err != nil {
		return nil, err
	}
	nt := &namedType{name: name, description: desc, kind: kindUnion}
	p.parseDirectives()
	if p.accept("punct", "=") {
		p.accept("punct", "|") // an optional leading | is legal
		for {
			member, err := p.expectName()
			if err != nil {
				return nil, err
			}
			nt.possibleTypes = append(nt.possibleTypes, member)
			if !p.accept("punct", "|") {
				break
			}
		}
	}
	return nt, nil
}

// directiveInfo is what the SDL parser extracts from a definition's directives.
type directiveInfo struct {
	deprecated         bool
	reason             string
	subscribeMutations []string // @aws_subscribe(mutations: [...]) on a Subscription field
}

// parseDirectives consumes zero or more `@name(args)` directives applied to a definition. It captures the
// two directives the engine acts on — @deprecated(reason:) (reported by introspection) and
// @aws_subscribe(mutations:) (AppSync's SDL-native subscription trigger declaration) — and skips the
// rest (e.g. AppSync's @aws_* auth directives, which are a separate rung).
func (p *sdlParser) parseDirectives() directiveInfo {
	var info directiveInfo
	for p.isPunct("@") {
		p.next() // @
		name := ""
		if p.peek().kind == "name" {
			name = p.next().val
		}
		args := map[string]valueNode{}
		if p.isPunct("(") {
			p.next()
			for !p.isPunct(")") && p.peek().kind != "eof" {
				an := ""
				if p.peek().kind == "name" {
					an = p.next().val
				}
				p.accept("punct", ":")
				v, err := p.parseValue()
				if err != nil {
					break
				}
				args[an] = v
			}
			p.accept("punct", ")")
		}
		switch name {
		case "deprecated":
			info.deprecated = true
			info.reason = "No longer supported" // the spec default
			if r, ok := args["reason"]; ok {
				if s, ok := r.val.(string); ok {
					info.reason = s
				}
			}
		case "aws_subscribe":
			if m, ok := args["mutations"]; ok && m.kind == "list" {
				for _, e := range m.val.([]valueNode) {
					if s, ok := e.val.(string); ok {
						info.subscribeMutations = append(info.subscribeMutations, s)
					}
				}
			}
		}
	}
	return info
}

// skipDirectiveDefinition consumes a top-level `directive @name(args) [repeatable] on LOC | LOC`.
func (p *sdlParser) skipDirectiveDefinition() error {
	p.next() // directive
	if !p.accept("punct", "@") {
		return fmt.Errorf("graphql: SDL: expected '@' in directive definition")
	}
	if _, err := p.expectName(); err != nil {
		return err
	}
	if p.isPunct("(") {
		if err := p.skipBalanced("(", ")"); err != nil {
			return err
		}
	}
	if p.peek().kind == "name" && p.peek().val == "repeatable" {
		p.next()
	}
	if p.peek().kind == "name" && p.peek().val == "on" {
		p.next()
		p.accept("punct", "|")
		for {
			if _, err := p.expectName(); err != nil {
				return err
			}
			if !p.accept("punct", "|") {
				break
			}
		}
	}
	return nil
}

// --- small helpers ---

func join(parts []string, sep string) string {
	out := ""
	for i, s := range parts {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}

// SubscriptionTriggers maps each mutation field to the subscription fields it triggers, derived from
// @aws_subscribe(mutations: [...]) on the Subscription root type's fields — the SDL-native equivalent of
// a subscription's config `triggeredBy`. Empty when the schema declares none.
func (s *Schema) SubscriptionTriggers() map[string][]string {
	out := map[string][]string{}
	if s.subscriptionType == "" {
		return out
	}
	sub := s.types[s.subscriptionType]
	if sub == nil {
		return out
	}
	for _, f := range sub.fields {
		for _, mut := range f.subscribeMutations {
			out[mut] = append(out[mut], f.name)
		}
	}
	return out
}

// sortedTypeNames returns the type map's names in a stable order (deterministic introspection output).
func (s *Schema) sortedTypeNames() []string {
	names := make([]string, 0, len(s.types))
	for n := range s.types {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
