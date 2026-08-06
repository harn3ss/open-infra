// Package vtl is a focused interpreter for AWS AppSync resolver mapping templates (Apache Velocity
// + AppSync's $util/$context). It is the heart of open-appsync (handoff §3.1, piece 2): on a field
// hit, the REQUEST template turns GraphQL args into a data-source operation, and the RESPONSE
// template turns the raw result into the GraphQL shape. Fidelity lives or dies in $util (see
// util.go). Scoped to the constructs real resolver templates use; widened as the probe corpus grows.
package vtl

import (
	"fmt"
	"strings"
)

// Engine renders VTL templates. Reuse one; it is stateless apart from its $util providers.
type Engine struct{ util *Util }

// New returns an Engine with real $util providers. For deterministic probes, set engine.Util fields.
func New() *Engine { return &Engine{util: NewUtil()} }

// Util exposes the $util providers so a probe can pin autoId()/time.* for byte-exact assertions.
func (e *Engine) Util() *Util { return e.util }

// Render evaluates a template against a resolver context (available as $ctx / $context). It returns
// the rendered string (usually a JSON document), or a *ThrowError if the template called
// $util.error(). ctx is typically {"args": {...}, "identity": {...}, "source": {...}, "result": ...}.
func (e *Engine) Render(tmpl string, ctx map[string]any) (string, error) {
	items, err := scanTemplate(tmpl)
	if err != nil {
		return "", err
	}
	nodes, _, err := buildBlock(items, 0, "")
	if err != nil {
		return "", err
	}
	env := &env{vars: map[string]any{"ctx": ctx, "context": ctx}, util: e.util}
	var b strings.Builder
	if err := renderNodes(nodes, env, &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

// --- flat scan ---

type item struct {
	kind string // "text" | "ref" | "dir"
	text string // text content, or raw ref text (for undefined-ref fallback)
	node exprNode
	// directive:
	name  string
	arg   string
	quiet bool
}

func scanTemplate(s string) ([]item, error) {
	var items []item
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			items = append(items, item{kind: "text", text: text.String()})
			text.Reset()
		}
	}
	i := 0
	for i < len(s) {
		c := s[i]
		// Comments: ## line, #* ... *# block.
		if c == '#' && i+1 < len(s) && s[i+1] == '#' {
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				i = len(s)
			} else {
				i += j // keep the newline as text
			}
			continue
		}
		if c == '#' && i+1 < len(s) && s[i+1] == '*' {
			end := strings.Index(s[i:], "*#")
			if end < 0 {
				i = len(s)
			} else {
				i += end + 2
			}
			continue
		}
		if c == '#' {
			if name, arg, next, ok := scanDirective(s, i); ok {
				flush()
				items = append(items, item{kind: "dir", name: name, arg: arg})
				i = next
				continue
			}
		}
		if c == '$' {
			if node, raw, quiet, next, ok := scanRef(s, i); ok {
				flush()
				items = append(items, item{kind: "ref", node: node, text: raw, quiet: quiet})
				i = next
				continue
			}
		}
		text.WriteByte(c)
		i++
	}
	flush()
	return items, nil
}

var directives = map[string]bool{"set": true, "if": true, "elseif": true, "else": true, "end": true, "foreach": true}

// scanDirective matches #name or #name(...). Returns the name, the raw content inside (...), and the
// next index. Unknown #words are not directives (treated as literal text).
func scanDirective(s string, i int) (name, arg string, next int, ok bool) {
	j := i + 1
	if j < len(s) && s[j] == '{' { // #{if}(...) formal form
		j++
	}
	start := j
	for j < len(s) && isIdentPart(s[j]) {
		j++
	}
	name = s[start:j]
	if !directives[name] {
		return "", "", 0, false
	}
	if j < len(s) && s[j] == '}' {
		j++
	}
	if j < len(s) && s[j] == '(' {
		content, end, bok := balanced(s, j, '(', ')')
		if !bok {
			return "", "", 0, false
		}
		return name, content, end, true
	}
	// #else / #end take no args.
	return name, "", j, true
}

// scanRef captures a reference beginning at '$' (optionally $!quiet and/or ${...} formal), parses
// it, and returns the AST + raw text + next index. Non-references (e.g. "$ ", "$5") return ok=false.
func scanRef(s string, i int) (node exprNode, raw string, quiet bool, next int, ok bool) {
	j := i + 1
	if j < len(s) && s[j] == '!' {
		quiet = true
		j++
	}
	if j < len(s) && s[j] == '{' { // ${...} / $!{...}
		inner, end, bok := balanced(s, j, '{', '}')
		if !bok {
			return nil, "", false, 0, false
		}
		n, perr := parseExpression("$" + inner)
		if perr != nil {
			return nil, "", false, 0, false
		}
		return n, s[i:end], quiet, end, true
	}
	if j >= len(s) || !isIdentStart(s[j]) {
		return nil, "", false, 0, false
	}
	// Bare $ident chain: root ident, then (.ident optional(...)) or [ ... ] repeatedly.
	k := j
	for k < len(s) && isIdentPart(s[k]) {
		k++
	}
	for k < len(s) {
		if s[k] == '.' && k+1 < len(s) && isIdentStart(s[k+1]) {
			k++
			for k < len(s) && isIdentPart(s[k]) {
				k++
			}
			if k < len(s) && s[k] == '(' {
				_, end, bok := balanced(s, k, '(', ')')
				if !bok {
					break
				}
				k = end
			}
		} else if s[k] == '[' {
			_, end, bok := balanced(s, k, '[', ']')
			if !bok {
				break
			}
			k = end
		} else {
			break
		}
	}
	refText := s[j:k]
	n, perr := parseExpression("$" + refText)
	if perr != nil {
		return nil, "", false, 0, false
	}
	return n, s[i:k], quiet, k, true
}

// balanced returns the content between an opening delimiter at s[open] and its matching close,
// respecting string literals. `next` is the index just past the close.
func balanced(s string, open int, oc, cc byte) (content string, next int, ok bool) {
	depth := 0
	i := open
	for i < len(s) {
		c := s[i]
		if c == '"' || c == '\'' {
			i++
			for i < len(s) && s[i] != c {
				if s[i] == '\\' {
					i++
				}
				i++
			}
			i++
			continue
		}
		if c == oc {
			depth++
		} else if c == cc {
			depth--
			if depth == 0 {
				return s[open+1 : i], i + 1, true
			}
		}
		i++
	}
	return "", 0, false
}

// --- block tree ---

type node interface{}

type textN struct{ s string }
type refN struct {
	node  exprNode
	raw   string
	quiet bool
}
type setN struct {
	name string
	expr exprNode
}
type ifBranch struct {
	cond exprNode // nil for #else
	body []node
}
type ifN struct{ branches []ifBranch }
type foreachN struct {
	varName string
	expr    exprNode
	body    []node
}

// buildBlock folds the flat items into a node tree until it hits a terminator directive (end/else/
// elseif) named in `stop`, returning the nodes, the index of the terminator, and any error.
func buildBlock(items []item, start int, _ string) ([]node, int, error) {
	var nodes []node
	i := start
	for i < len(items) {
		it := items[i]
		switch it.kind {
		case "text":
			nodes = append(nodes, textN{s: it.text})
			i++
		case "ref":
			nodes = append(nodes, refN{node: it.node, raw: it.text, quiet: it.quiet})
			i++
		case "dir":
			switch it.name {
			case "end", "else", "elseif":
				return nodes, i, nil // terminator: caller handles it
			case "set":
				name, expr, err := parseSet(it.arg)
				if err != nil {
					return nil, 0, err
				}
				nodes = append(nodes, setN{name: name, expr: expr})
				i++
			case "if":
				n, ni, err := buildIf(items, i)
				if err != nil {
					return nil, 0, err
				}
				nodes = append(nodes, n)
				i = ni
			case "foreach":
				n, ni, err := buildForeach(items, i)
				if err != nil {
					return nil, 0, err
				}
				nodes = append(nodes, n)
				i = ni
			default:
				i++
			}
		default:
			i++
		}
	}
	return nodes, i, nil
}

func buildIf(items []item, start int) (node, int, error) {
	var out ifN
	i := start
	for {
		it := items[i] // #if or #elseif
		var cond exprNode
		if it.name == "if" || it.name == "elseif" {
			c, err := parseExpression(it.arg)
			if err != nil {
				return nil, 0, err
			}
			cond = c
		}
		body, term, err := buildBlock(items, i+1, "")
		if err != nil {
			return nil, 0, err
		}
		out.branches = append(out.branches, ifBranch{cond: cond, body: body})
		if term >= len(items) {
			return nil, 0, fmt.Errorf("vtl: #if without #end")
		}
		switch items[term].name {
		case "end":
			return out, term + 1, nil
		case "elseif":
			i = term
		case "else":
			body, term2, err := buildBlock(items, term+1, "")
			if err != nil {
				return nil, 0, err
			}
			out.branches = append(out.branches, ifBranch{cond: nil, body: body})
			if term2 >= len(items) || items[term2].name != "end" {
				return nil, 0, fmt.Errorf("vtl: #else without #end")
			}
			return out, term2 + 1, nil
		}
	}
}

func buildForeach(items []item, start int) (node, int, error) {
	varName, listExprStr, err := parseForeach(items[start].arg)
	if err != nil {
		return nil, 0, err
	}
	expr, err := parseExpression(listExprStr)
	if err != nil {
		return nil, 0, err
	}
	body, term, err := buildBlock(items, start+1, "")
	if err != nil {
		return nil, 0, err
	}
	if term >= len(items) || items[term].name != "end" {
		return nil, 0, fmt.Errorf("vtl: #foreach without #end")
	}
	return foreachN{varName: varName, expr: expr, body: body}, term + 1, nil
}

// parseSet parses `$name = expr`.
func parseSet(arg string) (string, exprNode, error) {
	eq := strings.IndexByte(arg, '=')
	if eq < 0 {
		return "", nil, fmt.Errorf("vtl: malformed #set(%q)", arg)
	}
	lhs := strings.TrimSpace(arg[:eq])
	if !strings.HasPrefix(lhs, "$") {
		return "", nil, fmt.Errorf("vtl: #set target must be a $variable, got %q", lhs)
	}
	expr, err := parseExpression(strings.TrimSpace(arg[eq+1:]))
	if err != nil {
		return "", nil, err
	}
	return strings.TrimPrefix(lhs, "$"), expr, nil
}

// parseForeach parses `$var in expr`.
func parseForeach(arg string) (string, string, error) {
	// find " in " separating the loop var from the collection expression
	idx := strings.Index(arg, " in ")
	if idx < 0 {
		return "", "", fmt.Errorf("vtl: malformed #foreach(%q)", arg)
	}
	v := strings.TrimSpace(arg[:idx])
	if !strings.HasPrefix(v, "$") {
		return "", "", fmt.Errorf("vtl: #foreach var must be a $variable, got %q", v)
	}
	return strings.TrimPrefix(v, "$"), strings.TrimSpace(arg[idx+4:]), nil
}

// --- evaluate ---

func renderNodes(nodes []node, e *env, b *strings.Builder) error {
	for _, n := range nodes {
		switch x := n.(type) {
		case textN:
			b.WriteString(x.s)
		case refN:
			v, err := evalExpr(x.node, e)
			if err != nil {
				return err // includes *ThrowError from $util.error()
			}
			if v == nil && !x.quiet {
				b.WriteString(x.raw) // Velocity: undefined non-quiet ref renders as its literal text
			} else {
				b.WriteString(toStr(v))
			}
		case setN:
			v, err := evalExpr(x.expr, e)
			if err != nil {
				return err
			}
			e.vars[x.name] = v
		case ifN:
			for _, br := range x.branches {
				if br.cond == nil { // #else
					if err := renderNodes(br.body, e, b); err != nil {
						return err
					}
					break
				}
				c, err := evalExpr(br.cond, e)
				if err != nil {
					return err
				}
				if truthy(c) {
					if err := renderNodes(br.body, e, b); err != nil {
						return err
					}
					break
				}
			}
		case foreachN:
			v, err := evalExpr(x.expr, e)
			if err != nil {
				return err
			}
			list, _ := v.([]any)
			for _, el := range list {
				e.vars[x.varName] = el
				if err := renderNodes(x.body, e, b); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
