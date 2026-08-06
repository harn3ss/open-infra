package vtl

import (
	"fmt"
	"strconv"
	"strings"
)

// A small recursive-descent parser for VTL expressions (directive args + #set right-hand sides +
// references). Grammar, loosest → tightest:
//   or → and ('||' and)* ; and → eq ('&&' eq)* ; eq → cmp (('=='|'!=') cmp)* ;
//   cmp → add (('<'|'>'|'<='|'>=') add)* ; add → unary ('+' unary)* ; unary → '!' unary | postfix ;
//   postfix → primary ('.' ident ['(' args ')'] | '[' expr ']')* ;
//   primary → number | string | true|false|null | '$' ident postfix | '(' expr ')' | map | list

type token struct {
	kind string // num str ident op punct dollar kw eof
	val  string
	pos  int
}

type lexer struct {
	s    string
	i    int
	toks []token
	t    int // current token index
}

func lex(s string) (*lexer, error) {
	lx := &lexer{s: s}
	for lx.i < len(s) {
		c := s[lx.i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			lx.i++
		case c == '"' || c == '\'':
			str, err := lx.scanString(c)
			if err != nil {
				return nil, err
			}
			lx.emit("str", str)
		case c >= '0' && c <= '9':
			lx.scanNumber()
		case c == '$':
			lx.emit("dollar", "$")
			lx.i++
		case isIdentStart(c):
			lx.scanIdent()
		case strings.ContainsRune("().[]{},:", rune(c)):
			lx.emit("punct", string(c))
			lx.i++
		default:
			if op := lx.scanOp(); op != "" {
				lx.emit("op", op)
			} else {
				return nil, fmt.Errorf("vtl: unexpected char %q in expression %q", string(c), s)
			}
		}
	}
	lx.toks = append(lx.toks, token{kind: "eof", pos: lx.i})
	return lx, nil
}

func (lx *lexer) emit(kind, val string) {
	lx.toks = append(lx.toks, token{kind: kind, val: val, pos: lx.i})
}

func (lx *lexer) scanString(q byte) (string, error) {
	lx.i++ // opening quote
	var b strings.Builder
	for lx.i < len(lx.s) {
		c := lx.s[lx.i]
		if c == '\\' && lx.i+1 < len(lx.s) {
			b.WriteByte(lx.s[lx.i+1])
			lx.i += 2
			continue
		}
		if c == q {
			lx.i++
			return b.String(), nil
		}
		b.WriteByte(c)
		lx.i++
	}
	return "", fmt.Errorf("vtl: unterminated string in %q", lx.s)
}

func (lx *lexer) scanNumber() {
	start := lx.i
	for lx.i < len(lx.s) && (lx.s[lx.i] >= '0' && lx.s[lx.i] <= '9' || lx.s[lx.i] == '.') {
		lx.i++
	}
	lx.emit("num", lx.s[start:lx.i])
}

func (lx *lexer) scanIdent() {
	start := lx.i
	for lx.i < len(lx.s) && isIdentPart(lx.s[lx.i]) {
		lx.i++
	}
	word := lx.s[start:lx.i]
	if word == "true" || word == "false" || word == "null" || word == "in" {
		lx.emit("kw", word)
	} else {
		lx.emit("ident", word)
	}
}

func (lx *lexer) scanOp() string {
	two := ""
	if lx.i+1 < len(lx.s) {
		two = lx.s[lx.i : lx.i+2]
	}
	switch two {
	case "==", "!=", "<=", ">=", "&&", "||":
		lx.i += 2
		return two
	}
	one := lx.s[lx.i]
	if strings.ContainsRune("<>!+", rune(one)) {
		lx.i++
		return string(one)
	}
	return ""
}

func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}
func isIdentPart(c byte) bool { return isIdentStart(c) || c >= '0' && c <= '9' }

// --- parser ---

func (lx *lexer) peek() token { return lx.toks[lx.t] }
func (lx *lexer) next() token { t := lx.toks[lx.t]; lx.t++; return t }
func (lx *lexer) acceptOp(op string) bool {
	if lx.peek().kind == "op" && lx.peek().val == op {
		lx.t++
		return true
	}
	return false
}
func (lx *lexer) acceptPunct(p string) bool {
	if lx.peek().kind == "punct" && lx.peek().val == p {
		lx.t++
		return true
	}
	return false
}

// parseExpression parses a full VTL expression string into an AST.
func parseExpression(s string) (exprNode, error) {
	lx, err := lex(s)
	if err != nil {
		return nil, err
	}
	n, err := lx.parseOr()
	if err != nil {
		return nil, err
	}
	if lx.peek().kind != "eof" {
		return nil, fmt.Errorf("vtl: trailing tokens in expression %q", s)
	}
	return n, nil
}

func (lx *lexer) parseOr() (exprNode, error) {
	n, err := lx.parseAnd()
	if err != nil {
		return nil, err
	}
	for lx.acceptOp("||") {
		r, err := lx.parseAnd()
		if err != nil {
			return nil, err
		}
		n = binExpr{op: "||", l: n, r: r}
	}
	return n, nil
}

func (lx *lexer) parseAnd() (exprNode, error) {
	n, err := lx.parseEq()
	if err != nil {
		return nil, err
	}
	for lx.acceptOp("&&") {
		r, err := lx.parseEq()
		if err != nil {
			return nil, err
		}
		n = binExpr{op: "&&", l: n, r: r}
	}
	return n, nil
}

func (lx *lexer) parseEq() (exprNode, error) {
	n, err := lx.parseCmp()
	if err != nil {
		return nil, err
	}
	for lx.peek().kind == "op" && (lx.peek().val == "==" || lx.peek().val == "!=") {
		op := lx.next().val
		r, err := lx.parseCmp()
		if err != nil {
			return nil, err
		}
		n = binExpr{op: op, l: n, r: r}
	}
	return n, nil
}

func (lx *lexer) parseCmp() (exprNode, error) {
	n, err := lx.parseAdd()
	if err != nil {
		return nil, err
	}
	for lx.peek().kind == "op" && strings.Contains("< > <= >=", lx.peek().val) && lx.peek().val != "" {
		switch lx.peek().val {
		case "<", ">", "<=", ">=":
			op := lx.next().val
			r, err := lx.parseAdd()
			if err != nil {
				return nil, err
			}
			n = binExpr{op: op, l: n, r: r}
		default:
			return n, nil
		}
	}
	return n, nil
}

func (lx *lexer) parseAdd() (exprNode, error) {
	n, err := lx.parseUnary()
	if err != nil {
		return nil, err
	}
	for lx.acceptOp("+") {
		r, err := lx.parseUnary()
		if err != nil {
			return nil, err
		}
		n = binExpr{op: "+", l: n, r: r}
	}
	return n, nil
}

func (lx *lexer) parseUnary() (exprNode, error) {
	if lx.acceptOp("!") {
		x, err := lx.parseUnary()
		if err != nil {
			return nil, err
		}
		return unExpr{op: "!", x: x}, nil
	}
	return lx.parsePostfix()
}

func (lx *lexer) parsePostfix() (exprNode, error) {
	n, err := lx.parsePrimary()
	if err != nil {
		return nil, err
	}
	ref, isRef := n.(refExpr)
	if !isRef {
		return n, nil
	}
	for {
		if lx.acceptPunct(".") {
			if lx.peek().kind != "ident" {
				return nil, fmt.Errorf("vtl: expected identifier after '.'")
			}
			name := lx.next().val
			if lx.acceptPunct("(") {
				args, err := lx.parseArgs()
				if err != nil {
					return nil, err
				}
				ref.chain = append(ref.chain, accessor{kind: "method", name: name, args: args})
			} else {
				ref.chain = append(ref.chain, accessor{kind: "prop", name: name})
			}
		} else if lx.acceptPunct("[") {
			idx, err := lx.parseOr()
			if err != nil {
				return nil, err
			}
			if !lx.acceptPunct("]") {
				return nil, fmt.Errorf("vtl: expected ']'")
			}
			ref.chain = append(ref.chain, accessor{kind: "index", index: idx})
		} else {
			break
		}
	}
	return ref, nil
}

func (lx *lexer) parseArgs() ([]exprNode, error) {
	var args []exprNode
	if lx.acceptPunct(")") {
		return args, nil
	}
	for {
		a, err := lx.parseOr()
		if err != nil {
			return nil, err
		}
		args = append(args, a)
		if lx.acceptPunct(")") {
			return args, nil
		}
		if !lx.acceptPunct(",") {
			return nil, fmt.Errorf("vtl: expected ',' or ')' in args")
		}
	}
}

func (lx *lexer) parsePrimary() (exprNode, error) {
	t := lx.peek()
	switch t.kind {
	case "num":
		lx.next()
		f, _ := strconv.ParseFloat(t.val, 64)
		return litExpr{val: f}, nil
	case "str":
		lx.next()
		return litExpr{val: t.val}, nil
	case "kw":
		lx.next()
		switch t.val {
		case "true":
			return litExpr{val: true}, nil
		case "false":
			return litExpr{val: false}, nil
		case "null":
			return litExpr{val: nil}, nil
		}
		return nil, fmt.Errorf("vtl: unexpected keyword %q", t.val)
	case "dollar":
		lx.next()
		if lx.peek().kind != "ident" {
			return nil, fmt.Errorf("vtl: expected identifier after '$'")
		}
		return refExpr{root: lx.next().val}, nil
	case "punct":
		switch t.val {
		case "(":
			lx.next()
			n, err := lx.parseOr()
			if err != nil {
				return nil, err
			}
			if !lx.acceptPunct(")") {
				return nil, fmt.Errorf("vtl: expected ')'")
			}
			return n, nil
		case "{":
			return lx.parseMap()
		case "[":
			return lx.parseList()
		}
	}
	return nil, fmt.Errorf("vtl: unexpected token %q in expression", t.val)
}

func (lx *lexer) parseMap() (exprNode, error) {
	lx.next() // {
	m := mapExpr{}
	if lx.acceptPunct("}") {
		return m, nil
	}
	for {
		var key exprNode
		k := lx.peek()
		if k.kind == "str" || k.kind == "ident" {
			lx.next()
			key = litExpr{val: k.val}
		} else {
			var err error
			key, err = lx.parseOr()
			if err != nil {
				return nil, err
			}
		}
		if !lx.acceptPunct(":") {
			return nil, fmt.Errorf("vtl: expected ':' in map literal")
		}
		val, err := lx.parseOr()
		if err != nil {
			return nil, err
		}
		m.pairs = append(m.pairs, [2]exprNode{key, val})
		if lx.acceptPunct("}") {
			return m, nil
		}
		if !lx.acceptPunct(",") {
			return nil, fmt.Errorf("vtl: expected ',' or '}' in map literal")
		}
	}
}

func (lx *lexer) parseList() (exprNode, error) {
	lx.next() // [
	l := listExpr{}
	if lx.acceptPunct("]") {
		return l, nil
	}
	for {
		e, err := lx.parseOr()
		if err != nil {
			return nil, err
		}
		l.elems = append(l.elems, e)
		if lx.acceptPunct("]") {
			return l, nil
		}
		if !lx.acceptPunct(",") {
			return nil, fmt.Errorf("vtl: expected ',' or ']' in list literal")
		}
	}
}
