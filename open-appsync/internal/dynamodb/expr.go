// DynamoDB expression evaluation for UpdateItem and Query — the operations the capability
// characterization (evidence/appsync-dynamo-matrix.md) named as the gating gap over the slice-1
// Get/Put/Delete/Scan store.
//
// This is deliberately a FAITHFUL COMMON SUBSET, not a DynamoDB parity engine. It evaluates the
// expression forms real AppSync resolvers overwhelmingly use, and it FAILS LOUD on anything
// outside that subset — an unsupported update action, key-condition operator, or filter function
// returns an explicit error rather than a silently-wrong result. That fail-closed discipline is
// the whole point: a wrong item is worse than a refused one.
//
// Supported:
//   - UpdateItem update expressions: SET (assignment, +/- arithmetic on numbers,
//     if_not_exists(path, :v), list_append(a, b)); REMOVE; ADD (numeric add, string-set add).
//   - Query key-condition: `#pk = :pk` optionally AND a sort-key condition
//     (=, <, <=, >, >=, begins_with(#sk, :sk), #sk BETWEEN :a AND :b).
//   - Condition/filter booleans: comparisons (= <> < <= > >=), begins_with, contains,
//     attribute_exists, attribute_not_exists, combined with AND / OR / NOT and parentheses.
//
// Both MemStore and FerretStore call this same code on plain-value items, so a resolver behaves
// identically against either.
package dynamodb

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// exprBlock is one AppSync expression sub-object: the expression string plus its own name/value
// substitution maps. update/condition/query/filter each carry their own.
type exprBlock struct {
	expr   string
	names  map[string]string // "#x" -> real attribute name
	values map[string]any    // ":x" -> plain (un-marshalled) value
}

// readBlock pulls op[key] as an exprBlock (expressionValues un-marshalled from DynamoDB-typed to
// plain). present=false when the block is absent.
func readBlock(op map[string]any, key string) (exprBlock, bool, error) {
	raw, ok := op[key].(map[string]any)
	if !ok {
		return exprBlock{}, false, nil
	}
	expr, _ := raw["expression"].(string)
	if strings.TrimSpace(expr) == "" {
		return exprBlock{}, false, fmt.Errorf("dynamodb: %s block has no expression", key)
	}
	b := exprBlock{expr: expr, names: map[string]string{}, values: map[string]any{}}
	if names, ok := raw["expressionNames"].(map[string]any); ok {
		for k, v := range names {
			b.names[k] = fmt.Sprint(v)
		}
	}
	if vals, ok := raw["expressionValues"].(map[string]any); ok {
		for k, v := range vals {
			b.values[k] = fromDynamoDB(v)
		}
	}
	return b, true, nil
}

// attrName resolves a token to an attribute name: a "#alias" via expressionNames, else the token
// itself (a bare attribute path).
func (b exprBlock) attrName(tok string) (string, error) {
	if strings.HasPrefix(tok, "#") {
		n, ok := b.names[tok]
		if !ok {
			return "", fmt.Errorf("dynamodb: undefined expression name %q", tok)
		}
		return n, nil
	}
	return tok, nil
}

// value resolves a ":ref" via expressionValues, or a bare numeric literal.
func (b exprBlock) value(tok string) (any, error) {
	if strings.HasPrefix(tok, ":") {
		v, ok := b.values[tok]
		if !ok {
			return nil, fmt.Errorf("dynamodb: undefined expression value %q", tok)
		}
		return v, nil
	}
	if f, err := strconv.ParseFloat(tok, 64); err == nil {
		return f, nil
	}
	return nil, fmt.Errorf("dynamodb: expected a value reference (:x) or number, got %q", tok)
}

// tokenize splits an expression into tokens, treating operators and punctuation as their own
// tokens. It is intentionally simple — the supported grammar has no string literals (values come
// through expressionValues), so whitespace + operator splitting suffices.
func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			flush()
		case c == '(' || c == ')' || c == '+' || c == '-':
			flush()
			out = append(out, string(c))
		case c == '<' || c == '>' || c == '=':
			flush()
			// two-char operators: <=, >=, <>
			if c != '=' && i+1 < len(runes) && (runes[i+1] == '=' || runes[i+1] == '>') {
				out = append(out, string(c)+string(runes[i+1]))
				i++
			} else {
				out = append(out, string(c))
			}
		default:
			cur.WriteRune(c)
		}
	}
	flush()
	return out
}

// ---- UpdateItem ----

// updateItem evaluates an UpdateItem's optional condition against the current item and applies its
// update expression, re-asserting the key attributes. Shared by both stores so the semantics are
// identical. A failed condition returns an error (ConditionalCheckFailedException).
func updateItem(item, key map[string]any, op map[string]any) (map[string]any, error) {
	if cond, ok, err := readBlock(op, "condition"); err != nil {
		return nil, err
	} else if ok {
		pass, err := evalBool(item, cond)
		if err != nil {
			return nil, err
		}
		if !pass {
			return nil, fmt.Errorf("dynamodb: ConditionalCheckFailedException")
		}
	}
	upd, ok, err := readBlock(op, "update")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("dynamodb: UpdateItem requires an update expression")
	}
	newItem, err := applyUpdate(item, upd)
	if err != nil {
		return nil, err
	}
	for k, v := range key { // key attributes are always present on the item
		newItem[k] = v
	}
	return newItem, nil
}

// applyUpdate applies an UpdateItem update block to an item (plain values), in place-returning a
// new map. It parses the SET / REMOVE / ADD clauses; an unsupported action fails loud.
func applyUpdate(item map[string]any, b exprBlock) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range item {
		out[k] = v
	}
	// Split into clauses by keyword. DynamoDB allows SET/REMOVE/ADD/DELETE in one expression.
	clauses := splitClauses(b.expr)
	for kw, body := range clauses {
		switch kw {
		case "SET":
			if err := applySet(out, body, b); err != nil {
				return nil, err
			}
		case "REMOVE":
			for _, path := range strings.Fields(body) { // commas already dropped by the tokenizer
				name, err := b.attrName(path)
				if err != nil {
					return nil, err
				}
				delete(out, name)
			}
		case "ADD":
			if err := applyAdd(out, body, b); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("dynamodb: unsupported update action %q (supported: SET, REMOVE, ADD)", kw)
		}
	}
	return out, nil
}

// splitClauses breaks "SET a=:b REMOVE c ADD d :e" into {SET:"a=:b", REMOVE:"c", ADD:"d :e"}.
func splitClauses(expr string) map[string]string {
	toks := tokenize(expr)
	out := map[string]string{}
	cur := ""
	var buf []string
	flush := func() {
		if cur != "" {
			out[cur] = strings.Join(buf, " ")
		}
		buf = nil
	}
	for _, t := range toks {
		up := strings.ToUpper(t)
		if up == "SET" || up == "REMOVE" || up == "ADD" || up == "DELETE" {
			flush()
			cur = up
			continue
		}
		buf = append(buf, t)
	}
	flush()
	return out
}

// applySet handles "path = value [, path = value ...]". Values: operand, operand +/- operand,
// if_not_exists(path, operand), list_append(a, b).
func applySet(item map[string]any, body string, b exprBlock) error {
	for _, assign := range splitSetAssignments(body) {
		toks := tokenize(assign)
		eq := -1
		for i, t := range toks {
			if t == "=" {
				eq = i
				break
			}
		}
		if eq < 1 || eq == len(toks)-1 {
			return fmt.Errorf("dynamodb: malformed SET assignment %q", assign)
		}
		name, err := b.attrName(toks[0])
		if err != nil {
			return err
		}
		val, err := evalSetValue(item, strings.Join(toks[eq+1:], " "), b)
		if err != nil {
			return err
		}
		item[name] = val
	}
	return nil
}

// splitSetAssignments splits "a = :x b = :y" back into ["a = :x", "b = :y"]. Commas were dropped,
// so we detect the start of a new assignment as: a name token immediately followed by "=".
func splitSetAssignments(body string) []string {
	toks := tokenize(body)
	var out []string
	var cur []string
	depth := 0
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t == "(" {
			depth++
		}
		if t == ")" {
			depth--
		}
		// A new assignment begins when, at top level, the previous token completed a value and the
		// next tokens are `name =`.
		if depth == 0 && len(cur) > 0 && i+1 < len(toks) && toks[i+1] == "=" && !isOperator(t) {
			out = append(out, strings.Join(cur, " "))
			cur = nil
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		out = append(out, strings.Join(cur, " "))
	}
	return out
}

func isOperator(t string) bool {
	switch t {
	case "=", "<", ">", "<=", ">=", "<>", "+", "-", "(", ")":
		return true
	}
	return false
}

// evalSetValue evaluates a SET right-hand side.
func evalSetValue(item map[string]any, rhs string, b exprBlock) (any, error) {
	toks := tokenize(rhs)
	// if_not_exists(path, operand)
	if len(toks) > 0 && strings.EqualFold(toks[0], "if_not_exists") {
		args, err := fnArgs(toks)
		if err != nil || len(args) != 2 {
			return nil, fmt.Errorf("dynamodb: if_not_exists(path, value) expected")
		}
		name, err := b.attrName(args[0])
		if err != nil {
			return nil, err
		}
		if existing, ok := item[name]; ok {
			return existing, nil
		}
		return b.value(args[1])
	}
	// list_append(a, b)
	if len(toks) > 0 && strings.EqualFold(toks[0], "list_append") {
		args, err := fnArgs(toks)
		if err != nil || len(args) != 2 {
			return nil, fmt.Errorf("dynamodb: list_append(a, b) expected")
		}
		l1, err := b.operand(item, args[0])
		if err != nil {
			return nil, err
		}
		l2, err := b.operand(item, args[1])
		if err != nil {
			return nil, err
		}
		return append(toList(l1), toList(l2)...), nil
	}
	// operand [+|- operand]
	if len(toks) == 1 {
		return b.operand(item, toks[0])
	}
	if len(toks) == 3 && (toks[1] == "+" || toks[1] == "-") {
		l, err := b.operandNum(item, toks[0])
		if err != nil {
			return nil, err
		}
		r, err := b.operandNum(item, toks[2])
		if err != nil {
			return nil, err
		}
		if toks[1] == "+" {
			return l + r, nil
		}
		return l - r, nil
	}
	return nil, fmt.Errorf("dynamodb: unsupported SET value expression %q", rhs)
}

// operand resolves a token that is a value ref (:x), a numeric literal, or an attribute path (its
// current value in the item).
func (b exprBlock) operand(item map[string]any, tok string) (any, error) {
	if strings.HasPrefix(tok, ":") {
		return b.value(tok)
	}
	if f, err := strconv.ParseFloat(tok, 64); err == nil {
		return f, nil
	}
	name, err := b.attrName(tok)
	if err != nil {
		return nil, err
	}
	return item[name], nil
}

func (b exprBlock) operandNum(item map[string]any, tok string) (float64, error) {
	v, err := b.operand(item, tok)
	if err != nil {
		return 0, err
	}
	f, ok := toFloat(v)
	if !ok {
		return 0, fmt.Errorf("dynamodb: %q is not a number in arithmetic", tok)
	}
	return f, nil
}

// applyAdd handles "ADD path value [, path value ...]" — numeric add or string-set union.
func applyAdd(item map[string]any, body string, b exprBlock) error {
	toks := tokenize(body)
	for i := 0; i+1 < len(toks); i += 2 {
		name, err := b.attrName(toks[i])
		if err != nil {
			return err
		}
		val, err := b.value(toks[i+1])
		if err != nil {
			return err
		}
		cur, exists := item[name]
		if f, ok := toFloat(val); ok {
			base := 0.0
			if exists {
				bf, ok := toFloat(cur)
				if !ok {
					return fmt.Errorf("dynamodb: ADD to non-numeric attribute %q", name)
				}
				base = bf
			}
			item[name] = base + f
			continue
		}
		// string-set / list union
		item[name] = append(toList(cur), toList(val)...)
	}
	return nil
}

func fnArgs(toks []string) ([]string, error) {
	// toks: fn ( a b ) — return [a, b]
	if len(toks) < 4 || toks[1] != "(" || toks[len(toks)-1] != ")" {
		return nil, fmt.Errorf("dynamodb: malformed function call")
	}
	return toks[2 : len(toks)-1], nil
}

// ---- Query key-condition ----

// matchKeyCondition reports whether item satisfies the key-condition, and returns the sort-key
// attribute name used (for result ordering), if any.
func matchKeyCondition(item map[string]any, b exprBlock) (bool, string, error) {
	// Split on top-level AND into at most two conditions.
	parts := splitOnAnd(b.expr)
	sortKey := ""
	for _, p := range parts {
		ok, sk, err := evalKeyPart(item, strings.TrimSpace(p), b)
		if err != nil {
			return false, "", err
		}
		if sk != "" {
			sortKey = sk
		}
		if !ok {
			return false, sortKey, nil
		}
	}
	return true, sortKey, nil
}

// evalKeyPart evaluates one key-condition term. The partition term is `#pk = :pk`; a sort term may
// be =, <, <=, >, >=, begins_with(#sk, :sk), or #sk BETWEEN :a AND :b. Returns the attribute name
// when it is a comparison (candidate sort key).
func evalKeyPart(item map[string]any, part string, b exprBlock) (bool, string, error) {
	toks := tokenize(part)
	if len(toks) >= 4 && strings.EqualFold(toks[0], "begins_with") {
		args, err := fnArgs(toks)
		if err != nil || len(args) != 2 {
			return false, "", fmt.Errorf("dynamodb: begins_with(path, :v) expected")
		}
		name, err := b.attrName(args[0])
		if err != nil {
			return false, "", err
		}
		v, err := b.value(args[1])
		if err != nil {
			return false, "", err
		}
		return strings.HasPrefix(fmt.Sprint(item[name]), fmt.Sprint(v)), name, nil
	}
	// #sk BETWEEN :a AND :b
	for i, t := range toks {
		if strings.EqualFold(t, "BETWEEN") && i >= 1 && i+3 < len(toks) {
			name, err := b.attrName(toks[0])
			if err != nil {
				return false, "", err
			}
			lo, err := b.value(toks[i+1])
			if err != nil {
				return false, "", err
			}
			hi, err := b.value(toks[i+3])
			if err != nil {
				return false, "", err
			}
			cv := item[name]
			return cmpVals(cv, lo) >= 0 && cmpVals(cv, hi) <= 0, name, nil
		}
	}
	// name OP value
	if len(toks) == 3 {
		name, err := b.attrName(toks[0])
		if err != nil {
			return false, "", err
		}
		v, err := b.value(toks[2])
		if err != nil {
			return false, "", err
		}
		ok, err := compare(item[name], toks[1], v)
		return ok, name, err
	}
	return false, "", fmt.Errorf("dynamodb: unsupported key-condition term %q", part)
}

func splitOnAnd(expr string) []string {
	toks := tokenize(expr)
	var parts []string
	var buf []string
	depth := 0
	between := false
	for _, t := range toks {
		if t == "(" {
			depth++
		}
		if t == ")" {
			depth--
		}
		if strings.EqualFold(t, "BETWEEN") {
			between = true
		}
		if depth == 0 && strings.EqualFold(t, "AND") {
			if between { // this AND belongs to "x BETWEEN lo AND hi", not a separator
				between = false
				buf = append(buf, t)
				continue
			}
			parts = append(parts, strings.Join(buf, " "))
			buf = nil
			continue
		}
		buf = append(buf, t)
	}
	if len(buf) > 0 {
		parts = append(parts, strings.Join(buf, " "))
	}
	return parts
}

// ---- boolean condition / filter ----

// evalBool evaluates a condition/filter boolean expression against an item.
func evalBool(item map[string]any, b exprBlock) (bool, error) {
	p := &boolParser{toks: tokenize(b.expr), item: item, b: b}
	v, err := p.parseOr()
	if err != nil {
		return false, err
	}
	if p.pos != len(p.toks) {
		return false, fmt.Errorf("dynamodb: trailing tokens in condition %q", b.expr)
	}
	return v, nil
}

type boolParser struct {
	toks []string
	pos  int
	item map[string]any
	b    exprBlock
}

func (p *boolParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}
func (p *boolParser) next() string { t := p.peek(); p.pos++; return t }

func (p *boolParser) parseOr() (bool, error) {
	v, err := p.parseAnd()
	if err != nil {
		return false, err
	}
	for strings.EqualFold(p.peek(), "OR") {
		p.next()
		r, err := p.parseAnd()
		if err != nil {
			return false, err
		}
		v = v || r
	}
	return v, nil
}

func (p *boolParser) parseAnd() (bool, error) {
	v, err := p.parseUnary()
	if err != nil {
		return false, err
	}
	for strings.EqualFold(p.peek(), "AND") {
		p.next()
		r, err := p.parseUnary()
		if err != nil {
			return false, err
		}
		v = v && r
	}
	return v, nil
}

func (p *boolParser) parseUnary() (bool, error) {
	if strings.EqualFold(p.peek(), "NOT") {
		p.next()
		v, err := p.parseUnary()
		return !v, err
	}
	if p.peek() == "(" {
		p.next()
		v, err := p.parseOr()
		if err != nil {
			return false, err
		}
		if p.next() != ")" {
			return false, fmt.Errorf("dynamodb: expected )")
		}
		return v, nil
	}
	return p.parsePredicate()
}

func (p *boolParser) parsePredicate() (bool, error) {
	tok := p.peek()
	// functions
	switch strings.ToLower(tok) {
	case "attribute_exists", "attribute_not_exists", "begins_with", "contains":
		fn := strings.ToLower(p.next())
		if p.next() != "(" {
			return false, fmt.Errorf("dynamodb: expected ( after %s", fn)
		}
		var args []string
		for p.peek() != ")" && p.peek() != "" {
			args = append(args, p.next())
		}
		if p.next() != ")" {
			return false, fmt.Errorf("dynamodb: expected ) closing %s", fn)
		}
		return p.evalFunc(fn, args)
	}
	// path OP value
	name, err := p.b.attrName(p.next())
	if err != nil {
		return false, err
	}
	op := p.next()
	valTok := p.next()
	v, err := p.b.value(valTok)
	if err != nil {
		return false, err
	}
	return compare(p.item[name], op, v)
}

func (p *boolParser) evalFunc(fn string, args []string) (bool, error) {
	switch fn {
	case "attribute_exists":
		name, err := p.b.attrName(args[0])
		if err != nil {
			return false, err
		}
		_, ok := p.item[name]
		return ok, nil
	case "attribute_not_exists":
		name, err := p.b.attrName(args[0])
		if err != nil {
			return false, err
		}
		_, ok := p.item[name]
		return !ok, nil
	case "begins_with":
		name, err := p.b.attrName(args[0])
		if err != nil {
			return false, err
		}
		v, err := p.b.value(args[1])
		if err != nil {
			return false, err
		}
		return strings.HasPrefix(fmt.Sprint(p.item[name]), fmt.Sprint(v)), nil
	case "contains":
		name, err := p.b.attrName(args[0])
		if err != nil {
			return false, err
		}
		v, err := p.b.value(args[1])
		if err != nil {
			return false, err
		}
		return containsVal(p.item[name], v), nil
	}
	return false, fmt.Errorf("dynamodb: unsupported function %q", fn)
}

// ---- comparison helpers ----

func compare(a any, op string, b any) (bool, error) {
	switch op {
	case "=":
		return equalVals(a, b), nil
	case "<>":
		return !equalVals(a, b), nil
	case "<":
		return cmpVals(a, b) < 0, nil
	case "<=":
		return cmpVals(a, b) <= 0, nil
	case ">":
		return cmpVals(a, b) > 0, nil
	case ">=":
		return cmpVals(a, b) >= 0, nil
	}
	return false, fmt.Errorf("dynamodb: unsupported comparison operator %q", op)
}

func equalVals(a, b any) bool {
	if af, ok := toFloat(a); ok {
		if bf, ok := toFloat(b); ok {
			return af == bf
		}
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

// cmpVals returns -1/0/1, comparing numbers numerically and everything else lexically.
func cmpVals(a, b any) int {
	if af, ok := toFloat(a); ok {
		if bf, ok := toFloat(b); ok {
			switch {
			case af < bf:
				return -1
			case af > bf:
				return 1
			default:
				return 0
			}
		}
	}
	return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func toList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	if v == nil {
		return nil
	}
	return []any{v}
}

func containsVal(container, v any) bool {
	if s, ok := container.(string); ok {
		return strings.Contains(s, fmt.Sprint(v))
	}
	for _, e := range toList(container) {
		if equalVals(e, v) {
			return true
		}
	}
	return false
}

// ---- Query assembly (shared by both stores) ----

// runQuery filters candidate items by the key-condition (+ optional filter), sorts by the sort key
// honoring scanIndexForward, and paginates by limit/nextToken. Candidates are all items in the
// table; both stores supply them as plain maps, so the result is identical across stores.
func runQuery(candidates []map[string]any, op map[string]any) (map[string]any, error) {
	kc, ok, err := readBlock(op, "query")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("dynamodb: Query requires a query key-condition")
	}
	var filter exprBlock
	hasFilter := false
	if fb, ok, err := readBlock(op, "filter"); err != nil {
		return nil, err
	} else if ok {
		filter, hasFilter = fb, true
	}

	var matched []map[string]any
	sortKey := ""
	scanned := 0
	for _, it := range candidates {
		scanned++
		ok, sk, err := matchKeyCondition(it, kc)
		if err != nil {
			return nil, err
		}
		if sk != "" {
			sortKey = sk
		}
		if !ok {
			continue
		}
		if hasFilter {
			fok, err := evalBool(it, filter)
			if err != nil {
				return nil, err
			}
			if !fok {
				continue
			}
		}
		matched = append(matched, it)
	}

	// Sort by the sort key (DynamoDB orders Query results by sort key). Default ascending.
	forward := true
	if v, ok := op["scanIndexForward"].(bool); ok {
		forward = v
	}
	if sortKey != "" {
		sort.SliceStable(matched, func(i, j int) bool {
			c := cmpVals(matched[i][sortKey], matched[j][sortKey])
			if forward {
				return c < 0
			}
			return c > 0
		})
	}

	// Pagination: nextToken encodes the offset into the matched set.
	start := decodeToken(op["nextToken"])
	if start < 0 || start > len(matched) {
		start = 0
	}
	end := len(matched)
	limit := 0
	if l, ok := toFloat(op["limit"]); ok {
		limit = int(l)
	}
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	page := matched[start:end]

	items := make([]any, len(page))
	for i, it := range page {
		items[i] = it
	}
	res := map[string]any{"items": items, "scannedCount": float64(scanned), "count": float64(len(page))}
	if end < len(matched) {
		res["nextToken"] = encodeToken(end)
	}
	return res, nil
}

func decodeToken(v any) int {
	s, ok := v.(string)
	if !ok || s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func encodeToken(offset int) string { return strconv.Itoa(offset) }
