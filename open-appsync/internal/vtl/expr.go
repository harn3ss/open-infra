package vtl

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// The VTL expression engine: tokenizes + parses + evaluates the expressions that appear inside
// references ($ctx.args.id, $util.dynamodb.toDynamoDBJson($x)), #set right-hand sides, and #if
// conditions. Scoped to the constructs real AppSync resolver templates use (property/index access,
// $util method calls, collection/string methods, the boolean/comparison operators, and map/list
// literals) — widened as the probe corpus grows.

// env is an evaluation scope: #set/#foreach variables + the $util namespace.
type env struct {
	vars map[string]any
	util *Util
}

// --- expression AST ---

type exprNode interface{}

type litExpr struct{ val any }
type refExpr struct {
	root  string     // variable name after '$'
	chain []accessor // .prop / .method(args) / [index]
}
type accessor struct {
	kind  string // "prop" | "method" | "index"
	name  string
	args  []exprNode
	index exprNode
}
type binExpr struct {
	op   string
	l, r exprNode
}
type unExpr struct {
	op string
	x  exprNode
}
type mapExpr struct{ pairs [][2]exprNode }
type listExpr struct{ elems []exprNode }

// evalExpr evaluates a parsed expression against the environment.
func evalExpr(n exprNode, e *env) (any, error) {
	switch x := n.(type) {
	case litExpr:
		return x.val, nil
	case listExpr:
		out := make([]any, 0, len(x.elems))
		for _, el := range x.elems {
			v, err := evalExpr(el, e)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case mapExpr:
		out := map[string]any{}
		for _, p := range x.pairs {
			k, err := evalExpr(p[0], e)
			if err != nil {
				return nil, err
			}
			v, err := evalExpr(p[1], e)
			if err != nil {
				return nil, err
			}
			out[toStr(k)] = v
		}
		return out, nil
	case unExpr:
		v, err := evalExpr(x.x, e)
		if err != nil {
			return nil, err
		}
		if x.op == "!" {
			return !truthy(v), nil
		}
		return nil, fmt.Errorf("vtl: unknown unary op %q", x.op)
	case binExpr:
		return evalBin(x, e)
	case refExpr:
		return evalRef(x, e)
	}
	return nil, fmt.Errorf("vtl: cannot evaluate %T", n)
}

func evalBin(x binExpr, e *env) (any, error) {
	// Short-circuit boolean operators.
	if x.op == "&&" || x.op == "||" {
		l, err := evalExpr(x.l, e)
		if err != nil {
			return nil, err
		}
		if x.op == "&&" && !truthy(l) {
			return false, nil
		}
		if x.op == "||" && truthy(l) {
			return true, nil
		}
		r, err := evalExpr(x.r, e)
		if err != nil {
			return nil, err
		}
		return truthy(r), nil
	}
	l, err := evalExpr(x.l, e)
	if err != nil {
		return nil, err
	}
	r, err := evalExpr(x.r, e)
	if err != nil {
		return nil, err
	}
	switch x.op {
	case "==":
		return valuesEqual(l, r), nil
	case "!=":
		return !valuesEqual(l, r), nil
	case "<", ">", "<=", ">=":
		lf, lok := toNum(l)
		rf, rok := toNum(r)
		if !lok || !rok {
			return false, nil
		}
		switch x.op {
		case "<":
			return lf < rf, nil
		case ">":
			return lf > rf, nil
		case "<=":
			return lf <= rf, nil
		case ">=":
			return lf >= rf, nil
		}
	case "+":
		// numeric add if both numbers, else string concat (Velocity-ish).
		if lf, lok := toNum(l); lok {
			if rf, rok := toNum(r); rok {
				return lf + rf, nil
			}
		}
		return toStr(l) + toStr(r), nil
	}
	return nil, fmt.Errorf("vtl: unknown op %q", x.op)
}

// evalRef resolves $root followed by its access chain. $util/$utils is the special namespace.
func evalRef(x refExpr, e *env) (any, error) {
	if x.root == "util" || x.root == "utils" {
		return evalUtilChain(x.chain, e)
	}
	var cur any = e.vars[x.root] // undefined → nil (Velocity treats missing refs as null)
	for _, a := range x.chain {
		switch a.kind {
		case "prop":
			cur = memberOrMethod(cur, a.name, nil)
		case "method":
			args, err := evalArgs(a.args, e)
			if err != nil {
				return nil, err
			}
			cur = memberOrMethod(cur, a.name, args)
		case "index":
			idx, err := evalExpr(a.index, e)
			if err != nil {
				return nil, err
			}
			cur = indexInto(cur, idx)
		}
	}
	return cur, nil
}

// evalUtilChain walks a $util access: property segments build the method path, the terminal call
// invokes it (e.g. .dynamodb .toDynamoDBJson(x) → path "dynamodb.toDynamoDBJson").
func evalUtilChain(chain []accessor, e *env) (any, error) {
	path := ""
	for _, a := range chain {
		switch a.kind {
		case "prop":
			if path == "" {
				path = a.name
			} else {
				path += "." + a.name
			}
		case "method":
			args, err := evalArgs(a.args, e)
			if err != nil {
				return nil, err
			}
			full := a.name
			if path != "" {
				full = path + "." + a.name
			}
			res, cerr, ok := e.util.call(full, args)
			if cerr != nil {
				return nil, cerr
			}
			if !ok {
				return nil, fmt.Errorf("vtl: unknown $util method %q", full)
			}
			return res, nil
		case "index":
			return nil, fmt.Errorf("vtl: cannot index $util")
		}
	}
	return nil, fmt.Errorf("vtl: $util.%s is not callable here", path)
}

func evalArgs(nodes []exprNode, e *env) ([]any, error) {
	out := make([]any, 0, len(nodes))
	for _, n := range nodes {
		v, err := evalExpr(n, e)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// memberOrMethod does map property access, or a small set of Java/Velocity collection & string
// methods that resolver templates rely on. Unknown members → nil (quiet, Velocity-like).
func memberOrMethod(recv any, name string, args []any) any {
	// Method call (args != nil signals a call; note zero-arg calls pass an empty non-nil slice).
	if args != nil {
		switch v := recv.(type) {
		case map[string]any:
			switch name {
			case "get":
				return v[toStr(arg(args, 0))]
			case "containsKey":
				_, ok := v[toStr(arg(args, 0))]
				return ok
			case "put":
				v[toStr(arg(args, 0))] = arg(args, 1)
				return ""
			case "size":
				return float64(len(v))
			case "isEmpty":
				return len(v) == 0
			case "keySet":
				keys := make([]any, 0, len(v))
				for k := range v {
					keys = append(keys, k)
				}
				return keys
			}
		case []any:
			switch name {
			case "size":
				return float64(len(v))
			case "isEmpty":
				return len(v) == 0
			case "get":
				if f, ok := toNum(arg(args, 0)); ok && int(f) >= 0 && int(f) < len(v) {
					return v[int(f)]
				}
				return nil
			case "contains":
				for _, e := range v {
					if valuesEqual(e, arg(args, 0)) {
						return true
					}
				}
				return false
			}
		case string:
			switch name {
			case "length":
				return float64(len(v))
			case "toUpperCase":
				return strings.ToUpper(v)
			case "toLowerCase":
				return strings.ToLower(v)
			case "trim":
				return strings.TrimSpace(v)
			case "contains":
				return strings.Contains(v, toStr(arg(args, 0)))
			case "replace":
				return strings.ReplaceAll(v, toStr(arg(args, 0)), toStr(arg(args, 1)))
			case "isEmpty":
				return v == ""
			}
		}
		return nil
	}
	// Property access.
	if m, ok := recv.(map[string]any); ok {
		return m[name]
	}
	return nil
}

func indexInto(recv, idx any) any {
	switch v := recv.(type) {
	case map[string]any:
		return v[toStr(idx)]
	case []any:
		if f, ok := toNum(idx); ok && int(f) >= 0 && int(f) < len(v) {
			return v[int(f)]
		}
	}
	return nil
}

// --- value helpers (shared with util.go) ---

func toStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return numStr(x)
	case map[string]any, []any:
		return jsonString(x)
	}
	return fmt.Sprintf("%v", v)
}

func truthy(v any) bool {
	if v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return true // Velocity: any non-null, non-false reference is true
}

func toNum(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}

func valuesEqual(a, b any) bool {
	if af, aok := a.(float64); aok {
		if bf, bok := toNum(b); bok {
			return af == bf
		}
	}
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.DeepEqual(a, b)
}
