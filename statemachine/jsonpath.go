// A pragmatic JSONPath subset for ASL data shaping, plus the Parameters and
// ResultPath/OutputPath application rules.
//
// Supported reference paths: "$" (the whole value), dotted field access
// ("$.a.b.c"), and array indexing ("$.a[0].b"). Context-object paths start with
// "$$" ("$$.Execution.Name"). This covers the overwhelming majority of real state
// machines; the unsupported corners (filters, wildcards, slices) are documented in
// docs/state-machines.md rather than silently mis-evaluated.
package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// pathError signals an ASL data-shaping failure (States.Runtime).
type pathError struct{ msg string }

func (e *pathError) Error() string { return e.msg }

func perr(format string, a ...any) error { return &pathError{fmt.Sprintf(format, a...)} }

// tokenizePath turns "$.a[0].b" into ["a","0","b"]. The leading "$" or "$$" must
// be stripped by the caller. Bracket indices become their own tokens.
func tokenizePath(p string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '.':
			flush()
		case '[':
			flush()
			j := strings.IndexByte(p[i:], ']')
			if j < 0 {
				return nil, perr("unterminated '[' in path %q", p)
			}
			idx := strings.TrimSpace(p[i+1 : i+j])
			idx = strings.Trim(idx, "'\"") // allow ['key'] as well as [0]
			toks = append(toks, idx)
			i += j
		default:
			cur.WriteByte(p[i])
		}
	}
	flush()
	return toks, nil
}

// getPath resolves a reference path against data (and the context object for "$$").
// Returns (value, found). A path that walks off the data returns found=false.
func getPath(data any, ctx map[string]any, path string) (any, bool, error) {
	if path == "" {
		return nil, false, nil
	}
	root := data
	rest := path
	switch {
	case path == "$":
		return data, true, nil
	case path == "$$":
		return ctx, true, nil
	case strings.HasPrefix(path, "$$."):
		root, rest = ctx, path[len("$$."):]
	case strings.HasPrefix(path, "$."):
		root, rest = data, path[len("$."):]
	default:
		return nil, false, perr("path %q must start with $ or $$", path)
	}
	toks, err := tokenizePath(rest)
	if err != nil {
		return nil, false, err
	}
	cur := root
	for _, t := range toks {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[t]
			if !ok {
				return nil, false, nil
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(t)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false, nil
			}
			cur = node[i]
		default:
			return nil, false, nil
		}
	}
	return cur, true, nil
}

// applyInputPath selects a portion of the raw state input. "$" (default) keeps it
// all; "" (from explicit null) discards to {}; otherwise selects the sub-value.
func applyInputPath(data any, ctx map[string]any, p string) (any, error) {
	switch p {
	case "$":
		return data, nil
	case "":
		return map[string]any{}, nil
	}
	v, ok, err := getPath(data, ctx, p)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, perr("InputPath %q did not match the input", p)
	}
	return v, nil
}

// applyOutputPath narrows the state's result to what is passed on. Same rules as InputPath.
func applyOutputPath(data any, ctx map[string]any, p string) (any, error) {
	return applyInputPath(data, ctx, p)
}

// applyResultPath places result into data at path p and returns the combined value.
// "$" (default) => result replaces data entirely; "" (null) => result discarded,
// data passes through; "$.x.y" => result inserted at that location (objects created
// as needed).
func applyResultPath(data, result any, p string) (any, error) {
	switch p {
	case "$":
		return result, nil
	case "":
		return data, nil
	}
	if !strings.HasPrefix(p, "$.") {
		return nil, perr("ResultPath %q must be $, null, or start with $.", p)
	}
	toks, err := tokenizePath(p[len("$."):])
	if err != nil {
		return nil, err
	}
	// Copy-on-write into a map tree. data must be an object to receive a nested path.
	root, ok := data.(map[string]any)
	if !ok {
		// If the incoming data isn't an object, ASL still lets ResultPath build one.
		root = map[string]any{}
	}
	cur := root
	for i, t := range toks {
		if i == len(toks)-1 {
			cur[t] = result
			break
		}
		next, ok := cur[t].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[t] = next
		}
		cur = next
	}
	return root, nil
}

// resolveParameters evaluates an ASL Parameters block against the effective input
// and context. Keys ending in ".$" take a reference-path string value (resolved and
// re-keyed without the ".$"); all other values are passed through literally, with
// nested objects/arrays resolved recursively.
func resolveParameters(raw json.RawMessage, input any, ctx map[string]any) (any, error) {
	if len(raw) == 0 {
		return input, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, perr("Parameters is not valid JSON: %v", err)
	}
	return resolveNode(v, input, ctx)
}

func resolveNode(node, input any, ctx map[string]any) (any, error) {
	switch n := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(n))
		for k, val := range n {
			if strings.HasSuffix(k, ".$") {
				s, ok := val.(string)
				if !ok {
					return nil, perr("Parameters key %q must have a path string value", k)
				}
				resolved, found, err := getPath(input, ctx, s)
				if err != nil {
					return nil, err
				}
				if !found {
					return nil, perr("Parameters path %q (key %q) did not match the input", s, k)
				}
				out[strings.TrimSuffix(k, ".$")] = resolved
			} else {
				r, err := resolveNode(val, input, ctx)
				if err != nil {
					return nil, err
				}
				out[k] = r
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(n))
		for i, val := range n {
			r, err := resolveNode(val, input, ctx)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	default:
		return node, nil
	}
}
