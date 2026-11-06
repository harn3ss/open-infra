package graphql

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
)

// The resolver context ($ctx) a field's resolver sees, in AppSync's shape: $ctx.arguments (also
// $ctx.args), $ctx.identity, $ctx.source (below the root), $ctx.request.headers and $ctx.info — the
// field, its parent type, the operation's variables and the field's selection set. A direct Lambda
// resolver sends it to the function as the event (internal/directlambda).

type requestHeadersKey struct{}

// WithRequestHeaders carries the GraphQL request's HTTP headers into execution, for $ctx.request.headers.
// Header names are lower-cased (as AppSync gives them); a header sent once is a string, one sent more
// than once a list. AppSync leaves the cookie header out, and the platform's own trusted identity
// headers (X-OpenInfra-*, set by the aws-shim) are not the client's, so they are left out too.
func WithRequestHeaders(ctx context.Context, h http.Header) context.Context {
	headers := map[string]any{}
	for name, values := range h {
		lower := strings.ToLower(name)
		if lower == "cookie" || strings.HasPrefix(lower, "x-openinfra-") || len(values) == 0 {
			continue
		}
		if len(values) == 1 {
			headers[lower] = values[0]
			continue
		}
		list := make([]any, len(values))
		for i, v := range values {
			list[i] = v
		}
		headers[lower] = list
	}
	return context.WithValue(ctx, requestHeadersKey{}, headers)
}

// requestInfo is $ctx.request: the request's headers (none when execution carries none).
func requestInfo(ctx context.Context) map[string]any {
	headers, _ := ctx.Value(requestHeadersKey{}).(map[string]any)
	if headers == nil {
		headers = map[string]any{}
	}
	return map[string]any{"headers": headers}
}

// fieldContext builds the resolver context of one field resolution. source is the parent object (nil at
// the root, where $ctx.source is absent).
func (e *Engine) fieldContext(ec *execCtx, sel selection, parentType string, source map[string]any, id authz.Identity) map[string]any {
	return e.fieldContextWithInfo(ec, sel, source, id, e.fieldInfo(ec, sel, parentType))
}

// fieldContextWithInfo is fieldContext with $ctx.info already built (it is the same for every sibling).
func (e *Engine) fieldContextWithInfo(ec *execCtx, sel selection, source map[string]any, id authz.Identity, info map[string]any) map[string]any {
	args := evalArgs(sel.args, ec.vars)
	rctx := map[string]any{
		"args":      args,
		"arguments": args,
		"identity":  identityMap(id),
		"request":   requestInfo(ec.ctx),
		"info":      info,
	}
	if source != nil {
		rctx["source"] = source
	}
	return rctx
}

// fieldInfo is $ctx.info for a field: its name, its parent type, the operation's variables, and its
// selection set as AppSync gives it — selectionSetList (each selected field by its response key,
// nested ones as "parent/child", fragments expanded where they apply to the field's type) and
// selectionSetGraphQL (the selection set as written, fragment spreads not merged).
func (e *Engine) fieldInfo(ec *execCtx, sel selection, parentType string) map[string]any {
	vars := map[string]any{}
	for k, v := range ec.vars {
		vars[k] = v
	}
	list := []any{}
	e.selectionSetList(ec, sel.selections, namedFieldType(e.schema, parentType, sel.name), "", &list, map[string]bool{})
	return map[string]any{
		"fieldName":           sel.name,
		"parentTypeName":      parentType,
		"variables":           vars,
		"selectionSetList":    list,
		"selectionSetGraphQL": printSelectionSet(sel.selections),
	}
}

// selectionSetList appends the selection set's fields to out, prefixed. A fragment is expanded when it
// applies to the field's own type (no type condition, or that type): AppSync exposes only the fields
// that belong to the current type, so an interface field lists the interface's fields, not a member
// type's. Meta-fields (__typename) and fields @skip/@include drop are not listed.
func (e *Engine) selectionSetList(ec *execCtx, sels []selection, typeName, prefix string, out *[]any, open map[string]bool) {
	for _, s := range sels {
		if skip, err := shouldSkip(s.directives, ec.vars); err != nil || skip {
			continue
		}
		switch {
		case s.fragmentSpread != "":
			frag, ok := ec.frags[s.fragmentSpread]
			if !ok || open[s.fragmentSpread] || !conditionMatches(frag.typeCondition, typeName) {
				continue
			}
			open[s.fragmentSpread] = true
			e.selectionSetList(ec, frag.selections, typeName, prefix, out, open)
			delete(open, s.fragmentSpread)
		case s.inline:
			if conditionMatches(s.typeCondition, typeName) {
				e.selectionSetList(ec, s.selections, typeName, prefix, out, open)
			}
		default:
			if strings.HasPrefix(s.name, "__") {
				continue
			}
			key := prefix + responseKey(s)
			*out = append(*out, key)
			if len(s.selections) > 0 {
				e.selectionSetList(ec, s.selections, namedFieldType(e.schema, typeName, s.name), key+"/", out, open)
			}
		}
	}
}

// conditionMatches: a fragment applies to the field's type when it has no condition, names that type,
// or the type is unknown (no schema).
func conditionMatches(cond, typeName string) bool {
	return cond == "" || typeName == "" || cond == typeName
}

// printSelectionSet renders a selection set as GraphQL, two-space indented, as AppSync's
// selectionSetGraphQL does: "{\n  id\n  title\n}". Aliases, arguments (in name order) and directives are
// kept, a fragment spread is printed as a spread, an inline fragment as written. An empty selection
// set (a scalar field) is "".
func printSelectionSet(sels []selection) string {
	if len(sels) == 0 {
		return ""
	}
	var b strings.Builder
	writeSelectionSet(&b, sels, 0)
	return b.String()
}

func writeSelectionSet(b *strings.Builder, sels []selection, depth int) {
	b.WriteString("{\n")
	for _, s := range sels {
		b.WriteString(strings.Repeat("  ", depth+1))
		switch {
		case s.fragmentSpread != "":
			b.WriteString("... " + s.fragmentSpread)
		case s.inline:
			b.WriteString("...")
			if s.typeCondition != "" {
				b.WriteString(" on " + s.typeCondition)
			}
		default:
			if s.alias != "" {
				b.WriteString(s.alias + ": ")
			}
			b.WriteString(s.name)
			writeArgs(b, s.args)
		}
		for _, d := range s.directives {
			b.WriteString(" @" + d.name)
			writeArgs(b, d.args)
		}
		if len(s.selections) > 0 {
			b.WriteString(" ")
			writeSelectionSet(b, s.selections, depth+1)
		}
		b.WriteString("\n")
	}
	b.WriteString(strings.Repeat("  ", depth) + "}")
}

func writeArgs(b *strings.Builder, args map[string]valueNode) {
	if len(args) == 0 {
		return
	}
	names := make([]string, 0, len(args))
	for n := range args {
		names = append(names, n)
	}
	sort.Strings(names)
	b.WriteString("(")
	for i, n := range names {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(n + ": ")
		writeValue(b, args[n])
	}
	b.WriteString(")")
}

func writeValue(b *strings.Builder, v valueNode) {
	switch v.kind {
	case "var":
		b.WriteString("$" + v.val.(string))
	case "enum":
		b.WriteString(v.val.(string))
	case "list":
		b.WriteString("[")
		for i, el := range v.val.([]valueNode) {
			if i > 0 {
				b.WriteString(", ")
			}
			writeValue(b, el)
		}
		b.WriteString("]")
	case "object":
		fields := v.val.(map[string]valueNode)
		names := make([]string, 0, len(fields))
		for n := range fields {
			names = append(names, n)
		}
		sort.Strings(names)
		b.WriteString("{")
		for i, n := range names {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(n + ": ")
			writeValue(b, fields[n])
		}
		b.WriteString("}")
	default: // scalar
		switch s := v.val.(type) {
		case nil:
			b.WriteString("null")
		case string:
			q, _ := json.Marshal(s)
			b.Write(q)
		case float64:
			b.WriteString(strconv.FormatFloat(s, 'f', -1, 64))
		case bool:
			b.WriteString(strconv.FormatBool(s))
		default:
			q, _ := json.Marshal(s)
			b.Write(q)
		}
	}
}

// outcome is the batched outcome of the field at respKey, if it was resolved with its siblings.
func (p *siblingPlan) outcome(respKey string) (resolver.Outcome, bool) {
	if p == nil {
		return resolver.Outcome{}, false
	}
	o, ok := p.batched[respKey]
	return o, ok
}
