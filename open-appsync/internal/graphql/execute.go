package graphql

import (
	"context"
	"errors"

	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
)

// Engine executes GraphQL operations against a set of VTL resolvers. Resolvers are keyed by
// "<RootType>.<field>", e.g. "Query.getTodo" / "Mutation.createTodo" (schema intake / piece 1: the
// mapping of a field to the resolver that backs it).
type Engine struct {
	vtl       *vtl.Engine
	resolvers map[string]resolver.Resolver
}

func New(v *vtl.Engine, resolvers map[string]resolver.Resolver) *Engine {
	return &Engine{vtl: v, resolvers: resolvers}
}

// GqlError is a GraphQL error entry, carrying AppSync's errorType where the resolver threw one.
type GqlError struct {
	Message   string `json:"message"`
	Path      []any  `json:"path,omitempty"`
	ErrorType string `json:"errorType,omitempty"`
}

// Result is a GraphQL response: {data, errors}.
type Result struct {
	Data   map[string]any `json:"data,omitempty"`
	Errors []GqlError     `json:"errors,omitempty"`
}

// Execute parses and runs an operation, returning the GraphQL {data, errors} response. Each
// top-level field runs its resolver (request→execute→response); a resolver error becomes a GraphQL
// error with that field's path and its data set to null, exactly as AppSync surfaces it.
func (e *Engine) Execute(ctx context.Context, query string, variables map[string]any) Result {
	op, err := parseQuery(query)
	if err != nil {
		return Result{Errors: []GqlError{{Message: err.Error()}}}
	}
	rootType := "Query"
	if op.opType == "mutation" {
		rootType = "Mutation"
	}

	data := map[string]any{}
	var errs []GqlError
	for _, sel := range op.selections {
		respKey := sel.name
		if sel.alias != "" {
			respKey = sel.alias
		}
		if sel.name == "__typename" { // GraphQL meta-field: the root type's name
			data[respKey] = rootType
			continue
		}
		key := rootType + "." + sel.name
		r, ok := e.resolvers[key]
		if !ok {
			errs = append(errs, GqlError{Message: "no resolver for field " + key, Path: []any{respKey}})
			data[respKey] = nil
			continue
		}
		gctx := map[string]any{"args": evalArgs(sel.args, variables)}
		res, rerr := r.Resolve(ctx, e.vtl, gctx)
		if rerr != nil {
			ge := GqlError{Message: rerr.Error(), Path: []any{respKey}}
			var te *vtl.ThrowError
			if errors.As(rerr, &te) {
				ge.Message = te.Message
				ge.ErrorType = te.ErrorType
			}
			errs = append(errs, ge)
			data[respKey] = nil
			continue
		}
		data[respKey] = project(res, sel.selections)
	}
	return Result{Data: data, Errors: errs}
}

// evalArgs turns parsed argument values into plain Go values, resolving $variables.
func evalArgs(args map[string]valueNode, vars map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range args {
		out[k] = evalValue(v, vars)
	}
	return out
}

func evalValue(v valueNode, vars map[string]any) any {
	switch v.kind {
	case "scalar":
		return v.val
	case "var":
		return vars[v.val.(string)]
	case "list":
		src := v.val.([]valueNode)
		out := make([]any, len(src))
		for i, e := range src {
			out[i] = evalValue(e, vars)
		}
		return out
	case "object":
		src := v.val.(map[string]valueNode)
		out := map[string]any{}
		for k, e := range src {
			out[k] = evalValue(e, vars)
		}
		return out
	}
	return nil
}

// project applies a selection set to a resolver result: it picks the selected sub-fields from the
// result object (recursing into nested objects/lists). An empty selection set returns the value as a
// leaf. Nested per-field resolvers are a later rung; slice 1 projects structurally from the result.
func project(res any, sels []selection) any {
	if len(sels) == 0 {
		return res
	}
	switch v := res.(type) {
	case map[string]any:
		out := map[string]any{}
		for _, s := range sels {
			respKey := s.name
			if s.alias != "" {
				respKey = s.alias
			}
			out[respKey] = project(v[s.name], s.selections)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = project(e, sels)
		}
		return out
	default:
		return res // scalar (selection set on a scalar is ignored)
	}
}
