package graphql

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/resolver"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
)

// Limits are the hostile-load guards (drop-33 §7). GraphQL's cost asymmetry — the client composes
// demand, the server owns cost — makes an unguarded endpoint a denial-of-service risk, which matters
// MOST for the least-resourced operator this project is built for. So these are GraphQL properties
// (not AppSync ones) enforced in the neutral engine, with defaults that protect an operator who set
// nothing (DefaultLimits). 0 disables a numeric limit — that is opt-OUT, and is never the default.
type Limits struct {
	MaxDepth      int             // reject queries whose selection nesting exceeds this (0 = unlimited)
	MaxCost       int             // reject queries with more than this many fields (0 = unlimited)
	PersistedOnly bool            // when true, only pre-registered query documents run
	Persisted     map[string]bool // allow-list of sha256(query) hex digests, for PersistedOnly mode
}

// DefaultLimits protects an unconfigured operator: bounded depth and cost, arbitrary queries allowed.
func DefaultLimits() Limits { return Limits{MaxDepth: 10, MaxCost: 1000} }

// Engine executes GraphQL operations against a set of resolvers. Resolvers are keyed by
// "<RootType>.<field>", e.g. "Query.getTodo" / "Mutation.createTodo" (schema intake / piece 1: the
// mapping of a field to the resolver that backs it). Each resolver carries its own runtime, so the
// executor holds no VTL (or any other runtime) knowledge — it dispatches fields and projects
// selection sets. It enforces Limits before running any resolver.
type Engine struct {
	resolvers  map[string]resolver.Resolver
	limits     Limits
	authorizer authz.Authorizer
}

// Option configures an Engine (hostile-load guards, the field authorizer, …).
type Option func(*Engine)

// WithLimits sets the hostile-load guards (default: DefaultLimits).
func WithLimits(l Limits) Option { return func(e *Engine) { e.limits = l } }

// WithAuthorizer sets the field-level authorizer (default: authz.AllowAll — no enforcement).
func WithAuthorizer(a authz.Authorizer) Option { return func(e *Engine) { e.authorizer = a } }

// New builds an engine: safe-by-default limits and no field-auth enforcement (AllowAll) unless
// options say otherwise. The variadic options keep New(resolvers) valid.
func New(resolvers map[string]resolver.Resolver, opts ...Option) *Engine {
	e := &Engine{resolvers: resolvers, limits: DefaultLimits(), authorizer: authz.AllowAll{}}
	for _, o := range opts {
		o(e)
	}
	return e
}

// NewWithLimits builds an engine with explicit hostile-load guards (kept for existing callers).
func NewWithLimits(resolvers map[string]resolver.Resolver, limits Limits) *Engine {
	return New(resolvers, WithLimits(limits))
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
	// Hostile-load guards run before any resolver executes: a pathological document must be rejected
	// without being run (drop-33 §7).
	if ge := e.checkLimits(query, op); ge != nil {
		return Result{Errors: []GqlError{*ge}}
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
		// Field-level authorization (§6): consult the shared boundary BEFORE running the resolver. A
		// denial surfaces as Unauthorized with the field null, and the resolver — and its data source —
		// never runs. This is the lifecycle's job; the runtime step stays auth-unaware.
		id := authz.FromContext(ctx)
		if !r.Auth.IsZero() {
			if err := e.authorizer.Authorize(ctx, id, r.Auth); err != nil {
				errs = append(errs, GqlError{Message: err.Error(), Path: []any{respKey}, ErrorType: "Unauthorized"})
				data[respKey] = nil
				continue
			}
		}
		gctx := map[string]any{"args": evalArgs(sel.args, variables), "identity": identityMap(id)}
		res, rerr := r.Resolve(ctx, gctx)
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

// checkLimits enforces the hostile-load guards against a parsed operation, returning a GraphQL error
// (with an errorType naming the guard) if the document is rejected, or nil if it may run.
func (e *Engine) checkLimits(query string, op *operation) *GqlError {
	if e.limits.PersistedOnly {
		sum := sha256.Sum256([]byte(query))
		if !e.limits.Persisted[hex.EncodeToString(sum[:])] {
			return &GqlError{Message: "only persisted (pre-registered) queries are allowed", ErrorType: "PersistedQueryRequired"}
		}
	}
	if e.limits.MaxDepth > 0 {
		if d := selectionsDepth(op.selections); d > e.limits.MaxDepth {
			return &GqlError{Message: fmt.Sprintf("query depth %d exceeds the maximum of %d", d, e.limits.MaxDepth), ErrorType: "MaxDepthExceeded"}
		}
	}
	if e.limits.MaxCost > 0 {
		if c := selectionsCost(op.selections); c > e.limits.MaxCost {
			return &GqlError{Message: fmt.Sprintf("query cost %d exceeds the maximum of %d", c, e.limits.MaxCost), ErrorType: "MaxCostExceeded"}
		}
	}
	return nil
}

// selectionsDepth is the deepest selection-set nesting (top-level fields are depth 1).
func selectionsDepth(sels []selection) int {
	max := 0
	for _, s := range sels {
		d := 1
		if len(s.selections) > 0 {
			d += selectionsDepth(s.selections)
		}
		if d > max {
			max = d
		}
	}
	return max
}

// selectionsCost is the total number of fields in the query (a simple, honest cost proxy).
func selectionsCost(sels []selection) int {
	n := 0
	for _, s := range sels {
		n += 1 + selectionsCost(s.selections)
	}
	return n
}

// identityMap exposes the caller as $ctx.identity for mapping templates (username + groups), mirroring
// AppSync's $ctx.identity. Empty for an anonymous caller.
func identityMap(id authz.Identity) map[string]any {
	groups := make([]any, len(id.Groups))
	for i, g := range id.Groups {
		groups[i] = g
	}
	return map[string]any{"username": id.Username, "groups": groups}
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
