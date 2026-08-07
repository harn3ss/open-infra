// Package resolver is open-appsync's LIFECYCLE layer (drop-33 fork, decision B): it composes runtime
// steps into a resolved field value. A step (runtime.Runtime) knows nothing about how it is composed;
// the lifecycle does. Two lifecycles exist today; subscriptions will be a third:
//
//   - unit     — one step over one data source (the shape slice 1 shipped):
//                request → (data source, if the step emitted an Operation) → response.
//   - pipeline — before → [function…] → after, with $ctx.stash shared across all steps and
//                $ctx.prev.result carrying each function's output forward. before/after are steps that
//                emit NO Operation (they only transform $ctx); a function is a unit step with a source.
//
// A step's request phase may return a nil Operation (the loosened Out term): the lifecycle then skips
// the data-source call. A validation abort (VTL's $util.error()) is returned as a normal error and
// surfaces on the field. Nothing here is VTL-aware — any runtime plugs into any lifecycle.
package resolver

import (
	"context"

	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// Resolver is one field's lifecycle. By default it is a unit resolver (Runtime + Source). If Pipeline
// is set, it is a pipeline resolver and Runtime/Source are ignored. (Keeping one type — rather than a
// Lifecycle interface — lets the executor hold a single map and keeps the unit path byte-identical to
// the slice-1 shape; a Lifecycle interface can arrive with the subscription rung.)
type Resolver struct {
	Runtime  runtime.Runtime // unit lifecycle: the single step
	Source   dynamodb.Store  // unit lifecycle: its data source
	Pipeline *Pipeline       // if non-nil, run the pipeline lifecycle instead
}

// Pipeline is the pipeline lifecycle: a before step, an ordered list of functions, and an after step.
// Before/After may be nil. Before is invoked for its request phase only (side effects on $ctx.stash,
// or an abort); After for its response phase only (it shapes the final value from $ctx.prev.result).
type Pipeline struct {
	Before    runtime.Runtime
	Functions []Function
	After     runtime.Runtime
}

// Function is one stage of a pipeline: a unit step (request → data source → response) whose response
// output becomes $ctx.prev.result for the next stage.
type Function struct {
	Runtime runtime.Runtime
	Source  dynamodb.Store
}

// Resolve runs the field's lifecycle. rctx is the resolver context ($ctx): it must carry "args" (and
// optionally identity/source).
func (r Resolver) Resolve(reqCtx context.Context, rctx map[string]any) (any, error) {
	if r.Pipeline != nil {
		return r.Pipeline.resolve(reqCtx, rctx)
	}
	return runStep(reqCtx, r.Runtime, r.Source, rctx)
}

// runStep is one unit step: request phase → (data source, only if an Operation was emitted) → response
// phase. When the step emits a nil Operation the data source is skipped (the loosened Out term). For a
// unit resolver whose request always emits an Operation, this is byte-identical to the slice-1 lifecycle.
func runStep(reqCtx context.Context, rt runtime.Runtime, src dynamodb.Store, rctx map[string]any) (any, error) {
	op, err := rt.RenderRequest(rctx)
	if err != nil {
		return nil, err // includes *vtl.ThrowError from a validation $util.error()
	}
	if op != nil && src != nil {
		result, err := src.Execute(reqCtx, op)
		if err != nil {
			return nil, err
		}
		rctx["result"] = result
	}
	return rt.RenderResponse(rctx)
}

// resolve runs before → functions → after, threading $ctx.stash (shared, mutable) and $ctx.prev.result.
func (p *Pipeline) resolve(reqCtx context.Context, rctx map[string]any) (any, error) {
	if _, ok := rctx["stash"]; !ok {
		rctx["stash"] = map[string]any{} // shared across every step of this resolution
	}

	// before: request phase only — populate $ctx.stash or abort. It emits no Operation, so no data
	// source is called; its rendered output is discarded.
	if p.Before != nil {
		if _, err := p.Before.RenderRequest(rctx); err != nil {
			return nil, err
		}
	}

	// functions in order; each function's response output becomes $ctx.prev.result for the next.
	for _, fn := range p.Functions {
		out, err := runStep(reqCtx, fn.Runtime, fn.Source, rctx)
		if err != nil {
			return nil, err
		}
		rctx["prev"] = map[string]any{"result": out}
	}

	// after: response phase only — shape the final value from $ctx.prev.result / $ctx.stash.
	if p.After != nil {
		return p.After.RenderResponse(rctx)
	}
	if prev, ok := rctx["prev"].(map[string]any); ok {
		return prev["result"], nil // no after step: return the last function's result
	}
	return nil, nil
}
