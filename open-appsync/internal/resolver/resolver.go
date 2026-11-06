// Package resolver is open-appsync's LIFECYCLE layer (the step/lifecycle model): it composes runtime
// steps into a resolved field value. A step (runtime.Runtime) knows nothing about how it is composed;
// the lifecycle does. Two lifecycles exist today; subscriptions will be a third:
//
// - unit — one step over one data source (the shape slice 1 shipped):
// request → (data source, if the step emitted an Operation) → response.
// - pipeline — before → [function…] → after, with $ctx.stash shared across all steps and
// $ctx.prev.result carrying each function's output forward. before/after are steps that
// emit NO Operation (they only transform $ctx); a function is a unit step with a source.
//
// A step's request phase may return a nil Operation (the loosened Out term): the lifecycle then skips
// the data-source call. A validation abort (VTL's $util.error) is returned as a normal error and
// surfaces on the field. Nothing here is VTL-aware — any runtime plugs into any lifecycle.
//
// BATCHING (AppSync's BatchInvoke). ResolveAll resolves one field for a list of sibling contexts — the
// same field across a list of parent objects. Each step renders its request per sibling, as AppSync
// applies the template to every item; the siblings whose request is a BatchInvoke go to the data source
// together, at most MaxBatchSize (AppSync's default 5) per call, through the source's
// datasource.BatchStore capability, and each item's own result runs its response phase. Every other
// request runs per sibling exactly as Resolve does. A BatchInvoke on a source that cannot batch fails
// closed. Resolve is ResolveAll of one.
package resolver

import (
	"context"
	"errors"
	"time"

	"github.com/harn3ss/open-infra/open-appsync/internal/authz"
	"github.com/harn3ss/open-infra/open-appsync/internal/datasource"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// DefaultBatchSize is how many items one BatchInvoke carries when the resolver sets no maxBatchSize —
// AppSync's batch size before maxBatchSize was configurable, and still its default.
const DefaultBatchSize = 5

// Resolver is one field's lifecycle. By default it is a unit resolver (Runtime + Source). If Pipeline
// is set, it is a pipeline resolver and Runtime/Source are ignored. (Keeping one type — rather than a
// Lifecycle interface — lets the executor hold a single map and keeps the unit path byte-identical to
// the slice-1 shape; a Lifecycle interface can arrive with the subscription rung.)
type Resolver struct {
	Runtime  runtime.Runtime  // unit lifecycle: the single step
	Source   datasource.Store // unit lifecycle: its data source
	Pipeline *Pipeline        // if non-nil, run the pipeline lifecycle instead
	// MaxBatchSize is AppSync's maxBatchSize for a unit resolver: the most sibling resolutions one
	// BatchInvoke carries (0 = DefaultBatchSize). Whether the step batches at all is its request's
	// choice (a template that emits BatchInvoke, or a direct Lambda resolver with maxBatchSize > 0).
	MaxBatchSize int
	// Auth is the field's authorization requirement, enforced by the executor BEFORE the resolver runs
	// (field-level authz,). A zero Requirement means public. It lives on the resolver but is checked
	// in the executor/lifecycle, never in a runtime step — the step stays auth-unaware.
	Auth authz.Requirement
	// Caching, when non-nil, enables per-resolver response caching (AppSync's caching behavior). Like
	// Auth it is config the EXECUTOR acts on, not the step: the executor checks the cache before running
	// the resolver and stores the result after. A zero/nil Caching means no caching.
	Caching *CachingConfig
}

// CachingConfig configures per-resolver response caching. TTL is how long an entry lives; Keys are
// $context paths (e.g. "arguments.id") that — together with the caller identity, which the executor
// always folds in — form the cache key.
type CachingConfig struct {
	TTL  time.Duration
	Keys []string
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
// output becomes $ctx.prev.result for the next stage. MaxBatchSize is the function's maxBatchSize, as
// on a unit resolver.
type Function struct {
	Runtime      runtime.Runtime
	Source       datasource.Store
	MaxBatchSize int
}

// Outcome is one sibling's resolved value or error, from ResolveAll.
type Outcome struct {
	Value any
	Err   error
}

// Resolve runs the field's lifecycle. rctx is the resolver context ($ctx): it must carry "args" (and
// optionally identity/source).
func (r Resolver) Resolve(reqCtx context.Context, rctx map[string]any) (any, error) {
	o := r.ResolveAll(reqCtx, []map[string]any{rctx})[0]
	return o.Value, o.Err
}

// ResolveAll runs the field's lifecycle for sibling contexts — the same field across a list of parent
// objects — and returns one Outcome per context, in order. Requests that are BatchInvokes are sent
// together (see the package doc); everything else runs per context as Resolve does.
func (r Resolver) ResolveAll(reqCtx context.Context, rctxs []map[string]any) []Outcome {
	if r.Pipeline != nil {
		return r.Pipeline.resolveAll(reqCtx, rctxs)
	}
	return runStepAll(reqCtx, r.Runtime, r.Source, r.MaxBatchSize, rctxs)
}

// CanBatch reports whether a step of this resolver has a data source that can batch, so its sibling
// resolutions are worth gathering for ResolveAll. For any other resolver ResolveAll is just Resolve
// per context.
func (r Resolver) CanBatch() bool {
	if r.Pipeline != nil {
		for _, fn := range r.Pipeline.Functions {
			if _, ok := fn.Source.(datasource.BatchStore); ok {
				return true
			}
		}
		return false
	}
	_, ok := r.Source.(datasource.BatchStore)
	return ok
}

// IsBatchInvoke reports whether an Operation is AppSync's BatchInvoke.
func IsBatchInvoke(op runtime.Operation) bool {
	s, _ := op["operation"].(string)
	return s == "BatchInvoke"
}

// errBatchUnsupported is a BatchInvoke request on a data source that cannot batch.
var errBatchUnsupported = errors.New("BatchInvoke is supported only on a Lambda data source")

// runStepAll is one unit step over sibling contexts: request phase → (data source, only if an Operation
// was emitted) → response phase, per context, except that the contexts whose request is a BatchInvoke
// reach the source together, maxBatch (0 = DefaultBatchSize) per call. When a step emits a nil
// Operation the data source is skipped (the loosened Out term). For one context whose request is not a
// BatchInvoke, this is byte-identical to the slice-1 lifecycle.
func runStepAll(reqCtx context.Context, rt runtime.Runtime, src datasource.Store, maxBatch int, rctxs []map[string]any) []Outcome {
	out := make([]Outcome, len(rctxs))
	ops := make([]runtime.Operation, len(rctxs))
	var batched []int
	for i, rctx := range rctxs {
		op, err := rt.RenderRequest(rctx)
		if err != nil {
			out[i].Err = err // includes *vtl.ThrowError from a validation $util.error()
			continue
		}
		if op != nil && src != nil && IsBatchInvoke(op) {
			ops[i] = op
			batched = append(batched, i)
			continue
		}
		if op != nil && src != nil {
			result, err := src.Execute(reqCtx, op)
			if err != nil {
				out[i].Err = err
				continue
			}
			rctx["result"] = result
		}
		out[i].Value, out[i].Err = rt.RenderResponse(rctx)
	}
	if len(batched) == 0 {
		return out
	}

	bs, ok := src.(datasource.BatchStore)
	if !ok {
		for _, i := range batched {
			out[i].Err = errBatchUnsupported
		}
		return out
	}
	size := maxBatch
	if size <= 0 {
		size = DefaultBatchSize
	}
	for start := 0; start < len(batched); start += size {
		chunk := batched[start:min(start+size, len(batched))]
		chunkOps := make([]runtime.Operation, len(chunk))
		for j, i := range chunk {
			chunkOps[j] = ops[i]
		}
		results, err := bs.ExecuteBatch(reqCtx, chunkOps)
		if err == nil && len(results) != len(chunk) {
			err = errors.New("the data source returned a batch result that does not match the batch")
		}
		for j, i := range chunk {
			if err != nil {
				out[i].Err = err // a failed batch fails each of its items
				continue
			}
			rctxs[i]["result"] = results[j]
			out[i].Value, out[i].Err = rt.RenderResponse(rctxs[i])
		}
	}
	return out
}

// resolveAll runs before → functions → after for sibling contexts, threading each one's $ctx.stash
// (shared, mutable) and $ctx.prev.result. The siblings move through the functions together, so a
// function whose request is a BatchInvoke batches across them; a sibling that fails at a step drops out.
func (p *Pipeline) resolveAll(reqCtx context.Context, rctxs []map[string]any) []Outcome {
	out := make([]Outcome, len(rctxs))
	live := make([]int, 0, len(rctxs))
	for i, rctx := range rctxs {
		if _, ok := rctx["stash"]; !ok {
			rctx["stash"] = map[string]any{} // shared across every step of this resolution
		}
		// before: request phase only — populate $ctx.stash or abort. It emits no Operation, so no data
		// source is called; its rendered output is discarded.
		if p.Before != nil {
			if _, err := p.Before.RenderRequest(rctx); err != nil {
				out[i].Err = err
				continue
			}
		}
		live = append(live, i)
	}

	// functions in order; each function's response output becomes $ctx.prev.result for the next.
	for _, fn := range p.Functions {
		if len(live) == 0 {
			break
		}
		ctxs := make([]map[string]any, len(live))
		for j, i := range live {
			ctxs[j] = rctxs[i]
		}
		res := runStepAll(reqCtx, fn.Runtime, fn.Source, fn.MaxBatchSize, ctxs)
		next := make([]int, 0, len(live))
		for j, i := range live {
			if res[j].Err != nil {
				out[i].Err = res[j].Err
				continue
			}
			rctxs[i]["prev"] = map[string]any{"result": res[j].Value}
			next = append(next, i)
		}
		live = next
	}

	// after: response phase only — shape the final value from $ctx.prev.result / $ctx.stash.
	for _, i := range live {
		if p.After != nil {
			out[i].Value, out[i].Err = p.After.RenderResponse(rctxs[i])
			continue
		}
		if prev, ok := rctxs[i]["prev"].(map[string]any); ok {
			out[i].Value = prev["result"] // no after step: return the last function's result
		}
	}
	return out
}
