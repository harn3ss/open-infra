// Package runtime is open-appsync's runtime extension point. A "runtime" (VTL today, JS tomorrow) is
// what turns a resolver's context into work for a data source and the result back into a GraphQL
// value. AppSync structurally allows exactly two runtimes and no third-party can add one. Because
// open-appsync committed to open, `runtime` here is a REAL extension point: a stranger can implement a
// runtime we never wrote — but only if the contract underneath is frozen tight enough to implement
// against without asking us questions.
//
// SCOPING (the drop-33 fork, decision B): Runtime is the per-STEP contract, NOT "the resolver
// contract". A resolver is a *lifecycle* that composes steps (see internal/resolver): `unit` is one
// step over a data source; `pipeline` is before → functions → after; `subscription` (later) inverts to
// setup-then-push. What is shared across all of them — and across VTL/JS — is this one step. Naming it
// the step contract is what lets pipelines and subscriptions EXTEND open-appsync instead of forking it.
// The three frozen terms:
//
//  1. In    — what a step receives: the resolver $ctx (arguments, identity, source; $ctx.stash shared
//             across a pipeline's steps; $ctx.prev.result from the previous function; and — for the
//             response phase — the data-source result at ctx["result"]).
//  2. Out   — what it emits: a neutral Operation, a shape the data source understands REGARDLESS of
//             which runtime produced it (today VTL renders this; a JS runtime must render the same).
//             The Operation is OPTIONAL: a step may return a nil Operation, meaning "this step only
//             transformed $ctx; do not call a data source". That is how a pipeline's before/after
//             steps (which touch no source) are the SAME step abstraction as a function.
//  3. Error — how errors and null propagate: a step returns (value, error); a resolver-thrown error
//             (e.g. VTL's $util.error()) is returned as a normal error and surfaces on the field.
//
// VTL is the first tenant (internal/vtlruntime) and it plugs in through THIS interface with no
// backstage pass — if it needed a shortcut the others won't have, the seam would be theatre. The
// interface is deliberately NOT blessed as a stable/public extension point on one implementation:
// it is proven with VTL through the front door and (in tests) a second trivial runtime, and stays
// internal and changeable until a real second tenant lands (JS is the rung that blesses it stable).
// Openness earned by two tenants, not declared on one.
package runtime

// Operation is the neutral data-source operation — the "Out" term. It is the vendor-neutral document a
// runtime emits and a data source executes (e.g. {"operation":"GetItem","key":{"id":{"S":"1"}}} for
// the DynamoDB-style source). It is an alias for a plain map so any runtime can build one without
// importing a bespoke type, and so the data source reads it with ordinary map access; naming it here
// makes the data-source layer speak the neutral contract rather than "whatever VTL rendered".
type Operation = map[string]any

// Runtime is the per-STEP contract: the three frozen terms above and nothing more. One step is a
// request phase (→ an optional Operation) and a response phase (→ a value). A lifecycle (unit /
// pipeline / …) composes steps; it decides which phases to invoke and whether to call a data source.
// A runtime is stateless per call; the same instance serves every request for its step.
type Runtime interface {
	// RenderRequest turns the resolver $ctx into a neutral data-source Operation, or returns a nil
	// Operation to signal "no data-source call — this step only transformed $ctx" (e.g. a pipeline
	// before-step). A resolver-thrown error (validation abort) is returned as an error.
	RenderRequest(ctx map[string]any) (Operation, error)
	// RenderResponse turns the data-source result — already placed at ctx["result"] — into the
	// value this step contributes. A resolver-thrown error surfaces on the field.
	RenderResponse(ctx map[string]any) (any, error)
}

// Validator is an OPTIONAL capability a runtime may expose so the engine can fail closed at config
// load (handoff §2 negative-proof bar): validate every template up front and, if one is malformed,
// keep the WHOLE config from serving rather than discovering it on the first request. It is separate
// from the three-term Runtime contract on purpose — execution and pre-validation are different jobs,
// and a runtime that genuinely cannot pre-validate simply does not implement this.
type Validator interface {
	// Validate reports whether the runtime's templates are well-formed, without executing them.
	Validate() error
}
