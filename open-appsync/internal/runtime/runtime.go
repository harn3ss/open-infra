// Package runtime is open-appsync's resolver-runtime extension point (handoff §2.5). A "runtime" is
// what turns a resolver's context into work for a data source and the result back into a GraphQL
// value. AppSync structurally allows exactly two runtimes (VTL and its JS flavour) and no third-party
// can add one. Because open-appsync committed to open, `runtime` here is a REAL extension point: a
// stranger can implement a runtime we never wrote — but only if the contract underneath is frozen
// tight enough to implement against without asking us questions. That contract is exactly three terms:
//
//  1. In    — what a runtime receives: the resolver $ctx (arguments, identity, source, and — for the
//             response phase — the data-source result at ctx["result"]).
//  2. Out   — what it emits: a neutral Operation, a shape the data source understands REGARDLESS of
//             which runtime produced it. Today VTL renders this; a JS runtime must render the same.
//  3. Error — how errors and null propagate: a runtime returns (value, error); a resolver-thrown
//             error (e.g. VTL's $util.error()) is returned as a normal error and surfaces on the field.
//
// VTL is the first tenant (internal/vtlruntime) and it plugs in through THIS interface with no
// backstage pass — if it needed a shortcut the others won't have, the seam would be theatre. The
// interface is deliberately NOT blessed as a stable/public extension point on one implementation:
// it is proven with VTL through the front door and (in tests) a second trivial runtime, and stays
// internal and changeable until a real second tenant lands. Openness earned by two tenants, not
// declared on one.
package runtime

// Operation is the neutral data-source operation — the "Out" term. It is the vendor-neutral document a
// runtime emits and a data source executes (e.g. {"operation":"GetItem","key":{"id":{"S":"1"}}} for
// the DynamoDB-style source). It is an alias for a plain map so any runtime can build one without
// importing a bespoke type, and so the data source reads it with ordinary map access; naming it here
// makes the data-source layer speak the neutral contract rather than "whatever VTL rendered".
type Operation = map[string]any

// Runtime is the resolver-runtime contract: the three frozen terms above and nothing more.
//
// The lifecycle a resolver drives is: RenderRequest(ctx) → Operation → (data source executes it) →
// ctx["result"] = result → RenderResponse(ctx) → field value. A runtime is stateless per call; the
// same instance serves every request for its resolver.
type Runtime interface {
	// RenderRequest turns the resolver $ctx into a neutral data-source Operation. A resolver-thrown
	// error (validation abort) is returned as an error; the data source is never touched.
	RenderRequest(ctx map[string]any) (Operation, error)
	// RenderResponse turns the data-source result — already placed at ctx["result"] — into the
	// GraphQL field value. A resolver-thrown error surfaces on the field.
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
