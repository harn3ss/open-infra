// Package resolver is open-appsync's resolver lifecycle (handoff §3.1 piece 4): the request-execute-
// response cycle that IS the AppSync resolver contract. It drives a runtime.Runtime — it knows
// nothing about VTL — so any runtime (VTL today, JS or a neutral format later) plugs in the same way:
//
//	field hit → runtime.RenderRequest($ctx)  → a neutral data-source Operation
//	         → data source executes the operation
//	         → $ctx.result = result
//	         → runtime.RenderResponse($ctx)   → the GraphQL field value
//	         → return
//
// A validation abort in the runtime (e.g. VTL's $util.error()) is returned as a normal error and
// surfaces on the field with the AppSync error shape (a *vtl.ThrowError, unwrapped by the executor).
package resolver

import (
	"context"

	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
)

// Resolver binds a field to a runtime (its mapping logic) and a data source (a unit resolver —
// pipeline resolvers are a later rung).
type Resolver struct {
	Runtime runtime.Runtime
	Source  dynamodb.Store
}

// Resolve runs the request→execute→response cycle. ctx is the resolver context ($ctx): it must carry
// "args" (and optionally identity/source); Resolve sets ctx["result"] to the data-source result
// before the response phase, exactly as AppSync does.
func (r Resolver) Resolve(reqCtx context.Context, ctx map[string]any) (any, error) {
	// 1. Request phase → a neutral data-source operation (or a validation abort).
	op, err := r.Runtime.RenderRequest(ctx)
	if err != nil {
		return nil, err
	}

	// 2. Execute against the data source; its (un-marshalled) result becomes $ctx.result.
	result, err := r.Source.Execute(reqCtx, op)
	if err != nil {
		return nil, err
	}
	ctx["result"] = result

	// 3. Response phase → the GraphQL field value.
	return r.Runtime.RenderResponse(ctx)
}
