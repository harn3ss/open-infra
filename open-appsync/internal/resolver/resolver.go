// Package resolver is open-appsync's resolver lifecycle (handoff §3.1 piece 4): the request-execute-
// response cycle that IS the AppSync resolver contract. Getting it exactly right is what makes a
// specialist's existing VTL resolver run unmodified:
//
//	field hit → render REQUEST template (args → data-source operation)
//	         → data source executes the operation
//	         → render RESPONSE template (raw result → the GraphQL shape)
//	         → return
//
// A $util.error() in either template aborts the field with the AppSync error shape (a *vtl.ThrowError).
package resolver

import (
	"encoding/json"
	"fmt"

	"github.com/harn3ss/open-infra/open-appsync/internal/dynamodb"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
)

// Resolver binds a field to its request/response mapping templates and a data source (a unit
// resolver — pipeline resolvers are a later rung).
type Resolver struct {
	Request  string
	Response string
	Source   dynamodb.Store
}

// Resolve runs the request→execute→response cycle. ctx is the resolver context ($ctx): it must
// carry "args" (and optionally identity/source); Resolve sets ctx["result"] to the data-source
// result before rendering the response template, exactly as AppSync does.
func (r Resolver) Resolve(e *vtl.Engine, ctx map[string]any) (any, error) {
	// 1. Request mapping template → a data-source operation document.
	reqOut, err := e.Render(r.Request, ctx)
	if err != nil {
		return nil, err // includes *vtl.ThrowError from a validation $util.error()
	}
	var op map[string]any
	if err := json.Unmarshal([]byte(reqOut), &op); err != nil {
		return nil, fmt.Errorf("resolver: request template did not emit a JSON operation: %w\n---\n%s", err, reqOut)
	}

	// 2. Execute against the data source; its (un-marshalled) result becomes $ctx.result.
	result, err := r.Source.Execute(op)
	if err != nil {
		return nil, err
	}
	ctx["result"] = result

	// 3. Response mapping template → the GraphQL field value.
	respOut, err := e.Render(r.Response, ctx)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal([]byte(respOut), &v); err != nil {
		return nil, fmt.Errorf("resolver: response template did not emit JSON: %w\n---\n%s", err, respOut)
	}
	return v, nil
}
