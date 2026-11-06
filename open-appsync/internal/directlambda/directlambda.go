// Package directlambda is AppSync's DIRECT Lambda resolver: a resolver (or pipeline function) on a
// Lambda data source with no request and/or no response mapping template. AWS describes what it does in
// place of each missing template, and that is exactly what this runtime renders — it is a runtime tenant
// like VTL and JS, through the same runtime.Runtime front door, so the lifecycle does not branch on it.
//
// No request template: the resolver Context is sent to the function as the payload of an Invoke —
//
//	{"arguments", "identity", "source", "request": {"headers"}, "info": {"fieldName", "parentTypeName",
//	 "variables", "selectionSetList", "selectionSetGraphQL"}, "prev", "stash"}
//
// — or, with batching on (maxBatchSize > 0), of a BatchInvoke, so the function receives a LIST of
// Contexts, one per sibling resolution, at most maxBatchSize long.
//
// No response template: the function's return value is the field's value, and a thrown error is the
// field's GraphQL error with the function's errorType/errorMessage (raised by the Lambda source). With
// batching on, each item of the returned list is {"data", "errorMessage", "errorType"}: an item with an
// errorMessage is that field's error ($util.error(errorMessage, errorType, data)) and the field is null;
// otherwise the field is its data. That is AWS's documented default response,
//
//	#if( $context.result && $context.result.errorMessage )
//	  $utils.error($context.result.errorMessage, $context.result.errorType, $context.result.data)
//	#else
//	  $utils.toJson($context.result.data)
//	#end
//
// A resolver may give one of the two templates and leave the other to this runtime (AWS allows a
// request template, a response template, or neither); the template it gives runs as written.
package directlambda

import (
	"encoding/json"
	"fmt"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
)

// Runtime is one direct (or half-direct) Lambda step.
type Runtime struct {
	request  runtime.Runtime // the author's request template, or nil: the Context is the payload
	response runtime.Runtime // the author's response template, or nil: AWS's default response
	batch    bool            // maxBatchSize > 0: BatchInvoke, and the batched default response
}

var (
	_ runtime.Runtime   = (*Runtime)(nil)
	_ runtime.Validator = (*Runtime)(nil)
)

// New builds a direct Lambda step. request/response are the phases the resolver gives as templates
// (nil = the direct behavior for that phase); batch is maxBatchSize > 0.
func New(request, response runtime.Runtime, batch bool) *Runtime {
	return &Runtime{request: request, response: response, batch: batch}
}

// RenderRequest renders the author's request template if there is one; otherwise it sends the Context.
func (r *Runtime) RenderRequest(ctx map[string]any) (runtime.Operation, error) {
	if r.request != nil {
		return r.request.RenderRequest(ctx)
	}
	op := "Invoke"
	if r.batch {
		op = "BatchInvoke"
	}
	return runtime.Operation{"version": "2018-05-29", "operation": op, "payload": Event(ctx)}, nil
}

// RenderResponse renders the author's response template if there is one; otherwise it is AWS's default
// response: the result itself, or — batched — the item's data or its error.
func (r *Runtime) RenderResponse(ctx map[string]any) (any, error) {
	if r.response != nil {
		return r.response.RenderResponse(ctx)
	}
	res := ctx["result"]
	if !r.batch {
		return res, nil
	}
	item, ok := res.(map[string]any)
	if !ok {
		return nil, nil // a null item (valid), or one that is not an object: it has no data
	}
	if em := item["errorMessage"]; present(em) {
		return nil, &vtl.ThrowError{Message: text(em), ErrorType: text(item["errorType"]), Data: item["data"]}
	}
	return item["data"], nil
}

// Validate validates the templates the resolver gives (the direct phases have nothing to validate).
func (r *Runtime) Validate() error {
	for _, rt := range []runtime.Runtime{r.request, r.response} {
		if v, ok := rt.(runtime.Validator); ok {
			if err := v.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Event is the AppSync Context a direct Lambda resolver sends: the resolver context the engine built
// for the field, under AWS's names. An anonymous caller has a null identity (as AppSync's API_KEY mode
// does), and a root field a null source and prev.
func Event(ctx map[string]any) map[string]any {
	args, ok := ctx["arguments"]
	if !ok {
		args = ctx["args"]
	}
	if args == nil {
		args = map[string]any{}
	}
	stash := ctx["stash"]
	if stash == nil {
		stash = map[string]any{}
	}
	request := ctx["request"]
	if request == nil {
		request = map[string]any{"headers": map[string]any{}}
	}
	return map[string]any{
		"arguments": args,
		"identity":  identity(ctx["identity"]),
		"source":    ctx["source"],
		"request":   request,
		"info":      ctx["info"],
		"prev":      ctx["prev"],
		"stash":     stash,
	}
}

// identity is the caller's identity, or null for an anonymous one.
func identity(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	if u, _ := m["username"].(string); u != "" {
		return m
	}
	if g, _ := m["groups"].([]any); len(g) > 0 {
		return m
	}
	return nil
}

// present is VTL truthiness for an errorMessage: set and not empty.
func present(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	default:
		return true
	}
}

func text(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64, bool, json.Number:
		return fmt.Sprint(t)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}
