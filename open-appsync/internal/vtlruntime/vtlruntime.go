// Package vtlruntime is the FIRST tenant of the runtime extension point (handoff §2.5): it implements
// runtime.Runtime by rendering AppSync VTL request/response mapping templates. It holds the two
// templates and a *vtl.Engine and renders them to the neutral Operation / field value the contract
// asks for — nothing more. It reaches the resolver lifecycle only through the public runtime.Runtime
// interface, with no backstage pass; a second runtime (JS, or a neutral format) implements the same
// three terms and slots in identically. All AppSync-specific fidelity lives here and in internal/vtl,
// behind the neutral seam.
package vtlruntime

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
)

// Runtime is the appsync-vtl runtime for one resolver: its request + response mapping templates over
// a shared VTL engine. Construct one per resolver with New.
type Runtime struct {
	engine   *vtl.Engine
	request  string
	response string
}

// New builds the appsync-vtl runtime for a resolver from its request/response templates. The engine
// is shared across resolvers (it is stateless apart from its $util providers). Templates are parsed
// lazily on each render; call Validate to fail closed at load.
func New(engine *vtl.Engine, request, response string) *Runtime {
	return &Runtime{engine: engine, request: request, response: response}
}

// RenderRequest renders the request template against $ctx and decodes it into a neutral Operation.
// A template that renders to nothing (empty, or the literal null) emits NO Operation — a nil return —
// which the lifecycle reads as "this step only transformed $ctx; do not call a data source" (the
// loosened Out term; this is how a pipeline before-step is the same abstraction as a function). A
// $util.error() in the template returns a *vtl.ThrowError (validation abort) and no Operation.
func (r *Runtime) RenderRequest(ctx map[string]any) (runtime.Operation, error) {
	out, err := r.engine.Render(r.request, ctx)
	if err != nil {
		return nil, err // includes *vtl.ThrowError from a validation $util.error()
	}
	if t := strings.TrimSpace(out); t == "" || t == "null" {
		return nil, nil // no-operation step
	}
	var op runtime.Operation
	if err := json.Unmarshal([]byte(out), &op); err != nil {
		return nil, fmt.Errorf("vtlruntime: request template did not emit a JSON operation: %w\n---\n%s", err, out)
	}
	return op, nil
}

// RenderResponse renders the response template against $ctx (with ctx["result"] already set to the
// data-source result) and decodes it into the GraphQL field value.
func (r *Runtime) RenderResponse(ctx map[string]any) (any, error) {
	out, err := r.engine.Render(r.response, ctx)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return nil, fmt.Errorf("vtlruntime: response template did not emit JSON: %w\n---\n%s", err, out)
	}
	return v, nil
}

// Validate parses both templates without executing them, so a malformed resolver fails the whole
// config at load rather than on first request (runtime.Validator; handoff §2 fail-closed bar).
func (r *Runtime) Validate() error {
	if err := r.engine.Validate(r.request); err != nil {
		return fmt.Errorf("request template: %w", err)
	}
	if err := r.engine.Validate(r.response); err != nil {
		return fmt.Errorf("response template: %w", err)
	}
	return nil
}
