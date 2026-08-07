// Package jsruntime is the SECOND tenant of the runtime extension point — the rung
// that earns the stability claim. Drop 32 proved the interface implementable with a trivial
// staticRuntime; a real, non-VTL, production-shaped runtime proves it SUFFICIENT. It implements
// runtime.Runtime by running an AppSync-style JavaScript resolver module (exporting request(ctx) and
// response(ctx)) — through the EXACT same lifecycle as VTL, with no backstage pass.
//
// Sandboxing (a real security problem, stated honestly): user JavaScript is untrusted code, and the
// audience this project serves is the least able to survive a resolver that reads the filesystem or
// opens a socket. So the JS engine is goja (pure-Go ECMAScript): it has NO require, NO Node APIs, NO
// fs/net/fetch, NO timers — capability-by-injection, deny-by-absence. The ONLY capability a resolver
// gets is the `util` object we inject. A fresh goja.Runtime is created per invocation (goja runtimes
// are not goroutine-safe); the compiled program is shared. Reuses vtl.Util so $util fidelity is the
// single implementation both runtimes share — no second copy to drift.
package jsruntime

import (
	"fmt"

	"github.com/dop251/goja"
	"github.com/harn3ss/open-infra/open-appsync/internal/runtime"
	"github.com/harn3ss/open-infra/open-appsync/internal/vtl"
)

// Runtime runs one resolver's JavaScript (a module defining request(ctx) and response(ctx)).
type Runtime struct {
	util    *vtl.Util
	program *goja.Program
}

// New compiles the JavaScript resolver module. A syntax error fails here so the config fails closed.
func New(util *vtl.Util, source string) (*Runtime, error) {
	prog, err := goja.Compile("resolver.js", source, true)
	if err != nil {
		return nil, fmt.Errorf("jsruntime: compile: %w", err)
	}
	return &Runtime{util: util, program: prog}, nil
}

// RenderRequest runs request(ctx). It returns a nil Operation when request returns null/undefined
// (a no-Operation step, the loosened Out term); otherwise the returned object is the neutral Operation.
func (r *Runtime) RenderRequest(ctx map[string]any) (runtime.Operation, error) {
	v, err := r.invoke("request", ctx)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}
	op, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("jsruntime: request() must return an object, got %T", v)
	}
	return op, nil
}

// RenderResponse runs response(ctx) — ctx.result is already set by the lifecycle — and returns its value.
func (r *Runtime) RenderResponse(ctx map[string]any) (any, error) {
	return r.invoke("response", ctx)
}

// Validate confirms the module compiles and defines request/response functions (fail-closed load).
func (r *Runtime) Validate() error {
	vm := goja.New()
	r.installUtil(vm)
	if _, err := vm.RunProgram(r.program); err != nil {
		return fmt.Errorf("jsruntime: %w", err)
	}
	for _, fn := range []string{"request", "response"} {
		if _, ok := goja.AssertFunction(vm.Get(fn)); !ok {
			return fmt.Errorf("jsruntime: resolver must define a %s(ctx) function", fn)
		}
	}
	return nil
}

// invoke runs fn(ctx) in a FRESH sandboxed vm — the only capability is the injected `util`; everything
// else (require, fs, fetch, process, timers) is absent, so a resolver reaching for it fails closed.
func (r *Runtime) invoke(fn string, ctx map[string]any) (v any, err error) {
	vm := goja.New()
	r.installUtil(vm)
	if _, err := vm.RunProgram(r.program); err != nil {
		return nil, jsError(err)
	}
	callable, ok := goja.AssertFunction(vm.Get(fn))
	if !ok {
		return nil, fmt.Errorf("jsruntime: resolver does not define %s(ctx)", fn)
	}
	res, err := callable(goja.Undefined(), vm.ToValue(ctx))
	if err != nil {
		return nil, jsError(err)
	}
	if res == nil || goja.IsUndefined(res) || goja.IsNull(res) {
		return nil, nil
	}
	return res.Export(), nil
}

// jsError turns a thrown JS value into a Go error: a util.error surfaces as its *vtl.ThrowError (so
// the field carries the AppSync errorType); anything else (a ReferenceError from touching an absent
// capability, a TypeError, …) is returned as a plain error — fail closed.
func jsError(err error) error {
	if exc, ok := err.(*goja.Exception); ok {
		if te, ok := exc.Value().Export().(*vtl.ThrowError); ok {
			return te
		}
	}
	return err
}

// installUtil injects the ONLY capability a resolver has: the `util` object, backed by the shared
// vtl.Util so $util behaviour is identical to VTL's.
func (r *Runtime) installUtil(vm *goja.Runtime) {
	util := vm.NewObject()
	_ = util.Set("autoId", func() string { return r.util.AutoID() })
	_ = util.Set("toJson", func(v goja.Value) (string, error) {
		s, err := r.util.Call("toJson", []any{v.Export()})
		if err != nil {
			return "", err
		}
		return s.(string), nil
	})
	_ = util.Set("error", func(call goja.FunctionCall) goja.Value {
		msg := call.Argument(0).String()
		typ := ""
		if len(call.Arguments) > 1 && !goja.IsUndefined(call.Argument(1)) {
			typ = call.Argument(1).String()
		}
		panic(vm.ToValue(&vtl.ThrowError{Message: msg, ErrorType: typ}))
	})

	dynamodb := vm.NewObject()
	_ = dynamodb.Set("toDynamoDB", func(v goja.Value) any { return r.util.ToDynamoDB(v.Export()) })
	_ = dynamodb.Set("toMapValues", func(v goja.Value) any { return r.util.ToMapValues(v.Export()) })
	_ = util.Set("dynamodb", dynamodb)

	_ = vm.Set("util", util)
}
