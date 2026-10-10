package vtl

import sharedvtl "github.com/harn3ss/open-infra/vtl"

// The Velocity core moved to the shared module github.com/harn3ss/open-infra/vtl so the aws-shim's
// API Gateway mapping templates reuse the exact same parser/evaluator (one implementation, no drift).
// This file keeps open-appsync a THIN wrapper over it: only AppSync's concrete $util (util.go) stays
// here. Engine wraps *sharedvtl.Engine but keeps Util() returning the CONCRETE *Util, so every
// existing caller is source-unchanged — probes still pin Util().AutoID/Now, and the JS runtime still
// reuses the single *Util via engine.Util().

// Engine renders AppSync VTL templates over the shared Velocity core bound to AppSync's $util.
type Engine struct {
	inner *sharedvtl.Engine
	util  *Util
}

// New returns an Engine with real AppSync $util providers. For deterministic probes, set the fields of
// Util() (AutoID/Now) — the engine holds the same *Util, so the pin takes effect on the next render.
func New() *Engine {
	u := NewUtil()
	return &Engine{inner: sharedvtl.New(u), util: u}
}

// Util exposes the concrete AppSync $util so a probe can pin autoId/time.* for byte-exact assertions
// and the JS runtime can reuse the single $util implementation.
func (e *Engine) Util() *Util { return e.util }

// Render evaluates a template against a resolver context (available as $ctx / $context).
func (e *Engine) Render(tmpl string, ctx map[string]any) (string, error) {
	return e.inner.Render(tmpl, ctx)
}

// Validate parses a template into its block tree WITHOUT evaluating it (the fail-closed load bar).
func (e *Engine) Validate(tmpl string) error { return e.inner.Validate(tmpl) }
