package vtl

import (
	"errors"
	"testing"
)

// nopUtil is a $util that implements no methods — the engine-only tests below never touch $util, so
// an unknown-method stub is all they need. (The AppSync $util fidelity tests live with the concrete
// Util in open-appsync/internal/vtl.)
type nopUtil struct{}

func (nopUtil) Invoke(path string, args []any) (any, error, bool) { return nil, nil, false }
func (nopUtil) Call(path string, args []any) (any, error)         { return nil, errors.New("vtl: no $util") }

func render(t *testing.T, tmpl string, ctx map[string]any) string {
	t.Helper()
	out, err := New(nopUtil{}).Render(tmpl, ctx)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	return out
}

func TestRender_ContextInterpolation(t *testing.T) {
	out := render(t, `hello $ctx.args.name!`, map[string]any{"args": map[string]any{"name": "erin"}})
	if out != "hello erin!" {
		t.Fatalf("got %q", out)
	}
}

func TestRender_SetAndIfElse(t *testing.T) {
	tmpl := `#set($n = $ctx.args.n)#if($n > 10)big#{elseif}($n > 0)small#else none#end`
	if out := render(t, tmpl, map[string]any{"args": map[string]any{"n": float64(42)}}); out != "big" {
		t.Fatalf("n=42 got %q want big", out)
	}
	if out := render(t, tmpl, map[string]any{"args": map[string]any{"n": float64(3)}}); out != "small" {
		t.Fatalf("n=3 got %q want small", out)
	}
	if out := render(t, tmpl, map[string]any{"args": map[string]any{"n": float64(-1)}}); out != " none" {
		t.Fatalf("n=-1 got %q want ' none'", out)
	}
}

func TestRender_Foreach(t *testing.T) {
	tmpl := `#foreach($x in $ctx.args.list)[$x]#end`
	out := render(t, tmpl, map[string]any{"args": map[string]any{"list": []any{"a", "b", "c"}}})
	if out != "[a][b][c]" {
		t.Fatalf("got %q", out)
	}
}

func TestRender_UndefinedQuietVsNonQuiet(t *testing.T) {
	// Non-quiet undefined renders its literal text (Velocity); quiet renders empty.
	if out := render(t, `x=$ctx.args.missing`, map[string]any{"args": map[string]any{}}); out != "x=$ctx.args.missing" {
		t.Fatalf("non-quiet got %q", out)
	}
	if out := render(t, `x=$!ctx.args.missing`, map[string]any{"args": map[string]any{}}); out != "x=" {
		t.Fatalf("quiet got %q", out)
	}
}

// receiverStub exercises the Receiver hook: a host value with a property and a method.
type receiverStub struct{ body string }

func (r receiverStub) GetProp(name string) (any, bool) {
	if name == "body" {
		return r.body, true
	}
	return nil, false
}
func (r receiverStub) CallMethod(name string, args []any) (any, bool) {
	if name == "echo" && len(args) > 0 {
		return args[0], true
	}
	return nil, false
}

func TestRender_ReceiverPropertyAndMethod(t *testing.T) {
	out, err := New(nopUtil{}).RenderVars(
		`$input.body|$input.echo("hi")`,
		map[string]any{"input": receiverStub{body: "B"}},
	)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	if out != "B|hi" {
		t.Fatalf("got %q want %q", out, "B|hi")
	}
}

func TestRenderVars_TopLevelBinding(t *testing.T) {
	out, err := New(nopUtil{}).RenderVars(`$a-$b`, map[string]any{"a": "x", "b": "y"})
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	if out != "x-y" {
		t.Fatalf("got %q", out)
	}
}
