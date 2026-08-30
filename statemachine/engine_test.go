package main

import (
	"context"
	"reflect"
	"testing"
	"time"
)

type fakeInvoker struct {
	fn    func(resource string, input any) (any, *taskError)
	calls int
}

func (f *fakeInvoker) Invoke(_ context.Context, resource string, input any, _ int) (any, *taskError) {
	f.calls++
	return f.fn(resource, input)
}

func mustDef(t *testing.T, s string) *Definition {
	t.Helper()
	d, err := ParseDefinition([]byte(s))
	if err != nil {
		t.Fatalf("ParseDefinition: %v", err)
	}
	return d
}

// newTestEngine wires an engine with an instant sleep so Wait/Retry don't stall tests.
func newTestEngine(def *Definition, inv TaskInvoker) *Engine {
	e := newEngine(def, inv, map[string]any{"Execution": map[string]any{"Name": "t"}})
	e.sleep = func(context.Context, time.Duration) error { return nil }
	return e
}

func TestLinearTaskChain(t *testing.T) {
	def := mustDef(t, `{"StartAt":"A","States":{
		"A":{"Type":"Task","Resource":"function:double","ResultPath":"$.doubled","Next":"B"},
		"B":{"Type":"Succeed"}}}`)
	inv := &fakeInvoker{fn: func(_ string, input any) (any, *taskError) {
		n := input.(map[string]any)["n"].(float64)
		return n * 2, nil
	}}
	res := newTestEngine(def, inv).Run(context.Background(), "A", mustJSON(t, `{"n":3}`))
	if res.Phase != "Succeeded" {
		t.Fatalf("phase=%s cause=%s", res.Phase, res.Cause)
	}
	want := mustJSON(t, `{"n":3,"doubled":6}`)
	if !reflect.DeepEqual(res.Output, want) {
		t.Fatalf("output=%v want %v", res.Output, want)
	}
}

func TestRetryThenSucceed(t *testing.T) {
	def := mustDef(t, `{"StartAt":"A","States":{
		"A":{"Type":"Task","Resource":"function:flaky",
		     "Retry":[{"ErrorEquals":["States.TaskFailed"],"MaxAttempts":3,"IntervalSeconds":1}],
		     "End":true}}}`)
	inv := &fakeInvoker{fn: func(_ string, _ any) (any, *taskError) { return nil, nil }}
	fails := 2
	inv.fn = func(_ string, _ any) (any, *taskError) {
		if fails > 0 {
			fails--
			return nil, &taskError{ErrTaskFailed, "boom"}
		}
		return "ok", nil
	}
	res := newTestEngine(def, inv).Run(context.Background(), "A", nil)
	if res.Phase != "Succeeded" || res.Output != "ok" {
		t.Fatalf("phase=%s output=%v cause=%s", res.Phase, res.Output, res.Cause)
	}
	if inv.calls != 3 {
		t.Fatalf("calls=%d want 3 (2 retries + success)", inv.calls)
	}
}

func TestRetryExhaustedFails(t *testing.T) {
	def := mustDef(t, `{"StartAt":"A","States":{
		"A":{"Type":"Task","Resource":"function:x",
		     "Retry":[{"ErrorEquals":["States.ALL"],"MaxAttempts":1,"IntervalSeconds":1}],
		     "End":true}}}`)
	inv := &fakeInvoker{fn: func(_ string, _ any) (any, *taskError) { return nil, &taskError{ErrTaskFailed, "always"} }}
	res := newTestEngine(def, inv).Run(context.Background(), "A", nil)
	if res.Phase != "Failed" || res.Error != ErrTaskFailed {
		t.Fatalf("phase=%s error=%s", res.Phase, res.Error)
	}
	if inv.calls != 2 {
		t.Fatalf("calls=%d want 2 (initial + 1 retry)", inv.calls)
	}
}

func TestCatch(t *testing.T) {
	def := mustDef(t, `{"StartAt":"A","States":{
		"A":{"Type":"Task","Resource":"function:x",
		     "Catch":[{"ErrorEquals":["MyError"],"ResultPath":"$.err","Next":"Handler"}],"End":true},
		"Handler":{"Type":"Pass","Result":{"handled":true},"ResultPath":"$.h","End":true}}}`)
	inv := &fakeInvoker{fn: func(_ string, _ any) (any, *taskError) { return nil, &taskError{"MyError", "detail"} }}
	res := newTestEngine(def, inv).Run(context.Background(), "A", mustJSON(t, `{"n":1}`))
	if res.Phase != "Succeeded" {
		t.Fatalf("phase=%s cause=%s", res.Phase, res.Cause)
	}
	out := res.Output.(map[string]any)
	errObj, ok := out["err"].(map[string]any)
	if !ok || errObj["Error"] != "MyError" {
		t.Fatalf("catch did not place error object: %v", res.Output)
	}
	if h, ok := out["h"].(map[string]any); !ok || h["handled"] != true {
		t.Fatalf("handler result missing: %v", res.Output)
	}
}

func TestChoiceRouting(t *testing.T) {
	def := mustDef(t, `{"StartAt":"C","States":{
		"C":{"Type":"Choice","Choices":[{"Variable":"$.x","NumericGreaterThan":3,"Next":"Big"}],"Default":"Small"},
		"Big":{"Type":"Pass","Result":"big","End":true},
		"Small":{"Type":"Pass","Result":"small","End":true}}}`)
	eng := func() *Engine {
		return newTestEngine(def, &fakeInvoker{fn: func(string, any) (any, *taskError) { return nil, nil }})
	}
	if res := eng().Run(context.Background(), "C", mustJSON(t, `{"x":5}`)); res.Output != "big" {
		t.Fatalf("x=5 -> %v want big", res.Output)
	}
	if res := eng().Run(context.Background(), "C", mustJSON(t, `{"x":1}`)); res.Output != "small" {
		t.Fatalf("x=1 -> %v want small", res.Output)
	}
}

func TestWaitPassesInputThrough(t *testing.T) {
	def := mustDef(t, `{"StartAt":"W","States":{
		"W":{"Type":"Wait","Seconds":1,"Next":"D"},
		"D":{"Type":"Succeed"}}}`)
	res := newTestEngine(def, &fakeInvoker{fn: func(string, any) (any, *taskError) { return nil, nil }}).
		Run(context.Background(), "W", mustJSON(t, `{"keep":"me"}`))
	if res.Phase != "Succeeded" {
		t.Fatalf("phase=%s", res.Phase)
	}
	if !reflect.DeepEqual(res.Output, mustJSON(t, `{"keep":"me"}`)) {
		t.Fatalf("wait output=%v", res.Output)
	}
}

func TestFailState(t *testing.T) {
	def := mustDef(t, `{"StartAt":"F","States":{"F":{"Type":"Fail","Error":"BadThing","Cause":"nope"}}}`)
	res := newTestEngine(def, &fakeInvoker{fn: func(string, any) (any, *taskError) { return nil, nil }}).
		Run(context.Background(), "F", nil)
	if res.Phase != "Failed" || res.Error != "BadThing" || res.Cause != "nope" {
		t.Fatalf("got %+v", res)
	}
}

func TestParametersReachTask(t *testing.T) {
	def := mustDef(t, `{"StartAt":"A","States":{
		"A":{"Type":"Task","Resource":"function:echo","Parameters":{"val.$":"$.x","lit":1},"End":true}}}`)
	var seen any
	inv := &fakeInvoker{fn: func(_ string, input any) (any, *taskError) { seen = input; return input, nil }}
	newTestEngine(def, inv).Run(context.Background(), "A", mustJSON(t, `{"x":42}`))
	if !reflect.DeepEqual(seen, mustJSON(t, `{"val":42,"lit":1}`)) {
		t.Fatalf("task saw %v want {val:42,lit:1}", seen)
	}
}

func TestDanglingTransitionRejectedAtParse(t *testing.T) {
	_, err := ParseDefinition([]byte(`{"StartAt":"A","States":{"A":{"Type":"Pass","Next":"Ghost"}}}`))
	if err == nil {
		t.Fatal("expected parse error for dangling Next")
	}
}

func TestParallelNotImplemented(t *testing.T) {
	def := mustDef(t, `{"StartAt":"P","States":{"P":{"Type":"Parallel","End":true}}}`)
	res := newTestEngine(def, &fakeInvoker{fn: func(string, any) (any, *taskError) { return nil, nil }}).
		Run(context.Background(), "P", nil)
	if res.Phase != "Failed" || res.Error != ErrRuntime {
		t.Fatalf("Parallel should fail with States.Runtime, got %+v", res)
	}
}
