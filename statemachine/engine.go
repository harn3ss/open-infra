// The ASL interpreter: walk a Definition from a start state over a data value,
// invoking Task states and applying Choice/Wait/Pass/Succeed/Fail, with Retry,
// Catch, and per-state + per-execution timeouts. The engine is deliberately free of
// Kubernetes and HTTP specifics — it depends on a TaskInvoker and a set of callbacks
// so it can be exercised end-to-end in unit tests.
package main

import (
	"context"
	"fmt"
	"math"
	"time"
)

// Result is the terminal outcome of an execution.
type Result struct {
	Phase  string // Succeeded | Failed | TimedOut
	Output any
	Error  string
	Cause  string
}

// Engine runs one execution of one Definition.
type Engine struct {
	def     *Definition
	invoker TaskInvoker
	ctxObj  map[string]any

	// checkpoint persists the about-to-run state and current data (and, for a Wait,
	// when it will resume) so a controller restart can resume the execution.
	checkpoint func(state string, data any, waitUntil *time.Time) error
	// record appends an execution-history event (best-effort; errors ignored).
	record func(event map[string]any)

	// Injectable clock/sleep for tests.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error

	// resumeWait, when set, is the absolute resume time for the FIRST Wait state the
	// engine runs — set on resume so a checkpointed Wait honors its original deadline
	// instead of restarting the full duration. Consumed once.
	resumeWait *time.Time

	start time.Time
}

func newEngine(def *Definition, invoker TaskInvoker, ctxObj map[string]any) *Engine {
	return &Engine{
		def:        def,
		invoker:    invoker,
		ctxObj:     ctxObj,
		checkpoint: func(string, any, *time.Time) error { return nil },
		record:     func(map[string]any) {},
		now:        time.Now,
		sleep:      defaultSleep,
	}
}

func defaultSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type transition struct {
	next string  // next state to run
	data any     // data to carry into it
	done *Result // set when the execution has reached a terminal state
}

// Run executes from startState over data. For a fresh execution pass def.StartAt and
// the parsed input; to resume, pass the checkpointed state and data.
func (e *Engine) Run(ctx context.Context, startState string, data any) Result {
	e.start = e.now()
	state := startState
	for {
		s, ok := e.def.States[state]
		if !ok {
			return Result{Phase: "Failed", Error: ErrRuntime, Cause: fmt.Sprintf("no such state %q", state)}
		}
		if e.def.TimeoutSeconds > 0 && e.now().Sub(e.start) > time.Duration(e.def.TimeoutSeconds)*time.Second {
			return Result{Phase: "TimedOut", Error: ErrTimeout, Cause: "execution exceeded TimeoutSeconds"}
		}
		if e.ctxObj != nil {
			e.ctxObj["State"] = map[string]any{"Name": state, "EnteredTime": e.now().UTC().Format(time.RFC3339)}
		}
		var waitUntil *time.Time
		if s.Type == "Wait" {
			// Wait computes its own resume time; the checkpoint below records it.
		}
		if err := e.checkpoint(state, data, waitUntil); err != nil {
			return Result{Phase: "Failed", Error: ErrRuntime, Cause: "checkpoint failed: " + err.Error()}
		}
		e.record(map[string]any{"type": "StateEntered", "state": state, "time": e.now().UTC().Format(time.RFC3339)})

		var tr transition
		switch s.Type {
		case "Task":
			tr = e.runTask(ctx, state, s, data)
		case "Pass":
			tr = e.runPass(state, s, data)
		case "Wait":
			tr = e.runWait(ctx, state, s, data)
		case "Choice":
			tr = e.runChoice(state, s, data)
		case "Succeed":
			tr = e.runSucceed(state, s, data)
		case "Fail":
			tr = transition{done: &Result{Phase: "Failed", Error: s.Error, Cause: s.Cause}}
		case "Parallel", "Map":
			tr = failRuntime(fmt.Sprintf("state type %q is not implemented in v1", s.Type))
		default:
			tr = failRuntime(fmt.Sprintf("unknown state type %q", s.Type))
		}

		if tr.done != nil {
			if tr.done.Phase == "Succeeded" {
				e.record(map[string]any{"type": "ExecutionSucceeded", "time": e.now().UTC().Format(time.RFC3339)})
			} else {
				e.record(map[string]any{"type": "ExecutionFailed", "state": state, "error": tr.done.Error, "time": e.now().UTC().Format(time.RFC3339)})
			}
			return *tr.done
		}
		state, data = tr.next, tr.data
	}
}

func failRuntime(cause string) transition {
	return transition{done: &Result{Phase: "Failed", Error: ErrRuntime, Cause: cause}}
}

// advance turns a computed output into either the next state or a successful finish.
func (e *Engine) advance(s State, out any) transition {
	if s.End {
		return transition{done: &Result{Phase: "Succeeded", Output: out}}
	}
	if s.Next == "" {
		return failRuntime("state has neither Next nor End: true")
	}
	return transition{next: s.Next, data: out}
}

func (e *Engine) runTask(ctx context.Context, name string, s State, data any) transition {
	effInput, err := applyInputPath(data, e.ctxObj, s.InputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	params, err := resolveParameters(s.Parameters, effInput, e.ctxObj)
	if err != nil {
		return failRuntime(err.Error())
	}

	attempts := make([]int, len(s.Retry))
	for {
		result, terr := e.invoker.Invoke(ctx, s.Resource, params, s.TimeoutSeconds)
		if terr == nil {
			combined, err := applyResultPath(effInput, result, s.ResultPath.orDefault("$"))
			if err != nil {
				return failRuntime(err.Error())
			}
			out, err := applyOutputPath(combined, e.ctxObj, s.OutputPath.orDefault("$"))
			if err != nil {
				return failRuntime(err.Error())
			}
			return e.advance(s, out)
		}
		e.record(map[string]any{"type": "TaskFailed", "state": name, "error": terr.Name, "cause": terr.Cause, "time": e.now().UTC().Format(time.RFC3339)})

		// Retry: first matching retrier with attempts remaining.
		if ri := firstMatch(len(s.Retry), func(i int) bool { return matchesError(s.Retry[i].ErrorEquals, terr.Name) }); ri >= 0 {
			r := s.Retry[ri]
			if attempts[ri] < r.maxAttempts() {
				d := backoffDelay(r, attempts[ri])
				attempts[ri]++
				e.record(map[string]any{"type": "TaskRetry", "state": name, "attempt": attempts[ri], "delaySeconds": d.Seconds(), "time": e.now().UTC().Format(time.RFC3339)})
				if err := e.sleep(ctx, d); err != nil {
					return Result2Transition(ctx)
				}
				continue
			}
		}
		// Catch: first matching catcher.
		if ci := firstMatch(len(s.Catch), func(i int) bool { return matchesError(s.Catch[i].ErrorEquals, terr.Name) }); ci >= 0 {
			c := s.Catch[ci]
			errObj := map[string]any{"Error": terr.Name, "Cause": terr.Cause}
			cd, err := applyResultPath(effInput, errObj, c.ResultPath.orDefault("$"))
			if err != nil {
				return failRuntime(err.Error())
			}
			e.record(map[string]any{"type": "TaskCaught", "state": name, "next": c.Next, "error": terr.Name, "time": e.now().UTC().Format(time.RFC3339)})
			return transition{next: c.Next, data: cd}
		}
		return transition{done: &Result{Phase: "Failed", Error: terr.Name, Cause: terr.Cause}}
	}
}

// Result2Transition maps a cancelled context (controller shutdown) to a failed
// terminal — the execution is left checkpointed and will resume on the next start.
func Result2Transition(ctx context.Context) transition {
	return transition{done: &Result{Phase: "Failed", Error: ErrRuntime, Cause: "controller stopped: " + ctx.Err().Error()}}
}

func (e *Engine) runPass(name string, s State, data any) transition {
	effInput, err := applyInputPath(data, e.ctxObj, s.InputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	var result any = effInput
	if len(s.Result) > 0 {
		if err := jsonInto(s.Result, &result); err != nil {
			return failRuntime("Pass Result is not valid JSON: " + err.Error())
		}
	} else if len(s.Parameters) > 0 {
		result, err = resolveParameters(s.Parameters, effInput, e.ctxObj)
		if err != nil {
			return failRuntime(err.Error())
		}
	}
	combined, err := applyResultPath(effInput, result, s.ResultPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	out, err := applyOutputPath(combined, e.ctxObj, s.OutputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	return e.advance(s, out)
}

func (e *Engine) runWait(ctx context.Context, name string, s State, data any) transition {
	effInput, err := applyInputPath(data, e.ctxObj, s.InputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	var until time.Time
	if e.resumeWait != nil {
		until = *e.resumeWait
		e.resumeWait = nil
		goto sleepPhase
	}
	switch {
	case s.Seconds != nil:
		until = e.now().Add(time.Duration(*s.Seconds) * time.Second)
	case s.SecondsPath != "":
		v, ok, err := getPath(effInput, e.ctxObj, s.SecondsPath)
		if err != nil || !ok {
			return failRuntime(fmt.Sprintf("Wait SecondsPath %q did not resolve", s.SecondsPath))
		}
		f, ok := toFloat(v)
		if !ok {
			return failRuntime("Wait SecondsPath did not resolve to a number")
		}
		until = e.now().Add(time.Duration(f) * time.Second)
	case s.Timestamp != "":
		t, err := time.Parse(time.RFC3339, s.Timestamp)
		if err != nil {
			return failRuntime("Wait Timestamp is not RFC3339: " + err.Error())
		}
		until = t
	case s.TimestampPath != "":
		v, ok, err := getPath(effInput, e.ctxObj, s.TimestampPath)
		if err != nil || !ok {
			return failRuntime(fmt.Sprintf("Wait TimestampPath %q did not resolve", s.TimestampPath))
		}
		str, _ := v.(string)
		t, err := time.Parse(time.RFC3339, str)
		if err != nil {
			return failRuntime("Wait TimestampPath is not an RFC3339 string")
		}
		until = t
	default:
		return failRuntime("Wait state has none of Seconds/SecondsPath/Timestamp/TimestampPath")
	}

sleepPhase:
	// Persist the resume time so a restart mid-wait honors it.
	if err := e.checkpoint(name, effInput, &until); err != nil {
		return failRuntime("checkpoint failed: " + err.Error())
	}
	if d := until.Sub(e.now()); d > 0 {
		if err := e.sleep(ctx, d); err != nil {
			return Result2Transition(ctx)
		}
	}
	out, err := applyOutputPath(effInput, e.ctxObj, s.OutputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	return e.advance(s, out)
}

func (e *Engine) runChoice(name string, s State, data any) transition {
	effInput, err := applyInputPath(data, e.ctxObj, s.InputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	for _, rule := range s.Choices {
		match, err := rule.eval(effInput, e.ctxObj)
		if err != nil {
			return failRuntime(err.Error())
		}
		if match {
			out, err := applyOutputPath(effInput, e.ctxObj, s.OutputPath.orDefault("$"))
			if err != nil {
				return failRuntime(err.Error())
			}
			return transition{next: rule.Next(), data: out}
		}
	}
	if s.Default != "" {
		out, err := applyOutputPath(effInput, e.ctxObj, s.OutputPath.orDefault("$"))
		if err != nil {
			return failRuntime(err.Error())
		}
		return transition{next: s.Default, data: out}
	}
	return transition{done: &Result{Phase: "Failed", Error: "States.NoChoiceMatched", Cause: "no Choices matched and no Default"}}
}

func (e *Engine) runSucceed(name string, s State, data any) transition {
	effInput, err := applyInputPath(data, e.ctxObj, s.InputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	out, err := applyOutputPath(effInput, e.ctxObj, s.OutputPath.orDefault("$"))
	if err != nil {
		return failRuntime(err.Error())
	}
	return transition{done: &Result{Phase: "Succeeded", Output: out}}
}

// backoffDelay is IntervalSeconds * BackoffRate^attempt, capped by MaxDelaySeconds.
func backoffDelay(r Retrier, attempt int) time.Duration {
	secs := float64(r.interval()) * math.Pow(r.backoff(), float64(attempt))
	if r.MaxDelaySeconds > 0 && secs > float64(r.MaxDelaySeconds) {
		secs = float64(r.MaxDelaySeconds)
	}
	return time.Duration(secs * float64(time.Second))
}

func firstMatch(n int, pred func(int) bool) int {
	for i := 0; i < n; i++ {
		if pred(i) {
			return i
		}
	}
	return -1
}
