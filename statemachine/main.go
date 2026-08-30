// statemachine — open-infra's kind: StateMachine controller (the "Step Functions"
// execution engine). A single cluster-wide controller (deployed by
// statemachine-controller.yaml) watches kind: Execution objects across all
// namespaces; for each it reads the referenced StateMachine's ASL definition and
// runs the workflow — invoking Task states' Functions over their cluster-local URL,
// applying Choice/Wait/Pass/Retry/Catch, and checkpointing progress into the
// Execution's status so a Running execution resumes across a controller restart.
//
// Env: POLL_INTERVAL (seconds, default 5).
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	poll := 5
	if v := os.Getenv("POLL_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			poll = n
		}
	}

	client, err := newInClusterClient()
	if err != nil {
		log.Fatalf("kubernetes client: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	ctrl := &controller{client: client}
	ticker := time.NewTicker(time.Duration(poll) * time.Second)
	defer ticker.Stop()

	log.Printf("statemachine controller: watching executions cluster-wide, polling every %ds", poll)
	ctrl.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			log.Printf("statemachine controller: shutting down")
			ctrl.wg.Wait()
			return
		case <-ticker.C:
			ctrl.reconcile(ctx)
		}
	}
}

type controller struct {
	client *k8sClient
	active sync.Map // uid -> struct{}
	wg     sync.WaitGroup
}

func (c *controller) reconcile(ctx context.Context) {
	execs, err := c.client.listAllExecutions(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("list executions: %v", err)
		}
		return
	}
	for i := range execs {
		e := execs[i]
		switch e.Status.Phase {
		case "Succeeded", "Failed", "TimedOut":
			continue
		}
		if _, busy := c.active.LoadOrStore(e.Metadata.UID, struct{}{}); busy {
			continue
		}
		c.wg.Add(1)
		go func(e Execution) {
			defer c.wg.Done()
			defer c.active.Delete(e.Metadata.UID)
			c.run(ctx, e)
		}(e)
	}
}

func (c *controller) run(ctx context.Context, e Execution) {
	ns := e.Metadata.Namespace
	name := e.Metadata.Name
	smName := e.Spec.StateMachineRef.Name
	now := func() string { return time.Now().UTC().Format(time.RFC3339) }

	// Read + parse the referenced state machine's ASL definition.
	rawDef, err := c.client.getStateMachineDefinition(ctx, ns, smName)
	if err != nil {
		c.finalize(ns, name, map[string]any{
			"phase": "Failed", "error": ErrRuntime,
			"cause": "cannot read state machine " + smName + ": " + err.Error(), "stoppedAt": now(),
		})
		return
	}
	def, err := ParseDefinition([]byte(rawDef))
	if err != nil {
		c.finalize(ns, name, map[string]any{
			"phase": "Failed", "error": ErrRuntime,
			"cause": "state machine definition is invalid: " + err.Error(), "stoppedAt": now(),
		})
		return
	}

	resuming := e.Status.Phase == "Running" && e.Status.CurrentState != ""

	var startState string
	var data any
	var input any
	hist := e.Status.History

	if resuming {
		startState = e.Status.CurrentState
		if s := strings.TrimSpace(e.Status.Context); s != "" {
			if err := json.Unmarshal([]byte(s), &data); err != nil {
				data = map[string]any{}
			}
		} else {
			data = map[string]any{}
		}
		input = data
		log.Printf("execution %s/%s: resuming at %s", ns, name, startState)
	} else {
		in := strings.TrimSpace(e.Spec.Input)
		if in == "" {
			in = "{}"
		}
		if err := json.Unmarshal([]byte(in), &input); err != nil {
			c.finalize(ns, name, map[string]any{
				"phase": "Failed", "error": ErrRuntime,
				"cause": "spec.input is not valid JSON: " + err.Error(), "stoppedAt": now(),
			})
			return
		}
		startState = def.StartAt
		data = input
		hist = nil
		// Claim the execution: mark Running before we start doing work.
		if err := c.client.patchStatus(ctx, ns, name, map[string]any{
			"phase": "Running", "startedAt": now(), "currentState": startState,
			"context": toJSONString(input), "error": "", "cause": "",
		}); err != nil {
			log.Printf("execution %s/%s: claim failed: %v", ns, name, err)
			return
		}
		log.Printf("execution %s/%s: started %s at %s", ns, name, smName, startState)
	}

	startedAt := e.Status.StartedAt
	if startedAt == "" {
		startedAt = now()
	}
	ctxObj := map[string]any{
		"Execution":    map[string]any{"Id": e.Metadata.UID, "Name": name, "StartTime": startedAt, "Input": input},
		"StateMachine": map[string]any{"Name": smName},
	}

	// Task states invoke Functions in the execution's namespace.
	eng := newEngine(def, newHTTPInvoker(ns), ctxObj)
	eng.record = func(ev map[string]any) { hist = append(hist, ev) }
	eng.checkpoint = func(state string, d any, waitUntil *time.Time) error {
		st := map[string]any{
			"phase": "Running", "currentState": state,
			"context": toJSONString(d), "history": trimHistory(hist),
		}
		if waitUntil != nil {
			st["waitUntil"] = waitUntil.UTC().Format(time.RFC3339)
		} else {
			st["waitUntil"] = ""
		}
		return c.client.patchStatus(ctx, ns, name, st)
	}
	// Honor a checkpointed Wait's original deadline on resume.
	if resuming && e.Status.WaitUntil != "" {
		if s, ok := def.States[startState]; ok && s.Type == "Wait" {
			if t, err := time.Parse(time.RFC3339, e.Status.WaitUntil); err == nil {
				eng.resumeWait = &t
			}
		}
	}

	res := eng.Run(ctx, startState, data)

	// A controller shutdown mid-run leaves the execution checkpointed as Running so
	// the next controller resumes it — don't overwrite it with a terminal state.
	if ctx.Err() != nil {
		log.Printf("execution %s/%s: interrupted, left Running for resume", ns, name)
		return
	}

	final := map[string]any{
		"phase": res.Phase, "stoppedAt": now(), "currentState": "", "waitUntil": "",
		"history": trimHistory(hist),
	}
	if res.Phase == "Succeeded" {
		final["output"] = toJSONString(res.Output)
		final["error"] = ""
		final["cause"] = ""
	} else {
		final["error"] = res.Error
		final["cause"] = res.Cause
	}
	c.finalize(ns, name, final)
	log.Printf("execution %s/%s: %s", ns, name, res.Phase)
}

func (c *controller) finalize(ns, name string, status map[string]any) {
	// Use a fresh context for the terminal patch so a cancelled run still records
	// its outcome.
	pctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.client.patchStatus(pctx, ns, name, status); err != nil {
		log.Printf("execution %s/%s: final status patch failed: %v", ns, name, err)
	}
}
