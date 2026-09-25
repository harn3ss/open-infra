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
	client     *k8sClient
	active     sync.Map // uid -> struct{}
	cancels    sync.Map // uid -> context.CancelFunc (per-execution; StopExecution cancels it)
	stopCauses sync.Map // uid -> string (StopExecution cause, read back by run() on abort)
	wg         sync.WaitGroup
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
		case "Succeeded", "Failed", "TimedOut", "Aborted":
			continue
		}
		// StopExecution: the shim set status.stopRequested. Cancel the running goroutine (it finalizes
		// Aborted with the cause) — the shim never writes the terminal phase itself, so it can't race us.
		if e.Status.StopRequested {
			c.stopCauses.Store(e.Metadata.UID, e.Status.StopCause)
			if cf, ok := c.cancels.Load(e.Metadata.UID); ok {
				cf.(context.CancelFunc)()
			} else if _, busy := c.active.Load(e.Metadata.UID); !busy {
				// Nothing is driving it (e.g. a stop requested before the goroutine ever picked it up,
				// across a controller restart). Finalize it directly.
				cause := e.Status.StopCause
				if cause == "" {
					cause = "Execution stopped"
				}
				c.finalize(e.Metadata.Namespace, e.Metadata.Name, map[string]any{
					"phase": "Aborted", "error": "States.ExecutionAborted", "cause": cause,
					"stoppedAt": time.Now().UTC().Format(time.RFC3339), "currentState": "", "waitUntil": "",
				})
				c.stopCauses.Delete(e.Metadata.UID)
			}
			continue
		}
		if _, busy := c.active.LoadOrStore(e.Metadata.UID, struct{}{}); busy {
			continue
		}
		c.wg.Add(1)
		go func(e Execution) {
			defer c.wg.Done()
			defer c.active.Delete(e.Metadata.UID)
			execCtx, cancel := context.WithCancel(ctx)
			c.cancels.Store(e.Metadata.UID, cancel)
			defer func() {
				cancel()
				c.cancels.Delete(e.Metadata.UID)
				c.stopCauses.Delete(e.Metadata.UID)
			}()
			c.run(ctx, execCtx, e)
		}(e)
	}
}

// run drives one execution to completion. mainCtx is the controller's lifetime context (cancelled on
// shutdown); ctx is this execution's own context (also cancelled by StopExecution). The engine runs on
// ctx; the split lets run() tell a shutdown (leave Running to resume) apart from a stop (finalize Aborted).
func (c *controller) run(mainCtx, ctx context.Context, e Execution) {
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

	// Load the state-machine role's STS session (minted by the shim at StartExecution) so Task
	// invocations run under the role's authority. A missing/unreadable creds Secret fails the execution
	// rather than silently running Tasks unauthenticated — a state machine created with a role must run
	// its Tasks under that role (polyhedron#172/#168).
	credNS := e.Spec.CredentialsNamespace
	if credNS == "" {
		credNS = ns
	}
	creds, err := c.client.getCredentials(ctx, credNS, e.Spec.CredentialsSecret)
	if err != nil {
		c.finalize(ns, name, map[string]any{
			"phase": "Failed", "error": ErrRuntime,
			"cause": "cannot read execution credentials: " + err.Error(), "stoppedAt": now(),
		})
		return
	}

	// Task states invoke Functions in the execution's namespace, under the role's STS session (creds).
	eng := newEngine(def, newHTTPInvoker(ns, creds), ctxObj)
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
	if mainCtx.Err() != nil {
		log.Printf("execution %s/%s: interrupted by shutdown, left Running for resume", ns, name)
		return
	}
	// The execution's own context was cancelled while the controller is still up ⇒ StopExecution.
	// Finalize as Aborted (never resumed) with the caller's stop cause.
	if ctx.Err() != nil {
		cause := "Execution stopped"
		if v, ok := c.stopCauses.Load(e.Metadata.UID); ok {
			if s, _ := v.(string); s != "" {
				cause = s
			}
		}
		c.finalize(ns, name, map[string]any{
			"phase": "Aborted", "error": "States.ExecutionAborted", "cause": cause,
			"stoppedAt": now(), "currentState": "", "waitUntil": "", "history": trimHistory(hist),
		})
		log.Printf("execution %s/%s: aborted (StopExecution)", ns, name)
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
