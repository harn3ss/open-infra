# Workflows — kind: StateMachine

`kind: StateMachine` orchestrates Functions into a workflow: a sequence of steps
with branching, waits, retries and error handling. It is open-infra's equivalent of
AWS Step Functions, and it speaks the same language — the workflow is written in
**Amazon States Language (ASL)**, the same JSON you would put in
`aws_sfn_state_machine.definition`.

A workflow definition is inert on its own. You run it by creating a **`kind:
Execution`** that references it and carries an input; the state machine's controller
runs the execution to completion and records its output and history.

## A first workflow

A workflow whose one `Task` calls a Function, retrying on failure, then succeeds:

```yaml
apiVersion: openinfra.dev/v1
kind: StateMachine
metadata:
  name: order-workflow
spec:
  # The ASL definition, as a JSON string.
  definition: |
    {
      "Comment": "Validate an order, then charge it.",
      "StartAt": "Validate",
      "States": {
        "Validate": {
          "Type": "Task",
          "Resource": "function:validate-order",
          "Next": "Charge"
        },
        "Charge": {
          "Type": "Task",
          "Resource": "function:charge-card",
          "Retry": [
            { "ErrorEquals": ["States.TaskFailed"], "MaxAttempts": 3, "IntervalSeconds": 2, "BackoffRate": 2 }
          ],
          "Catch": [
            { "ErrorEquals": ["States.ALL"], "ResultPath": "$.error", "Next": "Refund" }
          ],
          "End": true
        },
        "Refund": {
          "Type": "Task",
          "Resource": "function:refund",
          "End": true
        }
      }
    }
```

`Validate` and `Charge` are ordinary `kind: Function`s. A `Task` names one with
`"Resource": "function:<name>"`, which the engine resolves to the Function's
cluster-local URL and calls with an HTTP `POST` — the first call wakes it from zero.
(A raw `"http://…"`/`"https://…"` URL also works, as an escape hatch.)

### Running it

Create an `Execution`:

```yaml
apiVersion: openinfra.dev/v1
kind: Execution
metadata:
  generateName: order-workflow-
spec:
  stateMachineRef:
    name: order-workflow
  input: '{"orderId": "A-1001", "amount": 4200}'
```

From the console: open the state machine, fill in the input JSON, and press **Start
execution**. The execution page shows the phase (live while running), the input and
output, and the step-by-step history.

## How a Task talks to a Function

- **Request:** the resolved task input is `POST`ed as a JSON body.
- **Success:** any `2xx` response — the JSON body becomes the task's result.
- **Failure:** a non-`2xx` response fails the task. The error name is taken from the
  `X-Openinfra-Error` response header, or a top-level `"error"`/`"Error"` field in
  the body, defaulting to `States.TaskFailed`; the cause comes from
  `X-Openinfra-Cause`, a `"cause"` field, or the body.
- **Timeout:** a `Task`'s `TimeoutSeconds` bounds the call; exceeding it yields
  `States.Timeout`.

## State types (v1)

| State | Purpose |
|-------|---------|
| `Task` | Invoke a Function (or an HTTP URL) and capture the result. |
| `Choice` | Branch to a state based on the data. |
| `Wait` | Pause for a duration or until a timestamp. |
| `Pass` | Inject or reshape data with no external call. |
| `Succeed` | End the execution successfully. |
| `Fail` | End the execution with an error and cause. |

**Error handling** on `Task`:

- `Retry` — retry on matching `ErrorEquals` with `IntervalSeconds`, `MaxAttempts`,
  `BackoffRate` (and an optional `MaxDelaySeconds` cap). `States.ALL` matches any
  error.
- `Catch` — route a matching error to another state; the error object
  (`{"Error", "Cause"}`) is placed at `ResultPath`.

**Choice** supports `StringEquals`/`LessThan`/`GreaterThan`(`Equals`),
`NumericEquals`/… , `BooleanEquals`, `TimestampEquals`/… , the `IsPresent` /
`IsNull` / `IsString` / `IsNumeric` / `IsBoolean` / `IsTimestamp` predicates, the
`And` / `Or` / `Not` compositions, every `<Op>Path` variant, and a `Default`.

**Data shaping** (`Task`, `Pass`; `Choice`/`Wait`/`Succeed` honor `InputPath` and
`OutputPath`): `InputPath`, `Parameters` (with `"key.$": "$.path"` references and the
`$$` context object), `ResultPath`, `OutputPath`. Reference paths support `$`, dotted
fields (`$.a.b`), and array indexing (`$.items[0]`).

## Executions are durable

The engine checkpoints each execution's current state and data into the Execution's
status after every step, so a running execution survives — and resumes from its last
checkpoint after — a controller restart. As with AWS Standard workflows, a `Task` may
therefore run more than once (on a retry, or on a resume that re-enters an in-flight
step), so **Task handlers should be idempotent.**

An execution ends in one of: `Succeeded` (with `output`), `Failed` (with `error` and
`cause`), or `TimedOut` (the state machine's or a task's `TimeoutSeconds` elapsed).

## Not yet implemented

v1 is a faithful subset. These ASL features are **not** available yet and are
rejected with a `States.Runtime` error rather than silently ignored:

- `Parallel` and `Map` states.
- The `Express` workflow type (only `Standard` is implemented).
- Task callbacks (`.waitForTaskToken`) and service integrations other than Functions.
- ASL intrinsic functions and JSONPath filters/wildcards/slices.

## Notes

- Executions are runtime objects, not declared infrastructure, so — like AWS —
  `kind: StateMachine` is a Terraform resource but you start executions from the
  console or `kubectl`, not from Terraform.
- Each state machine runs its own small controller (compiled from the definition), so
  deleting the `StateMachine` tears the controller down with it.
