# Hyperparameter tuning — kind: TuningJob

`kind: TuningJob` sweeps a training job over a hyperparameter search space and keeps the
best — open-infra's SageMaker Automatic Model Tuning. It runs a `kind: TrainingJob` per
hyperparameter combination (grid search), reads each trial's reported metric, and records
the winning trial and its hyperparameters.

Because every trial is a real `kind: TrainingJob`, tuning reuses the whole training data
plane (GPU placement, object-store wiring) for free.

## A first tuning job

```yaml
apiVersion: openinfra.dev/v1
kind: TuningJob
metadata:
  name: lr-sweep
spec:
  training:                     # the base TrainingJob each trial runs
    image: pytorch/pytorch:2.4.1-cuda12.1-cudnn9-runtime
    gpu: 1
    gpuTier: largegpu
    command: ["python", "train.py"]
    output: { bucket: models, prefix: sweeps/lr/ }   # each trial writes under <prefix>/<trial>/
  parameters:                   # the search space (grid search)
    - { name: LR,     values: ["0.001", "0.01", "0.1"] }
    - { name: EPOCHS, values: ["10", "50"] }
  objective:
    metric: loss
    goal: Minimize              # or Maximize
  maxParallel: 2                # trials running at once
```

This runs `3 × 2 = 6` trials (the cartesian product), two at a time. Each trial is a
TrainingJob named `lr-sweep-t<N>` with `LR` and `EPOCHS` set as environment variables.

## Reporting the objective

Each trial reports its objective by **printing a line the controller reads**. By default
that's `OPENINFRA_METRIC=<value>` — so your training script ends with something like:

```python
print(f"OPENINFRA_METRIC={final_loss}", flush=True)
```

Override the pattern with `spec.metricRegex` (one capture group), e.g.
`val_auc:\s*([0-9.]+)`. The **last** match in the trial's logs is used, so print the
final metric last.

## What you get

While it runs, the tuning job's status shows each trial (its hyperparameters, status, and
metric) and, once every trial is terminal, the **best trial**, its metric, and the winning
hyperparameters (`status.bestParameters`). In the console (Compute → Tuning Jobs) the
detail page's **Trials** tab lists them and highlights the winner; each trial links to its
Training Job.

## Fields

| Field | Purpose |
|-------|---------|
| `training` (required) | The base `kind: TrainingJob` spec each trial runs. |
| `parameters` (required) | The search space: a list of `{name, values}` swept as a grid. |
| `objective` `{metric, goal}` | `Minimize` (default) or `Maximize` the reported metric. |
| `metricRegex` | Regex (one group) that extracts the metric from a trial's logs. |
| `maxParallel` | Trials running concurrently (default 1). |
| `maxTrials` | Cap the number of trials (the grid is truncated). |

## Notes

- Like `kind: Execution`, a TuningJob is a **run** whose status the controller owns — it's
  started from the console or `kubectl`, not Terraform. Deleting it garbage-collects its
  trial Training Jobs (they're owner-referenced).
- v1 does **grid search**. Bayesian/random search and early-stopping are not implemented.
- The tuning controller reads each trial's metric from its pod logs, so keep the training
  container's logs available (don't set an aggressive TTL on the trial).
