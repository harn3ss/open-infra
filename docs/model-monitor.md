# Drift monitoring — kind: ModelMonitor

`kind: ModelMonitor` watches a model for **data drift** — open-infra's SageMaker Model
Monitor. On a cron schedule it compares recent data against a baseline dataset, computes
per-feature drift, writes a report to the object store, and flags features that have
drifted beyond a threshold. The drift check is **built in** — there's no monitoring
container to write.

## A first monitor

```yaml
apiVersion: openinfra.dev/v1
kind: ModelMonitor
metadata:
  name: fraud-drift
spec:
  schedule: "0 * * * *"        # hourly (cron)
  modelRef: fraud-endpoint     # which Model this monitors (informational)
  baseline:                    # the reference dataset (JSONL of feature records)
    bucket: monitoring
    key: fraud/baseline.jsonl
  current:                     # where recent data/predictions land (JSONL under this prefix)
    bucket: monitoring
    prefix: fraud/current/
  output:                      # where reports go (report-<ts>.json + latest.json)
    bucket: monitoring
    prefix: fraud/reports/
  threshold: 0.2               # relative mean shift that counts as drift (20%)
```

## What it does, each run

- Loads the **baseline** (one JSONL object) and the **current** data (all JSONL under the
  prefix) as records of feature → value.
- For every numeric feature present in both (or just those you list in `features`),
  computes the mean in each and the **relative shift**:
  `|current_mean - baseline_mean| / (|baseline_mean| + 1e-9)`.
- A feature **drifts** when that exceeds `threshold` (default `0.2`).
- Writes `report-<timestamp>.json` and `latest.json` to the output location, each with
  per-feature `baselineMean` / `currentMean` / `drift` / `violation`, plus a top-level
  `violation` flag and `driftedFeatures` list. Logs a one-line summary:
  `OPENINFRA_MONITOR violation=… drifted=[…]`.

Read the latest report from the output bucket (`.../latest.json`), or watch the CronJob's
logs.

## Fields

| Field | Purpose |
|-------|---------|
| `schedule` | Cron schedule (default hourly). |
| `baseline` `{bucket, key}` | Reference dataset. |
| `current` `{bucket, prefix}` | Where recent data to check lands. |
| `output` `{bucket, prefix}` | Where reports are written (bucket created on demand). |
| `features` | Numeric features to monitor (default: all numeric fields in both). |
| `threshold` | Relative mean-shift that counts as drift (default 0.2). |
| `modelRef` | The `kind: Model` this monitors (informational). |

## Notes

- v1 is a **tabular mean-shift** data-quality monitor over JSONL records. Distribution
  distances (PSI, KS), model-quality monitoring against labels, and bias/explainability
  (SageMaker Clarify) are not implemented.
- Run it now (instead of waiting for the schedule):
  `kubectl create job --from=cronjob/<name>-monitor run-1 -n <namespace>`.
- Wire it up by having your endpoint or pipeline log recent records/predictions to the
  `current` location (SageMaker's data-capture equivalent is left to your pipeline).
