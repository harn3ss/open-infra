# Scheduled Jobs

`kind: ScheduledJob` runs a container to completion on a schedule — the platform's equivalent of an
AWS scheduled task (an EventBridge/EventBridge-Scheduler rule targeting Lambda, ECS, or Batch). Use it
for the ordinary recurring work an application needs beside its always-on services: nightly rollups,
batch pricing runs, end-of-day reconciliation, report generation, cleanups.

It compiles to a Kubernetes CronJob whose runs are ordinary Jobs, so each fire has retries, a
concurrency policy, a per-run timeout, and a retained history you can inspect.

## Quick start

```yaml
apiVersion: openinfra.dev/v1
kind: ScheduledJob
metadata:
  name: nightly-rollup
spec:
  schedule: "0 2 * * *"        # 02:00 every day
  image: ghcr.io/acme/rollup:latest
  command: ["/bin/rollup", "--yesterday"]
  env:
    - { name: REGION, value: us-east }
  secrets: [shop-db]           # inject an existing Secret's keys as env (e.g. a database connection)
  retries: 2
  timeout: 3600                # cap a run at one hour
```

## Schedule

`schedule` accepts either a standard 5-field cron expression, or an AWS-style expression:

| You write | Runs |
|---|---|
| `0 2 * * *` | 02:00 daily (raw cron) |
| `cron(0 12 * * ? *)` | 12:00 daily (AWS 6-field cron; the `year` field is dropped, `?` becomes `*`) |
| `rate(5 minutes)` | every 5 minutes |
| `rate(1 hour)` | hourly |
| `rate(1 day)` | daily |

`rate()` values that don't divide evenly into an hour or a day (e.g. `rate(90 minutes)`) have no exact
cron equivalent — use an explicit cron expression instead. Set `timeZone` (e.g. `America/New_York`) to
interpret the schedule in a zone other than UTC.

## Run policy

- **`concurrencyPolicy`** — `Forbid` (default: skip a run if the previous is still going), `Allow`, or
  `Replace`.
- **`retries`** — how many times a failed run is retried before it is marked failed (default 2).
- **`timeout`** — a hard wall-clock cap per run, in seconds.
- **`suspend`** — pause the schedule without deleting it.
- **`startingDeadline`** — how late a missed run may still start (a catch-up window). Set it if the
  schedule may be paused or the cluster down for a long time.

## Resources and GPUs

Set `cpu` / `memory` (Kubernetes quantities) for the run's limits. For GPU work set `gpu: 1` and a
`gpuTier` (`smallgpu` or `largegpu`); the run is placed on a matching GPU node.

## Honest limits

- There is no dead-letter queue. A run that exhausts its retries is kept as a failed Job (visible in
  the run history and to the alerting stack); publish a failure record to a `kind: Queue` (via the
  `queues` field) if you need one downstream.
- `timeZone` requires a Kubernetes control plane at 1.27 or newer; on older clusters schedules run in
  UTC.
- Delivery is at-most-once with possible misses (a schedule can be skipped if the controller is down
  past `startingDeadline`). Keep jobs idempotent.
- Continuous, always-on work is not a scheduled job — run it as a `kind: Application`.
