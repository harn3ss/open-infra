# Convergence harness — proving multi-master doesn't lose or diverge writes

> This is the correctness evidence the [Maturity & guarantees](../README.md#maturity--guarantees)
> section calls out as *not yet automated*. It is a **start**: the write/verify core is here
> and runnable; automated fault orchestration is the next step (see [Roadmap](#roadmap)).

The experimental multi-master path (`Replication`, cross-engine `Migration`, multi-master
`DataFlow`) resolves conflicts with a Hybrid Logical Clock and last-write-wins. The failure
that matters isn't a crash — it's a **silently lost or diverged write**. This harness makes
that failure *visible and testable*: it drives concurrent and deliberately conflicting writes
across the members of a running flow, then asserts every member ends **byte-identical** —
same key set (no lost writes) and the same winning `version`+value per key (deterministic LWW).

Run it *while* injecting a fault, and you've proven convergence survives partition / node loss.

## What it asserts

1. **No lost writes** — every key written to any member is present on *every* member after convergence.
2. **Deterministic LWW** — for each key, the HLC-winning `_mm_version` and value are identical on
   every member (no split-brain: the mesh agrees on the same winner).
3. **Convergence within a deadline** — the above holds within `CONV_TIMEOUT` after writes stop
   (and after any injected fault heals).

## Prerequisites

- A **running** multi-master flow (`kind: Replication` or a multi-master `kind: DataFlow`) with
  ≥ 2 members.
- The flow must **capture** the test table. Easiest: enable `autoSyncTables` on the flow (a
  table created on one member auto-joins and is mm-prepped everywhere), or point `CONV_TABLE`
  at a table already in the flow that has `(id, val)` columns.
- Reach each member's database from where you run `go test` (LAN IP / port-forward / NodePort).

## Run

```bash
cd apply-sink
export CONV_MEMBERS='[
  {"name":"pg-a","engine":"postgres","dsn":"postgres://app:${PGPASS}@10.0.0.11:5432/app?sslmode=disable","site":"a","schema":"public"},
  {"name":"pg-b","engine":"postgres","dsn":"postgres://app:${PGPASS}@10.0.0.12:5432/app?sslmode=disable","site":"b","schema":"public"}
]'
export CONV_CREATE=true          # create + mm-prep public.conv_test on every member
export CONV_TABLE=public.conv_test
export CONV_KEYS=200 CONV_CONFLICTS=20 CONV_TIMEOUT=180

go test -tags convergence -run TestConvergence -timeout 30m -v ./...
```

`CONV_MEMBERS` is the **same JSON shape** the engine's `MEMBERS` uses, so you can copy it from a
Replication/DataFlow member secret. `${VAR}` in a DSN is expanded from the environment.

| var | default | meaning |
|-----|---------|---------|
| `CONV_MEMBERS` | — (required) | JSON array `[{name,engine,dsn,site,schema}]` |
| `CONV_TABLE` | `public.conv_test` | `schema.table` to exercise (needs `id`,`val` columns) |
| `CONV_CREATE` | `false` | create + mm-prep the table on every member first |
| `CONV_KEYS` | `200` | distinct keys, spread across members |
| `CONV_CONFLICTS` | `20` | keys updated from two members at once (LWW conflicts) |
| `CONV_SETTLE` | `8` | seconds to let seed rows replicate before racing updates |
| `CONV_TIMEOUT` | `120` | seconds to wait for convergence |
| `CONV_WRITE_RETRIES` | `40` | write attempts (×500ms) before giving up — must outlast the fault window |
| `CONV_PK` | `id` | primary-key column name |

> **Units: these are bare integers of seconds, not durations.** `CONV_TIMEOUT=300` — *not*
> `300s`. A value that fails to parse silently falls back to the default, so `"300s"` gives
> you 120s and the mis-set budget only shows up as a mystery red months later.

`CONV_WRITE_RETRIES` matters under a fault: a CNPG primary promotion takes ~4–10s, so a
driver that gives up after 3s produces spurious reds while the system under test is fine.

## Proving it under a fault (the point)

> **This is now automated.** The [Nightly Chaos Suite](chaos-suite.md) drives this harness
> unattended every night — partition, clock-skew, sink-kill, CNPG failover, and all of them at
> once — each scenario asserting the fault *actually landed* and that the mesh re-converges. A
> red night blocks the release. What follows is the manual equivalent, for one-off GameDays.

Run the harness with a generous `CONV_TIMEOUT`, and during the write/converge window apply a
`kind: FaultInjection` (blast-radius scoped, time-boxed — see [chaos.md](chaos.md)). The harness
retries writes through the fault and keeps polling until the mesh re-converges after it heals.

⚠️ If you hand-roll a fault, **prove it bit**. A partition between two databases whose
replication is pod-mediated injects nothing; a fault applied after the write phase lands on
already-converged data. Both look green. Check the elapsed time and `status.conditions`.

**Partition a member, then heal:**
```yaml
apiVersion: openinfra.dev/v1
kind: FaultInjection
metadata: { name: partition-member, namespace: mm }
spec: { type: network-partition, target: { labelSelector: { app: pg-b } }, duration: 120s }
```

**Kill a member mid-write (failover):**
```yaml
kind: FaultInjection
metadata: { name: kill-member, namespace: mm }
spec: { type: pod-kill, target: { labelSelector: { app: pg-b } }, mode: one }
```

**Skew a member's clock (HLC ordering):**
```yaml
kind: FaultInjection
metadata: { name: skew-clock, namespace: mm }
spec: { type: clock-skew, timeOffset: "-10m", target: { labelSelector: { app: pg-b } }, duration: 120s }
```

Expected result in every case: `CONVERGED: … zero lost writes`. A `LOST WRITES` or `did NOT
converge` failure (with a per-key divergence report) is a real correctness bug — capture the
member DSNs, the fault, and the output.

## Roadmap

This first version verifies convergence and tolerates a fault applied out-of-band. Next:

- ~~**Auto-orchestrated faults**~~ — **done**: the [Nightly Chaos Suite](chaos-suite.md)
  orchestrates the partition/kill/skew/failover matrix unattended (as scenario scripts around
  the harness rather than client-go inside it).
- **Continuous-write mode** — sustained writes across the whole fault window (not one burst)
  for a harsher test.
- ~~**A `workflow_dispatch` CI job**~~ — **done**: `nightly-chaos.yml` runs on a schedule *and*
  on demand against a disposable sandbox mesh.
- **More topologies** — 3+ members and cross-engine meshes (PG ⇄ MySQL ⇄ SQL Server).
