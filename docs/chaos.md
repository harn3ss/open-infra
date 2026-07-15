# Chaos engineering (`kind: FaultInjection`)

> AWS equivalent: **Fault Injection Simulator (FIS)**.

Fault injection lets you *prove* the platform's resilience instead of hoping for it. open-infra
runs **Chaos Mesh** (installed declaratively by Argo, `platform/resilience/chaos-mesh.yaml`),
but you never write raw Chaos Mesh CRDs — you declare a `kind: FaultInjection`, which compiles
to a Chaos Mesh experiment with the **blast radius enforced**: every experiment is scoped to a
single namespace + a label selector and is time-boxed by `duration`. No cluster-wide chaos.

## The resource

```yaml
apiVersion: openinfra.dev/v1
kind: FaultInjection
metadata: { name: kill-pg-primary, namespace: team-a }
spec:
  type: pod-kill            # see "Fault types"
  target:
    labelSelector: { role: primary }   # which pods (in this namespace by default)
  mode: one                 # one | all | fixed-percent
  duration: 60s             # how long (ignored by the instantaneous pod-kill)
```

## Fault types

| `type` | Chaos Mesh kind | What it does | Key knobs |
|--------|-----------------|--------------|-----------|
| `pod-kill` | PodChaos | Kill matching pods (test restart/failover) | — |
| `pod-failure` | PodChaos | Make pods unavailable for `duration` | — |
| `network-latency` | NetworkChaos | Add delay | `latency`, `direction` |
| `network-loss` | NetworkChaos | Drop a % of packets | `loss`, `direction` |
| `network-partition` | NetworkChaos | Cut the target off | `direction`, `partitionPeer` |
| `stress-cpu` | StressChaos | Burn CPU | `cpuWorkers`, `cpuLoad` |
| `stress-memory` | StressChaos | Consume memory | `memory` |
| `clock-skew` | TimeChaos | Shift the clock (exercises HLC/LWW) | `timeOffset` |
| `io-latency` | IOChaos | Slow disk I/O on a mount ⚠️ **currently inert — see below** | `latency`, `volumePath` |

`mode` selects how many matched pods are hit: `one`, `all`, or `fixed-percent` (with `value`).

> ⚠️ **`io-latency` does not currently inject.** Chaos Mesh's FUSE injector (`toda`)
> panics on this cluster, so the IOChaos is created and then sits at
> `phase: Not Injected/Wait, injectedCount: 0` — **silently**. The fault looks applied
> and does nothing. Don't rely on it until this is fixed. (Found by the chaos suite
> asserting `AllInjected=True` rather than trusting that the object exists — a good habit
> for any fault you write: check `status.conditions`, not just `kubectl get`.)

### `partitionPeer` — cutting A from B, not B from the world

By default `network-partition` isolates the target from **everything**, which also cuts it
off from any outside client (a test driver, your app, a probe). Set `partitionPeer` to a
second label selector to cut traffic **only between the two sets**, leaving both reachable
from elsewhere:

```yaml
spec:
  type: network-partition
  target: { labelSelector: { app: pg, site: b } }   # side 1
  partitionPeer: { app: my-engine }                 # side 2 — only B↔engine is cut
  mode: all
  direction: both
  duration: 90s
```

Useful whenever the thing you want to sever is a *link*, not a member. Note that if your
replication is **pod-mediated** (e.g. db → capture → bus → sink → db), cutting the two
databases from each other injects **nothing** — they never talk directly. Cut a member from
the engine that feeds it instead.

> Safety: keep network/time chaos off **host-network** pods, and always set a tight
> `target.labelSelector`. The abstraction refuses cluster-wide scope by construction (a
> namespace + selector are required).

## Curated experiments — validate the platform's own resilience

These prove the hardening the platform ships with.

**CNPG failover** — kill the Postgres primary, expect a standby to be promoted (HA dbs):
```yaml
kind: FaultInjection
metadata: { name: cnpg-failover, namespace: team-a }
spec: { type: pod-kill, target: { labelSelector: { cnpg.io/instanceRole: primary } }, mode: one }
```

**CDC offset durability** — kill a DataFlow capture pod; it must resume from its Longhorn PVC
offset (no full re-snapshot):
```yaml
kind: FaultInjection
metadata: { name: kill-capture, namespace: mm }
spec: { type: pod-kill, target: { labelSelector: { app: myflow-flow-pg-dbz } }, mode: one }
```

**Mesh convergence under partition** — isolate one multi-master member, then heal; the HLC
last-write-wins must converge:
```yaml
kind: FaultInjection
metadata: { name: partition-member, namespace: mm }
spec: { type: network-partition, target: { labelSelector: { app: pg } }, duration: 120s }
```

**HLC under clock skew** — skew a member's clock; exposes time-ordering bugs (e.g. an engine
whose version can go backwards under an NTP step):
```yaml
kind: FaultInjection
metadata: { name: skew-clock, namespace: mm }
spec: { type: clock-skew, timeOffset: "-10m", target: { labelSelector: { app: my } }, duration: 120s }
```

**Storage I/O pressure** — slow a database's disk and watch lag/timeouts behave:
```yaml
kind: FaultInjection
metadata: { name: slow-disk, namespace: team-a }
spec: { type: io-latency, latency: "300ms", volumePath: "/var/lib/postgresql", target: { labelSelector: { role: primary } }, duration: 90s }
```

Observe the impact in the usual places — the database **Peek** tab, the DataFlow per-edge
overlay, Grafana — and via the Chaos Mesh dashboard (`chaos-mesh` namespace).

## Validation (GameDays run)

These experiments aren't just documented — they've been run against **disposable** resources
(throwaway namespaces, created and torn down; never against anything in use), with the blast
radius scoped to those resources. Summary of what was validated:

**Single primitives**
- *Stateless app* — `pod-kill` a replica → the Deployment recreated it; service stayed at full
  replica count.
- *Block storage (Longhorn)* — `pod-kill` a pod holding a Longhorn volume → the replacement pod
  reattached the volume with its data intact.
- *Stateful database* — `pod-kill` a database pod → the new pod recovered its data from the
  persistent volume.
- *HA Postgres (CloudNativePG)* — `pod-kill` the primary → a standby was promoted to primary in
  ~15s and the cluster returned to full health, the old primary rejoining as a replica.

**Chained, multi-piece pipelines (Data Flows)**
- *9-piece mixed topology* — a 3-engine multi-master core (PostgreSQL + MySQL + MariaDB) plus a
  one-way migration spoke and a stream to a topic. Under **concurrent** faults (capture-pod
  kill + a member network-partition + an apply-sink kill) with writes flowing throughout, all
  members **converged** (last-write-wins resolved a cross-member conflict; the migration spoke
  stayed in sync).
- *4-engine migration relay* — PostgreSQL → MySQL → MariaDB → SQL Server, where one write
  cascades through every engine. Killing a **mid-chain** capture and the **last-hop** sink at
  once, while writing at the source, the cascade self-healed and every engine ended consistent.

**Fault types** — pod kill/failure, network latency/loss/partition, CPU/memory stress, clock
skew, and disk-IO latency have all been exercised.

**Chaos found (and we fixed) a real bug.** A `clock-skew` experiment on a multi-master member
revealed that the MySQL/MariaDB change-stamping lacked a *monotonic* clock guard (which
PostgreSQL and SQL Server already had): a backwards wall-clock produced a lower version, so the
write lost last-write-wins and silently diverged. The stamping was changed to a monotonic
hybrid logical clock, and re-running the **same** experiment confirmed the fix (the version
advanced instead of going backwards, and the write converged). That loop — *inject → observe →
fix → re-inject* — is the point of keeping these experiments around.

## See also

- [`databases.md`](databases.md) — managed DB HA / failover the experiments exercise
- [`dataflow.md`](dataflow.md) — replication mesh resilience
- [`architecture.md`](architecture.md) — where this sits in the platform
