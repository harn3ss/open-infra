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
| `network-partition` | NetworkChaos | Cut the target off | `direction` |
| `stress-cpu` | StressChaos | Burn CPU | `cpuWorkers`, `cpuLoad` |
| `stress-memory` | StressChaos | Consume memory | `memory` |
| `clock-skew` | TimeChaos | Shift the clock (exercises HLC/LWW) | `timeOffset` |
| `io-latency` | IOChaos | Slow disk I/O on a mount | `latency`, `volumePath` |

`mode` selects how many matched pods are hit: `one`, `all`, or `fixed-percent` (with `value`).

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

## See also

- [`databases.md`](databases.md) — managed DB HA / failover the experiments exercise
- [`dataflow.md`](dataflow.md) — replication mesh resilience
- [`architecture.md`](architecture.md) — where this sits in the platform
