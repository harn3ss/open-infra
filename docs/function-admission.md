# Function admission: Burstable memory + tenant concurrency (the Lambda model)

How `kind: Function` bounds warm capacity by **real use and admission control** instead of **promised
memory** — the closest AWS-Lambda-equivalent memory + concurrency model available on Kubernetes/Knative.

## The problem it fixes

A function pod is **Guaranteed QoS** by default: `requests.memory == limits.memory ==` the configured
Lambda memory. So **every warm or stuck instance reserves its full configured memory whether or not it
is serving traffic.** On an estate of thousands of mostly-idle functions this is the binding constraint —
the cluster runs out of *reservation* long before it runs out of *use*, and nodes hit 100% of allocatable
while real memory sits far lower. Storage and database pods then cannot schedule behind a wall of idle
function reservations.

Burstable admission makes warm reservation track the floor a function actually needs, and caps the burst
with admission control, so the platform's memory is governed by use + policy, not by promises.

## The model

Set on a function with one field — `spec.burstable: true` (default `false`). It turns on, together:

| # | Mechanism | AWS analog | Where |
|---|-----------|-----------|-------|
| 1 | **Burstable pod**: `requests.memory` = per-runtime floor, `limits.memory` = `spec.memory` | memory size (per-invocation ceiling) | composition |
| 2 | **`containerConcurrency: 1`** — one request per instance | one invocation per execution environment | composition |
| 3 | **`max-scale`** (from `reservedConcurrency`, else `scaling.max`) — per-function ceiling | reserved concurrency | composition |
| 4 | **Tenant `count/pods` quota** (scoped to function priority) — one running pod == one in-flight request | account concurrent-executions limit | `platform/compliance/function-concurrency-quota.yaml` |
| 5 | **Shed at the cap** — pod CREATE rejected by quota *before the pod exists*; a sync invoke via the shim returns a true `429` | throttle, don't kill | quota + Knative + aws-shim |
| 6 | **Tenant `requests.memory` quota** — ceiling on total reserved memory | — | same policy |
| 7 | **Low-priority, non-preempting pods** — reclaimed before platform pods under node pressure | (AWS isolates; see gaps) | `platform/serverless/function-priorityclass.yaml` |

Only function pods become Burstable. **MinIO is Guaranteed** (set 2026-10-27: `requests == limits`,
memory 4Gi / cpu 1000m) so it is reclaimed last and memory-bounded — it was the storage layer whose
eviction cascaded the 2026-10-26 outage. The rest of the platform (databases, the Knative/Crossplane
control plane, Longhorn, the registry) is still a mix of BestEffort/Burstable; raising those to
Guaranteed is a **separate platform-QoS hardening track**, not part of this model's acceptance. The
low-priority function class (row 7) means a ballooning function is reclaimed before any of them regardless.

## Per-runtime memory floor — NOT MEASURED YET

`requests.memory` for a burstable pod comes from a per-runtime floor table in the composition. **Every
entry is currently an UNMEASURED 128Mi placeholder.** Replace each with a value measured on a drained
estate (warm RSS per runtime, with headroom), then report the source of each number:

| runtime | floor | basis |
|---------|-------|-------|
| python3.12 | 128Mi | **not measured** (placeholder) |
| python3.13 | 128Mi | **not measured** (placeholder) |
| nodejs20 | 128Mi | **not measured** (placeholder) |
| nodejs22 | 128Mi | **not measured** (placeholder) |
| dotnet8 | 128Mi | **not measured** (placeholder) |

Override per function without a composition edit: `spec.memoryRequest: "192Mi"`.

## Enabling it (per tenant, per wave)

**Order matters — the quota goes on first.** Burstable without the quota is unbraked overcommit.

1. Put the tenant concurrency + memory cap on the namespace:
   ```
   kubectl label namespace <ns> \
     openinfra.dev/function-concurrency=200 \
     openinfra.dev/function-memory=48Gi
   ```
   With the opt-in `compliance` component (Kyverno), this generates a native `ResourceQuota` scoped to the
   `openinfra-function` priority class. Without that component, apply the equivalent by hand:
   ```yaml
   apiVersion: v1
   kind: ResourceQuota
   metadata: { name: function-concurrency-quota, namespace: <ns> }
   spec:
     hard: { count/pods: "200", requests.memory: "48Gi" }
     scopeSelector:
       matchExpressions:
         - { scopeName: PriorityClass, operator: In, values: [openinfra-function] }
   ```
2. Flip the wave's functions to `spec.burstable: true` (keep `spec.memory` set — it's the limit).
3. Watch: the pods should report `Burstable` QoS and the scoped quota should start counting.

## Known gaps — state them, don't paper over

- **Burstable pods can still be evicted/OOMed by a neighbour** under node memory pressure. AWS never does
  this — it throttles at the edge. (4)+(6) make it rare, not impossible. QoS + the low priority class
  ensure the *function furthest over its request* is the one reclaimed, not a quiet neighbour or a
  platform pod — but it is a real difference from Lambda.
- **At the tenant concurrency cap, a sync invoke through the aws-shim now returns a true `429
  TooManyRequestsException`** (+ `Retry-After`). The shim pre-checks the `function-concurrency-quota`
  `count/pods` at the front door and rejects there, rather than forwarding into Knative's activator —
  which would queue the request until it timed out into a `503` (`console-api/cmd/aws-shim/lambda.go`).
  Two residual edges, stated honestly: a request sent **directly to the Knative URL** (bypassing the
  shim) still sees the activator's `503`; and the **per-function `max-scale`** ceiling (as opposed to the
  tenant quota) is still shed by the activator as `503`, not 429. **Async** sources back off and retry
  (Knative Eventing / the function's event pump), so throttling an async path is lossless.
- Any capture-and-compare rig MUST treat a throttle (`429`/`503` at the cap) as **back-off-and-retry, never
  a runtime divergence** — otherwise throttling manufactures false not-equivalent findings.

## Rollout gates (do NOT do estate-wide)

This is a composition change; it is **inert until a function sets `burstable: true`**, but once set it
changes scaling and QoS. Follow the gates:

0. **Blocked on the estate drain** — stuck revisions gone, Services quota well under the ceiling, object
   storage fully writable — before enabling any wave.
1. **Measure** the per-runtime floors on the drained estate; commit the numbers (see the table above).
2. **One wave first.** Enable `burstable` for a single wave with its tenant quota already in place.
3. **Guardrails ship together** — the quota (4)(6) and the shed behaviour (5) are not "later."
4. **Deliberate failure test** (below) — prove the busiest function is the one reclaimed, that MinIO and
   databases are untouched, and that sync callers are shed at the cap.
5. **Coordinate** — announce before it lands and never land it mid-wave.

## Failure test

`tools/capacity/function-burstable-failure-test.sh` is the deliberate node-saturation test for gate 4.
It is **run after the drain**, against a labelled test namespace on a chosen node — it does not run in CI
and takes no action on its own. It proves, on live cluster evidence:

- burstable function pods report **QoS Burstable**; a platform pod on the same node reports **Guaranteed**;
- saturating the node reclaims the **busiest function pod first** — not MinIO, not a database;
- a synchronous caller is **shed (503/429) at the tenant cap** rather than queued forever;
- the scoped `ResourceQuota` shows `count/pods` at its hard limit at saturation.

## Done means (observed, not configured)

On-cluster, on the drained estate: function pods report QoS **Burstable**; **MinIO is Guaranteed** (the
one platform pod whose eviction caused an outage — the broader platform-QoS pass is a separate issue);
the tenant cap sheds at its limit (a sync invoke through the shim gets a true `429`); the failure-test
evidence is committed; and the per-runtime request values are backed by committed measurements (no
remaining "not measured" placeholder for a runtime in use).
