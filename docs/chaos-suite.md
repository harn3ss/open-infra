# Nightly Chaos Suite

> Makes multi-master correctness **mechanical instead of attention-dependent.**

The convergence harness ([convergence-harness.md](convergence-harness.md)) and
`kind: FaultInjection` ([chaos.md](chaos.md)) both exist — but a human has to drive
them. This suite closes that gap: every night, unattended, open-infra partitions its own
multi-master mesh, kills its own capture/sink pods, and proves the mesh still converges
byte-identical. **A red run is a release blocker** — the same enforcement as the
`needs: test` gate. It is the documented road from **Experimental → Stable** for
`Replication` / `Migration` / `DataFlow`.

## What it proves (stated precisely)

- **Byte-identical members** — after the fault heals, every member holds the same key
  set, winning value, and version per key.
- **Zero lost *keys*** — every key written during the fault window survives on every member.
- **Deterministic LWW winner** — concurrent writers to a key all agree on the winner
  (HLC version, ties broken by origin id).

It does **not** claim "no update is ever lost." A conflict's losing *value* is discarded
**by design** — that is what last-write-wins means. The guarantee is *convergence and
determinism*, not preservation of every write.

## Safety model — five layers of containment

There is one real cluster, so containment is built **before** any fault
([platform/resilience/chaos-sandbox.yaml](../platform/resilience/chaos-sandbox.yaml)):

1. **Disposable members.** Scenarios run against ephemeral Postgres in the
   `chaos-sandbox` namespace, seeded synthetically. The data under fault is designed to
   be destroyed — worst case costs nothing real.
2. **Pod-scoped faults only.** `FaultInjection` targets pods by label; the composition
   scopes every Chaos Mesh experiment to a single namespace. Nodes, host networking, and
   host clocks are never touched.
3. **RBAC that makes node harm impossible.** The `chaos-runner` ServiceAccount can
   create/delete faults, pods, and databases **only in `chaos-sandbox`** — nothing
   cluster-scoped except read-only pod list. A fat-fingered selector is *rejected by the
   API server*, not merely discouraged. **Runner creds = chaos creds.**
4. **Resource containment.** A `ResourceQuota` + `LimitRange` cap the sandbox, and a low
   (`-100`, non-preempting) `PriorityClass` means sandbox pods are evicted **first** under
   node pressure — the GPU workloads and HA VMs are protected by the scheduler.
5. **Dead-man's switch.** Every fault sets a `duration` (auto-reverts even if the runner
   crashes), and a **pre-flight guard** ([chaos/preflight.sh](../chaos/preflight.sh))
   resolves the selector and **aborts if it matches any pod outside the sandbox**.

> **`clock-skew` uses no real clock skew** (Chaos Mesh TimeChaos is too invasive). The HLC
> physical-clock read has an injectable offset — `mm_hlc_state.clk_off` (default 0, so
> production is untouched). Scenario 2 sets it backward and asserts the stamped version
> still increases. Safer than skewing a real clock, and a more reliable T6 regression.

## Architecture

```
GitHub (nightly schedule) ─► self-hosted runner on the validation cluster
   1. provision sandbox: ns + ephemeral members + a multi-master mesh
   2. PRE-FLIGHT: resolve selector; abort if it matches outside the sandbox
   3. apply kind: FaultInjection (time-boxed, pod-scoped, label-selected)
   4. run the convergence harness (go test -tags convergence) through the fault
   5. let the fault expire; poll until the mesh re-converges
   6. assert byte-identical / zero lost keys / deterministic LWW winner
   7. tear down; green: recorded · red: RELEASE BLOCKER + artifacts retained
```

## Scenario rollout

Each is one `FaultInjection` + one harness run, and a release gate once green:

1. **`multimaster-partition`** — cut a site off mid-write; assert re-convergence. *(shipped + validated live: a real ~90s diverge-then-converge)*
2. **`clock-skew`** — the T6 regression via an injectable clock offset (not TimeChaos). *(shipped + validated live: HLC stayed monotonic — Δ=1 — under a −1h backward clock instead of dropping ~2.4×10¹¹)*
3. **`sink-kill` / `capture-kill`** — kill the engine mid-flight; offsets + redelivery survive.
4. **`cnpg-failover`** — kill the CNPG primary; converge across promotion.
5. **`longhorn-replica-loss`** — storage degradation; CDC offsets survive.
6. **`mesh-under-concurrent-chaos`** — capture-kill + partition + sink-kill at once (graduation).

## Run it

```bash
# on the self-hosted runner (kubectl + Go + cluster reach):
./chaos/scenario-partition.sh          # provision → preflight → partition → harness → assert → teardown
CHAOS_KEEP=1 ./chaos/scenario-partition.sh   # leave the sandbox up to inspect
```

Nightly automation: [.github/workflows/nightly-chaos.yml](../.github/workflows/nightly-chaos.yml)
(needs a self-hosted runner labelled `openinfra-chaos`).

## Graduation criteria (Experimental → Stable)

`Replication` / `Migration` / `DataFlow` graduate when **all** hold: scenarios 1–4 run
nightly for **30 consecutive days**, **zero unexplained reds** ("flaky, we re-ran it" is
not an explanation), scenario 6 passes, and the README's maturity section is rewritten in
the present tense — *and that sentence is true.*

## Status

- ✅ **Containment foundation** — sandbox namespace, quota, limit range, priority class,
  scoped RBAC, and the pre-flight guard. Deployed and **validated live** (RBAC deny-tests
  pass; pre-flight aborts kube-system and outside-selector faults).
- ✅ **Scenario 1 — validated live, end-to-end.** The sandbox mesh stands up and
  converges (baseline 13s), and under a real partition the harness diverges then
  **re-converges byte-identical in ~108s** (200 keys, 20 conflicts, zero lost writes).
- 💡 **Insight from the first run: the mesh is pod-mediated.** Replication flows
  pg → Debezium → NATS → apply-sink → pg, *never* member-to-member — so a pg-a↔pg-b
  partition injects nothing (it completed in 13s = no cut). Scenario 1 therefore cuts a
  site from its **apply-sink** (the peer that feeds it), which is a real partition. This
  is exactly the class of "bug I hadn't paid for yet" the suite exists to surface. It
  also drove a platform enhancement: `kind: FaultInjection` gained **`partitionPeer`**
  (peer-scoped network-partition — cut A↔B while both stay reachable by outside clients).
- ⏭ **Next** — register the `openinfra-chaos` self-hosted runner to run it nightly;
  bidirectional isolation (also cut the site's Debezium — needs `partitionPeer` to accept
  multiple selectors); then Scenario 2 (injectable clock).
