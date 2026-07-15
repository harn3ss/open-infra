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
3. **`sink-kill` / `capture-kill`** — kill the engine mid-flight; offsets + redelivery survive. *(shipped + validated live: sink pod killed mid-write, mesh still converged with zero lost writes)*
4. **`cnpg-failover`** — kill the CNPG primary; converge across promotion. *(shipped + validated live: promoted cnpg-b-1→cnpg-b-2 with writes in flight, mesh converged; surfaced the `publication.autocreate.mode` bug below)*
5. **`longhorn-replica-loss`** — storage degradation; CDC offsets survive. **PARKED — not
   wired into the nightly**, for two independent reasons (see *Scenario 5 is blocked* below).
   Not required for graduation.
6. **`mesh-under-concurrent-chaos`** — capture-kill + partition + sink-kill at once (graduation). *(shipped + validated live: all three landed together, mesh converged in 124s — the cut genuinely bit)*

## Run it

```bash
# on the self-hosted runner (kubectl + Go + cluster reach):
./chaos/scenario-partition.sh   # provision → preflight → partition → harness → assert → teardown
./chaos/scenario-clockskew.sh   # T6: force the clock backward via clk_off, assert monotonic
./chaos/scenario-sinkkill.sh    # kill the apply-sink mid-write, assert the mesh still converges
./chaos/scenario-cnpgfailover.sh # kill the CNPG primary mid-write, assert convergence across promotion
./chaos/scenario-concurrent.sh   # GRADUATION: capture-kill + partition + sink-kill at once
CHAOS_KEEP=1 ./chaos/scenario-partition.sh   # leave the sandbox up to inspect
```

> **Every scenario must prove its fault landed, while the harness is still running.** A
> chaos test whose fault silently no-ops — or lands after the test finished — reports green
> while proving nothing, which is worse than no test. So: `sink-kill` asserts the pod was
> replaced; `cnpg-failover` asserts a promotion actually occurred *and* that the harness was
> still in flight; `partition` shows it as a ~90s diverge-then-converge (a ~13s run means
> nothing was injected); `clock-skew` shows it as Δ=1. Each of these guards exists because
> the corresponding false green actually happened here first.

Nightly automation: [.github/workflows/nightly-chaos.yml](../.github/workflows/nightly-chaos.yml)
(needs a self-hosted runner labelled `openinfra-chaos`).

## Graduation criteria (Experimental → Stable)

`Replication` / `Migration` / `DataFlow` graduate when **all** hold: scenarios 1–4 run
nightly for **30 consecutive days**, **zero unexplained reds** ("flaky, we re-ran it" is
not an explanation), scenario 6 passes, and the README's maturity section is rewritten in
the present tense — *and that sentence is true.*

## Status

- ✅ **Containment foundation** — sandbox namespace, quota, limit range, priority class,
  scoped RBAC, and the pre-flight guard. **Validated live** (RBAC deny-tests pass;
  pre-flight aborts kube-system and outside-selector faults).
- ✅ **Runner** — a self-hosted runner (`openinfra-chaos`) runs as a systemd service and
  authenticates as the sandbox-scoped `chaos-runner` SA: *runner creds = chaos creds*.
- ✅ **Scenarios 1–4 and 6 validated live** (partition · clock-skew · sink-kill · cnpg-failover ·
  concurrent-chaos). Only Scenario 5 (`longhorn-replica-loss`, not graduation-required) is open.
- ⏭ **Next** — the **30-consecutive-night clock** (all graduation scenarios now pass);
  Scenario 5 (`longhorn-replica-loss`); bidirectional isolation (needs `partitionPeer` to
  accept multiple selectors).

## Scenario 5 is blocked (and why that is the right call)

**1. A real Longhorn replica cannot be faulted safely here.** Replicas live in
`instance-manager` pods in `longhorn-system`, and each hosts replicas for *many* volumes —
this cluster has **11 real volumes** backing VMs, databases and MinIO. Faulting one would
degrade real workloads: forbidden by §3 ("nothing the suite does may endanger the cluster")
and correctly refused by the pre-flight guard. §10 already calls for a **separate validation
cluster** before scenarios 4–5 touch real storage.

**2. The safe alternative — `io-latency` — does not actually inject.** Degrading the
sandbox's *own* Longhorn-backed volume would have answered the same question safely, but
Chaos Mesh's FUSE injector (`toda`) **panics** on this cluster:

```
thread panicked at 'Send through channel failed', src/jsonrpc.rs:74
chaos-daemon: Starting toda takes too long or encounter an error → kill toda
```

The IOChaos then sits at `phase: Not Injected/Wait, injectedCount: 0` **forever, silently**.
`kind: FaultInjection` advertises `io-latency` in its XRD enum, so **any user selecting it
gets an inert fault that looks applied**. This was caught only because scenarios assert
`AllInjected=True` rather than "the object exists" — the weaker check passed it as green.

The script + fault manifest are kept (`chaos/scenario-storage.sh`) for when either blocker
clears, but shipping it nightly would mean a permanently-red scenario — which violates the
"zero unexplained reds" bar as surely as a false green does.

## What the suite has already caught

It has earned its keep before ever running a nightly — each of these was found by making a
scenario real, and each is fixed:

- **A partition that injected nothing.** The mesh is *pod-mediated* (pg → Debezium → NATS →
  apply-sink → pg), so cutting pg-a↔pg-b does nothing. Drove the `partitionPeer` fault
  primitive and a rewritten Scenario 1.
- **Replication could not capture from open-infra's own managed databases.** Debezium
  defaults to `publication.autocreate.mode=all_tables`, which issues
  `CREATE PUBLICATION … FOR ALL TABLES` — a **superuser-only** statement. CNPG (correctly)
  makes the app user a non-superuser, so `kind: Replication`/`DataFlow` over a managed
  database failed outright. It was masked because the raw `postgres` image makes its user a
  superuser. Fixed by `autocreate.mode=filtered` wherever an explicit table list exists.
- **A silently-ignored timeout.** `CONV_TIMEOUT`/`CONV_SETTLE` take *bare seconds*; passing
  `"300s"` fell back to the 120s default, leaving Scenario 1 passing at 107s with 13s of
  unnoticed margin.
- **A fault that landed after the test finished** (a false green), and **a driver that
  couldn't survive the fault it tested** (a 3s write-retry vs a ~4–10s promotion).
- **A fault type that never injects.** `io-latency` creates its IOChaos and reports nothing
  wrong, but `toda` panics and it never injects — inert while looking applied. Caught only by
  asserting `AllInjected=True`.
- **Chaos landing on already-converged data.** Concurrent-chaos first "passed" in 21s with
  all three faults provably landed — but the mesh had already replicated everything before
  they hit. Scenarios that use a timed cut now **assert the convergence delay** (`MIN_ELAPSED`),
  so a fault that fails to actually bite is a red, not a green.
