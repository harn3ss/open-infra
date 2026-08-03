# Nightly Chaos Suite

> **These four chaos docs:** [primitive](chaos.md) (`kind: FaultInjection`) → [judging](chaos-oracle.md) (the oracle: modes + pillars) → **[nightly program](chaos-suite.md)** (safety, graduation, you are here) → [catalog + live status](chaos-scenarios.md) (every scenario, generated).

> Makes multi-master correctness **mechanical instead of attention-dependent.**

The convergence harness ([convergence-harness.md](convergence-harness.md)) and
`kind: FaultInjection` ([chaos.md](chaos.md)) both exist — but a human has to drive
them. This suite closes that gap: every night, unattended, open-infra runs the **chaos lottery** —
a seeded, replayable draw of 2–4 concurrent faults (partitions, pod kills, latency/loss,
CPU/memory stress, clock skew) against its own multi-master mesh — and proves the mesh still
converges byte-identical. (The individual scenarios remain runnable on demand via
`workflow_dispatch`; the lottery is the scheduled capstone that composes from them.) **A red run is a release blocker** — the same enforcement as the
`needs: test` gate. It is the documented road from **Experimental → Stable** for
`Replication` / `Migration` / `DataFlow`.

## Scope — multi-master nightly, the wider plane on-demand

**What the _counted_ nightly proves is multi-master convergence.** The scheduled lottery drives
disposable multi-master meshes and asserts they reconverge; that is the clock gating
`Replication` / `Migration` / `DataFlow` from Experimental → Stable, and it is deliberately narrow so
a green streak means something precise.

**The chaos program is wider than the nightly, though.** The same oracle runner
([chaos-oracle.md](chaos-oracle.md)) generalized into **one framework, three modes
(recover / tolerate / deny), and ten per-kind adapters** across the whole workload plane — managed
databases, identity (`Directory`), files (`FileShare`), block storage (`Volume`), compute
(`VirtualMachine`), streaming (`Stream` / `Function`), and networking/security (`SecurityGroup` / IAM).
Every scenario — its chain, its ⚡ fault point, its invariant, and its last-verified date + method — is
published in the auto-generated gallery: **[chaos-scenarios.md](chaos-scenarios.md)**.

**Honest boundary:** those wider scenarios run **on-demand** (`workflow_dispatch`) and as hand-driven
batches — they are **not yet in the counted nightly clock**, which remains multi-master-only. Folding
the whole plane into the nightly beat is the open next step; until then the gallery's per-scenario
`Verified` dates state plainly which results are nightly-fresh vs point-in-time.

## What the nightly proves (multi-master, stated precisely)

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
   cluster-scoped except a read-only list of pods, namespaces and nodes (the two
   pre-flight guards need to see cluster state; they can change none of it). A
   fat-fingered selector is *rejected by the API server*, not merely discouraged.
   **Runner creds = chaos creds.**
4. **Resource containment.** A `ResourceQuota` + `LimitRange` cap the sandbox, and a low
   (`-100`, non-preempting) `PriorityClass` means sandbox pods are evicted **first** under
   node pressure — the GPU workloads and HA VMs are protected by the scheduler.
5. **Dead-man's switch.** Every fault sets a `duration` (auto-reverts even if the runner
   crashes), and a **pre-flight guard** ([chaos/preflight.sh](../chaos/preflight.sh))
   resolves the selector and **aborts if it matches any pod outside the sandbox**.
6. **Capacity pre-flight.** A second guard
   ([chaos/preflight-capacity.sh](../chaos/preflight-capacity.sh)) runs before every
   scenario provisions its sandbox: it sums allocatable headroom across the Ready,
   schedulable nodes and, if there isn't enough to run the sandbox, aborts **INCONCLUSIVE**
   (exit 42) rather than letting the pods sit `Pending` and the scenario time out as a
   **false red**. It deliberately does *not* require every node Ready — a node is often
   powered down on purpose in the reference cluster (its GPU node is halted nightly) — only
   that the survivors have room.
   An INCONCLUSIVE night is neither red nor green: it does not block a release and does not
   advance the graduation clock. It fails **open** — an unreadable cluster never blocks a
   run.

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

Each scenario is one `FaultInjection` + one harness run, and a **release gate once green**. The
graduation-required set is the multi-master convergence scenarios — a one-sided partition and its
magnitude variants (isolation, latency, loss, flapping), `clock-skew`, `sink-kill` / `capture-kill`,
and `cnpg-failover` — plus the **`mesh-under-concurrent-chaos`** capstone (all three faults at once).
`longhorn-replica-loss` is proven as admin but not graduation-required (pending a scoped
longhorn-system RBAC decision).

The **magnitude dial** — cut vs *degrade* (latency / loss) — is where the highest-value bugs live: a
clean cut trips a clean failover, but the *limping* zone is where conflict resolution actually breaks,
so the oracle's verdict *flips* with magnitude. That framework (per-magnitude expectations + their
proof-of-fire) lives in **[chaos-oracle.md](chaos-oracle.md)**.

**The full, current catalog** — every scenario, its chain, its ⚡ fault point, its invariant, and its
last-verified date + method — is the auto-generated gallery, **[chaos-scenarios.md](chaos-scenarios.md)**.
That is the source of truth for *what exists and its status*; this doc keeps only the nightly program's
design (safety, graduation, how to run).

## Run it

```bash
# on the self-hosted runner (kubectl + Go + cluster reach):
./chaos/scenario-partition.sh   # provision → preflight → partition → harness → assert → teardown
./chaos/scenario-clockskew.sh   # T6: force the clock backward via clk_off, assert monotonic
./chaos/scenario-sinkkill.sh    # kill the apply-sink mid-write, assert the mesh still converges
./chaos/scenario-cnpgfailover.sh # kill the CNPG primary mid-write, assert convergence across promotion
./chaos/scenario-concurrent.sh   # GRADUATION: capture-kill + partition + sink-kill at once
./chaos/scenario-partition-flapping.sh  # magnitude: repeated cut/heal, converge after it stops
./chaos/scenario-partition-latency.sh   # magnitude: 800ms degrade, must keep converging (no MIN_ELAPSED)
./chaos/scenario-partition-isolation.sh # magnitude: cut B from its whole mesh, both sides diverge + reconverge
./chaos/scenario-sink-drain-kill.sh   # target-selection: kill the sink MID-backlog-drain, offset must survive
./chaos/scenario-lottery.sh           # correlation: seeded draw of 2-4 concurrent faults (LOTTERY_SEED=N to replay)
./chaos/scenario-partition-loss.sh      # magnitude: 15% packet-loss degrade, must keep converging (statistical probe)
HEAL_ORDER=partition-first ./chaos/scenario-healing-order.sh  # timing/overlap: partition+sink outage, heal in order, reconverge
./chaos/scenario-stress-cpu.sh           # fault-variety: CPU pressure on the apply-sink, must keep converging
./chaos/scenario-stress-mem.sh           # fault-variety: memory pressure on pg-b, must keep converging
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

### The graduation record must name its exclusion

The clock runs on scenarios **1–4 + 6**. Scenario 5 is *structurally* un-runnable here
(faulting a real Longhorn replica would degrade ~11 real volumes; the pre-flight guard
refuses it) and its safe substitute `io-latency` is inert. **So the mesh graduates with no
storage-fault coverage.** When this graduates, the claim must say so, in these words:

> *Graduated on partition / clock-skew / sink-kill / cnpg-failover / concurrent-chaos.
> Storage-degradation coverage deferred to the validation cluster.*

Otherwise "chaos-proven" quietly implies a scenario that never ran — which is precisely the
claim-outruns-code failure this whole apparatus exists to prevent. A suite that refuses its
own false greens cannot then launder an untested dimension into a headline.

### Known reds (and why the clock survives them)

"Zero **unexplained** reds" — so an explained red must be named here, with a ruling on
whether it resets the clock. The test: **did the fault land on the system under test?** A red
where the replication mesh actually diverged is a product bug and resets the clock. A red in
the *harness's own scaffolding* — the fault never injected, so the mesh was never exercised —
is not attributable to the application's solidarity and does **not** reset it.

- **2026-07-23 — partition scenario, harness red, clock NOT reset.** Chaos Mesh's
  controller↔daemon mTLS certs had drifted (Helm `genSignedCert` is non-deterministic under
  `helm template`, so every Argo sync rewrote them; see [chaos.md](chaos.md) and
  `platform/resilience/chaos-mesh.yaml`), so `NetworkChaos` silently failed to inject. The
  mesh converged in 19s — not because it survived a partition, but because there was no
  partition — and the `MIN_ELAPSED` false-green guard correctly failed the run rather than
  bless it. The system under test never diverged; the cut never bit. This is the guard doing
  its job, not a correctness failure. Fixed durably (Argo `ignoreDifferences` freezes the
  cert chain) and re-run green. Off-net to the application; the clock stands.

### Epochs (re-epoch on a change to the system under test)

The clock counts nights on **one binary**. A material change to the code the oracle exercises
starts a new epoch — the same SUT-vs-harness test as the known-reds, applied to *code* rather
than *faults*. Prior nights are retained as history of the old binary, not chained across the
change. Documenting the boundary is the point: an unexplained streak that quietly spans a SUT
change is the asterisk an auditor distrusts.

- **Epoch 1 → Epoch 2 — `nats.go 1.34.1 → 1.52.0` in apply-sink.** NATS is the transport
  every nightly run rides (`db → Debezium → NATS → apply-sink`), for every engine, so this
  bump lands squarely on the system under test → **re-epoch**. Epoch 2, day 1 = the first
  nightly on the nats.go-1.52 binary; Epoch 1's ~15 nights are retained as pre-bump history.
  The live count lives in the Actions run history, not this file. *(The DB-driver bumps in the
  same batch — pgx unchanged; mysql/mssqldb not on the nightly Postgres path — did NOT drive
  this; the transport did.)*

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

## Scenario 5 — storage replica-loss (now runnable; mechanism proven 2026-08-01)

Formerly blocked for two reasons; the first is now **solved** and the second is **moot**. The
real replica-loss test runs end-to-end (`chaos/scenario-storage-replica-loss.sh`): provision the
sandbox DBs on Longhorn, lose a replica of pg-b's volume mid-write, and assert the volume
degrades-but-survives, the DB stays queryable off the surviving replica, the mesh converges
byte-identical (zero lost writes), and Longhorn rebuilds to healthy. *(Shaken out live as admin:
degrade confirmed, converged 22s, rebuilt to 2 replicas across 2 chaos nodes.)*

**1. Faulting a real replica used to be unsafe — now the sandbox has its OWN fault-able
storage.** Replicas live in `instance-manager` pods in `longhorn-system`, each hosting replicas
for many *production* volumes, so faulting one degraded real workloads. Resolved by the
dedicated disposable chaos nodes + a storage fence: the sandbox DBs use the `longhorn-chaos`
StorageClass (`nodeSelector: chaos`), so their replicas land ONLY on chaos nodes, while
`allowEmptyNodeSelectorVolume: false` keeps every production (empty-selector) volume OFF those
tagged nodes. Proven both directions live. Losing a chaos-node replica therefore never touches
production data — the §3 safety bar is met without a separate cluster.

**Re-add durability.** The segmentation (taint + `openinfra.dev/chaos` label) survives a node
rebuild because it lives in the k3s agent config. The Longhorn side did not — `tags:[chaos]`,
`allowScheduling` and the cleared eviction are runtime `nodes.longhorn.io` state, and
`createDefaultDiskLabeledNodes: true` means a rebuilt node gets no disk. A reconciler
([platform/storage/chaos-node-longhorn-reconciler.yaml](../platform/storage/chaos-node-longhorn-reconciler.yaml))
closes that from the one durable signal — the node label — setting the create-default-disk label
and the Longhorn node tag/scheduling on every `openinfra.dev/chaos` node (Sync Job now + a
self-healing CronJob), so a rebuilt chaos node reacquires its disk and `chaos` tag on its own.

**2. The safe alternative — `io-latency` — does not actually inject, and now we know
exactly why.** Degrading the sandbox's *own* Longhorn-backed volume would have answered the
same question safely, but every IOChaos sits at `phase: Not Injected/Wait, injectedCount: 0`
**forever, silently**. Re-tested 2026-07-27 (once the drop-17 cert freeze was in, on the
hypothesis it shared that root cause — it does **not**). The confirmed root cause is a
**cgroup-v2 incompatibility in Chaos Mesh 2.7.2**, not certs and not really `toda`:

```
chaos-daemon  main.go:83  grant access to /dev/fuse  {"error": "fail to find device cgroup"}
                          pkg/fusedev/fusedev_linux.go:60  fusedev.GrantAccess
```

Both chaos-daemons fail this identically at boot. `fusedev.GrantAccess` looks for a legacy
cgroup-v1 `devices` controller to grant the daemon `/dev/fuse`, but this host (Ubuntu 24.04)
runs the **unified cgroup-v2 hierarchy** — there is no `/sys/fs/cgroup/devices` to find. With
no `/dev/fuse`, `toda` (the FUSE injector) can't mount, so the earlier "Starting toda takes
too long → kill toda" / `jsonrpc.rs` panic is a *downstream* symptom of this grant failure.

**2b. `io-latency` is a confirmed DEAD END — and now moot.** io-latency was only ever a *safe
stand-in* for faulting storage; with the real replica-loss test above, it isn't needed. And the
one apparent fix is impossible: booting the chaos nodes to cgroup v1
(`systemd.unified_cgroup_hierarchy=0`) to restore the `devices` controller was **tried on all
three (2026-08-01) and reverted** — the devices controller reappeared, but **this k3s's kubelet
refuses to run on cgroup v1** (`kubelet is configured to not run on a host using cgroup v1`),
so the nodes went NotReady. io-latency needs cgroup v1; the kubelet needs cgroup v2 — mutually
exclusive on this Kubernetes version. The only theoretical path left is a Chaos Mesh release
whose `GrantAccess` speaks cgroup v2. So **`io-latency` stays disabled** (drop it from the XRD
enum — tracked), but Scenario 5's *purpose* (storage resilience) is now covered by real
replica-loss, not IO latency.

`kind: FaultInjection` still advertises `io-latency` in its XRD enum, so **any user selecting
it gets an inert fault that looks applied** (removing it from the enum is a tracked hardening
follow-up). This was caught only because scenarios assert `AllInjected=True` rather than "the
object exists" — the weaker check passed it as green.

**Remaining gap before nightly automation (the one safety-sensitive piece):** the scenario
deletes a `replicas.longhorn.io` in `longhorn-system` — outside the sandbox namespace. It's
proven runnable *as admin*, but granting the sandbox-scoped `chaos-runner` broad delete on
Longhorn replicas would let a bug reach *production* replicas, violating the blast-radius model.
So it is **not yet wired into the nightly**: the fault mechanism is proven, but automating it
needs a deliberately-scoped grant (or a narrower fault primitive) — a decision to make, not to
sneak in via a broad RBAC rule. Until then it runs on demand as admin.

## Scenario 7: the Chaos Lottery *(shipped — the capstone)*

Where scenarios 1–6 are hypothesis-driven and single-primitive ("does multi-master converge
across a partition?"), the lottery is exploration-driven and **cross-primitive**. A seeded draw
([chaos/lottery-draw.py](../chaos/lottery-draw.py)) picks **2–4** concurrent faults from the
composable palette, biased ~75% toward faults sharing a surface tag (interaction bugs live where
faults overlap) with a uniform wildcard tail; `scenario-lottery.sh` applies them all at once,
**proves each one fired**, drives the convergence harness through the combined chaos, heals, and
requires byte-identical reconvergence with zero lost. Design: seeded + **replayable** (a red
reruns with `LOTTERY_SEED=<seed>`, printed prominently), draw-**without-replacement**, blast-cap
2–4, convergence oracle as judge. *(Shaken out live: seed 7 `[latency, capture-kill, stress-mem]`
converged 250s; seed 42 `[isolation, stress-mem, sink-failure]` — a max-blast cut combo —
reconverged 599s.)*

Baked-in lessons (all learned the hard way here):

1. **The palette excludes inert faults.** `io-latency` and `dns-error` never inject on this
   cluster (their Chaos Mesh Rust injectors panic); a random draw of them would silently
   under-test. They're out of the pool.
2. **No member↔member partitions.** On a pod-mediated mesh the netB faults cut a member from the
   **engine that feeds it** via `partitionPeer` — never member↔member (which injects nothing).
3. **Per-fault proof-of-fire is mandatory.** Every drawn fault must be independently witnessed
   (Chaos Mesh `AllInjected` / pod-replaced); a partial draw is INCONCLUSIVE, never green — a
   silently-inert fault in a random chain would otherwise be invisible.
4. **Conflict model.** netem faults peer on mesh pods, so the draw never pairs one with a pod-KILL
   of a peer pod (the peer's IP churns and the netem can't inject) — those are two ways to break
   the same link, not an interesting combo.

**Bandit-weighting** (weighting arms by past yield) is the tracked next refinement; v1 uses
uniform arm weights + the surface-tag correlation bias, which is where the spec's value is.

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
