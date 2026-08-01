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

Each is one `FaultInjection` + one harness run, and a release gate once green:

1. **`multimaster-partition`** — cut a site off mid-write; assert re-convergence. *(shipped + validated live: a real ~90s diverge-then-converge)*
2. **`clock-skew`** — the T6 regression via an injectable clock offset (not TimeChaos). *(shipped + validated live: HLC stayed monotonic — Δ=1 — under a −1h backward clock instead of dropping ~2.4×10¹¹)*
3. **`sink-kill` / `capture-kill`** — kill the engine mid-flight; offsets + redelivery survive. *(shipped + validated live: sink pod killed mid-write, mesh still converged with zero lost writes)*
4. **`cnpg-failover`** — kill the CNPG primary; converge across promotion. *(shipped + validated live: promoted cnpg-b-1→cnpg-b-2 with writes in flight, mesh converged; surfaced the `publication.autocreate.mode` bug below)*
5. **`longhorn-replica-loss`** — storage degradation; CDC offsets survive. **PARKED — not
   wired into the nightly**, for two independent reasons (see *Scenario 5 is blocked* below).
   Not required for graduation.
6. **`mesh-under-concurrent-chaos`** — capture-kill + partition + sink-kill at once (graduation). *(shipped + validated live: all three landed together, mesh converged in 124s — the cut genuinely bit)*

### Magnitude variants (Phase 1)

The partition scenario also runs at other **magnitudes** — the "limping zone" where conflict
resolution actually breaks (see [docs/chaos-oracle.md](chaos-oracle.md)). The oracle's verdict
*flips* with magnitude, so each carries its own proof-of-fire and expectation:

- **`partition-flapping`** — the cut is injected/healed in short repeated cycles while the
  harness drives conflicting writes; the mesh must converge **after** the flapping stops, with
  ≥1 cut confirmed live. *(shipped + validated live: converged byte-identical, cut confirmed.)*
- **`partition-latency`** — a *degrade*, not a cut: 800ms both-ways on the sink↔B apply path,
  held for the whole run. The opposite expectation — the mesh **must keep converging** (a
  degrade never severs, so sustained divergence is a **bug**, and there is no `MIN_ELAPSED`
  floor). Proof-of-fire is the timed handshake reading `slow` (~1.6s), not `down`. *(shipped +
  validated live: converged byte-identical — 220 keys / 20 conflicts / zero lost — under
  sustained 800ms, ~4× slower apply path.)*
- **`partition-isolation`** — harsher cut: severs site B from its **whole** mesh at once (both
  the inbound a-b-sink→B and the outbound b-dbz→B links, via the shared `openinfra.dev/replication`
  label), so **both** members diverge and both must reconverge — vs the default partition's
  one-sided cut. Same `down` proof-of-fire and `MIN_ELAPSED` floor as the partition (it's a
  cut). *(shipped + validated live: both diverged, reconverged byte-identical in 126s, cut
  confirmed `down`.)*
- **`partition-loss`** — a *degrade* like latency: drop 15% of the sink↔B packets. The mesh
  **must keep converging** (TCP retransmits carry every write; sustained divergence is a bug,
  no `MIN_ELAPSED`). Proof-of-fire is **statistical** (`probe-loss.sh`: 20 handshakes, a
  non-trivial fraction impaired). 15% not higher: past ~20% an established TCP link brown-outs
  into a slow cut. *(shipped + validated live: converged byte-identical in 22s under sustained
  15% loss; the 40% attempt correctly failed to converge — a throughput brownout, which is why
  the value is calibrated down.)*

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
./chaos/scenario-partition-loss.sh      # magnitude: 15% packet-loss degrade, must keep converging (statistical probe)
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

## Scenario 5 is blocked (and why that is the right call)

**1. A real Longhorn replica cannot be faulted safely here.** Replicas live in
`instance-manager` pods in `longhorn-system`, and each hosts replicas for *many* volumes —
this cluster has **11 real volumes** backing VMs, databases and MinIO. Faulting one would
degrade real workloads: forbidden by §3 ("nothing the suite does may endanger the cluster")
and correctly refused by the pre-flight guard. §10 already calls for a **separate validation
cluster** before scenarios 4–5 touch real storage.

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

This is a host-level incompatibility, not a config we can flip: fixing it means either a
Chaos Mesh release whose `GrantAccess` understands cgroup v2, or booting the host back to
cgroup v1 (`systemd.unified_cgroup_hierarchy=0`) — a bad trade to enable one non-graduation
scenario, since k3s/containerd and much else assume v2. So **`io-latency` stays disabled on
this host** and Scenario 5's IO path stays blocked — now for a second, precisely-understood
reason on top of the real-replica one above.

`kind: FaultInjection` still advertises `io-latency` in its XRD enum, so **any user selecting
it gets an inert fault that looks applied** (removing it from the enum is a tracked hardening
follow-up). This was caught only because scenarios assert `AllInjected=True` rather than "the
object exists" — the weaker check passed it as green.

The script + fault manifest are kept (`chaos/scenario-storage.sh`) for when either blocker
clears, but shipping it nightly would mean a permanently-red scenario — which violates the
"zero unexplained reds" bar as surely as a false green does.

## Backlog — Scenario 7: the Chaos Lottery

**Gated on: 30 consecutive green nights.** Not started, deliberately.

Where scenarios 1–6 are hypothesis-driven and single-primitive ("does multi-master converge
across a partition?"), the lottery is exploration-driven and **cross-primitive**: draw 2–5
random faults from the `FaultInjection` enum, aim them at random targets across *different*
primitives (Replication · DataFlow · Query · Function · MinIO/NATS/Longhorn), randomise
durations and start offsets so they overlap and cascade, then assert the whole **platform**
re-cohered. Seeded and replayable (a lottery that finds a bug it can't reproduce is worse
than none), weekly rather than nightly, advisory before it ever gates a release.

It composes the primitives that already exist — `preflight.sh`, `partitionPeer`, the
injectable `clk_off` — so randomisation can never widen the blast radius.

**Two corrections to fold in when it is built** (both learned the hard way here):

1. **Drop `io-latency` from the fault pool until it works.** It never injects (`toda`
   panics) — a random draw would silently under-test and still report green. With scripted
   faults you can eyeball whether each one bit; a generator cannot.
2. **Never generate a member↔member partition.** On a pod-mediated mesh (db → capture → bus
   → sink → db) it injects *nothing*. The generator must cut a member from the **engine that
   feeds it** (that is what `partitionPeer` is for).

Both make the `AllInjected` / fault-landed assertions **mandatory infrastructure** for the
lottery rather than a nicety: a silently-inert fault in a random chain is invisible.

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
