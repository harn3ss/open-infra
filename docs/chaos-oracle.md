# The Chaos Oracle (Epoch 2 foundation)

> **These four chaos docs:** [primitive](chaos.md) (`kind: FaultInjection`) → **[judging](chaos-oracle.md)** (the oracle: modes + pillars, you are here) → [nightly program](chaos-suite.md) (safety, graduation) → [catalog + live status](chaos-scenarios.md) (every scenario, generated).

A chaos suite is only as trustworthy as the judge that prints "safe." This document defines
that judge — the **oracle**. The
prime directive: *the oracle comes before the injector.* An injector without a trustworthy
oracle just manufactures green you can't stand behind — which is precisely the 2026-07-23
failure (the fault silently didn't fire and the night went green on a lie).

## Verdict space — three outcomes, biased toward suspicion

The oracle's only honest output is a green it can **prove**. Everything else is not-green:

| Verdict | Meaning |
|---------|---------|
| **GREEN** | All applicable pillars witnessed and satisfied. Counts toward the clock. |
| **RED** | A safety or liveness contract was violated — a genuine convergence failure. Stops the clock; root-cause + seed-replay required. |
| **INCONCLUSIVE** | The fault didn't demonstrably fire, or the oracle couldn't tell. **Not green, not red** — the night is thrown out. |

A false red costs an hour; a false green costs a user their data. When in doubt, not-green.

## Two contracts — don't conflate them

- **Safety** — no key lost; every member agrees on the same last-write-wins value per key. A
  safety violation is *never* acceptable, at any fault magnitude.
- **Liveness** — after the fault heals, the mesh actually reconverges, **within a wall-clock
  bound** (not "eventually"). A liveness violation means it didn't recover in time.

They fail differently and are witnessed differently. A partition may be safe throughout
(no data lost) yet fail liveness (never reconverges); or reconverge promptly (liveness) but
lose a key (safety). Both are red.

## The four pillars

Before printing GREEN, the oracle must witness all four:

1. **The fault actually fired.** *(Hardest, most important — the 07-23 gap.)* Do **not** trust
   the injector's own status. Require independent evidence of the *effect* via an **active
   probe** during the fault window (see below). Probe succeeds when it should be cut →
   **INCONCLUSIVE**.
2. **No keys lost** across the whole episode (every write that was accepted survives).
3. **No conflicting winners** — every member ends with the same HLC-winning `(version, value)`
   per key (deterministic last-write-wins).
4. **Reconvergence within a bound** after healing — members become byte-identical inside a
   real wall-clock budget.

Pillars 2–4 are already implemented by the convergence harness
([`apply-sink/convergence_test.go`](../apply-sink/convergence_test.go), see
[convergence-harness.md](convergence-harness.md)): it drives concurrent/conflicting writes
through the fault and asserts every member ends byte-identical (same key set = pillar 2, same
winning version+value = pillar 3) after re-converging within `CONV_TIMEOUT` (pillar 4).
**Pillar 1 is the Epoch-2 addition.**

## One oracle, many workloads — the adapter contract

The suite must eventually judge more than multi-master convergence: a realistic workload chain
is a *migration* (one-way fidelity), an *app* (bounded availability), a *stream* (exactly-once),
a *query* (no torn reads). These are different definitions of "correct", so it is tempting to
write a bespoke oracle per workload — but that forks the verdict machinery (the GREEN/RED/
INCONCLUSIVE space, the reconvergence poll, the safety check) that must be **identical**
everywhere, and a monolithic oracle that branches per workload is one nobody can audit. Neither
is acceptable.

Instead there is **one oracle framework and many small adapters**
([`apply-sink/oracle_framework.go`](../apply-sink/oracle_framework.go)). The shared runner owns
everything that must never differ: drive the workload → poll to steady state within
`CONV_TIMEOUT` → assert no acknowledged work was lost. An adapter (`Oracle`) supplies only the
three workload-specific decisions:

- **`Drive`** — generate work and return the **ledger** of acknowledged units (the promises the
  system made).
- **`SteadyState`** — the predicate for "reconverged to *this* workload's correctness contract".
- **`Reconcile`** — which ledger entries are missing/corrupt in the settled state (lost work).

The unifying principle every adapter instantiates is **conservation of acknowledged work**: the
system may drop in-flight/unacked work and may serve degraded during a fault, but it must never
lose or corrupt what it *acknowledged*, and must reconverge to a state consistent with those
acks. Each workload only defines what an "acknowledged unit" and a "consistent state" are.

### Two oracle MODES

Not every workload is judged after the fault heals. There are two modes, and an adapter belongs to
exactly one:

- **`recover` (conservation)** — drive work, then after healing assert no acknowledged unit was
  lost and the end state is correct. This is `runOracle`. Convergence and migration are here.
- **`tolerate` (continuous SLO)** — a property measured *continuously while the fault is live*, not
  a state checked after it heals. The workload is sampled at a steady cadence and the contract is
  that the measured property stays within an SLO **throughout** the window, then returns to full
  health. Availability (a web service surviving a replica loss) is here.

- **`deny` (negative invariant)** — a thing that must NEVER happen, verified continuously with
  **zero tolerance** (unlike `tolerate`'s SLO, which permits a small breach). A security fence may
  not leak, not once. Cross-tenant isolation (a SecurityGroup that must *refuse* a connection) is
  here.

The three modes share the verdict vocabulary (GREEN/RED/INCONCLUSIVE) and the proof-of-fire
discipline; they differ only in *when* and *how* the property is evaluated (after heal / continuous
SLO / continuous zero-tolerance).

### The adapters that ship today

| Adapter | Mode | Contract | Measured | Lives in |
|---|---|---|---|---|
| **replication** (convergence) | recover | symmetric — every peer agrees | all members byte-identical after heal | `convergence_test.go` |
| **migration** (fidelity) | recover | asymmetric — one-way source → target | target reflects every acked source row | `migration_test.go` |
| **availability** | tolerate | HA service survives instance loss | HTTP success rate ≥ SLO *during* the fault | `scenario-app-availability.sh` |
| **security-deny** | deny | egress fence never leaks | locked client reaches svc-forbidden **0** times while it churns | `scenario-security-deny.sh` |
| **stream-noloss** | recover | CDC stream drops no events | cdc-evt message count ≥ driven changes after a capture kill | `scenario-stream-noloss.sh` |
| **directory-recover** | recover | AD directory survives a DC kill | an account created pre-fault still exists after the DC restarts | `scenario-directory-recover.sh` |
| **fileshare-durable** | recover | SMB share data survives a server kill | a file written pre-fault is present + writable after the Samba pod restarts | `scenario-fileshare-durable.sh` |
| **volume-durable** | recover | block volume data survives a pod reschedule | a raw-block signature reads back after the attached pod is killed | `scenario-volume-durable.sh` |
| **vm-resilience** | recover | VM survives a virt-launcher kill | the VMI returns to Running after its launcher pod is killed | `scenario-vm-resilience.sh` |
| **dataflow-converge** | recover | the DataFlow kind's mesh reconverges | members byte-identical after a DataFlow capture kill | `scenario-dataflow-converge.sh` |

The migration adapter was the first **non-convergence** oracle (proving the runner is a contract,
not a replication harness — it dropped on with zero runner changes). The availability adapter is the
first **non-conservation** oracle, and the security-deny adapter completes the three-mode set. The
coverage then widened across every blast-zone-testable kind — identity (Directory), files
(FileShare), block storage (Volume), compute (VirtualMachine), and the DataFlow topology — so the
suite now exercises the whole workload plane, not just multi-master. (Query is the one kind that is
NOT blast-zone-testable: its composition runs the query Job in the shared `minio` namespace, outside
the sandbox, so a fault there would escape containment.) Every adapter is proven live, and each is
proven to **fail loud** — the suite's prime directive, since an oracle that only prints green is
worthless:

- **convergence** — RED on non-convergence (40% loss brownout); GREEN through a partition.
- **migration** — RED if the target loses rows; GREEN through an apply-sink kill (300 units, zero lost).
- **availability** — RED on a genuine outage (all replicas killed → 87% < 90% SLO, streak 5); GREEN
  on a survivable single-replica kill (100%, streak 0).
- **security-deny** — RED when the fence leaks (an unlocked client reaches svc-forbidden 15/15);
  GREEN when the fence holds (0 breaches across 45 probes while svc-forbidden churns).
- **stream-noloss** — RED on a count shortfall (fewer events on cdc-evt than source changes =
  dropped events); GREEN when the restarted capture drains every change from its durable offset
  (all 151 events after a kill). The gate is the JetStream message *count*, not a body read-back:
  reading N message bodies through the nats CLI (a fresh connection per `stream get`) under-returns
  past a few dozen and is unreliable, whereas the stream's count is exact O(1) metadata; a
  durable-slot capture cannot lose a committed change, so count ≥ driven == nothing dropped.
- **directory / fileshare / volume / vm** — RED if the state is lost after the kill (the account,
  the file, the block signature, or the VM does not come back); GREEN when it does. Verified via
  samba-tool / smbclient / raw-block read / the KubeVirt VMI phase respectively (reliable, no
  guessing).
- **dataflow-converge** — RED on divergence after a capture kill; GREEN when the mesh reconverges.
  Building this chain **found a real product bug**: a DataFlow node named with a hyphen (`pg-a`)
  leaked the hyphen into the Debezium Postgres replication slot name, which PostgreSQL rejects, so
  the capture crash-looped and replication never started. Fixed by sanitizing the node name in the
  slot/publication derivation (`dataflow-composition.yaml`). This is exactly the suite's purpose —
  an injector that surfaces a real defect, caught before a user hit it.

The availability and deny probers run **in-cluster** because the Application's own NetworkPolicy
correctly denies off-cluster ingress (a host-side prober is blocked by Cilium) — the fence working
is itself part of what those oracles witness. See the scenarios under [`chaos/`](../chaos/):
`scenario-migration.sh`, `scenario-app-availability.sh`, `scenario-security-deny.sh`.

## Expectation moves with magnitude (the subtle part)

The oracle reads its definition of "safe" from a **shared timeline** with the injector — what
fault, what magnitude, injected when. The same observation flips verdict with magnitude:

| Observation (mid-fault) | Under a FULL partition | Under MILD latency |
|-------------------------|------------------------|--------------------|
| Sites temporarily diverge | **EXPECTED** — they're cut; fine | **BUG** — a mild delay must not diverge |
| A key present on A, absent on B | EXPECTED during the cut; must heal after | BUG |

So the real cost of the magnitude axis (Phase 1) is not injecting a partial fault — it's
teaching the oracle a *per-magnitude* expectation. The injector and oracle therefore must
share the fault/magnitude/timing timeline; the oracle keys its expectation table off it.

## Expectation table — full partition

The cut severs **site-B pods ↔ the `a→b` apply-sink pod** (`partitionPeer:
{app: chaos-mesh-pg-repl-a-b-sink}`), for 90s, `direction: both`. The mesh path into B is
`pg-a → Debezium → NATS → apply-sink(a→b) → pg-b`; the fault breaks the final
`apply-sink(a→b) → pg-b` hop. Both DBs stay reachable by the harness (only the sink↔B link is
cut), so writes are driven through the cut.

| Pillar | Witness | Expected (full partition) | Verdict if not met |
|--------|---------|---------------------------|--------------------|
| **1. Fired** | Active TCP probe **from the a→b sink pod → `pg-b:5432`** during the fault window | Connect **fails** (SYN dropped / timeout) mid-fault; **succeeds** before & after | Probe *succeeds* mid-fault → fault didn't land → **INCONCLUSIVE** |
| **2. No loss** | Harness key set on every member after heal | All accepted keys present on A **and** B | Missing key → **RED** (safety) |
| **3. Deterministic winner** | `(_mm_version, value)` per key across members | Identical HLC winner on A and B | Divergent winner → **RED** (safety) |
| **4. Reconvergence** | Members byte-identical within `CONV_TIMEOUT` after heal | Diverge during the ~90s cut (**expected** at this magnitude), reconverge after | Not identical within bound → **RED** (liveness) |

Note pillar 4's "diverge during the cut" is **expected** here — at full-partition magnitude,
mid-fault divergence is not a bug. That same divergence under mild latency (now implemented —
see the latency row below) **would** be a bug; the oracle must know the magnitude to grade it.

## Pillar 1 — the proof-of-fire probe (vantage matters)

The probe must run **from the same path the mesh uses**, or it proves nothing. The mesh
reaches B via the `a→b` sink pod, and the partition drops exactly the sink↔B link — so:

- **Vantage:** the `a→b` sink pod's network namespace (its pod IP is what B's drop rules
  target). A probe from the harness or an unrelated pod would **not** be cut and would give a
  false "fault fired = no."
- **Probe:** a **timed** TCP connect to `pg-b:5432`, sampled repeatedly across the fault
  window. `probe-partition.sh` times the handshake with busybox `time` (0.01s resolution —
  busybox `date` has no `%N`) and classifies three states, so one probe witnesses both cuts
  and degrades: `up` (< 0.30s), `slow` (connects but ≥ 0.30s — a latency degrade), `down`
  (connect fails within the timeout — a cut).
- **Verdict logic:**
  - the expected state holds throughout the window → fault fired ✓ (proceed to pillars 2–4).
    For a partition that's `down`; for a latency degrade that's `slow`;
  - the link stays `up` when a fault is meant to be biting → the fault isn't biting →
    **INCONCLUSIVE** (throw the night out; do not let pillars 2–4 bless a fault that didn't
    happen);
  - also sample **before** injection and **after** heal → must be `up`, else the probe path
    itself is broken (→ INCONCLUSIVE, not red).

The probe supersedes the older `MIN_ELAPSED` heuristic (which merely *infers* the cut from a slow
convergence) with a **direct observation** of the severed link. `MIN_ELAPSED` stays as a
secondary guard; the probe is the primary proof-of-fire.

## Method — the oracle comes before the injector

Every fault, and every *magnitude* of it, earns its place the same way: prove all four pillars on
it, give it an **independent proof-of-fire**, and demonstrate the oracle catches a **known-bad
seed** (fails loud) *before* it counts toward the graduation clock. A magnitude whose expectation
isn't encoded in the table below, or whose fail-loud hasn't been demonstrated, is not folded in.
The magnitude axis spans **cut → total isolation → latency → loss → flapping**.

## Magnitude axis — per-magnitude expectations (Phase 1)

The magnitude dial is where the highest-value bugs live: a clean full failure trips a clean
failover, but the *limping* zone (a link that's slow or lossy, not dead) is where conflict
resolution actually breaks. The cost of this axis is **not** injecting the partial fault — the
`FaultInjection` abstraction already exposes the knobs (`direction`, `loss`, `latency`). The
cost is that **the oracle's definition of "safe" flips with magnitude**, so each magnitude
needs its own expectation and its own proof-of-fire. The injector and oracle share the
fault/magnitude timeline; the oracle grades against the row below.

**The load-bearing distinction:** a *cut* makes mid-fault divergence **expected**; a *degrade*
(loss/latency) must **not** diverge — a lossy-but-connected link still carries every write
eventually, so sustained divergence under a degrade is a **real bug**, not a tolerated cut.

| Magnitude | Fault (`FaultInjection`) | Proof-of-fire (independent witness) | Mid-fault expectation | Post-heal |
|-----------|--------------------------|-------------------------------------|-----------------------|-----------|
| **One-directional cut** | `network-partition`, `partitionPeer: a-b-sink`, `direction: both` — cuts a→b apply only | `probe up|down` (TCP to `pg-b:5432` from sink netns) | B misses A's writes; **divergence EXPECTED** (b→a still flows, so A stays whole) | converge |
| **Total isolation** *(harsher)* | `network-partition`, `partitionPeer: {openinfra.dev/replication: <name>}` — cuts pg-b from its **whole** mesh at once: the inbound `a-b-sink→B` **and** the outbound `b-dbz→B` links (the other rules it adds are harmless no-ops — those pods talk to pg-a) | `probe down` (the a-b-sink↔B link, one of the two cut, is the witness) | B fully isolated; **divergence EXPECTED both sides** (B misses A's writes *and* A misses B's) | converge |
| **% packet loss** *(degrade)* | `network-loss`, `loss: "15"`, `direction: both`, same peer | **statistical** (`probe-loss.sh`): 20 connects from sink netns; a *fraction* must be impaired (≥0.10) but not all (that'd be a cut) → loss is biting. 15%, not more: throughput falls ~1/√p, so beyond ~20% an established TCP link brown-outs into a de-facto slow cut (40% left B 119 writes behind) | TCP retransmits carry the data; **NO sustained divergence — divergence = BUG** | converge, tight bound |
| **Latency / jitter** *(degrade)* | `network-latency`, `latency: "800ms"`, `direction: both`, `partitionPeer: a-b-sink` (the peer `target` is what makes `both` legal) | `probe slow` — timed handshake from sink netns elevated to ~1.6s (≫ baseline ~0s) but succeeds | apply lags but lands; **NO sustained divergence — divergence = BUG** | converge, tight bound |
| **Flapping** *(intermittent)* | the partition injected/healed in short repeated cycles *(scenario-level loop)* | `probe up|down` **oscillates** (≥1 `down` observed across cycles) | transient divergence per cut; churn is expected | must converge **after** flapping stops |

### Per-magnitude witnesses

- **Cuts** (partition, total-isolation, flapping) use the up/down `probe-partition.sh`. Total
  isolation cuts pg-b from its whole mesh via the shared `openinfra.dev/replication` label — which
  must be on the pod template, not just the Deployment metadata, or Chaos Mesh / NetworkPolicy
  (which select pods) can't see it.
- **Degrades** (latency, loss) need a witness an up/down probe can't give — a degraded-but-connected
  link reads as "up = no fault." Latency uses a **timed handshake** (`slow` classification); a netem
  `delay` with `direction: both` requires a peer `target` block, so the FaultInjection composition
  emits one for any peer-scoped NetworkChaos, not just partitions. Loss uses a **statistical** witness
  (`probe-loss.sh`: a non-trivial impaired fraction over N connects — a single connect can't witness
  probabilistic loss). Loss is calibrated to 15%: throughput falls ~1/√p, so past ~20% a TCP link
  brown-outs into a de-facto slow cut rather than a degrade.
- **The reconvergence bound tightens for degrades.** Under a cut the bound spans the fault window;
  under loss / latency the mesh should track continuously, so the bound is tighter and a breach is a
  real liveness bug — encoded per row, not one global bound.
