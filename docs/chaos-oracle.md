# The Chaos Oracle (Epoch 2 foundation)

A chaos suite is only as trustworthy as the judge that prints "safe." This document defines
that judge — the **oracle** — before any new injector or the lottery draw is built. The
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

(A third mode, `deny` — a negative invariant, e.g. a SecurityGroup must *refuse* cross-tenant
access — is anticipated but not yet built.) The modes share the verdict vocabulary
(GREEN/RED/INCONCLUSIVE) and the proof-of-fire discipline; they differ only in *when* the property
is evaluated.

### The adapters that ship today

| Adapter | Mode | Contract | Measured | Lives in |
|---|---|---|---|---|
| **replication** (convergence) | recover | symmetric — every peer agrees | all members byte-identical after heal | `convergence_test.go` |
| **migration** (fidelity) | recover | asymmetric — one-way source → target | target reflects every acked source row | `migration_test.go` |
| **availability** | tolerate | HA service survives instance loss | HTTP success rate ≥ SLO *during* the fault | `scenario-app-availability.sh` |

The migration adapter was the first **non-convergence** oracle (proving the runner is a contract,
not a replication harness — it dropped on with zero runner changes). The availability adapter is
the first **non-conservation** oracle, proving the framework spans *modes*, not just workloads: its
prober runs **in-cluster** because the Application's own NetworkPolicy correctly denies off-cluster
ingress (a host-side prober is blocked by Cilium) — the fence working is part of what the oracle
witnesses. All three are proven live, and each is proven to **fail loud**: convergence RED on
non-convergence (40% loss brownout), migration RED if the target loses rows, availability RED on a
genuine outage (all replicas killed → 87% < 90% SLO, failure streak 5) while GREEN on a survivable
single-replica kill (100%, streak 0). See [`chaos/scenario-migration.sh`](../chaos/scenario-migration.sh)
and [`chaos/scenario-app-availability.sh`](../chaos/scenario-app-availability.sh).

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

## Expectation table — full partition (Scenario 1, the one fault run so far)

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

This replaces the current `MIN_ELAPSED` heuristic (which merely *infers* the cut from a slow
convergence) with a **direct observation** of the severed link. `MIN_ELAPSED` stays as a
secondary guard; the probe is the primary proof-of-fire.

## Build order (Phase 0 → 1)

1. **This table + the proof-of-fire probe for the full partition** — prove all four pillars on
   the one fault already run, before touching the injector or the draw. ✅ *(done — the probe
   is shaken out up→down→up live; see `chaos/probe-partition.sh`, `scenario-partition.sh`.)*
2. Only then bring up the magnitude axis — and for **each** magnitude, extend this table with
   its per-magnitude expectation and prove the oracle catches a known-bad seed before it counts.
   ✅ *(shipped so far: **flapping** — `scenario-partition-flapping.sh`, converges after
   repeated cut/heal with ≥1 cut confirmed live; **latency degrade** — `scenario-partition-latency.sh`,
   converges byte-identical under sustained 800ms with the handshake confirmed `slow`;
   **total isolation** — `scenario-partition-isolation.sh`, both members diverge under a
   whole-mesh cut and reconverge byte-identical (126s, cut confirmed `down`); **% loss** —
   `scenario-partition-loss.sh`, converges byte-identical under sustained 15% loss (22s) with a
   statistical proof-of-fire. That completes the magnitude axis (cut → total isolation →
   latency → loss → flapping). All shaken out live off-gate before folding in.)*

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
| **One-directional cut** *(current)* | `network-partition`, `partitionPeer: a-b-sink`, `direction: both` — cuts a→b apply only | `probe up|down` (TCP to `pg-b:5432` from sink netns) | B misses A's writes; **divergence EXPECTED** (b→a still flows, so A stays whole) | converge |
| **Total isolation** *(harsher — current)* | `network-partition`, `partitionPeer: {openinfra.dev/replication: <name>}` — cuts pg-b from its **whole** mesh at once: the inbound `a-b-sink→B` **and** the outbound `b-dbz→B` links (the other rules it adds are harmless no-ops — those pods talk to pg-a) | `probe down` (the a-b-sink↔B link, one of the two cut, is the witness) | B fully isolated; **divergence EXPECTED both sides** (B misses A's writes *and* A misses B's) | converge |
| **% packet loss** *(degrade — current)* | `network-loss`, `loss: "15"`, `direction: both`, same peer | **statistical** (`probe-loss.sh`): 20 connects from sink netns; a *fraction* must be impaired (≥0.10) but not all (that'd be a cut) → loss is biting. 15%, not more: throughput falls ~1/√p, so beyond ~20% an established TCP link brown-outs into a de-facto slow cut (40% left B 119 writes behind) | TCP retransmits carry the data; **NO sustained divergence — divergence = BUG** | converge, tight bound |
| **Latency / jitter** *(degrade — current)* | `network-latency`, `latency: "800ms"`, `direction: both`, `partitionPeer: a-b-sink` (the peer `target` is what makes `both` legal) | `probe slow` — timed handshake from sink netns elevated to ~1.6s (≫ baseline ~0s) but succeeds | apply lags but lands; **NO sustained divergence — divergence = BUG** | converge, tight bound |
| **Flapping** *(intermittent — current)* | the partition injected/healed in short repeated cycles *(scenario-level loop)* | `probe up|down` **oscillates** (≥1 `down` observed across cycles) | transient divergence per cut; churn is expected | must converge **after** flapping stops |

### Build increments (each: build → un-gated shakedown → prove fail-loud → fold in)

- **Cuts reuse the proven probe.** Total-isolation and flapping use the existing up/down
  `probe-partition.sh` unchanged. Both are **done**: flapping is a scenario loop; total-isolation
  needed **no** `partitionPeer`-list enhancement after all — the mesh pods share an
  `openinfra.dev/replication` label, so one peer selector cuts pg-b from its whole mesh. (That
  required fixing a latent omission: the label was on the Deployment metadata but not the pod
  template, so Chaos Mesh/NetworkPolicy — which select pods — couldn't see it.)
- **Degrades need a new witness.** `latency`'s RTT witness is **done**: `probe-partition.sh`
  now times the handshake and classifies `slow` (a degraded-but-connected link an up/down probe
  would have misread as "up = no fault fired"); shaken out live up→slow→down. It also required
  a composition fix — a netem `delay` with `direction: both` is rejected by Chaos Mesh unless a
  peer `target` block is present, so the FaultInjection composition now emits that block for any
  peer-scoped NetworkChaos, not just partitions. `%-loss` is also **done**: `probe-loss.sh`
  samples 20 connects and asserts a non-trivial impaired fraction (a single connect can't witness
  probabilistic loss). Calibrated to 15% — throughput falls ~1/√p, so a higher loss brown-outs
  the link into a de-facto slow cut, not a degrade (validated: 40% left B 119 writes behind).
- **The oracle's reconvergence bound tightens for degrades.** Under a cut, the bound spans the
  fault window; under loss/latency the mesh should track continuously, so the bound is much
  tighter and a breach is a real liveness bug — encode that per row, not a single global bound.
