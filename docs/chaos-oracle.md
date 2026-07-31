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
mid-fault divergence is not a bug. That same divergence under mild latency (a future axis)
would be a bug; the oracle must know the magnitude to grade it.

## Pillar 1 — the proof-of-fire probe (vantage matters)

The probe must run **from the same path the mesh uses**, or it proves nothing. The mesh
reaches B via the `a→b` sink pod, and the partition drops exactly the sink↔B link — so:

- **Vantage:** the `a→b` sink pod's network namespace (its pod IP is what B's drop rules
  target). A probe from the harness or an unrelated pod would **not** be cut and would give a
  false "fault fired = no."
- **Probe:** a short-timeout TCP connect to `pg-b:5432` (e.g. 3s), sampled repeatedly across
  the fault window.
- **Verdict logic:**
  - fails throughout the window → fault fired ✓ (proceed to pillars 2–4);
  - succeeds at any mid-window sample → the cut isn't biting → **INCONCLUSIVE** (throw the
    night out; do not let pillars 2–4 bless a fault that didn't happen);
  - also sample **before** injection and **after** heal → must succeed, else the probe path
    itself is broken (→ INCONCLUSIVE, not red).

This replaces the current `MIN_ELAPSED` heuristic (which merely *infers* the cut from a slow
convergence) with a **direct observation** of the severed link. `MIN_ELAPSED` stays as a
secondary guard; the probe is the primary proof-of-fire.

## Build order (Phase 0 → 1)

1. **This table + the proof-of-fire probe for the full partition** — prove all four pillars on
   the one fault already run, before touching the injector or the draw.
2. Only then bring up the magnitude axis (partial/asymmetric partitions, %-loss, jittering
   latency) — and for **each** magnitude, extend this table with its per-magnitude expectation
   and prove the oracle catches a known-bad seed before it counts.
