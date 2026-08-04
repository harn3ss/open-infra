#!/usr/bin/env python3
# The Chaos Lottery — seeded draw engine (correlation axis; see docs/chaos-oracle.md).
#
# Where scenarios 1-6 are hypothesis-driven and single-primitive, the lottery is
# exploration-driven and CROSS-primitive: draw 2-4 faults at once and let the convergence oracle
# judge. This file is just the DRAW — pure, deterministic, no cluster — so it can be unit-tested
# and, crucially, REPLAYED: the same seed always yields the same fault set, so a red night is
# reproducible from the seed alone (the driver prints it).
#
# Design (from the lottery spec / handoff):
#   - Seeded + deterministically replayable (a red is re-runnable from its seed).
#   - Draw WITHOUT replacement, blast-radius cap of 2-4 concurrent faults.
#   - ~75% biased toward faults that SHARE a surface tag with what's already drawn (correlation —
#     interaction bugs live where faults touch the same surface); a uniform-random wildcard tail
#     for the rest (a WILDCARD red means the surface tags are wrong — the highest-value signal).
#   - Never draw two faults from the same EXCLUSION GROUP (they'd conflict, e.g. two netem on
#     site-b, or two lifecycle faults on the sink) — those combos are invalid, not interesting.
#
# Bandit-weighting (weighting arms by past yield) is a deliberate later refinement; v1 uses
# uniform arm weights + the surface-tag correlation bias, which is where the spec's value is.
import json
import os
import sys
from random import Random

# The palette: only SIMPLE, concurrently-composable faults that actually inject on this cluster.
# Excluded on purpose: io-latency + dns-error (inert — Chaos Mesh injector panics here), and
# cnpg-failover (a different, CNPG sandbox). Each fault carries surface tags (for the correlation
# bias) and an exclusion group (mutually-exclusive picks). `fault` is the manifest the driver applies.
# `surfaces` = the COMPONENT each fault actually stresses, NOT its location. Correlation is only
# meaningful if a shared surface means a genuine interaction (two faults piling onto the same
# component); location tags like "site-b"/"apply-link" were on ~every fault, so every pair looked
# "correlated", the wildcard tail never fired, and the multi-surface faults out-competed the cuts.
# Components: `pg-b` (the DB — its network AND memory), `sink` (the a→b apply engine — its link,
# lifecycle, CPU), `dbz` (B's capture). netB faults touch pg-b's network AND peer the sink, so they
# carry both; stress-cpu/sink-lifecycle touch only the sink; stress-mem only pg-b; capture-kill only dbz.
# `oracle` = which adapter judges this fault; `sandbox` = which workload stack must be stood up for
# the fault to mean anything (design: open-infra-plane-wide-lottery-design.md §4). Today every fault
# is judged by `convergence` in the `conv_test` sandbox — the palette is all-mesh BY CONSTRUCTION, so
# the single convergence oracle fits every draw. Plane-wide expansion adds faults carrying a different
# `oracle` (e.g. `migration`), at which point the oracle-partitioned draw (below) routes each night to
# one judge + one sandbox. Faults sharing an `oracle` must share a `sandbox`.
PALETTE = [
    {"name": "partition",   "fault": "fault-partition.yaml",  "group": "netB",  "surfaces": ["pg-b", "sink"],        "oracle": "convergence", "sandbox": "conv_test"},
    {"name": "isolation",   "fault": "fault-isolation.yaml",  "group": "netB",  "surfaces": ["pg-b", "sink", "dbz"], "oracle": "convergence", "sandbox": "conv_test"},
    {"name": "latency",     "fault": "fault-latency.yaml",    "group": "netB",  "surfaces": ["pg-b", "sink"],        "oracle": "convergence", "sandbox": "conv_test"},
    {"name": "loss",        "fault": "fault-loss.yaml",       "group": "netB",  "surfaces": ["pg-b", "sink"],        "oracle": "convergence", "sandbox": "conv_test"},
    {"name": "sink-kill",   "fault": "fault-sink-kill.yaml",  "group": "sink",  "surfaces": ["sink"],               "oracle": "convergence", "sandbox": "conv_test"},
    {"name": "sink-failure","fault": "fault-sink-failure.yaml","group": "sink", "surfaces": ["sink"],               "oracle": "convergence", "sandbox": "conv_test"},
    {"name": "stress-cpu",  "fault": "fault-stress-cpu.yaml", "group": "sink",  "surfaces": ["sink"],               "oracle": "convergence", "sandbox": "conv_test"},
    {"name": "capture-kill","fault": "fault-capture-kill.yaml","group": "dbz",  "surfaces": ["dbz"],                "oracle": "convergence", "sandbox": "conv_test"},
    {"name": "stress-mem",  "fault": "fault-stress-mem.yaml", "group": "db",    "surfaces": ["pg-b"],               "oracle": "convergence", "sandbox": "conv_test"},
]

CORRELATION_BIAS = float(os.environ.get("LOTTERY_CORRELATION_BIAS", "0.75"))  # P(prefer a shared-surface pick)
MIN_DRAW = int(os.environ.get("LOTTERY_MIN", "2"))
MAX_DRAW = int(os.environ.get("LOTTERY_MAX", "4"))  # blast-radius cap

# Cross-group CONFLICTS — combos that don't physically compose (vs merely share a surface). A
# netem fault programs a qdisc PEERED on specific mesh pods (via an ipset of their IPs). A co-drawn
# pod-KILL of a peer pod recreates it with a new IP, so the netem can't resolve/inject its peer and
# never reaches AllInjected — and it's a degenerate combo anyway (two ways to break the same link).
# Note pod-FAILURE keeps the pod (same IP), so it does NOT conflict (healing-order composes
# partition + sink-failure). Peer sets: partition/latency/loss peer on a-b-sink; isolation peers on
# the WHOLE mesh (openinfra.dev/replication), so any mesh pod-kill stales it.
def _conflicts(a: str, b: str) -> bool:
    pair = {a, b}
    if (pair & {"partition", "latency", "loss"}) and "sink-kill" in pair:
        return True  # these peer on a-b-sink; sink-kill recreates it
    if "isolation" in pair and (pair & {"sink-kill", "capture-kill"}):
        return True  # isolation peers on the whole mesh; any mesh pod-kill stales its peer set
    return False


def draw(seed: int):
    """Return (list-of-fault-dicts, meta) for a seed. Deterministic: same seed -> same draw."""
    rng = Random(seed)
    # Oracle-partitioned draw (design §5, recommended-first): pick ONE oracle for the night, then
    # draw only its faults — so a night has one judge + one sandbox (lowest false-green surface). With
    # a single oracle in the palette this MUST be a no-op that consumes no RNG, so historical seeds
    # replay identically; the meta-draw only activates once a second oracle is added to the palette.
    oracles = sorted({f["oracle"] for f in PALETTE})
    oracle = oracles[0] if len(oracles) == 1 else rng.choice(oracles)
    pool = [f for f in PALETTE if f["oracle"] == oracle]

    # Cap the draw at how many distinct exclusion groups exist in this oracle's pool (one-per-group).
    ngroups = len({f["group"] for f in pool})
    k = rng.randint(MIN_DRAW, min(MAX_DRAW, ngroups))

    chosen, used_groups, used_surfaces = [], set(), set()
    wildcards = 0

    while len(chosen) < k:
        avail = [f for f in pool
                 if f["group"] not in used_groups
                 and not any(_conflicts(f["name"], c["name"]) for c in chosen)]
        if not avail:
            break
        shared = [f for f in avail if used_surfaces & set(f["surfaces"])]
        # First pick is always "wildcard" (nothing drawn yet); after that, bias toward shared surface.
        if chosen and shared and rng.random() < CORRELATION_BIAS:
            pick = rng.choice(shared)
        else:
            pick = rng.choice(avail)
            if chosen and pick not in shared:
                wildcards += 1
        chosen.append(pick)
        used_groups.add(pick["group"])
        used_surfaces.update(pick["surfaces"])

    # All faults of one oracle share a sandbox; surface that for the composer/driver to stand up.
    sandboxes = sorted({f["sandbox"] for f in chosen})
    meta = {
        "seed": seed,
        "oracle": oracle,
        "sandbox": sandboxes[0] if len(sandboxes) == 1 else sandboxes,
        "count": len(chosen),
        "faults": [f["name"] for f in chosen],
        "shared_surfaces": sorted(used_surfaces),
        "wildcard_picks": wildcards,
        "replay": f"LOTTERY_SEED={seed}",
    }
    return chosen, meta


def resolve_seed() -> int:
    """LOTTERY_SEED if set (for replay), else a fresh random seed (printed for reproducibility)."""
    env = os.environ.get("LOTTERY_SEED")
    if env is not None and env != "":
        return int(env)
    # os.urandom, not time — no wall-clock dependency, and still unique per night.
    return int.from_bytes(os.urandom(4), "big")


if __name__ == "__main__":
    # CLI: `lottery-draw.py [seed]` prints the draw as JSON (dry-run friendly; the driver reads it).
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else resolve_seed()
    chosen, meta = draw(seed)
    print(json.dumps({"meta": meta, "faults": chosen}, indent=2))
