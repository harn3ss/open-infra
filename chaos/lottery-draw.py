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
PALETTE = [
    {"name": "partition",   "fault": "fault-partition.yaml",  "group": "netB",  "surfaces": ["network", "apply-link", "site-b"]},
    {"name": "isolation",   "fault": "fault-isolation.yaml",  "group": "netB",  "surfaces": ["network", "apply-link", "mesh", "site-b"]},
    {"name": "latency",     "fault": "fault-latency.yaml",    "group": "netB",  "surfaces": ["network", "apply-link", "site-b"]},
    {"name": "loss",        "fault": "fault-loss.yaml",       "group": "netB",  "surfaces": ["network", "apply-link", "site-b"]},
    {"name": "sink-kill",   "fault": "fault-sink-kill.yaml",  "group": "sink",  "surfaces": ["pod", "sink", "apply-link"]},
    {"name": "sink-failure","fault": "fault-sink-failure.yaml","group": "sink", "surfaces": ["pod", "sink", "apply-link"]},
    {"name": "stress-cpu",  "fault": "fault-stress-cpu.yaml", "group": "sink",  "surfaces": ["compute", "sink"]},
    {"name": "capture-kill","fault": "fault-capture-kill.yaml","group": "dbz",  "surfaces": ["pod", "capture", "site-b"]},
    {"name": "stress-mem",  "fault": "fault-stress-mem.yaml", "group": "db",    "surfaces": ["compute", "memory", "db", "site-b"]},
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
    # Cap the draw at how many distinct exclusion groups exist (can't exceed one-per-group).
    ngroups = len({f["group"] for f in PALETTE})
    k = rng.randint(MIN_DRAW, min(MAX_DRAW, ngroups))

    chosen, used_groups, used_surfaces = [], set(), set()
    wildcards = 0
    pool = list(PALETTE)

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

    meta = {
        "seed": seed,
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
