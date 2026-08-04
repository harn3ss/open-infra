#!/usr/bin/env python3
# Unit test for the lottery draw engine (chaos/lottery-draw.py). Pure, no cluster.
# Run: python3 chaos/test_lottery_draw.py   (exit 0 = pass). Wired into CI (test.yml chaosdraw job).
#
# Guards, in order of importance:
#  1. REPLAY: a fixed seed yields a fixed draw — a red night is reproducible from its seed alone.
#     Adding the oracle/sandbox tags must NOT shift the RNG, so historical seeds replay identically.
#  2. Invariants: draw size in [MIN,MAX]; never two faults from one exclusion group; never a
#     physically-conflicting pair; every fault carries oracle+sandbox.
#  3. Oracle-partitioning: each night's draw is confined to ONE oracle (one judge + one sandbox),
#     proven both on the real (single-oracle) palette and on a synthetic two-oracle palette.
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("lottery_draw", os.path.join(HERE, "lottery-draw.py"))
ld = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ld)

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


# 1. Replay / regression guard — this exact draw is the pre-tag baseline. If the tag addition (or any
#    future change) shifts the RNG, this trips and every historical red seed becomes unreplayable.
_, meta = ld.draw(12345)
check(meta["faults"] == ["partition", "capture-kill", "sink-failure"],
      f"replay changed for seed 12345: {meta['faults']}")
# determinism: same seed twice -> identical
_, meta2 = ld.draw(12345)
check(meta2["faults"] == meta["faults"], "draw is non-deterministic for a fixed seed")

# 2 + 3 on the real palette (all convergence today).
by_name = {f["name"]: f for f in ld.PALETTE}
for seed in range(1000):
    chosen, meta = ld.draw(seed)
    names = meta["faults"]
    check(ld.MIN_DRAW <= len(names) <= ld.MAX_DRAW, f"draw size {len(names)} out of range, seed={seed}")
    check(len(names) == len(set(names)), f"duplicate fault drawn, seed={seed}: {names}")
    groups = [by_name[n]["group"] for n in names]
    check(len(groups) == len(set(groups)), f"two faults from one group, seed={seed}: {names}")
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            check(not ld._conflicts(names[i], names[j]),
                  f"physically-conflicting pair drawn, seed={seed}: {names[i]}+{names[j]}")
    check(all("oracle" in f and "sandbox" in f for f in chosen), f"fault missing oracle/sandbox, seed={seed}")
    # oracle-partitioned: all drawn faults share the meta's oracle + sandbox
    check(all(by_name[n]["oracle"] == meta["oracle"] for n in names), f"draw mixed oracles, seed={seed}: {names}")
    check(meta["oracle"] == "convergence" and meta["sandbox"] == "conv_test",
          f"unexpected oracle/sandbox on the all-mesh palette, seed={seed}: {meta['oracle']}/{meta['sandbox']}")

# 3b. Synthetic second oracle — proves the meta-draw confines a night to ONE oracle and covers all of
#     them over time, BEFORE any real non-mesh fault exists. (This is the plane-wide path in miniature.)
saved = ld.PALETTE
try:
    ld.PALETTE = saved + [
        {"name": "mig-a", "fault": "a.yaml", "group": "migA", "surfaces": ["mig"], "oracle": "migration", "sandbox": "mig_test"},
        {"name": "mig-b", "fault": "b.yaml", "group": "migB", "surfaces": ["mig"], "oracle": "migration", "sandbox": "mig_test"},
    ]
    by = {f["name"]: f for f in ld.PALETTE}
    seen = set()
    for seed in range(500):
        chosen, meta = ld.draw(seed)
        seen.add(meta["oracle"])
        check(all(by[n]["oracle"] == meta["oracle"] for n in meta["faults"]),
              f"two-oracle palette produced a cross-oracle draw, seed={seed}: {meta['faults']}")
        check(all(by[n]["sandbox"] == meta["sandbox"] for n in meta["faults"]),
              f"cross-sandbox draw, seed={seed}: {meta['faults']}")
    check(seen == {"convergence", "migration"}, f"meta-draw did not cover both oracles over 500 seeds: {seen}")
finally:
    ld.PALETTE = saved

if fails:
    print("lottery-draw: FAIL")
    for m in fails[:20]:
        print("  -", m)
    sys.exit(1)
print("lottery-draw: all checks passed")
