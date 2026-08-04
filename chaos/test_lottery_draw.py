#!/usr/bin/env python3
# Unit test for the lottery draw engine (chaos/lottery-draw.py). Pure, no cluster.
# Run: python3 chaos/test_lottery_draw.py   (exit 0 = pass). Wired into CI (test.yml chaos-draw job).
#
# Guards, in order of importance:
#  1. REPLAY: a fixed seed yields a fixed draw — a red night is reproducible from its seed alone.
#     Adding the oracle/sandbox tags and the gated migration fault must NOT shift the counted-nightly
#     RNG, so historical seeds replay identically.
#  2. GATING: a gated fault is in the palette (tagged/routable) but NEVER appears in the default
#     (counted) draw; LOTTERY_ORACLE=<name> forces it for un-gated shakeout.
#  3. Invariants: draw size within bounds; never two faults from one exclusion group; never a
#     physically-conflicting pair; every fault carries oracle+sandbox; a draw is confined to ONE oracle.
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


def invariants(chosen, meta, by_name, seed):
    names = meta["faults"]
    check(1 <= len(names) <= ld.MAX_DRAW, f"draw size {len(names)} out of range, seed={seed}")
    check(len(names) == len(set(names)), f"duplicate fault drawn, seed={seed}: {names}")
    groups = [by_name[n]["group"] for n in names]
    check(len(groups) == len(set(groups)), f"two faults from one group, seed={seed}: {names}")
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            check(not ld._conflicts(names[i], names[j]), f"conflicting pair, seed={seed}: {names[i]}+{names[j]}")
    check(all("oracle" in f and "sandbox" in f for f in chosen), f"fault missing oracle/sandbox, seed={seed}")
    check(all(by_name[n]["oracle"] == meta["oracle"] for n in names), f"draw mixed oracles, seed={seed}: {names}")


by_name = {f["name"]: f for f in ld.PALETTE}
os.environ.pop("LOTTERY_ORACLE", None)

# 1. Replay / regression guard — the pre-tag baseline. The gated migration fault must not perturb it.
_, meta = ld.draw(12345)
check(meta["faults"] == ["partition", "capture-kill", "sink-failure"], f"replay changed for seed 12345: {meta['faults']}")
_, meta2 = ld.draw(12345)
check(meta2["faults"] == meta["faults"], "draw is non-deterministic for a fixed seed")

# 2. Default (counted) draw: convergence-only, gated faults NEVER appear, invariants hold.
gated = {f["name"] for f in ld.PALETTE if f.get("gated")}
check(gated, "expected at least one gated fault in the palette (migration)")
for seed in range(1000):
    chosen, meta = ld.draw(seed)
    check(meta["oracle"] == "convergence" and meta["sandbox"] == "conv_test",
          f"default draw was not convergence, seed={seed}: {meta['oracle']}")
    check(not (set(meta["faults"]) & gated), f"gated fault leaked into the counted draw, seed={seed}: {meta['faults']}")
    check(ld.MIN_DRAW <= len(meta["faults"]) <= ld.MAX_DRAW, f"convergence draw size out of [2,4], seed={seed}")
    invariants(chosen, meta, by_name, seed)

# 3. LOTTERY_ORACLE forces a gated oracle (un-gated shakeout): migration night draws only migration.
os.environ["LOTTERY_ORACLE"] = "migration"
try:
    for seed in range(200):
        chosen, meta = ld.draw(seed)
        check(meta["oracle"] == "migration", f"forced migration draw wrong oracle, seed={seed}: {meta['oracle']}")
        check(meta["sandbox"] == "mig_test", f"forced migration wrong sandbox, seed={seed}: {meta['sandbox']}")
        check(all(by_name[n]["oracle"] == "migration" for n in meta["faults"]), f"forced draw not all-migration, seed={seed}")
        check(len(meta["faults"]) >= 1, f"forced migration drew nothing, seed={seed}")
        invariants(chosen, meta, by_name, seed)
finally:
    os.environ.pop("LOTTERY_ORACLE", None)

# 4. Synthetic SECOND un-gated oracle — proves the meta-draw's cross-oracle pick confines a night to
#    one oracle and covers all of them over seeds (the rng.choice path the real gated palette doesn't hit).
saved = ld.PALETTE
try:
    ld.PALETTE = [f for f in saved if not f.get("gated")] + [
        {"name": "mig-a", "fault": "a.yaml", "group": "migA", "surfaces": ["mig"], "oracle": "migration", "sandbox": "mig_test"},
        {"name": "mig-b", "fault": "b.yaml", "group": "migB", "surfaces": ["mig"], "oracle": "migration", "sandbox": "mig_test"},
    ]
    by = {f["name"]: f for f in ld.PALETTE}
    seen = set()
    for seed in range(500):
        chosen, meta = ld.draw(seed)
        seen.add(meta["oracle"])
        check(all(by[n]["oracle"] == meta["oracle"] for n in meta["faults"]), f"cross-oracle draw, seed={seed}: {meta['faults']}")
    check(seen == {"convergence", "migration"}, f"meta-draw did not cover both un-gated oracles over 500 seeds: {seen}")
finally:
    ld.PALETTE = saved

if fails:
    print("lottery-draw: FAIL")
    for m in fails[:20]:
        print("  -", m)
    sys.exit(1)
print("lottery-draw: all checks passed")
