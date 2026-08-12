#!/usr/bin/env python3
"""Unit tests for the capacity ledger's pure accounting (no cluster)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import capacity_ledger as cl  # noqa: E402


def test_empty_fits_within_budget():
    assert cl.fits({"runs": {}}, "a", 4000, 8000, 12000, 36000)


def test_totals_sum_across_runs():
    led = {"runs": {"a": {"cpu": 4000, "mem": 8000}, "b": {"cpu": 3000, "mem": 6000}}}
    assert cl.totals(led) == (7000, 14000)


def test_reservation_excludes_self_so_reserve_is_idempotent():
    led = {"runs": {"a": {"cpu": 10000, "mem": 30000}}}
    # 'a' re-reserving the same footprint must still fit (not double-counted against itself).
    assert cl.fits(led, "a", 10000, 30000, 12000, 36000)


def test_over_budget_cpu_rejected():
    led = {"runs": {"a": {"cpu": 10000, "mem": 8000}}}
    assert not cl.fits(led, "b", 4000, 8000, 12000, 36000)  # 10000+4000 > 12000


def test_over_budget_mem_rejected():
    led = {"runs": {"a": {"cpu": 2000, "mem": 32000}}}
    assert not cl.fits(led, "b", 2000, 8000, 12000, 36000)  # 32000+8000 > 36000


def test_claim_then_release_frees_budget():
    led = {"runs": {}}
    led = cl.claim(led, "a", 12000, 36000)
    assert not cl.fits(led, "b", 1000, 1000, 12000, 36000)  # full
    led = cl.release(led, "a")
    assert cl.fits(led, "b", 12000, 36000, 12000, 36000)  # freed


def test_claim_overwrites_same_run():
    led = cl.claim({"runs": {}}, "a", 1000, 1000)
    led = cl.claim(led, "a", 5000, 5000)
    assert led["runs"]["a"] == {"cpu": 5000, "mem": 5000}
    assert cl.totals(led) == (5000, 5000)


def run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"OK: {len(fns)} capacity-ledger tests passed.")


if __name__ == "__main__":
    run()
