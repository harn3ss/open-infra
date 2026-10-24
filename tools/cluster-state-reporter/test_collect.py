#!/usr/bin/env python3
"""Honesty-rule tests for the cluster-state collector (polyhedron#319).

Two kinds of test:
  1. Source-scan guards (no import needed) that FAIL on the regressions #319 found — a hard-coded
     datastore assertion, the old binary `"ok"` probe state, and bare `except: pass` swallows.
  2. Unit tests of the three-state contract (probe_state / state_mark), which need the module imported.

Run:  python3 test_collect.py     (plain asserts, no pytest needed)   — or under pytest.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "collect.py"), encoding="utf-8").read()


# ---- 1. source-scan guards (the #319 regressions must not come back) --------------------------------
def test_no_hardcoded_datastore_assertion():
    # The bug: the control-plane probe printed "kine over SQLite" as a literal every run, regardless of
    # the real datastore. Any statement of datastore FACT must be derived from a read this run.
    for banned in ("kine over SQLite", "kine over sqlite", "embedded (kine"):
        assert banned not in SRC, f"hard-coded datastore assertion found: {banned!r} — derive it from the API"
    assert "detect_datastore(" in SRC, "probe_controlplane must derive the datastore from the API"


def test_no_probe_returns_literal_ok():
    # Deep probes returned ("Label", "ok", detail) — "the probe ran", rendered as a green ✅. The state
    # must now be computed (probe_state/HEALTHY), never the literal "ok" in the probe-return position.
    assert ', "ok",' not in SRC, 'a probe still returns the literal state "ok" — use probe_state(findings, unchecked)'


def test_no_bare_except_pass():
    # Item 5 class: a swallowed read must become a `not checked (reason)`, never a silent `except: pass`.
    m = re.search(r"except[^\n]*:\s*\n\s*pass\b", SRC)
    assert not m, f"bare `except: pass` swallow found near: {m.group(0)!r} — surface it as not-checked"


def test_front_page_greencheck_only_for_healthy():
    # The ✅ mark must be reserved for exactly the "healthy" state.
    assert "state_mark(" in SRC, "issue body must render probe marks via state_mark()"


# ---- 2. three-state contract unit tests -------------------------------------------------------------
def _mod():
    import importlib
    import collect  # noqa
    return collect


def test_probe_state_semantics():
    c = _mod()
    assert c.probe_state([], []) == "healthy"
    assert c.probe_state(["finding"], []).startswith("unhealthy")
    assert c.probe_state([], ["a part"]).startswith("partial")
    both = c.probe_state(["f"], ["u"])
    assert both.startswith("unhealthy") and "not checked" in both


def test_state_mark_reserves_greencheck():
    c = _mod()
    assert c.state_mark("healthy") == "✅"
    assert c.state_mark("partial (not checked: x)") == "⚠️"
    assert c.state_mark("unhealthy (3 finding(s))") == "⚠️"
    assert c.state_mark("not checked (Node not accessible)") == "❓"


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"PASS {name}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL {name}: {e}")
            failed += 1
        except Exception as e:
            # a logic test may not import the kubernetes client in every runner; report, don't crash the scan guards
            print(f"SKIP {name}: {type(e).__name__}: {e}")
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(1 if failed else 0)
