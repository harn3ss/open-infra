#!/usr/bin/env python3
"""Capacity RESERVATION for parallel chaos runs.

preflight-capacity.sh answers "is there room right now?" by MEASURING free CPU/mem on the chaos
nodes — but it does not reserve it. With many runs starting at once, each measures the same free
headroom and they all proceed, oversubscribing the nodes into Pending pods and false reds. Parallel
runs need a RESERVATION, not a measurement.

This keeps a shared ledger of each run's reserved footprint in a single ConfigMap and claims against
a budget ATOMICALLY, using Kubernetes optimistic concurrency (`kubectl replace` fails on a
resourceVersion mismatch, so two runners racing the same claim can't both win — the loser retries
against the latest ledger). A run reserves before it provisions and releases on teardown.

  capacity_ledger.py reserve --run-id ID --cpu 4000 --mem 8192 --budget-cpu 12000 --budget-mem 36000
      exit 0  reserved   | exit 42 does-not-fit (INCONCLUSIVE, back off) | exit 1 error
  capacity_ledger.py release --run-id ID
  capacity_ledger.py status

The accounting (fits/claim/release) is pure and unit-tested; only the CAS I/O touches the cluster.
"""
import argparse
import json
import os
import subprocess
import sys

LEDGER_NS = os.environ.get("CHAOS_LEDGER_NS", "chaos-mesh")
LEDGER_CM = os.environ.get("CHAOS_LEDGER_CM", "chaos-capacity-ledger")

# ---- pure accounting ----


def totals(ledger, exclude=None):
    cpu = mem = 0
    for rid, r in ledger.get("runs", {}).items():
        if rid == exclude:
            continue
        cpu += int(r.get("cpu", 0))
        mem += int(r.get("mem", 0))
    return cpu, mem


def fits(ledger, run_id, cpu, mem, budget_cpu, budget_mem):
    """Does run_id's footprint fit within budget alongside the OTHER runs? (Excludes run_id so a
    re-reservation by the same run is idempotent, never double-counted.)"""
    used_cpu, used_mem = totals(ledger, exclude=run_id)
    return (used_cpu + cpu <= budget_cpu) and (used_mem + mem <= budget_mem)


def claim(ledger, run_id, cpu, mem):
    runs = dict(ledger.get("runs", {}))
    runs[run_id] = {"cpu": int(cpu), "mem": int(mem)}
    return {"runs": runs}


def release(ledger, run_id):
    runs = dict(ledger.get("runs", {}))
    runs.pop(run_id, None)
    return {"runs": runs}


# ---- cluster I/O (optimistic concurrency) ----


def _kubectl(args, stdin=None, check=True):
    return subprocess.run(
        ["kubectl", "-n", LEDGER_NS, *args],
        input=stdin, capture_output=True, text=True, check=check,
    )


def _get_cm():
    """Return (resourceVersion, ledger_dict). Creates an empty ledger CM if absent."""
    r = _kubectl(["get", "configmap", LEDGER_CM, "-o", "json"], check=False)
    if r.returncode != 0:
        empty = {"runs": {}}
        cm = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": LEDGER_CM, "namespace": LEDGER_NS},
            "data": {"ledger": json.dumps(empty)},
        }
        _kubectl(["create", "-f", "-"], stdin=json.dumps(cm), check=False)
        r = _kubectl(["get", "configmap", LEDGER_CM, "-o", "json"])
    obj = json.loads(r.stdout)
    rv = obj["metadata"]["resourceVersion"]
    ledger = json.loads(obj.get("data", {}).get("ledger", '{"runs":{}}'))
    return rv, ledger


def _replace_cm(rv, ledger):
    """CAS: replace the CM at resourceVersion rv. Returns True on success, False on conflict."""
    cm = {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": LEDGER_CM, "namespace": LEDGER_NS, "resourceVersion": rv},
        "data": {"ledger": json.dumps(ledger)},
    }
    r = _kubectl(["replace", "-f", "-"], stdin=json.dumps(cm), check=False)
    return r.returncode == 0


def _mutate(fn, retries=6):
    """Read-modify-write the ledger under optimistic concurrency. fn(ledger) -> (new_ledger, result)
    where result is returned to the caller. Retries on CAS conflict."""
    for _ in range(retries):
        rv, ledger = _get_cm()
        new_ledger, result = fn(ledger)
        if new_ledger is None:  # fn declined (e.g. does not fit) — no write
            return result
        if _replace_cm(rv, new_ledger):
            return result
    return "CONFLICT"


# ---- commands ----


def cmd_reserve(a):
    def fn(ledger):
        if not fits(ledger, a.run_id, a.cpu, a.mem, a.budget_cpu, a.budget_mem):
            return None, "NOFIT"
        return claim(ledger, a.run_id, a.cpu, a.mem), "OK"

    res = _mutate(fn)
    if res == "OK":
        print(f"reserved {a.run_id}: cpu={a.cpu}m mem={a.mem}Mi")
        return 0
    if res == "NOFIT":
        uc, um = totals(_get_cm()[1], exclude=a.run_id)
        print(f"INCONCLUSIVE — {a.run_id} does not fit: {uc}+{a.cpu}m / {um}+{a.mem}Mi "
              f"exceeds budget {a.budget_cpu}m / {a.budget_mem}Mi. Back off.")
        return 42
    print(f"error: could not reserve ({res})", file=sys.stderr)
    return 1


def cmd_release(a):
    _mutate(lambda ledger: (release(ledger, a.run_id), "OK"))
    print(f"released {a.run_id}")
    return 0


def cmd_status(_a):
    _, ledger = _get_cm()
    uc, um = totals(ledger)
    print(f"reserved: cpu={uc}m mem={um}Mi across {len(ledger.get('runs', {}))} run(s)")
    print(json.dumps(ledger, indent=2, sort_keys=True))
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("reserve")
    r.add_argument("--run-id", required=True)
    r.add_argument("--cpu", type=int, required=True, help="millicores")
    r.add_argument("--mem", type=int, required=True, help="Mi")
    r.add_argument("--budget-cpu", type=int, default=int(os.environ.get("CHAOS_BUDGET_CPU_M", 12000)))
    r.add_argument("--budget-mem", type=int, default=int(os.environ.get("CHAOS_BUDGET_MEM_MI", 36000)))
    r.set_defaults(fn=cmd_reserve)
    rel = sub.add_parser("release")
    rel.add_argument("--run-id", required=True)
    rel.set_defaults(fn=cmd_release)
    st = sub.add_parser("status")
    st.set_defaults(fn=cmd_status)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
