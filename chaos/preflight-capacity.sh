#!/usr/bin/env bash
# Node-capacity pre-flight for the Nightly Chaos Suite.
#
# preflight.sh answers "is this fault safe to apply?" (blast radius). This answers a
# DIFFERENT question: "can the cluster even RUN a scenario right now?" If a node is down
# AND the survivors are full, the sandbox pods sit Pending and the scenario times out
# RED — a false red charged to the product when the real cause is just infrastructure.
# When schedulable headroom is short we abort INCONCLUSIVE (exit 42); the nightly-chaos
# workflow treats that as neither a green night nor a red one.
#
# It deliberately does NOT require every node Ready — a node is often off on purpose here
# (the GPU box is powered down nightly). What matters is whether the Ready, schedulable
# nodes have room for the sandbox, not the size of the roster.
#
# Fail-OPEN: if cluster state can't be read (e.g. the read-only `nodes` grant hasn't
# synced yet), it warns and proceeds — a capacity guard must never itself block a run on
# a read error. It only ever STOPS a run when it is confident capacity is short.
#
# exit 0 = enough headroom (or the check was skipped) → proceed
# exit 42 = INCONCLUSIVE (capacity short) → skip; count as neither red nor green
set -uo pipefail

MIN_READY_NODES="${CHAOS_MIN_READY_NODES:-1}"   # usable Ready/schedulable nodes required
REQ_FREE_CPU_M="${CHAOS_REQ_FREE_CPU_M:-1500}"  # millicores of unreserved CPU the sandbox needs
REQ_FREE_MEM_MI="${CHAOS_REQ_FREE_MEM_MI:-3072}" # Mi of unreserved memory the sandbox needs
# The sandbox is PINNED to the dedicated chaos nodes (nodeSelector) and TOLERATES their taint,
# so capacity must be measured on THOSE nodes — not the untainted general pool. (An empty label
# key falls back to counting the general untainted pool, for non-segmented clusters.)
CHAOS_NODE_LABEL="${CHAOS_NODE_LABEL:-openinfra.dev/chaos}"
CHAOS_NODE_LABEL_VALUE="${CHAOS_NODE_LABEL_VALUE:-true}"
CHAOS_TOLERATED_TAINT="${CHAOS_TOLERATED_TAINT:-openinfra.dev/chaos}"

# Read cluster state into temp files — `kubectl get pods -A -o json` is far too large to
# pass through argv or the environment (E2BIG), so python reads the files by path.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
kubectl get nodes -o json >"$TMP/nodes.json" 2>/dev/null || : >"$TMP/nodes.json"
kubectl get pods -A -o json >"$TMP/pods.json" 2>/dev/null || : >"$TMP/pods.json"
if [ ! -s "$TMP/nodes.json" ] || [ ! -s "$TMP/pods.json" ]; then
  echo "▸ capacity preflight: SKIPPED — cannot read nodes/pods (RBAC not synced yet?); proceeding." >&2
  exit 0
fi

python3 - "$MIN_READY_NODES" "$REQ_FREE_CPU_M" "$REQ_FREE_MEM_MI" "$TMP/nodes.json" "$TMP/pods.json" "$CHAOS_NODE_LABEL" "$CHAOS_NODE_LABEL_VALUE" "$CHAOS_TOLERATED_TAINT" <<'PY'
import sys, json

min_ready = int(sys.argv[1]); req_cpu = int(sys.argv[2]); req_mem = int(sys.argv[3])
nodes = json.load(open(sys.argv[4])).get("items", [])
pods  = json.load(open(sys.argv[5])).get("items", [])
label_key = sys.argv[6]; label_val = sys.argv[7]; tolerated_taint = sys.argv[8]

def cpu_m(q):
    if not q: return 0
    q = str(q)
    if q.endswith("m"): return int(float(q[:-1]))
    if q.endswith("n"): return int(float(q[:-1]) / 1e6)
    if q.endswith("u"): return int(float(q[:-1]) / 1e3)
    return int(float(q) * 1000)

# Ordered so binary suffixes (Ki/Mi/…) are tested before decimal (K/M/…).
_MEM = [("Ki", 1/1024), ("Mi", 1), ("Gi", 1024), ("Ti", 1024*1024), ("Pi", 1024**3),
        ("K", 1000/(1024*1024)), ("M", 1000*1000/(1024*1024)),
        ("G", 1000**3/(1024*1024)), ("T", 1000**4/(1024*1024))]
def mem_mi(q):
    if not q: return 0.0
    q = str(q)
    for suf, mul in _MEM:
        if q.endswith(suf):
            return float(q[:-len(suf)]) * mul
    return float(q) / (1024*1024)  # bare bytes

# Usable node = where the sandbox can actually schedule: carries the chaos node label (if the
# cluster is segmented), Ready, schedulable, no resource pressure, and no NoSchedule/NoExecute
# taint OTHER than the one the sandbox tolerates. Measuring the untainted general pool here
# would be a false-OK — the sandbox pins to the (tainted) chaos nodes.
usable = set(); alloc_cpu = {}; alloc_mem = {}
for n in nodes:
    name = n["metadata"]["name"]
    labels = n.get("metadata", {}).get("labels", {}) or {}
    if label_key and labels.get(label_key) != label_val:
        continue  # not a chaos node — the sandbox won't land here
    spec = n.get("spec", {}) or {}
    if spec.get("unschedulable"):
        continue
    if any(t.get("effect") in ("NoSchedule", "NoExecute") and t.get("key") != tolerated_taint
           for t in (spec.get("taints") or [])):
        continue
    conds = {c["type"]: c["status"] for c in n.get("status", {}).get("conditions", [])}
    if conds.get("Ready") != "True":
        continue
    if "True" in (conds.get("MemoryPressure"), conds.get("DiskPressure"), conds.get("PIDPressure")):
        continue
    al = n.get("status", {}).get("allocatable", {}) or {}
    alloc_cpu[name] = cpu_m(al.get("cpu")); alloc_mem[name] = mem_mi(al.get("memory"))
    usable.add(name)

# Sum pod requests on usable nodes. Effective request = max(sum(containers), max(initContainer)),
# which is how the scheduler reserves for a pod with init containers.
req_cpu_by = {}; req_mem_by = {}
for p in pods:
    if p.get("status", {}).get("phase") in ("Succeeded", "Failed"):
        continue
    node = p.get("spec", {}).get("nodeName")
    if node not in usable:
        continue
    sc = sm = 0
    for ct in p["spec"].get("containers") or []:
        r = (ct.get("resources", {}) or {}).get("requests", {}) or {}
        sc += cpu_m(r.get("cpu")); sm += mem_mi(r.get("memory"))
    ic = im = 0
    for ct in p["spec"].get("initContainers") or []:
        r = (ct.get("resources", {}) or {}).get("requests", {}) or {}
        ic = max(ic, cpu_m(r.get("cpu"))); im = max(im, mem_mi(r.get("memory")))
    req_cpu_by[node] = req_cpu_by.get(node, 0) + max(sc, ic)
    req_mem_by[node] = req_mem_by.get(node, 0) + max(sm, im)

free_cpu = sum(alloc_cpu[n] - req_cpu_by.get(n, 0) for n in usable)
free_mem = sum(alloc_mem[n] - req_mem_by.get(n, 0) for n in usable)
ready = len(usable)

print(f"▸ capacity preflight: usable nodes={ready} (need >= {min_ready}); "
      f"free CPU={free_cpu}m (need >= {req_cpu}m); "
      f"free mem={int(free_mem)}Mi (need >= {req_mem}Mi)")

short = []
if ready < min_ready:   short.append(f"only {ready} usable node(s), need {min_ready}")
if free_cpu < req_cpu:  short.append(f"free CPU {free_cpu}m < {req_cpu}m")
if free_mem < req_mem:  short.append(f"free mem {int(free_mem)}Mi < {req_mem}Mi")
if short:
    print("▸ capacity preflight: INCONCLUSIVE — " + "; ".join(short) +
          ". Skipping (this counts as neither a red nor a green night).", file=sys.stderr)
    sys.exit(42)
print("▸ capacity preflight OK.")
sys.exit(0)
PY
