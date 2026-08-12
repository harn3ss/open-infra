#!/usr/bin/env python3
"""chain -> manifests compiler (database / replication plane).

Takes a GENERATED chain (from `chainforge generate --only database`) and emits the Kubernetes
manifests to stand that exact topology up: one Postgres node per database node, one kind: Replication
per replication edge, and the drawn fault as a kind: FaultInjection. This generalizes the fixed
2-master mesh to ANY generated DB topology (N-master, chain, fan) — the convergence oracle, which
reads CONV_MEMBERS (N members), then judges whether it reconverges.

Nodes/Replications/faults are CLONED from the maintained sandbox templates (chaos/sandbox/members.yaml
and mesh.yaml) so they can't drift from the hand-run mesh.

FAIL-CLOSED: this compiler handles ONLY database nodes wired by database→database edges. A chain with
any other node kind, or an edge that isn't database→database, is REFUSED (exit 3) — the honest
boundary; other planes need their own node/edge templates.

  compile_chain.py --namespace NS [--meta run-spec.json] [--in chain.json] [--index 0]
Reads the chain from stdin when --in is absent; emits multi-doc YAML manifests to stdout and a run-spec
JSON (members + fault + oracle, for the executor to wire CONV_MEMBERS + proof-of-fire) to --meta.
"""
import argparse
import copy
import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MEMBERS = os.path.join(HERE, "sandbox", "members.yaml")
MESH = os.path.join(HERE, "sandbox", "mesh.yaml")

# fault.kind (grammar palette) -> FaultInjection spec.type
FAULT_TYPE = {
    "PodChaos": "pod-kill",
    "StressChaos": "stress-cpu",
    "NetworkChaos": "network-partition",
    "NetworkChaos+PodChaos": "pod-kill",
    "seeded multi-fault": "pod-kill",
    "": "pod-kill",
}
HOLD_TYPES = {"stress-cpu", "stress-memory", "network-partition", "network-latency", "network-loss"}


def _first(docs, kind):
    for d in docs:
        if d and d.get("kind") == kind:
            return d
    raise SystemExit(f"template {kind} not found")


def load_templates():
    md = [d for d in yaml.safe_load_all(open(MEMBERS, encoding="utf-8")) if d]
    secret = _first(md, "Secret")
    ss = _first(md, "StatefulSet")
    svc = _first(md, "Service")
    repl = _first([d for d in yaml.safe_load_all(open(MESH, encoding="utf-8")) if d], "Replication")
    return secret, ss, svc, repl


def make_node(nid, ns, ss_t, svc_t):
    ss = copy.deepcopy(ss_t)
    ss["metadata"]["name"] = f"pg-{nid}"
    ss["metadata"]["namespace"] = ns
    ss["metadata"].setdefault("labels", {})["site"] = nid
    ss["spec"]["serviceName"] = f"pg-{nid}"
    ss["spec"]["selector"]["matchLabels"]["site"] = nid
    ss["spec"]["template"]["metadata"]["labels"]["site"] = nid
    svc = copy.deepcopy(svc_t)
    svc["metadata"]["name"] = f"pg-{nid}"
    svc["metadata"]["namespace"] = ns
    svc["metadata"].setdefault("labels", {})["site"] = nid
    svc["spec"]["selector"]["site"] = nid
    return [ss, svc]


def make_repl(frm, to, ns, repl_t):
    r = copy.deepcopy(repl_t)
    r["metadata"]["name"] = f"repl-{frm}-{to}"
    r["metadata"]["namespace"] = ns
    r["spec"]["siteA"]["name"] = frm
    r["spec"]["siteA"]["host"] = f"pg-{frm}.{ns}.svc.cluster.local"
    r["spec"]["siteB"]["name"] = to
    r["spec"]["siteB"]["host"] = f"pg-{to}.{ns}.svc.cluster.local"
    return r


def make_fault(fault, node_ids, ns):
    tid = fault.get("target") or (fault.get("edge") or [None, None])[1] or node_ids[0]
    if tid not in node_ids:
        tid = node_ids[0]
    ftype = FAULT_TYPE.get(fault.get("kind", ""), "pod-kill")
    spec = {"type": ftype, "target": {"labelSelector": {"app": "pg", "site": tid}}, "mode": "all"}
    if ftype in HOLD_TYPES:
        spec["duration"] = "90s"
    fi = {
        "apiVersion": "openinfra.dev/v1",
        "kind": "FaultInjection",
        "metadata": {"name": "gen-fault", "namespace": ns},
        "spec": spec,
    }
    return fi, tid, ftype


def compile_chain(chain_obj, ns):
    nodes = chain_obj["chain"]["nodes"]
    edges = chain_obj["chain"].get("edges", [])
    fault = chain_obj.get("fault", {})

    # FAIL-CLOSED validation.
    bad_nodes = [n for n in nodes if n.get("kind") != "database"]
    if bad_nodes:
        raise SystemExit(f"UNSUPPORTED: this compiler handles only database nodes; got kinds "
                         f"{sorted({n['kind'] for n in bad_nodes})}. Refusing (fail-closed).")
    kind_of = {n["id"]: n["kind"] for n in nodes}
    bad_edges = [e for e in edges if kind_of.get(e["from"]) != "database" or kind_of.get(e["to"]) != "database"]
    if bad_edges:
        raise SystemExit(f"UNSUPPORTED: every edge must be database→database; got "
                         f"{[(e['from'], e['to']) for e in bad_edges]}. Refusing (fail-closed).")
    if not nodes:
        raise SystemExit("empty chain")

    secret, ss_t, svc_t, repl_t = load_templates()
    node_ids = [n["id"] for n in nodes]

    manifests = []
    sec = copy.deepcopy(secret)
    sec["metadata"]["namespace"] = ns
    manifests.append(sec)
    for nid in node_ids:
        manifests.extend(make_node(nid, ns, ss_t, svc_t))
    for e in edges:
        manifests.append(make_repl(e["from"], e["to"], ns, repl_t))
    fi, tid, ftype = make_fault(fault, node_ids, ns)
    manifests.append(fi)

    meta = {
        "namespace": ns,
        "members": [{"name": nid, "site": nid, "service": f"pg-{nid}",
                     "host": f"pg-{nid}.{ns}.svc.cluster.local"} for nid in node_ids],
        "edges": [{"from": e["from"], "to": e["to"]} for e in edges],
        "fault": {"name": "gen-fault", "kind": fault.get("kind", ""), "type": ftype, "target": tid},
        "oracle": "convergence",
        "tables": ["conv_test"],
    }
    return manifests, meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", default="chaos-sandbox")
    ap.add_argument("--meta", help="write the run-spec JSON here (members/fault/oracle)")
    ap.add_argument("--in", dest="infile", help="chain JSON file (default: stdin)")
    ap.add_argument("--index", type=int, default=0, help="if the input is an array, which chain to compile")
    a = ap.parse_args()

    raw = open(a.infile, encoding="utf-8").read() if a.infile else sys.stdin.read()
    obj = json.loads(raw)
    if isinstance(obj, list):
        if not obj:
            raise SystemExit("empty chain array")
        obj = obj[a.index]

    manifests, meta = compile_chain(obj, a.namespace)
    sys.stdout.write(yaml.safe_dump_all(manifests, default_flow_style=False, sort_keys=False))
    if a.meta:
        with open(a.meta, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    else:
        sys.stderr.write("run-spec: " + json.dumps(meta) + "\n")


if __name__ == "__main__":
    main()
