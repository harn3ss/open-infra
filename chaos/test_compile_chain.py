#!/usr/bin/env python3
"""Tests for compile_chain.py — the chain->manifest compiler (database plane)."""
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import compile_chain as cc  # noqa: E402


def db_chain(n, fault_kind="PodChaos", fault_target="n2"):
    nodes = [{"id": f"n{i}", "label": "database", "kind": "database"} for i in range(1, n + 1)]
    edges = [{"from": f"n{i}", "to": f"n{i+1}", "label": "replication"} for i in range(1, n)]
    return {"chain": {"nodes": nodes, "edges": edges}, "fault": {"kind": fault_kind, "target": fault_target}}


def kinds(manifests):
    out = {}
    for m in manifests:
        out.setdefault(m["kind"], []).append(m)
    return out


def test_db_chain_manifest_counts():
    manifests, meta = cc.compile_chain(db_chain(3), "chaos-run-x")
    k = kinds(manifests)
    assert len(k["Secret"]) == 1
    assert len(k["StatefulSet"]) == 3 and len(k["Service"]) == 3
    assert len(k["Replication"]) == 2  # a 3-node chain has 2 edges
    assert len(k["FaultInjection"]) == 1
    # every object lands in the per-run namespace
    for m in manifests:
        assert m["metadata"]["namespace"] == "chaos-run-x"
    # meta drives CONV_MEMBERS
    assert [m["name"] for m in meta["members"]] == ["n1", "n2", "n3"]
    assert meta["oracle"] == "convergence"


def test_names_and_hosts():
    manifests, meta = cc.compile_chain(db_chain(2), "ns1")
    names = {(m["kind"], m["metadata"]["name"]) for m in manifests}
    assert ("StatefulSet", "pg-n1") in names and ("Service", "pg-n2") in names
    assert ("Replication", "repl-n1-n2") in names
    repl = [m for m in manifests if m["kind"] == "Replication"][0]
    assert repl["spec"]["siteA"]["host"] == "pg-n1.ns1.svc.cluster.local"
    assert repl["spec"]["siteB"]["name"] == "n2"
    # the topology-spread selector (app=pg) is preserved so masters spread across chaos nodes
    ss = [m for m in manifests if m["kind"] == "StatefulSet" and m["metadata"]["name"] == "pg-n1"][0]
    assert ss["spec"]["template"]["metadata"]["labels"]["site"] == "n1"
    assert ss["spec"]["template"]["metadata"]["labels"]["app"] == "pg"


def test_fault_kind_maps_to_faultinjection_type():
    for kind, want in [("PodChaos", "pod-kill"), ("NetworkChaos", "network-partition"),
                       ("StressChaos", "stress-cpu"), ("", "pod-kill")]:
        manifests, meta = cc.compile_chain(db_chain(2, fault_kind=kind, fault_target="n1"), "ns")
        fi = [m for m in manifests if m["kind"] == "FaultInjection"][0]
        assert fi["spec"]["type"] == want, (kind, fi["spec"]["type"])
        assert fi["spec"]["target"]["labelSelector"] == {"app": "pg", "site": "n1"}
        assert meta["fault"]["type"] == want


def test_refuse_non_database_node():
    ch = db_chain(2)
    ch["chain"]["nodes"].append({"id": "a1", "label": "app", "kind": "app"})
    try:
        cc.compile_chain(ch, "ns")
    except SystemExit as e:
        assert "database nodes" in str(e)
        return
    raise AssertionError("must refuse a non-database node (fail-closed)")


def test_refuse_non_db_edge():
    # database nodes but an edge to a (spoofed) non-db id
    ch = {"chain": {"nodes": [{"id": "n1", "kind": "database"}, {"id": "s1", "kind": "storage"}],
                    "edges": [{"from": "n1", "to": "s1", "label": "snapshot"}]}, "fault": {"kind": "PodChaos"}}
    try:
        cc.compile_chain(ch, "ns")
    except SystemExit:
        return
    raise AssertionError("must refuse a non-database node/edge")


def test_manifests_are_valid_yaml():
    import io
    manifests, _ = cc.compile_chain(db_chain(4), "ns")
    text = yaml.safe_dump_all(manifests)
    again = list(yaml.safe_load_all(io.StringIO(text)))
    assert len([d for d in again if d]) == len(manifests)


def run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"OK: {len(fns)} compile_chain tests passed.")


if __name__ == "__main__":
    run()
