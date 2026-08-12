#!/usr/bin/env python3
"""Tests for runspace.py — the per-run sandbox isolation renderer."""
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import runspace  # noqa: E402

MEMBERS = os.path.join(HERE, "sandbox", "members.yaml")
TEMPLATE = os.path.join(HERE, "..", "platform", "resilience", "chaos-sandbox.yaml")


def docs(text):
    return [d for d in yaml.safe_load_all(text) if d is not None]


def test_members_move_to_run_namespace_names_unchanged():
    out = runspace.render(open(MEMBERS, encoding="utf-8").read(), "abc123")
    ds = docs(out)
    assert ds, "expected documents"
    names = set()
    for d in ds:
        md = d["metadata"]
        # Every namespaced object landed in the per-run namespace...
        assert md.get("namespace") == "chaos-run-abc123", f"{d['kind']} {md.get('name')} ns={md.get('namespace')}"
        names.add((d["kind"], md["name"]))
    # ...and the fixed names are UNCHANGED (no collision because the namespace differs).
    assert ("Secret", "pg-creds") in names
    assert ("StatefulSet", "pg-a") in names and ("StatefulSet", "pg-b") in names
    assert ("Service", "pg-a") in names


def test_two_run_ids_are_disjoint():
    text = open(MEMBERS, encoding="utf-8").read()
    a = docs(runspace.render(text, "aaa"))
    b = docs(runspace.render(text, "bbb"))
    nsa = {d["metadata"]["namespace"] for d in a}
    nsb = {d["metadata"]["namespace"] for d in b}
    assert nsa == {"chaos-run-aaa"} and nsb == {"chaos-run-bbb"}
    assert nsa.isdisjoint(nsb), "two runs must never share a namespace"


def test_other_namespaces_left_alone():
    # A manifest referencing a non-sandbox namespace (e.g. nats) must not be rewritten.
    src = """
apiVersion: v1
kind: ConfigMap
metadata: { name: x, namespace: nats }
"""
    d = docs(runspace.render(src, "zzz"))[0]
    assert d["metadata"]["namespace"] == "nats"


def test_template_cluster_scoped_handling():
    out = runspace.render(open(TEMPLATE, encoding="utf-8").read(), "run7")
    by_kind = {}
    for d in docs(out):
        by_kind.setdefault(d["kind"], []).append(d)

    # Namespace object renamed to the per-run namespace.
    assert any(d["metadata"]["name"] == "chaos-run-run7" for d in by_kind.get("Namespace", []))

    # Namespaced template objects moved into the per-run namespace.
    for kind in ("ResourceQuota", "LimitRange", "ServiceAccount", "Role", "RoleBinding"):
        for d in by_kind.get(kind, []):
            assert d["metadata"]["namespace"] == "chaos-run-run7", f"{kind} not in per-run ns"

    # Shared cluster-scoped objects emitted UNCHANGED.
    for d in by_kind.get("PriorityClass", []):
        assert d["metadata"]["name"] == "chaos-sandbox-low"
    for d in by_kind.get("ClusterRole", []):
        assert d["metadata"]["name"] == "chaos-runner-preflight-readonly"

    # ClusterRoleBinding renamed per-run and its subject namespace rewritten (so the per-run SA binds).
    for d in by_kind.get("ClusterRoleBinding", []):
        assert d["metadata"]["name"].endswith("-run7"), d["metadata"]["name"]
        for s in d.get("subjects", []):
            if s.get("kind") == "ServiceAccount":
                assert s["namespace"] == "chaos-run-run7"


def test_output_is_valid_yaml_roundtrip():
    out = runspace.render(open(MEMBERS, encoding="utf-8").read(), "rt")
    # Must parse cleanly a second time.
    again = runspace.render(out, "rt")
    assert docs(again)


def run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"OK: {len(fns)} runspace tests passed.")


if __name__ == "__main__":
    run()
