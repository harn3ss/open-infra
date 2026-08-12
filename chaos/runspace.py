#!/usr/bin/env python3
"""Render a per-run copy of the chaos sandbox so many runs can execute in PARALLEL.

The nightly runs exactly one mesh in the fixed `chaos-sandbox` namespace; every CR name is fixed
(pg-a, pg-creds, chaos-mesh-pg, mm-*) and teardown is a namespace-wide `delete ... --all`. Two runs
would clobber each other. This is the #1 blocker to "continuous = parallel."

The unlock: give each run its OWN namespace `chaos-run-<id>`. Because every sandbox object is
namespaced and refers to the others BY NAME WITHIN THE NAMESPACE, the fixed names stop colliding the
moment each run is in a distinct namespace — no object renaming required — and teardown becomes a
single `kubectl delete namespace chaos-run-<id>` (scoped, never `--all`).

The transform, applied to any manifest (the namespace template or a sandbox/fault manifest):
  - namespaced objects: metadata.namespace `chaos-sandbox` -> `chaos-run-<id>` (other namespaces,
    e.g. `nats`, are left alone; names are left alone).
  - the cluster-scoped Namespace: metadata.name `chaos-sandbox` -> `chaos-run-<id>`.
  - the cluster-scoped ClusterRoleBinding: name suffixed `-<id>` and its subjects' namespace
    rewritten, so the per-run runner SA is bound (the shared ClusterRole/PriorityClass are emitted
    unchanged).
  - any subject (RoleBinding/ClusterRoleBinding) pointing at the SA in `chaos-sandbox` follows.

Usage:
  runspace.py --run-id <id> FILE [FILE ...]   # rewrite the given manifests onto the per-run ns
  runspace.py --run-id <id> --ns              # print just the per-run namespace name
Reads stdin when no FILE is given. Emits multi-doc YAML to stdout.

Note (scope): the mesh/convergence sandbox is fully self-contained in its namespace, so this isolates
it completely. Oracles that reuse shared JetStream streams in the `nats` namespace still need per-run
stream prefixes — a separate, additive concern, not handled here.
"""
import argparse
import sys

import yaml

BASE_NS = "chaos-sandbox"
CLUSTER_SCOPED = {"Namespace", "PriorityClass", "ClusterRole", "ClusterRoleBinding"}


def run_namespace(run_id: str) -> str:
    return f"chaos-run-{run_id}"


def transform(doc, run_id):
    """Rewrite one YAML document onto the per-run namespace. Returns the (mutated) doc."""
    if not isinstance(doc, dict):
        return doc
    ns = run_namespace(run_id)
    kind = doc.get("kind")
    md = doc.get("metadata")
    if not isinstance(md, dict):
        md = {}
        doc["metadata"] = md

    if kind == "Namespace":
        if md.get("name") == BASE_NS:
            md["name"] = ns
    elif kind == "ClusterRoleBinding":
        if md.get("name"):
            md["name"] = f"{md['name']}-{run_id}"
    elif kind in CLUSTER_SCOPED:
        pass  # PriorityClass / ClusterRole are shared — emit unchanged
    else:
        # A namespaced object: move it into the per-run namespace, but only if it was in the
        # sandbox (never rewrite a reference to another namespace such as `nats`).
        if md.get("namespace") == BASE_NS:
            md["namespace"] = ns

    # RoleBinding / ClusterRoleBinding subjects that point at the sandbox SA must follow it.
    for s in doc.get("subjects") or []:
        if isinstance(s, dict) and s.get("namespace") == BASE_NS:
            s["namespace"] = ns
    return doc


def render(text: str, run_id: str) -> str:
    docs = [transform(d, run_id) for d in yaml.safe_load_all(text)]
    docs = [d for d in docs if d is not None]
    return yaml.safe_dump_all(docs, default_flow_style=False, sort_keys=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--ns", action="store_true", help="print the per-run namespace name and exit")
    ap.add_argument("files", nargs="*")
    args = ap.parse_args()

    if args.ns:
        print(run_namespace(args.run_id))
        return 0

    if args.files:
        text = "\n---\n".join(open(f, encoding="utf-8").read() for f in args.files)
    else:
        text = sys.stdin.read()
    sys.stdout.write(render(text, args.run_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
