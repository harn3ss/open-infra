#!/usr/bin/env python3
"""chain -> manifests compiler (database / stream / function planes).

Takes a GENERATED chain (from `chainforge generate`) and emits the Kubernetes manifests to stand that
exact topology up. It dispatches on node kind and edge port through a small REGISTRY instead of assuming
the database plane, so the FIRST cross-kind chain — database -> stream -> function — compiles alongside
the pure multi-master DB mesh.

NODE builders (keyed by node kind):
  - database: one Postgres StatefulSet + Service per node (wal_level=logical, which serves both the
    Replication engine's capture and a Stream's CDC). Named pg-<id>, sharing the pg-creds Secret. Cloned
    from the maintained sandbox templates (chaos/sandbox/members.yaml) so they can't drift from the mesh.
  - stream: one kind: Stream per node, source = the database node on this stream's incoming change-stream
    edge (host pg-<upstream>.<ns>.svc...). Its durable JetStream stream is cdc-<streamNodeId>; its
    Debezium capture pod is labelled app=<streamNodeId>-stream (see platform/abstraction/stream-*).
  - function: one kind: Function per node, spec.trigger.stream = the stream node on its incoming
    stream-out edge. kind: Function then renders a Benthos pump Deployment (<fn>-pump) holding a durable
    JetStream consumer fn-<fn> that POSTs each CDC event to the function and acks only on 2xx.

EDGE handling (keyed by port, inferred from the from/to node kinds):
  - replication-peer (database->database): a SEPARATE kind: Replication resource (make_repl).
  - change-stream    (database->stream):  NOT a resource — it wires the downstream Stream's source host.
  - stream-out       (stream->function):  NOT a resource — it wires the downstream Function's trigger.

meta.oracle dispatch (by chain SHAPE):
  - pure database                     -> "convergence"           (byte-identical to the DB-only compiler)
  - database -> stream (no function)  -> "stream-no-loss"
  - database -> stream -> function    -> "stream-function-noloss" (meta carries the exact env contract the
    apply-sink/stream_function_noloss_test.go oracle reads: STREAM_NAME=cdc-<stream>, FN_CONSUMER=fn-<fn>,
    CAPTURE_LABEL=app=<stream>-stream, STREAM_SRC_POD=pg-<db>-0, CHAOS_SANDBOX_NS, STREAM_ROWS).

FAIL-CLOSED: any node kind other than database/stream/function, or any edge that isn't
replication-peer/change-stream/stream-out, is REFUSED (exit 3) — the honest boundary; other planes need
their own node/edge builders.

  compile_chain.py --namespace NS [--meta run-spec.json] [--in chain.json] [--index 0]
Reads the chain from stdin when --in is absent; emits multi-doc YAML manifests to stdout and a run-spec
JSON (members/env + fault + oracle, for the executor to wire the oracle contract) to --meta.
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

# Node kinds this compiler can stand up, and the edge ports it understands. Anything outside these is
# refused (fail-closed) — the honest boundary of what is actually compilable + oracled today.
SUPPORTED_NODES = ("database", "stream", "function")
# (fromKind, toKind) -> port. Unambiguous for the supported cross-kind chain; the grammar's other
# port overloads (e.g. database->database as CDC) are not compiled here.
PORT_OF = {
    ("database", "database"): "replication-peer",
    ("database", "stream"): "change-stream",
    ("stream", "function"): "stream-out",
}

# Default NATS service + per-oracle timeouts the stream oracles need (see the test file NOTEs: healthy
# capture resume is deliberately slow, so a lossless-but-slow drain must not t.Fatalf as a false red).
NATS_URL = "nats://nats.nats.svc:4222"
STREAM_ROWS = "150"
STREAM_TIMEOUT = "360"        # stream-no-loss: ~40s Debezium JVM start + slot connect timeout
STREAM_FN_TIMEOUT = "420"     # +ack_wait redelivery + function cold-start from scale-to-zero


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


# ---- NODE builders ----

def make_node(nid, ns, ss_t, svc_t):
    """database node -> a Postgres StatefulSet + Service (pg-<id>), cloned from the sandbox template."""
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


def make_stream(sid, db_id, ns):
    """stream node -> a kind: Stream tapping pg-<db_id>'s change log into JetStream cdc-<sid>.

    Mirrors chaos/sandbox/stream.yaml; the source password lives in the shared pg-creds Secret.
    """
    return {
        "apiVersion": "openinfra.dev/v1",
        "kind": "Stream",
        "metadata": {"name": sid, "namespace": ns},
        "spec": {
            "source": {
                "engine": "postgres",
                "host": f"pg-{db_id}.{ns}.svc.cluster.local",
                "port": 5432,
                "database": "app",
                "username": "app",
                "passwordSecretRef": {"name": "pg-creds"},
                "schemas": ["public"],
                "tables": ["events"],
            }
        },
    }


def make_function(fid, sid, ns):
    """function node -> a kind: Function triggered by the Stream <sid>.

    Mirrors chaos/sandbox/function.yaml: an always-200 echo that honours the Knative-injected PORT, so
    every delivered CDC event is 2xx-acked. The composition renders the <fid>-pump Deployment holding the
    durable consumer fn-<fid> on cdc-<sid>.
    """
    return {
        "apiVersion": "openinfra.dev/v1",
        "kind": "Function",
        "metadata": {"name": fid, "namespace": ns},
        "spec": {
            "image": "ealen/echo-server:latest",
            "port": 8080,
            "expose": False,
            "trigger": {"stream": sid},
        },
    }


# ---- EDGE builder ----

def make_repl(frm, to, ns, repl_t):
    """replication-peer edge -> a kind: Replication (bidirectional multi-master link)."""
    r = copy.deepcopy(repl_t)
    r["metadata"]["name"] = f"repl-{frm}-{to}"
    r["metadata"]["namespace"] = ns
    r["spec"]["siteA"]["name"] = frm
    r["spec"]["siteA"]["host"] = f"pg-{frm}.{ns}.svc.cluster.local"
    r["spec"]["siteB"]["name"] = to
    r["spec"]["siteB"]["host"] = f"pg-{to}.{ns}.svc.cluster.local"
    return r


# ---- FAULT (targeting dispatches on the target node's kind) ----

def _fault_selector(kind, nid):
    """The labelSelector that picks the fault target's pod(s), per node kind."""
    if kind == "stream":
        return {"app": f"{nid}-stream"}      # kind: Stream's Debezium capture pod
    if kind == "function":
        return {"app": f"{nid}-pump"}        # kind: Function's Benthos pump pod
    return {"app": "pg", "site": nid}        # database node's Postgres pod


def make_fault(fault, node_ids, kind_of, ns, force_target=None, force_type=None):
    tid = force_target or fault.get("target") or (fault.get("edge") or [None, None])[1] or node_ids[0]
    if tid not in node_ids:
        tid = node_ids[0]
    ftype = force_type or FAULT_TYPE.get(fault.get("kind", ""), "pod-kill")
    spec = {"type": ftype, "target": {"labelSelector": _fault_selector(kind_of.get(tid, "database"), tid)},
            "mode": "all"}
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
    if not nodes:
        raise SystemExit("empty chain")

    kind_of = {n["id"]: n["kind"] for n in nodes}

    # FAIL-CLOSED node validation.
    bad_nodes = sorted({n["kind"] for n in nodes if n.get("kind") not in SUPPORTED_NODES})
    if bad_nodes:
        raise SystemExit(
            "UNSUPPORTED: this compiler compiles only database, stream and function nodes "
            "(database nodes + the database->stream->function cross-kind chain); got kinds "
            f"{bad_nodes}. Refusing (fail-closed).")

    # FAIL-CLOSED edge classification: infer each edge's port from its endpoint kinds.
    repl_edges = []          # replication-peer -> a kind: Replication resource
    stream_src = {}          # streamId -> upstream databaseId (change-stream)
    fn_stream = {}           # functionId -> upstream streamId (stream-out)
    for e in edges:
        fk, tk = kind_of.get(e["from"]), kind_of.get(e["to"])
        port = PORT_OF.get((fk, tk))
        if port is None:
            raise SystemExit(
                f"UNSUPPORTED: edge {e['from']}({fk})->{e['to']}({tk}) is not one of "
                "replication-peer / change-stream / stream-out. Refusing (fail-closed).")
        if port == "replication-peer":
            repl_edges.append(e)
        elif port == "change-stream":
            stream_src[e["to"]] = e["from"]
        elif port == "stream-out":
            fn_stream[e["to"]] = e["from"]

    node_ids = [n["id"] for n in nodes]
    db_ids = [nid for nid in node_ids if kind_of[nid] == "database"]
    stream_ids = [nid for nid in node_ids if kind_of[nid] == "stream"]
    fn_ids = [nid for nid in node_ids if kind_of[nid] == "function"]

    secret, ss_t, svc_t, repl_t = load_templates()

    manifests = []
    sec = copy.deepcopy(secret)
    sec["metadata"]["namespace"] = ns
    manifests.append(sec)
    for n in nodes:
        nid, k = n["id"], kind_of[n["id"]]
        if k == "database":
            manifests.extend(make_node(nid, ns, ss_t, svc_t))
        elif k == "stream":
            up = stream_src.get(nid)
            if up is None:
                raise SystemExit(f"UNSUPPORTED: stream node {nid} has no incoming change-stream edge from "
                                 "a database. Refusing (fail-closed).")
            manifests.append(make_stream(nid, up, ns))
        elif k == "function":
            up = fn_stream.get(nid)
            if up is None:
                raise SystemExit(f"UNSUPPORTED: function node {nid} has no incoming stream-out edge from a "
                                 "stream. Refusing (fail-closed).")
            manifests.append(make_function(nid, up, ns))
    for e in repl_edges:
        manifests.append(make_repl(e["from"], e["to"], ns, repl_t))

    # ---- oracle dispatch by chain SHAPE ----
    if not stream_ids and not fn_ids:
        # Pure database mesh -> convergence. Byte-identical to the DB-only compiler.
        fi, tid, ftype = make_fault(fault, node_ids, kind_of, ns)
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

    # Cross-kind chain: the fault is the capture-kill on the Stream's Debezium pod (the fault the
    # stream / stream-function oracles detect via CaptureUID replacement) — pod-kill on app=<stream>-stream.
    stream_id = stream_ids[0]
    db_id = stream_src.get(stream_id)
    if db_id is None:
        raise SystemExit(f"UNSUPPORTED: stream node {stream_id} has no incoming change-stream edge from a "
                         "database. Refusing (fail-closed).")
    fi, tid, ftype = make_fault(fault, node_ids, kind_of, ns,
                                force_target=stream_id, force_type="pod-kill")
    manifests.append(fi)

    if fn_ids:
        # database -> stream -> function : the end-to-end no-loss oracle.
        fn_id = fn_ids[0]
        env = {
            "CHAOS_SANDBOX_NS": ns,
            "CAPTURE_LABEL": f"app={stream_id}-stream",
            "STREAM_SRC_POD": f"pg-{db_id}-0",
            "STREAM_NATS_URL": NATS_URL,
            "STREAM_NAME": f"cdc-{stream_id}",
            "FN_CONSUMER": f"fn-{fn_id}",
            "STREAM_ROWS": STREAM_ROWS,
            "CONV_TIMEOUT": STREAM_FN_TIMEOUT,
        }
        meta = {
            "namespace": ns,
            "oracle": "stream-function-noloss",
            "source": {"database": db_id, "stream": stream_id, "function": fn_id,
                       "srcPod": f"pg-{db_id}-0", "streamName": f"cdc-{stream_id}",
                       "consumer": f"fn-{fn_id}"},
            "fault": {"name": "gen-fault", "kind": fault.get("kind", ""), "type": ftype, "target": tid},
            "env": env,
        }
        return manifests, meta

    # database -> stream (no function) : the stream no-loss oracle.
    env = {
        "CHAOS_SANDBOX_NS": ns,
        "CAPTURE_LABEL": f"app={stream_id}-stream",
        "STREAM_SRC_POD": f"pg-{db_id}-0",
        "STREAM_NATS_URL": NATS_URL,
        "STREAM_NAME": f"cdc-{stream_id}",
        "STREAM_ROWS": STREAM_ROWS,
        "CONV_TIMEOUT": STREAM_TIMEOUT,
    }
    meta = {
        "namespace": ns,
        "oracle": "stream-no-loss",
        "source": {"database": db_id, "stream": stream_id,
                   "srcPod": f"pg-{db_id}-0", "streamName": f"cdc-{stream_id}"},
        "fault": {"name": "gen-fault", "kind": fault.get("kind", ""), "type": ftype, "target": tid},
        "env": env,
    }
    return manifests, meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", default="chaos-sandbox")
    ap.add_argument("--meta", help="write the run-spec JSON here (members/env/fault/oracle)")
    ap.add_argument("--in", dest="infile", help="chain JSON file (default: stdin)")
    ap.add_argument("--index", type=int, default=0, help="if the input is an array, which chain to compile")
    a = ap.parse_args()

    raw = open(a.infile, encoding="utf-8").read() if a.infile else sys.stdin.read()
    obj = json.loads(raw)
    if isinstance(obj, list):
        if not obj:
            raise SystemExit("empty chain array")
        obj = obj[a.index]

    try:
        manifests, meta = compile_chain(obj, a.namespace)
    except SystemExit as e:
        # Fail-closed refusals (unsupported node kind / edge port) exit 3 with the message on stderr, so
        # a caller can tell "this plane isn't compilable yet" apart from a crash. compile_chain still
        # raises the message-carrying SystemExit so in-process callers/tests can read it.
        msg = str(e.code) if isinstance(e.code, str) else ""
        if msg.startswith("UNSUPPORTED"):
            sys.stderr.write(msg + "\n")
            raise SystemExit(3)
        raise
    sys.stdout.write(yaml.safe_dump_all(manifests, default_flow_style=False, sort_keys=False))
    if a.meta:
        with open(a.meta, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    else:
        sys.stderr.write("run-spec: " + json.dumps(meta) + "\n")


if __name__ == "__main__":
    main()
