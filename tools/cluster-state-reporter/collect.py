#!/usr/bin/env python3
"""Machine cluster-state collector (polyhedron#314) — Layer 1 (discovery + generic health) + Layer 5
(coverage). Read-only. Observes the whole cluster, writes a tree of small files to harn3ss/cluster-state
(one commit per run), and rewrites one pinned polyhedron issue as the front page.

Honesty rules (from #314): unread != healthy; a kind with no recognisable health signal is counted
`no health signal`, never healthy; a failed list is recorded in coverage with its reason, never defaulted
OK. Security: only allowlisted fields are ever read off an object (names/counts/states/timestamps —
NEVER spec, data, env, or Secret contents); a pre-publish scanner greps the generated text for
credential-shaped strings and, if anything trips, publishes NOTHING and exits non-zero (fail closed).
"""
import os
import re
import sys
import json
import time
import shutil
import subprocess
import datetime
import urllib.request
import urllib.error

from kubernetes import client, config
from kubernetes.dynamic import DynamicClient

# ---- config (env) -----------------------------------------------------------------------------------
STATE_REPO = os.environ.get("STATE_REPO", "harn3ss/cluster-state")
ISSUE_REPO = os.environ.get("ISSUE_REPO", "harn3ss/polyhedron")
ISSUE_NUMBER = os.environ.get("ISSUE_NUMBER", "315")
INTERVAL_HOURS = float(os.environ.get("INTERVAL_HOURS", "4"))
MAX_ISSUE_CHARS = 10000
MAX_FILE_LINES = 300
def _token(env_key, default_path):
    return open(os.environ.get(env_key, default_path)).read().strip()

# Kinds we never enumerate (secret material / pure noise). Secrets especially: no get, ever.
SKIP_KINDS = {"Secret"}
# Conditions that signal health, and how to read them.
GOOD_TRUE = {"Ready", "Synced", "Available", "Succeeded", "Complete", "Established", "NamesAccepted", "Initialized", "PodScheduled", "ContainersReady"}
BAD_TRUE = {"Degraded", "Failed", "Stalled"}  # True == bad
# A good-condition reported False for one of these reasons is a normal idle/done state, not a fault:
# a scale-to-zero Knative revision/KPA sits at Ready=False/NoTraffic; a finished pod at Ready=False/PodCompleted.
BENIGN_FALSE_REASONS = {"NoTraffic", "PodCompleted", "Completed", "ScaleToZero", "Succeeded"}

NOW = datetime.datetime.now(datetime.timezone.utc)
STAMP = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")


def age(ts):
    if not ts:
        return "?"
    try:
        t = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        d = NOW - t
        s = int(d.total_seconds())
        if s < 3600:
            return f"{s // 60}m"
        if s < 86400:
            return f"{s // 3600}h"
        return f"{s // 86400}d"
    except Exception:
        return "?"


def classify(obj):
    """Return (health, detail). health in healthy|unhealthy|unknown|nosignal."""
    status = obj.get("status") or {}
    meta = obj.get("metadata") or {}
    phase = status.get("phase")
    if phase == "Succeeded":  # a completed pod/job is done, not unhealthy
        return "healthy", ""
    gen = meta.get("generation")
    og = status.get("observedGeneration")
    if gen is not None and og is not None and og < gen:
        return "unhealthy", f"stuck reconcile (observedGeneration {og} < generation {gen})"
    conds = status.get("conditions") or []
    if not isinstance(conds, list) or not conds:
        # no conditions: fall back to phase where one exists
        if phase in ("Running", "Active", "Bound"):
            return "healthy", ""
        if phase in ("Failed", "Pending", "Unknown"):
            return "unhealthy", f"phase={phase}"
        return "nosignal", ""
    bad = []
    saw_good = False
    for c in conds:
        t, s, reason = c.get("type"), c.get("status"), (c.get("reason") or "")
        msg = reason + (": " + c.get("message") if c.get("message") else "")
        if t in BAD_TRUE and s == "True":
            bad.append(f"{t} {msg}".strip())
        elif t in GOOD_TRUE:
            if s == "True":
                saw_good = True
            elif s == "False":
                if reason in BENIGN_FALSE_REASONS:
                    saw_good = True  # idle/done, not a fault
                else:
                    bad.append(f"{t}=False {msg}".strip())
    if bad:
        return "unhealthy", "; ".join(bad)[:200]
    if saw_good:
        return "healthy", ""
    return "nosignal", ""


def allowlisted(obj, kind):
    """Extract ONLY name/namespace/age/health — never spec/data/env/annotations content."""
    meta = obj.get("metadata") or {}
    health, detail = classify(obj)
    return {
        "name": meta.get("name", "?"),
        "ns": meta.get("namespace"),
        "age": age(meta.get("creationTimestamp")),
        "health": health,
        "detail": detail,
    }


# ---- Layer 2: deep probes (specific, where generic conditions don't tell the whole story) -----------
# Each probe returns (files, unhealthy_additions, status) where status = (name, state, detail) and
# state is "ok" | "partial" | "not checked (reason)". No probe reads a Secret or queries a DB — anything
# that would need credentials or host access is reported as not-checked, never defaulted OK.
def _res(dyn, group, kind):
    try:
        for r in dyn.resources.search(group=group, kind=kind):
            if r.__class__.__name__ == "ResourceList" or "/" in (getattr(r, "name", "") or ""):
                continue
            if "list" in (getattr(r, "verbs", None) or []):
                return r
    except Exception:
        return None
    return None


def _items(res):
    return res.get().to_dict().get("items", [])


def _conds(o):
    return {c.get("type"): (c.get("status"), c.get("reason") or "", c.get("message") or "")
            for c in ((o.get("status") or {}).get("conditions") or [])}


def probe_databases(dyn):
    # The DB abstraction is kind: Application with spec.database (engine sqlserver/babelfish/postgres/mysql).
    res = _res(dyn, "openinfra.dev", "Application")
    if res is None:
        return [], [], ("Database restore-state", "not checked (kind: Application not accessible)", "")
    try:
        items = _items(res)
    except Exception as e:
        return [], [], ("Database restore-state", f"not checked (list failed: {type(e).__name__})", "")
    lines = ["# Databases — engine, restore state, readiness", "", f"observed_at: {STAMP}", "",
             "Restore state is inferred from the Application claim: the engine keeps it NotReady until RESTORE "
             "completes and surfaces a failed restore as a NotReady reason. Row counts vs source need a read-only "
             "SQL login — the collector holds no DB credentials, so **row counts are not checked**.", "",
             "| database | engine | restore | Ready |", "|---|---|---|---|"]
    unhealthy = []
    sql_count = 0
    found = 0
    for o in items:
        spec = o.get("spec") or {}
        db = spec.get("database") or {}
        engine = (db.get("engine") or "").lower()
        if not engine:
            continue
        found += 1
        if engine in ("sqlserver", "babelfish"):
            sql_count += 1
        meta = o.get("metadata") or {}
        nm, ns = meta.get("name"), meta.get("namespace")
        has_restore = bool(db.get("restoreFrom"))
        cds = _conds(o)
        ready, rreason, rmsg = cds.get("Ready", (None, "", ""))
        if not has_restore:
            st = "— (fresh)"
        elif ready == "True":
            st = "**restored**"
        elif ready == "False":
            st = f"restoring/FAILED ({rreason})"
        else:
            st = f"unknown (Ready={ready})"
        flag = " ⚠️" if (ready != "True") else ""
        lines.append(f"| `{ns}/{nm}` | {engine} | {st} | {ready}{flag} |")
        if ready != "True":
            why = f"restore {st}" if has_restore else f"DB not Ready ({rreason})"
            unhealthy.append(("Database", ns, nm, why))
    if found == 0:
        lines.append("| _none_ | | | |")
    return [("databases/overview.md", "\n".join(lines) + "\n")], unhealthy, ("Database restore-state", "ok", f"{found} DBs ({sql_count} SQL-Server-family)")


def probe_knative(dyn):
    lines = ["# Knative", "", f"observed_at: {STAMP}", ""]
    unhealthy = []
    state = "ok"
    dres = _res(dyn, "apps", "Deployment")
    if dres is None:
        state = "partial"
        lines.append("components: not checked (Deployment not accessible)")
    else:
        lines.append("## components (knative-serving)")
        for d in _items(dres):
            m = d.get("metadata") or {}
            if m.get("namespace") != "knative-serving":
                continue
            s = d.get("status") or {}
            rdy, rep = s.get("readyReplicas", 0) or 0, s.get("replicas", 0) or 0
            flag = " ⚠️" if rdy < rep else ""
            lines.append(f"- {m.get('name')}: {rdy}/{rep} ready{flag}")
            if rdy < rep:
                unhealthy.append(("KnativeComponent", "knative-serving", m.get("name"), f"{rdy}/{rep} ready"))
    for grp, kind, label in [("serving.knative.dev", "Service", "ksvc"),
                             ("serving.knative.dev", "Revision", "revisions"),
                             ("autoscaling.internal.knative.dev", "PodAutoscaler", "podautoscalers")]:
        r = _res(dyn, grp, kind)
        if r is None:
            lines += ["", f"## {label}: not checked (not accessible)"]
            continue
        try:
            xs = _items(r)
            rdy = sum(1 for x in xs if _conds(x).get("Ready", (None,))[0] == "True")
            lines += ["", f"## {label}: {rdy}/{len(xs)} Ready"]
        except Exception as e:
            lines += ["", f"## {label}: not checked ({type(e).__name__})"]
    return [("cluster/knative.md", "\n".join(lines) + "\n")], unhealthy, ("Knative", state, "")


def probe_mirror(dyn):
    res = _res(dyn, "openinfra.dev", "Function")
    if res is None:
        return [], [], ("Mirror inventory (Functions)", "not checked (kind: Function not accessible)", "")
    try:
        items = _items(res)
    except Exception as e:
        return [], [], ("Mirror inventory (Functions)", f"not checked ({type(e).__name__})", "")
    from collections import Counter
    by_rt = {}  # runtime -> [total, ready]
    unhealthy = []
    for o in items:
        code = (o.get("spec") or {}).get("code") or {}
        rt = code.get("runtime") or (("runtimeImage:" + (code.get("runtimeImage", "").split("/")[-1])) if code.get("runtimeImage") else "unset")
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in ((o.get("status") or {}).get("conditions") or []))
        t = by_rt.setdefault(rt, [0, 0])
        t[0] += 1
        t[1] += 1 if ready else 0
    lines = ["# Mirror inventory — Functions by runtime", "", f"observed_at: {STAMP}", "",
             f"total Functions: {len(items)}", "", "| runtime | Ready / total |", "|---|---|"]
    for rt in sorted(by_rt):
        t = by_rt[rt]
        flag = " ⚠️" if t[1] < t[0] else ""
        lines.append(f"| {rt} | {t[1]} / {t[0]}{flag} |")
    # tenant quota (main-dev)
    qres = _res(dyn, "", "ResourceQuota")
    if qres is not None:
        try:
            for q in _items(qres):
                m = q.get("metadata") or {}
                if m.get("namespace") != "main-dev":
                    continue
                hard = (q.get("status") or {}).get("hard", {})
                used = (q.get("status") or {}).get("used", {})
                lines += ["", f"## tenant quota ({m.get('name')})",
                          f"- services: {used.get('services')}/{hard.get('services')}",
                          f"- pods: {used.get('pods')}/{hard.get('pods')}"]
        except Exception:
            pass
    total_ready = sum(t[1] for t in by_rt.values())
    return [("mirror/inventory.md", "\n".join(lines) + "\n")], unhealthy, ("Mirror inventory", "ok", f"{total_ready}/{len(items)} Functions Ready")


def probe_controlplane(dyn):
    lines = ["# control plane", "", f"observed_at: {STAMP}", "",
             "datastore: k3s embedded (kine over SQLite) — **size / fsync / snapshot age: not checked** "
             "(needs node filesystem access; a Layer 3 off-cluster/node probe).", ""]
    nres = _res(dyn, "", "Node")
    state = "partial"  # thin without node access
    if nres is not None:
        try:
            nodes = _items(nres)
            ready = sum(1 for n in nodes if _conds(n).get("Ready", (None,))[0] == "True")
            lines += [f"nodes: {ready}/{len(nodes)} Ready", ""]
            for n in nodes:
                m = n.get("metadata") or {}
                st = n.get("status") or {}
                r = _conds(n).get("Ready", (None,))[0]
                sched = (n.get("spec") or {}).get("unschedulable")
                ver = (st.get("nodeInfo") or {}).get("kubeletVersion", "?")
                flag = " ⚠️" if r != "True" else (" (cordoned)" if sched else "")
                lines.append(f"- {m.get('name')}: Ready={r} {ver}{flag}")
            state = "ok"
        except Exception as e:
            lines.append(f"nodes: not checked ({type(e).__name__})")
    return [("cluster/control-plane.md", "\n".join(lines) + "\n")], [], ("Control plane", state, "datastore size needs node access")


def probe_longhorn(dyn):
    vres = _res(dyn, "longhorn.io", "Volume")
    if vres is None:
        return [], [], ("Longhorn", "not checked (longhorn.io/Volume not accessible)", "")
    try:
        vols = _items(vres)
    except Exception as e:
        return [], [], ("Longhorn", f"not checked ({type(e).__name__})", "")
    bad, by_rob = [], {}
    for v in vols:
        st = v.get("status") or {}
        rob = st.get("robustness") or "?"
        by_rob[rob] = by_rob.get(rob, 0) + 1
        if rob in ("degraded", "faulted"):
            m = v.get("metadata") or {}
            bad.append(("LonghornVolume", m.get("namespace"), m.get("name"), f"robustness={rob} state={st.get('state')}"))
    lines = ["# Longhorn volumes", "", f"observed_at: {STAMP}", "", f"volumes: {len(vols)}", ""]
    for r in sorted(by_rob):
        lines.append(f"- {r}: {by_rob[r]}")
    nres = _res(dyn, "longhorn.io", "Node")
    if nres is not None:
        lines += ["", "## nodes (longhorn)"]
        for n in _items(nres):
            m = n.get("metadata") or {}
            c = _conds(n)
            lines.append(f"- {m.get('name')}: Ready={c.get('Ready',(None,))[0]} Schedulable={c.get('Schedulable',(None,))[0]}")
    return [("storage/longhorn.md", "\n".join(lines) + "\n")], bad, ("Longhorn", "ok", f"{len(vols)} volumes, {len(bad)} degraded/faulted")


def probe_gitops(dyn):
    res = _res(dyn, "argoproj.io", "Application")
    if res is None:
        return [], [], ("GitOps (ArgoCD)", "not checked (Application not accessible)", "")
    try:
        apps = _items(res)
    except Exception as e:
        return [], [], ("GitOps (ArgoCD)", f"not checked ({type(e).__name__})", "")
    bad = []
    lines = ["# GitOps — ArgoCD Applications", "", f"observed_at: {STAMP}", "",
             "| app | sync | health | synced-revision |", "|---|---|---|---|"]
    for a in apps:
        m = a.get("metadata") or {}
        s = a.get("status") or {}
        sync = (s.get("sync") or {}).get("status", "?")
        health = (s.get("health") or {}).get("status", "?")
        rev = ((s.get("sync") or {}).get("revision", "") or "")[:8]
        flag = " ⚠️" if (sync != "Synced" or health == "Degraded") else ""
        lines.append(f"| {m.get('name')} | {sync} | {health} | {rev}{flag} |")
        if sync != "Synced" or health == "Degraded":
            bad.append(("ArgoCDApp", m.get("namespace"), m.get("name"), f"sync={sync} health={health}"))
    return [("gitops/argocd.md", "\n".join(lines) + "\n")], bad, ("GitOps (ArgoCD)", "ok", f"{len(apps)} apps, {len(bad)} off")


def probe_registry(dyn):
    lines = ["# Registry (ECR doorway) + runtimeImage pull path", "", f"observed_at: {STAMP}", ""]
    bad = []
    cmres = _res(dyn, "", "ConfigMap")
    repos = None
    if cmres is not None:
        try:  # scope to the ECR namespace rather than re-listing every ConfigMap cluster-wide
            cms = cmres.get(namespace="open-infra-ecr").to_dict().get("items", [])
            repos = sum(1 for cm in cms if ((cm.get("metadata") or {}).get("labels") or {}).get("app.kubernetes.io/managed-by") == "ecr")
        except Exception:
            repos = None
    lines.append(f"ECR repositories (bookkeeping records): {repos if repos is not None else 'not checked'}")
    dsres = _res(dyn, "apps", "DaemonSet")
    if dsres is not None:
        for d in _items(dsres):
            m = d.get("metadata") or {}
            if m.get("name") == "ecr-node-pull-agent":
                st = d.get("status") or {}
                des, rdy = st.get("desiredNumberScheduled", 0), st.get("numberReady", 0)
                flag = " ⚠️" if rdy < des else ""
                lines += ["", f"pull-path agent (ecr-node-pull-agent): {rdy}/{des} armed nodes ready{flag}"]
                if rdy < des:
                    bad.append(("ECRpullAgent", m.get("namespace"), "ecr-node-pull-agent", f"{rdy}/{des} ready"))
    return [("registry/ecr.md", "\n".join(lines) + "\n")], bad, ("Registry + pull-path", "ok", f"{repos if repos is not None else '?'} repos")


def probe_networking(dyn):
    lines = ["# Networking", "", f"observed_at: {STAMP}", ""]
    bad = []
    dsres = _res(dyn, "apps", "DaemonSet")
    if dsres is not None:
        lines.append("## CNI / network DaemonSets")
        for d in _items(dsres):
            m = d.get("metadata") or {}
            nm = m.get("name", "")
            if any(k in nm for k in ("kube-ovn", "multus", "kube-proxy")):
                st = d.get("status") or {}
                des, rdy = st.get("desiredNumberScheduled", 0), st.get("numberReady", 0)
                flag = " ⚠️" if rdy < des else ""
                lines.append(f"- {m.get('namespace')}/{nm}: {rdy}/{des}{flag}")
                if rdy < des:
                    bad.append(("CNI", m.get("namespace"), nm, f"{rdy}/{des} ready"))
    npres = _res(dyn, "networking.k8s.io", "NetworkPolicy")
    if npres is not None:
        from collections import Counter
        c = Counter((p.get("metadata") or {}).get("namespace") for p in _items(npres))
        lines += ["", "## NetworkPolicies per namespace"]
        for ns in sorted(c):
            lines.append(f"- {ns}: {c[ns]}")
    mres = _res(dyn, "metallb.io", "IPAddressPool")
    if mres is not None:
        lines += ["", "## MetalLB IPAddressPools"]
        for p in _items(mres):
            m = p.get("metadata") or {}
            lines.append(f"- {m.get('name')}: {(p.get('spec') or {}).get('addresses', [])}")
    return [("network/overview.md", "\n".join(lines) + "\n")], bad, ("Networking", "ok", "")


def probe_policy(dyn):
    res = _res(dyn, "kyverno.io", "ClusterPolicy")
    if res is None:
        return [], [], ("Policy (Kyverno)", "not checked (ClusterPolicy not accessible)", "")
    try:
        pols = _items(res)
    except Exception as e:
        return [], [], ("Policy (Kyverno)", f"not checked ({type(e).__name__})", "")
    bad = []
    lines = ["# Policy (Kyverno)", "", f"observed_at: {STAMP}", "", f"ClusterPolicies: {len(pols)}", "",
             "| policy | action | ready |", "|---|---|---|"]
    for p in pols:
        m = p.get("metadata") or {}
        sp = p.get("spec") or {}
        action = sp.get("validationFailureAction") or ("background" if sp.get("background") else "?")
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in ((p.get("status") or {}).get("conditions") or []))
        lines.append(f"| {m.get('name')} | {action} | {ready} |")
        if not ready:
            bad.append(("KyvernoPolicy", "", m.get("name"), "not Ready"))
    return [("policy/kyverno.md", "\n".join(lines) + "\n")], bad, ("Policy (Kyverno)", "ok", f"{len(pols)} policies")


def probe_chaos(dyn):
    lines = ["# Chaos", "", f"observed_at: {STAMP}", ""]
    total = 0
    for kind in ("PodChaos", "NetworkChaos", "StressChaos", "IOChaos", "Schedule", "Workflow"):
        r = _res(dyn, "chaos-mesh.org", kind)
        if r is not None:
            try:
                total += len(_items(r))
            except Exception:
                pass
    lines.append(f"chaos-mesh experiments present: {total}")
    nres = _res(dyn, "", "Node")
    if nres is not None:
        tainted = []
        for n in _items(nres):
            for t in ((n.get("spec") or {}).get("taints", []) or []):
                if "chaos" in (t.get("key", "")).lower():
                    tainted.append((n.get("metadata") or {}).get("name"))
        lines.append(f"nodes with a chaos taint: {tainted or 'none'}")
    return [("chaos/state.md", "\n".join(lines) + "\n")], [], ("Chaos", "ok", f"{total} experiments")


def probe_node_metrics(dyn):
    res = _res(dyn, "metrics.k8s.io", "NodeMetrics")
    if res is None:
        return [], [], ("Node metrics", "not checked (metrics.k8s.io not accessible)", "")
    try:
        items = _items(res)
    except Exception as e:
        return [], [], ("Node metrics", f"not checked ({type(e).__name__})", "")
    lines = ["# Node metrics (CPU / memory usage)", "", f"observed_at: {STAMP}", "",
             "| node | cpu | memory |", "|---|---|---|"]
    for n in items:
        m = n.get("metadata") or {}
        u = n.get("usage") or {}
        lines.append(f"| {m.get('name')} | {u.get('cpu')} | {u.get('memory')} |")
    return [("cluster/node-metrics.md", "\n".join(lines) + "\n")], [], ("Node metrics", "ok", f"{len(items)} nodes")


def deep_probes(dyn):
    files, unhealthy, status = [], [], []
    for fn in (probe_databases, probe_controlplane, probe_knative, probe_mirror,
               probe_longhorn, probe_gitops, probe_registry, probe_networking,
               probe_policy, probe_chaos, probe_node_metrics):
        try:
            f, u, s = fn(dyn)
            files += f
            unhealthy += u
            status.append(s)
        except Exception as e:
            status.append((fn.__name__, f"not checked (probe error: {type(e).__name__}: {str(e)[:60]})", ""))
    return files, unhealthy, status


# ---- collection -------------------------------------------------------------------------------------
def collect():
    try:
        config.load_incluster_config()
    except Exception:
        config.load_kube_config()  # local dry-run path
    dyn = DynamicClient(client.ApiClient())
    coverage = []  # (resource, reason)
    per_kind = {}   # "group/Kind" -> list of allowlisted dicts
    per_ns = {}     # ns -> {kind -> counts}
    t0 = time.time()
    seen_resources = 0

    for res in dyn.resources.search():
        try:
            verbs = getattr(res, "verbs", None) or []
            if "list" not in verbs or not hasattr(res, "get"):
                continue
            kind = getattr(res, "kind", None)
            name = getattr(res, "name", "") or ""
            if not kind or "/" in name:  # subresources (status, scale) carry a '/' in name
                continue
            # search() also returns the "<Kind>List" pseudo-resources; their .get() has a different
            # signature. The real kind is covered by its Resource entry, so skip the List forms.
            if res.__class__.__name__ == "ResourceList" or kind.endswith("List"):
                continue
            if kind in SKIP_KINDS:
                coverage.append((f"{getattr(res, 'group', '') or 'core'}/{kind}", "skipped by policy (secret material)"))
                continue
        except Exception:
            continue
        key = f"{(getattr(res, 'group', '') or 'core')}/{kind}"
        if key in per_kind:
            continue
        try:
            items = res.get().to_dict().get("items", [])
        except Exception as e:
            coverage.append((key, f"list failed: {type(e).__name__}: {str(e)[:80]}"))
            continue
        seen_resources += 1
        rows = [allowlisted(o, res.kind) for o in items]
        per_kind[key] = rows
        for r in rows:
            if r["ns"]:
                per_ns.setdefault(r["ns"], {}).setdefault(res.kind, {"healthy": 0, "unhealthy": 0, "unknown": 0, "nosignal": 0})
                per_ns[r["ns"]][res.kind][r["health"]] += 1
    dur = round(time.time() - t0, 1)
    probe_files, probe_unhealthy, probe_status = deep_probes(dyn)
    return per_kind, per_ns, coverage, seen_resources, dur, probe_files, probe_unhealthy, probe_status


# ---- rendering --------------------------------------------------------------------------------------
def counts(rows):
    c = {"healthy": 0, "unhealthy": 0, "unknown": 0, "nosignal": 0}
    for r in rows:
        c[r["health"]] += 1
    return c


def chunk_lines(lines, header):
    """Split body lines into files that stay under MAX_FILE_LINES (header + part annotation included)."""
    body = MAX_FILE_LINES - 20  # leave room for the header + "_part N of M_"
    chunks = [lines[i:i + body] for i in range(0, len(lines), body)] or [[]]
    if len(chunks) == 1:
        return [("", header + "\n".join(chunks[0]) + "\n")]
    return [(f".part-{i+1}", header + f"\n_part {i+1} of {len(chunks)}_\n\n" + "\n".join(c) + "\n") for i, c in enumerate(chunks)]


def render(per_kind, per_ns, coverage, seen_resources, dur, probe_files, probe_unhealthy, probe_status):
    files = {}  # path -> text
    for p, t in probe_files:  # Layer 2 deep-probe files
        files[p] = t
    tot = {"healthy": 0, "unhealthy": 0, "unknown": 0, "nosignal": 0}
    unhealthy_all = []  # (kind, ns, name, detail)

    # per-kind rollups
    for key in sorted(per_kind):
        rows = per_kind[key]
        c = counts(rows)
        for k in tot:
            tot[k] += c[k]
        group, kind = key.split("/", 1)
        # collect ALL unhealthy for the front page, regardless of the display cap below
        for r in rows:
            if r["health"] == "unhealthy":
                unhealthy_all.append((kind, r["ns"], r["name"], r["detail"]))
        lines = []
        shown = 0
        for r in sorted(rows, key=lambda x: (x["health"] != "unhealthy", x["ns"] or "", x["name"])):
            if r["health"] != "unhealthy" and shown >= LISTCAP:
                continue  # keep listing unhealthy, cap the rest
            loc = f"{r['ns']}/" if r["ns"] else ""
            mark = {"healthy": "ok", "unhealthy": "UNHEALTHY", "unknown": "unknown", "nosignal": "no-signal"}[r["health"]]
            lines.append(f"- `{loc}{r['name']}` ({r['age']}) — {mark}{(' — ' + r['detail']) if r['detail'] else ''}")
            shown += 1
        if shown < len(rows):
            lines.append(f"- …and {len(rows) - shown} more (healthy/no-signal) not individually listed — see counts above")
        header = (f"# {key}\n\nobserved_at: {STAMP}\nhealthy {c['healthy']} · unhealthy {c['unhealthy']} · "
                  f"unknown {c['unknown']} · no-signal {c['nosignal']} · total {len(rows)}\n\n")
        fname = f"cluster/kinds/{group.replace('/', '_') or 'core'}-{kind}.md"
        for suffix, text in chunk_lines(lines, header):
            files[fname.replace(".md", f"{suffix}.md")] = text

    # per-namespace summaries
    for ns in sorted(per_ns):
        lines = [f"# namespace: {ns}", "", f"observed_at: {STAMP}", ""]
        for kind in sorted(per_ns[ns]):
            c = per_ns[ns][kind]
            flag = " ⚠️" if c["unhealthy"] else ""
            lines.append(f"- {kind}: healthy {c['healthy']} · unhealthy {c['unhealthy']} · unknown {c['unknown']} · no-signal {c['nosignal']}{flag}")
        files[f"cluster/namespaces/{ns}/_summary.md"] = "\n".join(lines) + "\n"

    # coverage (Layer 5) — everything NOT read
    cov_header = (f"# coverage — what was NOT read, and why\n\nobserved_at: {STAMP}\n\n"
                  f"resource types listed: {seen_resources}\nresource types unread: {len(coverage)}\n")
    cov_rows = [f"- `{r}` — not checked ({reason})" for r, reason in sorted(coverage)]
    for suffix, text in chunk_lines(cov_rows, cov_header):
        files[f"coverage{suffix}.md"] = text

    verdict = "UNHEALTHY" if (tot["unhealthy"] or probe_unhealthy) else ("DEGRADED-SIGNAL" if tot["unknown"] else "OK")
    summary = {
        "observed_at": STAMP, "verdict": verdict, "totals": tot,
        "resource_types_listed": seen_resources, "resource_types_unread": len(coverage),
        "collect_seconds": dur, "unhealthy": [{"kind": k, "ns": n, "name": nm, "detail": d} for k, n, nm, d in unhealthy_all],
        "probes": [{"name": n, "state": s, "detail": d} for n, s, d in probe_status],
        "deep_findings": [{"kind": k, "ns": n, "name": nm, "detail": d} for k, n, nm, d in probe_unhealthy],
    }
    files["summary.json"] = json.dumps(summary, sort_keys=True) + "\n"  # compact: one line (machine-read)

    # INDEX (chunked so it never exceeds the line cap)
    idx_header = ("# INDEX\n\n" + f"snapshot {STAMP} · verdict **{verdict}** · "
                  f"healthy {tot['healthy']} / unhealthy {tot['unhealthy']} / unknown {tot['unknown']} / no-signal {tot['nosignal']}\n\n"
                  "| file | lines |\n|---|---|")
    idx_rows = [f"| {p} | {len(files[p].splitlines())} |" for p in sorted(files)]
    for suffix, text in chunk_lines(idx_rows, idx_header):
        files[f"INDEX{suffix}.md"] = text
    return files, summary, unhealthy_all, tot, verdict, probe_unhealthy, probe_status


# ---- redaction (fail-closed) ------------------------------------------------------------------------
CREDPAT = re.compile(
    r"(AKIA[0-9A-Z]{16})|(github_pat_[A-Za-z0-9_]{20,})|(gh[pousr]_[A-Za-z0-9]{36,})|"
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)|(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)|"
    r"((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+_-]{12,})",
    re.IGNORECASE,
)
LISTCAP = 150  # per-kind: list all unhealthy + up to this many others (keeps high-cardinality kinds bounded)


def redaction_scan(files):
    hits = []
    for path, text in files.items():
        for m in CREDPAT.finditer(text):
            hits.append((path, m.group(0)[:12] + "…"))
    return hits


# ---- publish ----------------------------------------------------------------------------------------
def publish_repo(files):
    work = "/tmp/cs-work"
    shutil.rmtree(work, ignore_errors=True)
    url = f"https://x-access-token:{_token('CONTENTS_TOKEN_FILE', '/secrets/contents-token')}@github.com/{STATE_REPO}.git"
    subprocess.run(["git", "clone", "--depth", "1", url, work], check=True, capture_output=True)
    # wipe tracked content (keep .git) so removed objects disappear from the snapshot
    for entry in os.listdir(work):
        if entry == ".git":
            continue
        p = os.path.join(work, entry)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    for path, text in files.items():
        full = os.path.join(work, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        open(full, "w").write(text)
    subprocess.run(["git", "-C", work, "config", "user.email", "cluster-state@collector.local"], check=True)
    subprocess.run(["git", "-C", work, "config", "user.name", "cluster-state-collector"], check=True)
    subprocess.run(["git", "-C", work, "add", "-A"], check=True)
    r = subprocess.run(["git", "-C", work, "commit", "-m", f"snapshot {STAMP}"], capture_output=True, text=True)
    if "nothing to commit" in (r.stdout + r.stderr):
        return "no-change"
    subprocess.run(["git", "-C", work, "push", "origin", "HEAD:main"], check=True, capture_output=True)
    return "committed"


def issue_body(summary, unhealthy_all, tot, verdict, probe_unhealthy, probe_status):
    lines = [f"# Environment state — {verdict}", "",
             f"snapshot **{STAMP}** · collector {summary['collect_seconds']}s · "
             f"{summary['resource_types_listed']} resource types read, {summary['resource_types_unread']} unread (coverage)",
             "",
             f"**healthy {tot['healthy']} · unhealthy {tot['unhealthy']} · unknown {tot['unknown']} · no-signal {tot['nosignal']}**"]
    # Layer 2 deep-probe status (each reports ok / partial / not-checked)
    lines += ["", "## Deep probes"]
    for n, s, d in probe_status:
        mark = "✅" if s == "ok" else ("⚠️" if s == "partial" else "❓")
        lines.append(f"- {mark} **{n}**: {s}{(' — ' + d) if d else ''}")
    if probe_unhealthy:
        lines += ["", "### Deep-probe findings"]
        for k, n, nm, d in probe_unhealthy[:25]:
            loc = f"{n}/" if n else ""
            lines.append(f"- **{k}** `{loc}{nm}` — {d}")
    lines += ["", "## Unhealthy (generic health)"]
    if not unhealthy_all:
        lines.append("_none observed_")
    else:
        shown = unhealthy_all[:50]
        for k, n, nm, d in shown:
            loc = f"{n}/" if n else ""
            lines.append(f"- **{k}** `{loc}{nm}` — {d}")
        if len(unhealthy_all) > len(shown):
            lines.append(f"- …and {len(unhealthy_all) - len(shown)} more — see `cluster/` in {STATE_REPO}")
    lines += ["", "## Data",
              f"Full snapshot (one commit per run, diffable): `{STATE_REPO}` — start at `INDEX.md`.",
              "Coverage (what was NOT read): `coverage*.md`.",
              "", "_Machine-generated (#314); body rewritten each run. Do not edit or comment._"]
    body = "\n".join(lines)
    if len(body) > MAX_ISSUE_CHARS:
        body = body[:MAX_ISSUE_CHARS - 200] + f"\n\n…TRUNCATED at {MAX_ISSUE_CHARS} chars — full detail in {STATE_REPO}."
    return body


def publish_issue(body):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{ISSUE_REPO}/issues/{ISSUE_NUMBER}",
        data=json.dumps({"body": body}).encode(), method="PATCH",
        headers={"Authorization": f"Bearer {_token('ISSUE_TOKEN_FILE', '/secrets/issue-token')}",
                 "Accept": "application/vnd.github+json", "User-Agent": "cluster-state-collector"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def main():
    per_kind, per_ns, coverage, seen, dur, probe_files, probe_unhealthy, probe_status = collect()
    files, summary, unhealthy_all, tot, verdict, probe_unhealthy, probe_status = render(
        per_kind, per_ns, coverage, seen, dur, probe_files, probe_unhealthy, probe_status)
    hits = redaction_scan(files)
    if hits:
        sys.stderr.write(f"REDACTION TRIPPED — publishing nothing (fail closed). {len(hits)} match(es):\n")
        for path, frag in hits[:10]:
            sys.stderr.write(f"  {path}: {frag}\n")
        sys.exit(3)
    if os.environ.get("DRY_RUN") == "1":
        print(f"DRY RUN: verdict={verdict} types={seen} unhealthy={tot['unhealthy']} files={len(files)} "
              f"redaction_clean=yes collect={dur}s")
        from collections import Counter
        bykind = Counter(f"{k}" for k, n, nm, d in unhealthy_all)
        print("  unhealthy by kind (top 20):")
        for k, c in bykind.most_common(20):
            print(f"    {k}: {c}")
        print("  deep probes:")
        for n, s, d in probe_status:
            print(f"    {n}: {s}{(' — ' + d) if d else ''}")
        print(f"  deep-probe findings: {len(probe_unhealthy)}")
        for k, n, nm, d in probe_unhealthy[:8]:
            print(f"    {k} {n or '-'}/{nm}: {d}")
        print("  sample generic-unhealthy:")
        for k, n, nm, d in unhealthy_all[:8]:
            print(f"    {k} {n or '-'}/{nm}: {d}")
        oversize = [(p, len(t.splitlines())) for p, t in files.items() if len(t.splitlines()) > 300]
        print(f"  files over 300 lines: {oversize}")
        from collections import Counter as _C
        covtext = "".join(t for p, t in files.items() if p.startswith("coverage"))
        covreasons = _C(ln.split("(", 1)[1].rstrip(")") for ln in covtext.splitlines() if ln.startswith("- ") and "(" in ln)
        print("  coverage reasons (top 8):")
        for r, c in covreasons.most_common(8):
            print(f"    {c}× {r}")
        return
    repo_result = publish_repo(files)
    code = publish_issue(issue_body(summary, unhealthy_all, tot, verdict, probe_unhealthy, probe_status))
    print(f"snapshot {STAMP}: verdict={verdict} types={seen} unhealthy={tot['unhealthy']} "
          f"deep_findings={len(probe_unhealthy)} repo={repo_result} issue_http={code} collect={dur}s")


if __name__ == "__main__":
    main()
