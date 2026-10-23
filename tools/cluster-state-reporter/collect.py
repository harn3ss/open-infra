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
CONTENTS_TOKEN = open(os.environ.get("CONTENTS_TOKEN_FILE", "/secrets/contents-token")).read().strip()
ISSUE_TOKEN = open(os.environ.get("ISSUE_TOKEN_FILE", "/secrets/issue-token")).read().strip()

# Kinds we never enumerate (secret material / pure noise). Secrets especially: no get, ever.
SKIP_KINDS = {"Secret"}
# Conditions that signal health, and how to read them.
GOOD_TRUE = {"Ready", "Synced", "Available", "Succeeded", "Established", "NamesAccepted", "Initialized", "PodScheduled", "ContainersReady"}
BAD_TRUE = {"Degraded", "Failed", "Stalled"}  # True == bad

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
    gen = meta.get("generation")
    og = status.get("observedGeneration")
    if gen is not None and og is not None and og < gen:
        return "unhealthy", f"stuck reconcile (observedGeneration {og} < generation {gen})"
    conds = status.get("conditions") or []
    if not isinstance(conds, list) or not conds:
        # pods carry phase instead of conditions for our purposes
        phase = status.get("phase")
        if phase in ("Running", "Succeeded", "Active", "Bound"):
            return "healthy", ""
        if phase in ("Failed", "Pending", "Unknown"):
            return "unhealthy", f"phase={phase}"
        return "nosignal", ""
    bad = []
    saw_good = False
    for c in conds:
        t, s = c.get("type"), c.get("status")
        msg = (c.get("reason") or "") + (": " + c.get("message") if c.get("message") else "")
        if t in BAD_TRUE and s == "True":
            bad.append(f"{t} {msg}".strip())
        elif t in GOOD_TRUE:
            if s == "True":
                saw_good = True
            elif s == "False":
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


# ---- collection -------------------------------------------------------------------------------------
def collect():
    config.load_incluster_config()
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
    return per_kind, per_ns, coverage, seen_resources, dur


# ---- rendering --------------------------------------------------------------------------------------
def counts(rows):
    c = {"healthy": 0, "unhealthy": 0, "unknown": 0, "nosignal": 0}
    for r in rows:
        c[r["health"]] += 1
    return c


def chunk_lines(lines, header):
    """Split a list of body lines into <=MAX_FILE_LINES files; return list of (suffix, text)."""
    out, buf = [], []
    for ln in lines:
        if len(buf) + len(header.splitlines()) + 1 >= MAX_FILE_LINES:
            out.append(buf)
            buf = []
        buf.append(ln)
    if buf or not out:
        out.append(buf)
    if len(out) == 1:
        return [("", header + "\n".join(out[0]) + "\n")]
    return [(f".part-{i+1}", header + f"\n_part {i+1} of {len(out)}_\n\n" + "\n".join(b) + "\n") for i, b in enumerate(out)]


def render(per_kind, per_ns, coverage, seen_resources, dur, outdir):
    files = {}  # path -> text
    tot = {"healthy": 0, "unhealthy": 0, "unknown": 0, "nosignal": 0}
    unhealthy_all = []  # (kind, ns, name, detail)

    # per-kind rollups
    for key in sorted(per_kind):
        rows = per_kind[key]
        c = counts(rows)
        for k in tot:
            tot[k] += c[k]
        group, kind = key.split("/", 1)
        lines = []
        for r in sorted(rows, key=lambda x: (x["health"] != "unhealthy", x["ns"] or "", x["name"])):
            loc = f"{r['ns']}/" if r["ns"] else ""
            mark = {"healthy": "ok", "unhealthy": "UNHEALTHY", "unknown": "unknown", "nosignal": "no-signal"}[r["health"]]
            lines.append(f"- `{loc}{r['name']}` ({r['age']}) — {mark}{(' — ' + r['detail']) if r['detail'] else ''}")
            if r["health"] == "unhealthy":
                unhealthy_all.append((kind, r["ns"], r["name"], r["detail"]))
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
    cov_lines = ["# coverage — what was NOT read, and why", "", f"observed_at: {STAMP}", "",
                 f"resource types listed: {seen_resources}", f"resource types unread: {len(coverage)}", ""]
    for r, reason in sorted(coverage):
        cov_lines.append(f"- `{r}` — not checked ({reason})")
    files["coverage.md"] = "\n".join(cov_lines) + "\n"

    verdict = "UNHEALTHY" if tot["unhealthy"] else ("DEGRADED-SIGNAL" if tot["unknown"] else "OK")
    summary = {
        "observed_at": STAMP, "verdict": verdict, "totals": tot,
        "resource_types_listed": seen_resources, "resource_types_unread": len(coverage),
        "collect_seconds": dur, "unhealthy": [{"kind": k, "ns": n, "name": nm, "detail": d} for k, n, nm, d in unhealthy_all],
    }
    files["summary.json"] = json.dumps(summary, indent=2, sort_keys=True) + "\n"

    # INDEX
    idx = ["# INDEX", "", f"snapshot {STAMP} · verdict **{verdict}** · "
           f"healthy {tot['healthy']} / unhealthy {tot['unhealthy']} / unknown {tot['unknown']} / no-signal {tot['nosignal']}", "",
           "| file | lines |", "|---|---|"]
    for p in sorted(files):
        idx.append(f"| {p} | {len(files[p].splitlines())} |")
    files["INDEX.md"] = "\n".join(idx) + "\n"
    return files, summary, unhealthy_all, tot, verdict


# ---- redaction (fail-closed) ------------------------------------------------------------------------
CREDPAT = re.compile(
    r"(AKIA[0-9A-Z]{16})|(github_pat_[A-Za-z0-9_]{20,})|(gh[pousr]_[A-Za-z0-9]{36,})|"
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)|(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.)|"
    r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+_-]{12,}"
)


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
    url = f"https://x-access-token:{CONTENTS_TOKEN}@github.com/{STATE_REPO}.git"
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


def issue_body(summary, unhealthy_all, tot, verdict):
    stale = ""  # this run is fresh by definition
    lines = [f"# Environment state — {verdict}", "",
             f"snapshot **{STAMP}** · collector {summary['collect_seconds']}s · "
             f"{summary['resource_types_listed']} resource types read, {summary['resource_types_unread']} unread (coverage)",
             "",
             f"**healthy {tot['healthy']} · unhealthy {tot['unhealthy']} · unknown {tot['unknown']} · no-signal {tot['nosignal']}**",
             "", "## Unhealthy"]
    if not unhealthy_all:
        lines.append("_none observed_")
    else:
        shown = unhealthy_all[:60]
        for k, n, nm, d in shown:
            loc = f"{n}/" if n else ""
            lines.append(f"- **{k}** `{loc}{nm}` — {d}")
        if len(unhealthy_all) > len(shown):
            lines.append(f"- …and {len(unhealthy_all) - len(shown)} more — see `cluster/` in {STATE_REPO}")
    lines += ["", "## Data",
              f"Full snapshot (one commit per run, diffable): `{STATE_REPO}` — start at `INDEX.md`.",
              "Coverage (what was NOT read): `coverage.md`.",
              "", "_Machine-generated (#314); body rewritten each run. Do not edit or comment._"]
    body = "\n".join(lines)
    if len(body) > MAX_ISSUE_CHARS:
        body = body[:MAX_ISSUE_CHARS - 200] + f"\n\n…TRUNCATED at {MAX_ISSUE_CHARS} chars — full detail in {STATE_REPO}."
    return body


def publish_issue(body):
    req = urllib.request.Request(
        f"https://api.github.com/repos/{ISSUE_REPO}/issues/{ISSUE_NUMBER}",
        data=json.dumps({"body": body}).encode(), method="PATCH",
        headers={"Authorization": f"Bearer {ISSUE_TOKEN}", "Accept": "application/vnd.github+json",
                 "User-Agent": "cluster-state-collector"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def main():
    per_kind, per_ns, coverage, seen, dur = collect()
    files, summary, unhealthy_all, tot, verdict = render(per_kind, per_ns, coverage, seen, dur, None)
    hits = redaction_scan(files)
    if hits:
        sys.stderr.write(f"REDACTION TRIPPED — publishing nothing (fail closed). {len(hits)} match(es):\n")
        for path, frag in hits[:10]:
            sys.stderr.write(f"  {path}: {frag}\n")
        sys.exit(3)
    repo_result = publish_repo(files)
    code = publish_issue(issue_body(summary, unhealthy_all, tot, verdict))
    print(f"snapshot {STAMP}: verdict={verdict} types={seen} unhealthy={tot['unhealthy']} "
          f"repo={repo_result} issue_http={code} collect={dur}s")


if __name__ == "__main__":
    main()
