"""The AWS coverage registry: CloudFormation resource types joined with the aws-shim front doors.

probe/shimgen.py (the one generator and drift gate for the shim's docs) imports this module. It joins
the two halves the Go tests read from code —

  probe/registry/cfn-types.json    the cfn engine's mapping table + translator dispatch
  probe/registry/shim-router.json  the aws-shim router's services + each handler's operations

— with each shim service's proof (probe/shim-services.yaml), the in-repo templates and probes, and the
few hand-kept facts in probe/registry/coverage.yaml, into probe/registry/registry.json: one row per AWS
resource type (does CloudFormation create it, which shim service serves it, which of its read calls are
served, which probe deploys it). From that one registry it

  - gates (errors()): a type a stack can create must have its own service's front door, and that door
    must serve a call that reads it — unless an exception with a reason and a tracking reference says
    why not. An exception that no longer applies fails too.
  - ranks breadth gaps: services the shim serves that no CloudFormation type creates.
  - renders the coverage blocks of README.md, docs/aws-shim.md, docs/cloudformation.md and
    docs/aws-coverage.md.

Python 3 stdlib + PyYAML (as the rest of shimgen).
"""
import glob
import json
import os
import re
from collections import Counter

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))

READ_VERBS = ("Describe", "Get", "List", "Head")
CHECKS = ("front-door", "read")

# The IAM action prefix of a signing name, where the two differ (an action a handler authorizes by name
# is an operation it serves).
IAM_PREFIX = {"monitoring": "cloudwatch", "email": "ses", "dynamodbstreams": "dynamodb"}

# In-repo CloudFormation templates the breadth ranking counts: the engine's fixtures, the examples, and
# the probes' stacks. Only these, the repository's own fixtures, are read.
TEMPLATE_SOURCES = [
    ("cfn/testdata", ["cfn/testdata/**/*.yaml", "cfn/testdata/**/*.yml", "cfn/testdata/**/*.json"]),
    ("examples", ["examples/**/*.yaml", "examples/**/*.yml", "examples/**/*.json"]),
    ("probe", ["probe/aws-shim-*.sh"]),
]
TYPE_RE = re.compile(r"""["']?\bType["']?\s*:\s*["']?(AWS::[A-Za-z0-9]+::[A-Za-z0-9]+)\b""")

# The example apps' own calls to an AWS API — an SDK client or a CLI command — name the service by its
# SDK/CLI name, which is the signing name except for these.
API_CALL_RE = re.compile(r"""client\(\s*["']([a-z0-9-]+)["']|@aws-sdk/client-([a-z0-9-]+)|\baws\s+([a-z0-9-]+)\s+[a-z]""")
SDK_TO_SIGNING = {"cloudwatch": "monitoring", "sesv2": "email", "stepfunctions": "states", "sfn": "states",
                  "apigatewayv2": "apigateway", "cognito-identity-provider": "cognito-idp",
                  "cloudwatch-logs": "logs", "eventbridge": "events", "dynamodb-streams": "dynamodbstreams"}


# ---------------------------------------------------------------------------------------------- inputs

def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _paths(root):
    reg = os.path.join(root, "probe", "registry")
    return {
        "cfn": os.path.join(reg, "cfn-types.json"),
        "shim": os.path.join(reg, "shim-router.json"),
        "facts": os.path.join(reg, "coverage.yaml"),
        "services": os.path.join(root, "probe", "shim-services.yaml"),
        "out": os.path.join(reg, "registry.json"),
    }


def template_usage(root):
    """How often each type appears as a resource in the in-repo templates, and which probes deploy it."""
    uses, probes, files = Counter(), {}, Counter()
    for label, pats in TEMPLATE_SOURCES:
        seen = set()
        for pat in pats:
            for p in glob.glob(os.path.join(root, pat), recursive=True):
                if p in seen:
                    continue
                seen.add(p)
                found = TYPE_RE.findall(read_text(p))
                if not found:
                    continue
                files[label] += 1
                uses.update(found)
                if label == "probe":
                    name = os.path.basename(p)[len("aws-shim-"):-len(".sh")]
                    for t in set(found):
                        probes.setdefault(t, set()).add(name)
    # which example apps call each API (an app counts once per API, however often it calls it)
    apps = {}
    for p in glob.glob(os.path.join(root, "examples", "*", "**", "*"), recursive=True):
        if not os.path.isfile(p):
            continue
        app = os.path.relpath(p, os.path.join(root, "examples")).split(os.sep)[0]
        for m in API_CALL_RE.finditer(read_text(p)):
            name = next(g for g in m.groups() if g)
            apps.setdefault(SDK_TO_SIGNING.get(name, name), set()).add(app)
    return {"uses": dict(uses), "probes": {t: sorted(v) for t, v in probes.items()}, "files": dict(files),
            "exampleApps": {k: len(v) for k, v in sorted(apps.items())}}


def load_inputs(root=ROOT):
    p = _paths(root)
    return {
        "cfn": json.loads(read_text(p["cfn"]))["types"],
        "shim": json.loads(read_text(p["shim"]))["services"],
        "facts": yaml.safe_load(read_text(p["facts"])) or {},
        "services": yaml.safe_load(read_text(p["services"]))["services"],
        "usage": template_usage(root),
    }


# ----------------------------------------------------------------------------------------------- build

def namespace_of(cfn_type):
    if cfn_type.startswith("Custom::"):
        return "AWS::CloudFormation"
    return "::".join(cfn_type.split("::")[:2])


def served_ops(shim, keys):
    """Every operation the front doors `keys` serve: the ones they dispatch on, and the ones they
    authorize by name under their own IAM prefix."""
    out = set()
    for k in keys:
        svc = shim.get(k) or {}
        out.update(svc.get("operations") or [])
        prefix = IAM_PREFIX.get(k, k)
        for a in svc.get("actions") or []:
            pre, _, op = a.partition(":")
            if pre == prefix:
                out.add(op)
    return out


def read_calls(cfn_type, ops, reads):
    """The served operations that read cfn_type: the listed calls, or by default any
    Describe/Get/List/Head call that starts with the type's own name (singular or plural)."""
    if cfn_type in reads:
        want = set(reads[cfn_type])
        return sorted(o for o in ops if o in want)
    noun = cfn_type.split("::")[-1].lower()
    stem = noun[:-1] if noun.endswith("y") else noun  # Repository -> Repositories, Policy -> Policies
    out = []
    for o in ops:
        lo = o.lower()
        for v in READ_VERBS:
            if lo.startswith(v.lower() + stem):
                out.append(o)
                break
    return sorted(out)


def validate_sigv4(services, shim):
    """shim-services.yaml ⇄ the router: each router key is claimed by exactly one service; a proven or
    gated service is routed under every name it claims; a planned one under none."""
    errs, claimed = [], {}
    for s in services:
        name, tier = s.get("name", "<unnamed>"), s.get("tier")
        keys = s.get("sigv4") or []
        if not keys:
            errs.append(f"{name}: no sigv4 (the SigV4 signing name(s) it is served under)")
        for k in keys:
            if k in claimed:
                errs.append(f"signing name {k!r} claimed by both {claimed[k]!r} and {name!r}")
            claimed[k] = name
            if tier in ("proven", "gated") and k not in shim:
                errs.append(f"{name}: tier {tier}, but the aws-shim router serves no {k!r} "
                            f"(console-api/cmd/aws-shim/main.go) — the docs would claim a front door the code lacks")
            if tier == "planned" and k in shim:
                errs.append(f"{name}: tier planned, but the router serves {k!r} — it is built: add its probe and promote it")
    for k in sorted(shim):
        if k not in claimed:
            errs.append(f"the aws-shim router serves {k!r} but no service in probe/shim-services.yaml claims it "
                        f"(add `sigv4: [{k}]` to its entry, or a new entry)")
    return errs


def service_for_key(services):
    """signing name -> its shim-services.yaml entry."""
    out = {}
    for s in services:
        for k in s.get("sigv4") or []:
            out[k] = s
    return out


def build(inp):
    """Join the inputs into the registry. Returns (registry, errors)."""
    cfn, shim, facts = inp["cfn"], inp["shim"], inp["facts"]
    nsmap = facts.get("namespaces") or {}
    reads = facts.get("reads") or {}
    by_key = service_for_key(inp["services"])
    usage = inp["usage"]
    errs = []

    exc_by_type = {}
    for i, e in enumerate(facts.get("exceptions") or []):
        where = f"coverage.yaml exceptions[{i}]"
        for f in ("types", "check", "reason", "issue"):
            if not e.get(f):
                errs.append(f"{where}: needs {f!r} (an exception states what it excuses, why, and where it is tracked)")
        if e.get("check") and e["check"] not in CHECKS:
            errs.append(f"{where}: check must be one of {', '.join(CHECKS)} (got {e['check']!r})")
        for t in e.get("types") or []:
            if any(ch in t for ch in "*?["):
                errs.append(f"{where}: {t!r} is a wildcard — name each type, so a new type is never excused by an old entry")
            elif t in exc_by_type:
                errs.append(f"{where}: {t} is excused twice")
            exc_by_type[t] = e

    for t in reads:
        if t not in cfn:
            errs.append(f"coverage.yaml reads: {t} is not a type the cfn engine knows (stale entry)")

    rows = {}
    for t in sorted(cfn):
        c = cfn[t]
        ns = namespace_of(t)
        signing = nsmap.get(ns)
        if signing is None:
            errs.append(f"{t}: its namespace {ns} has no signing name in probe/registry/coverage.yaml namespaces "
                        f"(add the AWS API that serves it)")
            signing = []
        doors = [k for k in signing if k in shim]
        ops = served_ops(shim, doors)
        reading = read_calls(t, ops, reads) if doors else []
        problem = None
        if c["deployable"]:
            if not doors:
                problem = "front-door"
            elif not reading:
                problem = "read"
        exc = exc_by_type.get(t)
        row = {
            "namespace": ns,
            "status": c["status"],
            "flattened": bool(c.get("flattened")),
            "kind": c.get("kind", ""),
            "deployable": c["deployable"],
            "signingNames": signing,
            "frontDoor": doors,
            "readCalls": reading,
            "service": by_key[doors[0]]["name"] if doors and doors[0] in by_key else None,
            "serviceTier": by_key[doors[0]]["tier"] if doors and doors[0] in by_key else None,
            "stackProbes": usage["probes"].get(t, []),
            "templateUses": usage["uses"].get(t, 0),
        }
        if problem:
            if exc and exc.get("check") == problem:
                row["verdict"] = "excepted"
                row["exception"] = {"check": exc["check"], "reason": exc.get("reason", ""), "issue": exc.get("issue", "")}
            else:
                row["verdict"] = "violation"
                row["problem"] = problem
                if exc:
                    errs.append(f"{t}: its exception is for {exc.get('check')!r} but the gap is now {problem!r} — update the exception")
                elif problem == "front-door":
                    errs.append(f"{t}: a stack can create it (cfn deployable), but the aws-shim serves no {ns} front door "
                                f"({'/'.join(signing) or '?'}) — the stack's {t.split('::')[-1]} could not be found through its own API. "
                                f"Build the front door, or list it under exceptions in probe/registry/coverage.yaml with a reason")
                else:
                    want = reads.get(t) or [f"{v}{t.split('::')[-1]}…" for v in READ_VERBS]
                    errs.append(f"{t}: a stack can create it, and the {'/'.join(doors)} front door exists, but it serves no call "
                                f"that reads one ({', '.join(want)}). Serve one, add the right call under reads, or list it under "
                                f"exceptions in probe/registry/coverage.yaml with a reason")
        else:
            row["verdict"] = "ok" if c["deployable"] else ("flattened" if c.get("flattened") else "not-deployable")
            if exc:
                why = "it is not create-deployable" if not c["deployable"] else "its front door and read call are now served"
                errs.append(f"{t}: excused under {exc.get('check')!r}, but {why} — remove the exception")
        rows[t] = row

    for t in exc_by_type:
        if t not in cfn:
            errs.append(f"coverage.yaml exceptions: {t} is not a type the cfn engine knows — remove it")

    # shim services: the router's view, joined with the proof registry
    services = {}
    for k in sorted(shim):
        s = shim[k]
        entry = by_key.get(k)
        nss = sorted(ns for ns, keys in nsmap.items() if k in keys)
        if not nss and k not in (facts.get("noResourceTypes") or {}):
            errs.append(f"the shim serves {k!r}, but no CloudFormation namespace in probe/registry/coverage.yaml maps to it "
                        f"(add it under namespaces, or under noResourceTypes with why)")
        services[k] = {
            "service": entry["name"] if entry else None,
            "tier": entry["tier"] if entry else None,
            "probes": (entry or {}).get("probes") or [],
            "handler": s.get("handler"),
            "operations": s.get("operations") or [],
            "refused": s.get("refused") or [],
            "actions": sorted(a for a in s.get("actions") or [] if a.partition(":")[0] == IAM_PREFIX.get(k, k)),
            "conditional": bool(s.get("conditional")),
            "namespaces": nss,
            "deployableTypes": sorted(t for t, r in rows.items() if r["deployable"] and k in r["frontDoor"]),
        }

    reg = {
        "generatedBy": "probe/shimgen.py (probe/coverage.py) from probe/registry/cfn-types.json, "
                       "probe/registry/shim-router.json, probe/shim-services.yaml and probe/registry/coverage.yaml",
        "summary": summarize(rows, services),
        "types": rows,
        "services": services,
        "breadth": breadth(rows, services, inp),
    }
    return reg, errs


def summarize(rows, services):
    dep = [r for r in rows.values() if r["deployable"]]
    names = {s["service"] for s in services.values() if s["service"]}
    return {
        "cfnTypes": len(rows),
        "deployable": len(dep),
        "planOnly": sum(1 for r in rows.values() if not r["deployable"] and r["status"] in ("supported", "partial")),
        "refused": sum(1 for r in rows.values() if r["status"] in ("unsupported", "gated") and not r["flattened"]),
        "flattened": sum(1 for r in rows.values() if r["flattened"]),
        "covered": sum(1 for r in dep if r["verdict"] == "ok"),
        "excepted": sum(1 for r in dep if r["verdict"] == "excepted"),
        "excFrontDoor": sum(1 for r in dep if r["verdict"] == "excepted" and r["exception"]["check"] == "front-door"),
        "excRead": sum(1 for r in dep if r["verdict"] == "excepted" and r["exception"]["check"] == "read"),
        "violations": sum(1 for r in dep if r["verdict"] == "violation"),
        "signingNames": len(services),
        "services": len(names),
        "operations": len({(s["service"] or k, o) for k, s in services.items() for o in s["operations"]}),
    }


def breadth(rows, services, inp):
    """Shim services that no CloudFormation type creates, ranked by in-repo demand (see BREADTH_BASIS)."""
    facts, usage = inp["facts"], inp["usage"]
    no_types = facts.get("noResourceTypes") or {}
    groups = {}
    for k, s in services.items():
        if k in no_types:
            continue
        groups.setdefault(s["service"] or k, []).append(k)
    out = []
    for name, keys in groups.items():
        dep = sorted({t for k in keys for t in services[k]["deployableTypes"]})
        if dep:
            continue
        nss = sorted({ns for k in keys for ns in services[k]["namespaces"]})
        demand = sum(n for t, n in usage["uses"].items() if namespace_of(t) in nss)
        known = sorted(t for t in rows if rows[t]["namespace"] in nss)
        out.append({
            "service": name,
            "signingNames": sorted(keys),
            "namespaces": nss,
            "templateUses": demand,
            "exampleApps": max([usage.get("exampleApps", {}).get(k, 0) for k in keys] or [0]),
            "probes": len({p for k in keys for p in services[k]["probes"]}),
            "operations": len({o for k in keys for o in services[k]["operations"]}),
            "knownTypes": known,  # types the engine knows in that namespace (plan-only or refused)
        })
    out.sort(key=lambda g: (-g["templateUses"], -g["exampleApps"], -g["probes"], -g["operations"], g["service"]))
    for i, g in enumerate(out, 1):
        g["rank"] = i
    # the other direction of demand: types the in-repo templates use that no stack can create here
    undeployable = sorted(((n, t) for t, n in usage["uses"].items()
                           if not (rows.get(t) or {}).get("deployable") and not (rows.get(t) or {}).get("flattened")),
                          key=lambda x: (-x[0], x[1]))
    return {"services": out, "undeployableUses": [{"type": t, "templateUses": n,
                                                     "status": (rows.get(t) or {}).get("status", "unknown")}
                                                    for n, t in undeployable],
            "sources": usage["files"]}


def write_registry(reg, root=ROOT):
    return json.dumps(reg, indent=2, sort_keys=True) + "\n"


# ------------------------------------------------------------------------------- docs claims, checked

_TABLE_TYPES = re.compile(r"`(AWS::[A-Za-z0-9]+::[A-Za-z0-9]+)`")


def _section_rows(text, heading):
    """The table rows (split into cells) of the first table under `heading`."""
    i = text.find("\n" + heading + "\n")
    if i < 0:
        return None
    rows, in_table = [], False
    for line in text[i + len(heading) + 2:].splitlines():
        if line.startswith("#"):
            break
        if line.startswith("|"):
            in_table = True
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells and not set(cells[0]) <= set("-: "):
                rows.append(cells)
        elif in_table and line.strip() == "":
            break
    return rows[1:]  # drop the header


def check_cfn_doc_claims(text, rows):
    """docs/cloudformation.md's hand-written tables may not claim more than the code does: a type in the
    Supported table is supported, one in the Partial table maps, and one in the create-translators table
    is create-deployable (unless that row says it is refused)."""
    errs = []
    claims = [
        ("### Supported — a faithful backing kind", lambda r, cells: r["status"] == "supported", "supported"),
        ("### Partial — a backing kind exists, but the mapping is lossy",
         lambda r, cells: r["status"] in ("supported", "partial"), "mappable (supported or partial)"),
        ("Today's create translators (live-verified on the cluster):",
         lambda r, cells: r["deployable"] or any(c.startswith("**Refused**") for c in cells[2:3]) or cells[1:2] == ["—"],
         "create-deployable"),
    ]
    for heading, ok, what in claims:
        trs = _section_rows(text, heading)
        if trs is None:
            errs.append(f"docs/cloudformation.md: section {heading!r} not found (the claims check reads it)")
            continue
        for cells in trs:
            for t in _TABLE_TYPES.findall(cells[0]):
                r = rows.get(t)
                if r is None:
                    errs.append(f"docs/cloudformation.md {heading!r}: lists {t}, which the cfn engine does not know")
                elif not ok(r, cells):
                    errs.append(f"docs/cloudformation.md {heading!r}: lists {t} as {what}, but the code says "
                                f"status={r['status']} deployable={r['deployable']}")
    return errs


# ---------------------------------------------------------------------------------------------- render

BREADTH_BASIS = (
    "**Ranking basis.** A service ranks higher the more the in-repo CloudFormation templates use its resource "
    "types (every `Type: AWS::…` in `cfn/testdata/`, `examples/` and the probes' stacks — {sources}), then "
    "the more example apps under `examples/` call its API (an SDK client or a CLI command; each app counts "
    "once), then the more probes prove it, then the more operations it serves (how much of the API a "
    "resource type would make reachable). Only the repository's own fixtures are counted, never usage data "
    "from a deployment, so treat the order as a starting point that real usage refines, not as the verdict.")


def _code(xs):
    return ", ".join(f"`{x}`" for x in xs) if xs else "—"


def render_coverage_summary(reg):
    s = reg["summary"]
    nested = (", and the nested stack, which is inlined into its parent before planning" if s["flattened"] else "")
    return (
        f"The cfn engine knows **{s['cfnTypes']}** CloudFormation resource types: **{s['deployable']}** a stack can "
        f"create, {s['planOnly']} that plan maps but cannot create, {s['refused']} it refuses{nested}. Of the "
        f"{s['deployable']} a stack can create, **{s['covered']}** are served by their own API's front door here, "
        f"with a call that reads them; **{s['excepted']}** are listed exceptions — {s['excFrontDoor']} whose API "
        f"has no front door yet, {s['excRead']} whose front door serves no call that reads them — each with its "
        f"reason. The aws-shim router serves **{s['services']}** services under {s['signingNames']} signing names, "
        f"**{s['operations']}** operations in all.")


def render_coverage_gate(reg):
    groups = {}
    for t, r in reg["types"].items():
        if r["verdict"] == "excepted":
            e = r["exception"]
            groups.setdefault((e["check"], e["reason"], e["issue"]), []).append(t)
    if not groups:
        return "No exceptions: every type a stack can create is served by its own API's front door."
    lines = ["| Types | Gap | Why a stack may still create it | Tracked |", "|---|---|---|---|"]
    for (check, reason, issue), ts in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[1])):
        gap = "no front door for its API" if check == "front-door" else "no call that reads it"
        lines.append(f"| {_code(sorted(ts))} | {gap} | {reason} | {issue} |")
    return "\n".join(lines)


def render_coverage_types(reg):
    lines = ["| CloudFormation type | Plan | Stack can create | Front door | Calls that read it | Stack probe |",
             "|---|---|---|---|---|---|"]
    for t, r in reg["types"].items():
        create = "yes" if r["deployable"] else "no"
        if r["verdict"] == "excepted":
            create += " (exception)"
        door = _code(r["frontDoor"]) if r["frontDoor"] else ("none" if r["deployable"] else "—")
        plan = "nested stack, inlined into its parent" if r["flattened"] else r["status"]
        lines.append(f"| `{t}` | {plan} | {create} | {door} | {_code(r['readCalls'])} | {_code(r['stackProbes'])} |")
    return "\n".join(lines)


def render_coverage_breadth(reg):
    b = reg["breadth"]
    srcs = ", ".join(f"{n} file{'s' if n != 1 else ''} under `{k}`" for k, n in sorted(b["sources"].items())) or "none found"
    out = [BREADTH_BASIS.format(sources=srcs), ""]
    if b["services"]:
        out += ["| Rank | Service | Signing name | Template uses | Example apps | Probes | Operations served | "
                "Types the engine knows there |",
                "|---|---|---|---|---|---|---|---|"]
        for g in b["services"]:
            out.append(f"| {g['rank']} | {g['service']} | {_code(g['signingNames'])} | {g['templateUses']} | "
                       f"{g['exampleApps']} | {g['probes']} | {g['operations']} | "
                       f"{_code(g['knownTypes']) if g['knownTypes'] else 'none'} |")
    else:
        out.append("Every service the shim serves has at least one CloudFormation type a stack can create.")
    if b["undeployableUses"]:
        out += ["", "The other side of the same demand — types the in-repo templates use that no stack can create "
                "here (plan-only or refused), most used first:", "",
                "| CloudFormation type | Template uses | Plan |", "|---|---|---|"]
        for u in b["undeployableUses"]:
            out.append(f"| `{u['type']}` | {u['templateUses']} | {u['status']} |")
    return "\n".join(out)


def render_cfn_namespaces(reg):
    by_ns = {}
    for t, r in reg["types"].items():
        by_ns.setdefault(r["namespace"], []).append((t, r))
    lines = ["| Namespace | A stack can create | Plan maps, cannot create | Refused | Front door here |",
             "|---|---|---|---|---|"]
    for ns in sorted(by_ns):
        ts = by_ns[ns]
        dep = sum(1 for _, r in ts if r["deployable"])
        plan_only = sum(1 for _, r in ts if not r["deployable"] and r["status"] in ("supported", "partial"))
        refused = sum(1 for _, r in ts if r["status"] in ("unsupported", "gated") and not r["flattened"])
        doors = sorted({k for _, r in ts for k in r["frontDoor"]})
        lines.append(f"| `{ns}` | {dep} | {plan_only} | {refused} | {_code(doors) if doors else 'none'} |")
    return "\n".join(lines)


def render_shim_operations(reg):
    lines = ["| Service | Signing name | Operations served | Types a stack creates for it |", "|---|---|---|---|"]
    for k, s in reg["services"].items():
        ops = s["operations"]
        extra = [a for a in s["actions"] if a.partition(":")[2] not in ops]
        parts = [f"{len(ops)}: " + ", ".join(ops)] if ops else []
        if extra:
            parts.append(("authorizes " if ops else "no named operations; authorizes ") +
                         ", ".join(f"`{a}`" for a in extra))
        if s["refused"]:
            parts.append("recognized and refused: " + ", ".join(s["refused"]))
        cell = "; ".join(parts) or "—"
        lines.append(f"| {s['service'] or '?'} | `{k}` | {cell} | {len(s['deployableTypes'])} |")
    return "\n".join(lines)


def render_readme_coverage(reg):
    s = reg["summary"]
    return (f"**CloudFormation ⇄ front doors:** of the {s['cfnTypes']} resource types the `cfn` engine knows, a stack "
            f"can create {s['deployable']}; {s['covered']} of those are served by their own API's front door with a "
            f"call that reads them, and the other {s['excepted']} are listed exceptions with their reasons. CI fails "
            f"when a type a stack can create has no front door for its own API — the full registry, the exceptions "
            f"and the breadth gaps are in [`docs/aws-coverage.md`](docs/aws-coverage.md).")
