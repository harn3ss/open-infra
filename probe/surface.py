"""The customer surface: every capability a customer can reach, each with its AWS-shaped registry entry.

probe/shimgen.py (the one generator and drift gate for the AWS coverage registry) imports this module. It
joins what the code says a customer can reach —

  platform/**/*.yaml                    the claim kinds (XRDs and CRDs) and each one's spec fields
  probe/registry/iam-actions.json       the kinds table: each kind's AWS service, resource type, ARN, and
                                        the IAM action each verb and field change is
                                        (console-api/internal/awsaction, go test)
  probe/registry/console-routes.json    every console API route with its IAM action and resource ARN
                                        (console-api/cmd/server, go test)
  ui/src/router.tsx + nav-items.ts      the console's screens, and the service each belongs to
  probe/registry/shim-router.json       the aws-shim's AWS services and operations
  probe/shim-services.yaml              each AWS service's proof

— with the few hand-kept rulings in probe/registry/surface.yaml, into probe/registry/customer-surface.json
and the inventory docs/customer-surface.md. Each capability is one of

  aws       AWS-shaped: an AWS service's action on an AWS ARN, as AWS names them;
  extra     a platform extra with its own AWS-style API (openinfra:<Action>), on the operator's say-so;
  operator  the platform operator's alone (openinfra-operator:<Action>; never a tenant's);
  removed   withdrawn from the customer surface.

The gate (errors()) fails when a customer-reachable capability has no AWS-shaped entry: a claim kind with
no row in the kinds table, an openinfra:* kind or route the operator has not approved, a console route
whose AWS action AWS does not document, a screen that belongs to no service, a spec field in Kubernetes
vocabulary with no disposition — and when a ruling in surface.yaml no longer matches the code. With
--check, shimgen also names each capability the committed registry does not list yet.

Python 3 stdlib + PyYAML (as the rest of shimgen).
"""
import glob
import json
import os
import re

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))

CLASSES = ("aws", "extra", "operator", "removed")
EXTRA_PREFIX = "openinfra"
OPERATOR_PREFIX = "openinfra-operator"
PLATFORM_GROUPS = ("openinfra.dev", "iam.openinfra.dev")  # the groups the kinds table maps
VERBS = ("get", "list", "create", "update", "delete")

# A spec field whose name is Kubernetes vocabulary: a customer would have to know Kubernetes to use it.
KUBERNETES_FIELD = re.compile(
    r"[nN]amespace|storageClass|^node(Selector|Name|IP|Affinity)|[sS]ecretRef$|serviceAccount|runtimeClass|"
    r"toleration|affinity|^pod|kube|helm|crossplane|composition|providerConfig|configMap|annotation|"
    r"^labels$|labelSelector|hostNetwork|privileged")
DISPOSITIONS = ("extra", "operator", "pending")

SURFACE_JSON = os.path.join(HERE, "registry", "customer-surface.json")


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


# ---------------------------------------------------------------------------------------------- inputs

def platform_kinds(root):
    """Every XRD claim kind and CRD kind in an openinfra API group under platform/, with its spec fields.
    Returns {kind: {group, plural, fields, file, claim}}; claim=False for a composite-only XRD (no claim:
    nothing a customer creates in an account)."""
    out = {}
    for p in sorted(glob.glob(os.path.join(root, "platform", "**", "*.yaml"), recursive=True)):
        for doc in re.split(r"(?m)^---\s*$", read_text(p)):
            try:
                d = yaml.safe_load(doc)
            except yaml.YAMLError:
                continue
            if not isinstance(d, dict) or d.get("kind") not in ("CompositeResourceDefinition", "CustomResourceDefinition"):
                continue
            spec = d.get("spec") or {}
            group = spec.get("group") or ""
            if group != "openinfra.dev" and not group.endswith(".openinfra.dev"):
                continue
            names = spec.get("names") or {}
            kind, plural, claim = names.get("kind"), names.get("plural"), True
            if d["kind"] == "CompositeResourceDefinition":
                cn = spec.get("claimNames")
                if cn:
                    kind, plural = cn.get("kind"), cn.get("plural")
                else:
                    claim = False
            fields = set()
            for v in spec.get("versions") or []:
                props = ((((v.get("schema") or {}).get("openAPIV3Schema") or {}).get("properties") or {})
                         .get("spec") or {}).get("properties") or {}
                fields.update(props)
            out[kind] = {"group": group, "plural": plural, "fields": sorted(fields),
                         "file": os.path.relpath(p, root), "claim": claim}
    return out


def router_screens(text):
    """The console's screens: every path router.tsx registers."""
    return sorted(set(re.findall(r"""\bpath:\s*["'](/[^"']*)["']""", text)))


def _objects(text):
    """The top-level {...} object literals of an array literal's text (brace-matched; strings skipped)."""
    out, depth, start, i, q = [], 0, None, 0, None
    while i < len(text):
        c = text[i]
        if q:
            if c == "\\":
                i += 1
            elif c == q:
                q = None
        elif c in "\"'`":
            q = c
        elif c == "/" and text[i:i + 2] == "//":
            j = text.find("\n", i)
            i = len(text) if j < 0 else j
            continue
        elif c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                out.append(text[start:i + 1])
        i += 1
    return out


def _str(obj, key):
    m = re.search(r"\b" + key + r"""\s*:\s*["']([^"']*)["']""", obj)
    return m.group(1) if m else None


def nav_services(text):
    """The console's service catalog (nav-items.ts SERVICES): each service's label, landing route, sub-nav
    leaves, extra route prefixes and capability gate."""
    m = re.search(r"export const SERVICES[^=]*=\s*\[", text)
    if not m:
        return []
    body = text[m.end():]
    end = re.search(r"(?m)^\];", body)
    body = body[:end.start()] if end else body
    out = []
    for obj in _objects(body):
        children_txt, own = "", obj
        cm = re.search(r"\bchildren\s*:\s*\[", obj)
        if cm:
            depth, j = 1, cm.end()
            while j < len(obj) and depth:
                depth += {"[": 1, "]": -1}.get(obj[j], 0)
                j += 1
            children_txt = obj[cm.end():j - 1]
            own = obj[:cm.start()] + obj[j:]
        prefixes = []
        pm = re.search(r"\brouteprefixes\s*:\s*\[([^\]]*)\]", own, re.I)
        if pm:
            prefixes = re.findall(r"""["'](/[^"']*)["']""", pm.group(1))
        out.append({
            "label": _str(own, "label"), "to": _str(own, "to"), "requires": _str(own, "requires"),
            "flag": _str(own, "flag"), "routePrefixes": prefixes,
            "children": [{"label": _str(c, "label"), "to": _str(c, "to")} for c in _objects(children_txt)],
        })
    return out


def _match_len(path, to):
    if to == "/":
        return 1 if path == "/" else -1
    if path == to or path.startswith(to + "/"):
        return len(to)
    return -1


def screen_service(path, nav):
    """The nav service (and sub-nav leaf) a screen belongs to, as the console resolves it (serviceForPath,
    leafForPath): the longest matching anchor. Returns (key, service) or (None, None)."""
    best, best_len = None, -1
    for s in nav:
        for anchor in [s["to"]] + [c["to"] for c in s["children"]] + s["routePrefixes"]:
            if not anchor:
                continue
            n = _match_len(path, anchor)
            if n > best_len:
                best, best_len = s, n
    if best is None:
        return None, None
    key = best["label"]
    if best["children"]:
        leaf, leaf_len = None, -1
        for c in best["children"]:
            n = _match_len(path, c["to"] or "")
            if n > leaf_len:
                leaf, leaf_len = c, n
        if leaf is not None and leaf_len >= 0 and leaf["label"] != best["label"]:
            key = best["label"] + " / " + leaf["label"]
    return key, best


def documented_actions(root):
    path = os.path.join(root, "console-api", "internal", "awsaction", "testdata", "aws-actions.txt")
    return {l.strip() for l in read_text(path).splitlines() if l.strip() and not l.startswith("#")}


def load_inputs(root=ROOT):
    reg = os.path.join(root, "probe", "registry")
    ui = os.path.join(root, "ui", "src")
    return {
        "xrds": platform_kinds(root),
        "kinds": json.loads(read_text(os.path.join(reg, "iam-actions.json")))["kinds"],
        "routes": json.loads(read_text(os.path.join(reg, "console-routes.json"))),
        "screens": router_screens(read_text(os.path.join(ui, "router.tsx"))),
        "nav": nav_services(read_text(os.path.join(ui, "components", "layout", "nav-items.ts"))),
        "shim": json.loads(read_text(os.path.join(reg, "shim-router.json")))["services"],
        "services": yaml.safe_load(read_text(os.path.join(root, "probe", "shim-services.yaml")))["services"],
        "documented": documented_actions(root),
        "facts": yaml.safe_load(read_text(os.path.join(reg, "surface.yaml"))) or {},
    }


# ----------------------------------------------------------------------------------------------- build

def prefix_of(action):
    return action.partition(":")[0]


def class_of_action(action):
    p = prefix_of(action)
    if p == OPERATOR_PREFIX:
        return "operator"
    if p == EXTRA_PREFIX:
        return "extra"
    return "aws"


def field_actions(entry, field):
    """The IAM actions changing one top-level spec field takes: its own rule, else the kind's update."""
    rule = (entry.get("fieldActions") or {}).get(field)
    if not rule:
        return [entry["actions"]["update"]], "update"
    acts = list(rule.get("actions") or [])
    for vs in (rule.get("byValue") or {}).values():
        acts += vs
    return sorted(set(acts)), "field"


def build(inp):
    """Join the inputs into the customer surface. Returns (surface, errors)."""
    facts = inp["facts"]
    xrds, table, documented = inp["xrds"], inp["kinds"], inp["documented"]
    extras = facts.get("extras") or {}
    extra_kinds = extras.get("kinds") or {}
    extra_actions = extras.get("actions") or {}
    operator_kinds = facts.get("operatorKinds") or {}
    removed = facts.get("removed") or []
    kube_fields = facts.get("kubernetesFields") or {}
    per_request = facts.get("perRequest") or {}
    screen_facts = facts.get("screens") or {}
    errs = []

    def need_reason(where, entry, *keys):
        for k in keys:
            if not (entry or {}).get(k):
                errs.append(f"surface.yaml {where}: needs {k!r}")

    # --- claim kinds ---------------------------------------------------------------------------------
    kinds = {}
    for k, x in sorted(xrds.items()):
        if x["group"] in PLATFORM_GROUPS and x["claim"]:
            e = table.get(k)
            if e is None:
                errs.append(f"kind {k} ({x['file']}) is customer-reachable but has no row in the kinds table "
                            f"(console-api/internal/awsaction): map it to its AWS service, resource type, ARN and actions, "
                            f"or to openinfra: with the operator's approval in probe/registry/surface.yaml")
                continue
            cls = class_of_action(e["actions"]["create"])
            row = {"class": cls, "group": e["group"], "resource": e["resource"], "service": e["service"],
                   "resourceType": e["resourceType"], "arn": e["arn"], "cfnType": e.get("cfnType", ""),
                   "actions": {v: e["actions"].get(v, "") for v in VERBS}, "file": x["file"]}
            if cls == "extra":
                ap = extra_kinds.get(k)
                if ap is None:
                    errs.append(f"kind {k} is a platform extra (openinfra:{e['actions']['create'].partition(':')[2]}) with no "
                                f"operator ruling: list it under extras.kinds in probe/registry/surface.yaml (why it has no AWS "
                                f"analog, and the operator's approval), or map it to its AWS analog")
                else:
                    need_reason(f"extras.kinds.{k}", ap, "reason", "approval")
                    row["reason"], row["approval"] = ap.get("reason", ""), ap.get("approval", "")
            elif k in extra_kinds:
                errs.append(f"surface.yaml extras.kinds.{k}: {k} is AWS-shaped now ({e['actions']['create']}) — remove the entry")
            for v in VERBS:
                a = e["actions"].get(v, "")
                if not a:
                    errs.append(f"kind {k}: no IAM action for {v}")
                elif class_of_action(a) == "aws" and a not in documented:
                    errs.append(f"kind {k}: {v} is {a}, which AWS does not document (testdata/aws-actions.txt)")
            kinds[k] = row
        else:
            # A composite-only XRD, or a kind in another openinfra group: not in any account; its Kubernetes
            # object is the operator's (openinfra-operator:*). What customers reach of it is an AWS API.
            ap = operator_kinds.get(k)
            if ap is None:
                errs.append(f"kind {k} ({x['group']}, {x['file']}) is not in the kinds table: list it under operatorKinds in "
                            f"probe/registry/surface.yaml with the AWS API customers reach it through, or give it a claim and a row")
                continue
            need_reason(f"operatorKinds.{k}", ap, "reason")
            kinds[k] = {"class": "operator", "group": x["group"], "resource": x["plural"], "service": OPERATOR_PREFIX,
                        "resourceType": "", "arn": "", "cfnType": "", "actions": {}, "file": x["file"],
                        "reason": ap.get("reason", ""), "via": ap.get("via", "")}
    for k in table:
        if k not in xrds:
            errs.append(f"the kinds table maps {k}, which no XRD or CRD under platform/ defines")
    for k in operator_kinds:
        if k not in xrds:
            errs.append(f"surface.yaml operatorKinds.{k}: no XRD or CRD defines it — remove the entry")
        elif xrds[k]["group"] in PLATFORM_GROUPS and xrds[k]["claim"]:
            errs.append(f"surface.yaml operatorKinds.{k}: it is a claim kind in the kinds table — remove the entry")
    for k in extra_kinds:
        if k not in table:
            errs.append(f"surface.yaml extras.kinds.{k}: not a kind the table maps — remove the entry")

    # --- claim fields --------------------------------------------------------------------------------
    fields = {}
    for k, row in kinds.items():
        if k not in table:
            continue
        e = table[k]
        for f in xrds[k]["fields"]:
            acts, how = field_actions(e, f)
            frow = {"class": row["class"], "kind": k, "field": f, "actions": acts, "how": how}
            key = f"{k}.{f}"
            if KUBERNETES_FIELD.search(f):
                d = kube_fields.get(key)
                if d is None:
                    errs.append(f"{k} spec.{f} is Kubernetes vocabulary on a customer surface: give it an AWS name, or list it "
                                f"under kubernetesFields in probe/registry/surface.yaml with its disposition "
                                f"({'|'.join(DISPOSITIONS)}) and why")
                else:
                    need_reason(f"kubernetesFields.{key}", d, "disposition", "reason")
                    if d.get("disposition") and d["disposition"] not in DISPOSITIONS:
                        errs.append(f"surface.yaml kubernetesFields.{key}: disposition must be one of {', '.join(DISPOSITIONS)}")
                    frow["kubernetes"] = {"disposition": d.get("disposition", ""), "reason": d.get("reason", "")}
                    if d.get("disposition") == "operator":
                        frow["class"] = "operator"
                    elif d.get("disposition") in ("extra", "pending") and row["class"] == "aws":
                        frow["class"] = "extra"
            for a in acts:
                if class_of_action(a) == "aws" and a not in documented:
                    errs.append(f"{k} spec.{f}: a change is {a}, which AWS does not document (testdata/aws-actions.txt)")
            fields[key] = frow
    for key in kube_fields:
        k, _, f = key.partition(".")
        if key not in fields:
            errs.append(f"surface.yaml kubernetesFields.{key}: {k} has no spec.{f} — remove the entry")
        elif not KUBERNETES_FIELD.search(f):
            errs.append(f"surface.yaml kubernetesFields.{key}: not Kubernetes vocabulary — remove the entry")

    # --- console routes ------------------------------------------------------------------------------
    approved_extra_nouns = {a.partition(":")[2] for k in extra_kinds if k in table
                            for a in table[k]["actions"].values()}
    routes = {}
    for r in inp["routes"]["routes"]:
        key = f"{r['method']} {r['path']}"
        a = r["action"]
        cls = class_of_action(a)
        row = {"class": cls, "action": a, "resource": r.get("resource", "*")}
        if cls == "aws" and a not in documented:
            errs.append(f"console route {key}: {a} is not an action AWS documents (console-api/internal/awsaction/testdata/"
                        f"aws-actions.txt, from AWS's Service Authorization Reference): name the AWS API call it is")
        if cls == "extra" and a.partition(":")[2] not in approved_extra_nouns and a not in extra_actions:
            errs.append(f"console route {key}: {a} is a platform extra with no operator ruling: list it under extras.actions "
                        f"in probe/registry/surface.yaml, or name the AWS API call it is")
        routes[key] = row
    for a in extra_actions:
        if not any(r["action"] == a for r in inp["routes"]["routes"]):
            errs.append(f"surface.yaml extras.actions.{a}: no console route is decided on it — remove the entry")
        need_reason(f"extras.actions.{a}", extra_actions[a], "reason", "approval")
    seen_pr = set()
    for r in inp["routes"]["perRequest"]:
        path = r["path"]
        seen_pr.add(path)
        f = per_request.get(path)
        if f is None:
            errs.append(f"console route {r['method']} {path} decides its IAM action per request ({r['decided']}) but "
                        f"probe/registry/surface.yaml perRequest does not say how it is AWS-shaped")
            continue
        need_reason(f"perRequest.{path}", f, "class", "how")
        if f.get("class") and f["class"] not in CLASSES:
            errs.append(f"surface.yaml perRequest.{path}: class must be one of {', '.join(CLASSES)}")
        routes.setdefault(f"* {path}", {"class": f.get("class", ""), "action": r["decided"], "resource": "per request",
                                        "how": f.get("how", ""), "methods": []})
        routes[f"* {path}"]["methods"].append(r["method"])
    for path in per_request:
        if path not in seen_pr:
            errs.append(f"surface.yaml perRequest.{path}: the console serves no such per-request route — remove the entry")
    for r in inp["routes"]["public"]:
        routes[f"{r['method']} {r['path']}"] = {"class": "aws", "public": True, "action": "", "resource": "",
                                                "reason": r["reason"]}

    # --- console screens -----------------------------------------------------------------------------
    nav = inp["nav"]
    known = {e["service"] for e in table.values()} | {prefix_of(r["action"]) for r in inp["routes"]["routes"]}
    for svc in inp["shim"].values():
        known |= {prefix_of(a) for a in svc.get("actions") or []}
    screens, used = {}, set()
    for path in inp["screens"]:
        key, svc = screen_service(path, nav)
        if path in screen_facts:
            key = path  # a screen named on its own (the home dashboard) rather than by its service
        f = screen_facts.get(key) if key else None
        if f is None:
            errs.append(f"console screen {path} (nav: {key or 'none'}) has no entry in probe/registry/surface.yaml screens: "
                        f"name the AWS service it is (its IAM prefix), or mark it operator")
            continue
        used.add(key)
        cls = f.get("class", "aws")
        service = f.get("service") or []
        service = [service] if isinstance(service, str) else list(service)
        if cls not in CLASSES:
            errs.append(f"surface.yaml screens.{key}: class must be one of {', '.join(CLASSES)}")
        if cls in ("aws", "extra"):
            if not service and not f.get("reason"):
                errs.append(f"surface.yaml screens.{key}: an {cls} screen names its service (the IAM prefix of its actions)")
            for sv in service:
                if sv not in known:
                    errs.append(f"console screen {path} ({key}): service {sv!r} has no actions anywhere in the registry "
                                f"(kinds, console routes, aws-shim) — the screen is not AWS-shaped")
                elif (sv == EXTRA_PREFIX) != (cls == "extra"):
                    errs.append(f"surface.yaml screens.{key}: service {sv} and class {cls} disagree")
        gated = bool(svc and svc.get("requires") == "operator")
        if cls == "operator" and not gated:
            errs.append(f"console screen {path} ({key}) is classified operator but the console shows it to everyone "
                        f"(nav-items.ts: add requires: \"operator\")")
        if gated and cls != "operator":
            errs.append(f"console screen {path} ({key}) is the operator's in the console (requires: \"operator\") but "
                        f"surface.yaml classifies it {cls}")
        screens[path] = {"class": cls, "nav": key, "service": service, "flag": (svc or {}).get("flag") or "",
                         "reason": f.get("reason", "")}
    for key in screen_facts:
        if key not in used:
            errs.append(f"surface.yaml screens.{key}: no console screen belongs to it — remove the entry")

    # --- the AWS APIs --------------------------------------------------------------------------------
    by_key = {}
    for s in inp["services"]:
        for k in s.get("sigv4") or []:
            by_key[k] = s
    services = {}
    for k, s in sorted(inp["shim"].items()):
        entry = by_key.get(k) or {}
        services[k] = {"class": "aws", "service": entry.get("name", ""), "tier": entry.get("tier", ""),
                       "operations": len(s.get("operations") or []), "actions": len(s.get("actions") or [])}

    # --- removed -------------------------------------------------------------------------------------
    present = set(kinds) | set(fields) | set(routes) | set(screens) | set(services)
    for i, rm in enumerate(removed):
        need_reason(f"removed[{i}]", rm, "capability", "reason")
        if rm.get("capability") in present:
            errs.append(f"surface.yaml removed[{i}]: {rm['capability']} is listed removed but is still reachable")

    surf = {
        "generatedBy": "probe/shimgen.py (probe/surface.py) from platform/, probe/registry/iam-actions.json, "
                       "probe/registry/console-routes.json, ui/src/router.tsx, ui/src/components/layout/nav-items.ts, "
                       "probe/registry/shim-router.json, probe/shim-services.yaml and probe/registry/surface.yaml",
        "kinds": kinds, "fields": fields, "routes": routes, "screens": screens, "services": services,
        "removed": removed,
    }
    surf["summary"] = summarize(surf)
    return surf, errs


def summarize(surf):
    out = {}
    for section in ("kinds", "fields", "routes", "screens", "services"):
        c = {cls: 0 for cls in CLASSES}
        for row in surf[section].values():
            c[row["class"]] = c.get(row["class"], 0) + 1
        c["removed"] += sum(1 for rm in surf["removed"] if rm.get("section") == section)
        c["total"] = sum(c[cls] for cls in CLASSES)
        out[section] = c
    out["publicRoutes"] = sum(1 for r in surf["routes"].values() if r.get("public"))
    out["pendingKubernetesFields"] = sum(1 for f in surf["fields"].values()
                                         if (f.get("kubernetes") or {}).get("disposition") == "pending")
    out["pendingExtras"] = sum(1 for k in surf["kinds"].values() if k.get("approval") == "pending")
    return out


def write(surf):
    return json.dumps(surf, indent=2, sort_keys=True) + "\n"


def unregistered(surf, committed_text):
    """The capabilities the code reaches that the committed registry does not list (or lists differently),
    and the ones it lists that the code no longer reaches — named one by one, so a drift says WHICH
    capability is unregistered rather than only that a file is stale."""
    try:
        old = json.loads(committed_text) if committed_text else {}
    except ValueError:
        old = {}
    out = []
    names = {"kinds": "kind", "fields": "claim field", "routes": "console route", "screens": "console screen",
             "services": "AWS service"}
    for section, what in names.items():
        cur, prev = surf.get(section) or {}, old.get(section) or {}
        for k in sorted(set(cur) - set(prev)):
            row = cur[k]
            svc, acts = row.get("service") or "", row.get("actions") or []
            if isinstance(acts, dict):
                acts = [acts[v] for v in VERBS if acts.get(v)]
            how = row.get("action") or ", ".join(acts) or (", ".join(svc) if isinstance(svc, list) else svc)
            out.append(f"{what} {k}: reachable but not in the committed registry (it registers as {row['class']}"
                       f"{': ' + how if how else ''})")
        for k in sorted(set(prev) - set(cur)):
            out.append(f"{what} {k}: in the committed registry but no longer reachable")
        for k in sorted(set(cur) & set(prev)):
            if cur[k] != prev[k]:
                out.append(f"{what} {k}: its registry entry changed")
    return out


# ---------------------------------------------------------------------------------------------- render

CLASS_LABEL = {"aws": "AWS-shaped", "extra": "platform extra", "operator": "operator-only", "removed": "removed"}


def _code(xs):
    return ", ".join(f"`{x}`" for x in xs) if xs else "—"


def render_summary(surf):
    s = surf["summary"]
    rows = ["| Capability | AWS-shaped | Platform extra (own API) | Operator-only | Removed | Total |",
            "|---|---|---|---|---|---|"]
    names = [("kinds", "Resource types (claim kinds)"), ("fields", "Resource properties (spec fields)"),
             ("routes", "Console API routes"), ("screens", "Console screens"), ("services", "AWS APIs (signing names)")]
    for sec, label in names:
        c = s[sec]
        rows.append(f"| {label} | {c['aws']} | {c['extra']} | {c['operator']} | {c['removed']} | {c['total']} |")
    tot = {cls: sum(s[sec][cls] for sec, _ in names) for cls in CLASSES}
    rows.append(f"| **All** | **{tot['aws']}** | **{tot['extra']}** | **{tot['operator']}** | **{tot['removed']}** | "
                f"**{sum(tot.values())}** |")
    rows += ["", f"{s['publicRoutes']} of the console routes need no authorization (sign-in, sign-out, who-am-I, the "
                 f"console's own configuration), as AWS's sign-in and console metadata need none. "
                 f"{s['pendingExtras']} platform extras and {s['pendingKubernetesFields']} properties in Kubernetes "
                 f"vocabulary await the operator's ruling (below)."]
    return "\n".join(rows)


def render_kinds(surf):
    lines = ["| Resource type | Class | Service | AWS resource | ARN | Create · Read · List · Update · Delete |",
             "|---|---|---|---|---|---|"]
    for k, r in sorted(surf["kinds"].items()):
        if r["class"] == "operator":
            via = f" Customers reach it through {r['via']}." if r.get("via") else ""
            lines.append(f"| `{k}` | {CLASS_LABEL['operator']} | — | — | — | {r.get('reason', '')}{via} |")
            continue
        a = r["actions"]
        acts = " · ".join(f"`{a[v]}`" for v in ("create", "get", "list", "update", "delete"))
        res = r["resourceType"] + (f" (`{r['cfnType']}`)" if r["cfnType"] else "")
        lines.append(f"| `{k}` | {CLASS_LABEL[r['class']]} | `{r['service']}` | {res} | `{r['arn']}` | {acts} |")
    return "\n".join(lines)


def render_fields(surf):
    by_kind = {}
    for f in surf["fields"].values():
        by_kind.setdefault(f["kind"], []).append(f)
    lines = ["| Resource type | Properties | Changing one is |", "|---|---|---|"]
    for k in sorted(by_kind):
        fs = sorted(by_kind[k], key=lambda f: f["field"])
        upd = [f["field"] for f in fs if f["how"] == "update"]
        own = [f for f in fs if f["how"] == "field"]
        parts = []
        if upd:
            parts.append(f"{', '.join(upd)} → `{surf['kinds'][k]['actions']['update']}`")
        for f in own:
            parts.append(f"{f['field']} → {_code(f['actions'])}")
        lines.append(f"| `{k}` | {len(fs)} | {'; '.join(parts)} |")
    return "\n".join(lines)


def render_kubernetes_fields(surf):
    ks = [f for f in surf["fields"].values() if f.get("kubernetes")]
    if not ks:
        return "None: every property is in AWS's vocabulary."
    lines = ["| Property | Disposition | Why |", "|---|---|---|"]
    for f in sorted(ks, key=lambda f: (f["kind"], f["field"])):
        d = f["kubernetes"]
        label = {"pending": "awaiting the operator's ruling", "extra": "platform extra", "operator": "operator-only"}[d["disposition"]]
        lines.append(f"| `{f['kind']}` `spec.{f['field']}` | {label} | {d['reason']} |")
    return "\n".join(lines)


def render_extras(surf):
    lines = ["| Resource type | Its API | Why it has no AWS analog | Operator's ruling |", "|---|---|---|---|"]
    for k, r in sorted(surf["kinds"].items()):
        if r["class"] != "extra":
            continue
        approval = "awaiting the operator's ruling" if r.get("approval") == "pending" else r.get("approval", "")
        lines.append(f"| `{k}` | `{r['service']}:*` on `{r['arn']}` | {r.get('reason', '')} | {approval} |")
    return "\n".join(lines)


def render_routes(surf):
    lines = ["| Route | Class | IAM action | Resource |", "|---|---|---|---|"]
    fixed = {k: r for k, r in surf["routes"].items() if not r.get("public") and not k.startswith("* ")}
    for k in sorted(fixed, key=lambda k: (k.split(" ", 1)[1], k)):
        r = fixed[k]
        lines.append(f"| `{k}` | {CLASS_LABEL[r['class']]} | `{r['action']}` | `{r['resource']}` |")
    lines += ["", "Decided per request:", "", "| Route | Methods | Class | How |", "|---|---|---|---|"]
    for k, r in sorted(surf["routes"].items()):
        if k.startswith("* "):
            lines.append(f"| `{k[2:]}` | {len(r['methods'])} | {CLASS_LABEL.get(r['class'], r['class'])} | {r['how']} |")
    lines += ["", "No authorization:", "", "| Route | Why |", "|---|---|"]
    for k, r in sorted(surf["routes"].items()):
        if r.get("public"):
            lines.append(f"| `{k}` | {r['reason']} |")
    return "\n".join(lines)


def render_screens(surf):
    by_nav = {}
    for path, s in surf["screens"].items():
        by_nav.setdefault(s["nav"], []).append((path, s))
    lines = ["| Console service | Screens | Class | Service |", "|---|---|---|---|"]
    for nav in sorted(by_nav):
        items = sorted(by_nav[nav])
        s = items[0][1]
        flag = f" (shown when the install enables `{s['flag']}`)" if s["flag"] else ""
        lines.append(f"| {nav} | {_code([p for p, _ in items])} | {CLASS_LABEL[s['class']]}{flag} | "
                     f"{_code(s['service']) if s['service'] else s['reason'] or '—'} |")
    return "\n".join(lines)


def render_services(surf):
    lines = ["| AWS API | Signing name | Proof | Operations |", "|---|---|---|---|"]
    for k, s in sorted(surf["services"].items(), key=lambda kv: (kv[1]["service"], kv[0])):
        lines.append(f"| {s['service']} | `{k}` | {s['tier']} | {s['operations']} |")
    return "\n".join(lines)


def render_removed(surf):
    if not surf["removed"]:
        return "Nothing has been withdrawn from the customer surface."
    lines = ["| Capability | Why | Instead |", "|---|---|---|"]
    for rm in surf["removed"]:
        lines.append(f"| {rm['capability']} | {rm['reason']} | {rm.get('instead', '—')} |")
    return "\n".join(lines)


BLOCKS = [
    ("surface-summary", render_summary),
    ("surface-extras", render_extras),
    ("surface-kubernetes-fields", render_kubernetes_fields),
    ("surface-kinds", render_kinds),
    ("surface-fields", render_fields),
    ("surface-routes", render_routes),
    ("surface-screens", render_screens),
    ("surface-services", render_services),
    ("surface-removed", render_removed),
]
