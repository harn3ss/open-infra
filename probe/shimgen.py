#!/usr/bin/env python3
"""Generate the aws-shim service list + count in README.md and docs/aws-shim.md from the single
source of truth, probe/shim-services.yaml, cross-checked against the probe/ directory — and the AWS
coverage registry (probe/coverage.py): CloudFormation resource types joined with the shim's front doors.

The list and count used to be hand-typed in two places and drifted — a service could be built AND
probe-proven yet still documented as "not fronted" (the EKS bug). Now the docs are rendered from the
registry, and --check fails CI if the committed docs are stale OR the registry disagrees with the
filesystem. Same shape as docs/openapi/generate.py and tools/chaosdoc: one source, generated output,
a drift gate.

The coverage registry's two halves are read from code by Go tests (cfn/coverage_registry_test.go and
console-api/cmd/aws-shim/coverage_registry_test.go), which keep probe/registry/cfn-types.json and
probe/registry/shim-router.json current — their CI jobs fail when either is stale. This script joins
them into probe/registry/registry.json and FAILS (both modes) when a CloudFormation type a stack can
create has no front door for its own API, or a front door that serves no call reading it, unless
probe/registry/coverage.yaml excuses it with a reason.

It also builds the customer-surface registry (probe/surface.py): every claim kind, spec field, console
route, console screen and AWS API a customer can reach, each AWS-shaped, a platform extra the operator
approved, or the operator's alone — into probe/registry/customer-surface.json and docs/customer-surface.md,
and FAILS when one has no AWS-shaped entry (with --check, naming each capability the committed registry
does not list yet). And it holds each proven service to a live denial: one of its probes asserts AWS's
access-denied, and the no-policy probe (probe/iam-no-policy.sh) calls every service the router serves.

  probe/shimgen.py            # refresh the Go-read halves (when Go is on PATH), rewrite every generated block
  probe/shimgen.py --no-go    # the same, from the committed halves
  probe/shimgen.py --check    # fail if a generated block, registry.json or customer-surface.json is stale,
                              # the registry ⇄ probe/ ⇄ router drifted, or the coverage or surface gate fails
"""
import glob
import os
import re
import shutil
import subprocess
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
REGISTRY = os.path.join(HERE, "shim-services.yaml")
PROBE_GLOB = os.path.join(HERE, "aws-shim-*.sh")

sys.path.insert(0, HERE)
import coverage  # noqa: E402  (probe/coverage.py)
import surface  # noqa: E402  (probe/surface.py)

_ONES = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
         "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen",
         "nineteen"]
_TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]


def num2word(n):
    """Spell 0..99 for prose; fall back to the digits above that."""
    if n < 20:
        return _ONES[n]
    if n < 100:
        t, o = divmod(n, 10)
        return _TENS[t] + ("-" + _ONES[o] if o else "")
    return str(n)


def load_registry():
    data = yaml.safe_load(open(REGISTRY, encoding="utf-8"))
    return data["services"]


def probe_basenames():
    """Every probe/aws-shim-<name>.sh, as <name>."""
    out = set()
    for p in glob.glob(PROBE_GLOB):
        b = os.path.basename(p)
        out.add(b[len("aws-shim-"):-len(".sh")])
    return out


def validate(services, probes):
    """The registry ⇄ filesystem contract. Returns a list of error strings (empty = OK)."""
    errs = []
    claimed = {}
    for s in services:
        tier = s.get("tier")
        name = s.get("name", "<unnamed>")
        plist = s.get("probes") or []
        # pending: probes written for the service but not yet run live (exit 0) — claimed, so a new probe
        # still needs its registry entry, but never counted as proof: move one to probes once it passes.
        pending = s.get("pending") or []
        if tier not in ("proven", "gated", "planned"):
            errs.append(f"{name}: tier must be proven|gated|planned (got {tier!r})")
        for field, lst in (("probes", plist), ("pending", pending)):
            for pr in lst:
                if pr in claimed:
                    errs.append(f"probe {pr!r} claimed by both {claimed[pr]!r} and {name!r}")
                claimed[pr] = name
                if pr not in probes:
                    errs.append(f"{name}: {field} names {pr!r} but probe/aws-shim-{pr}.sh does not exist")
        if tier == "proven" and not plist:
            errs.append(f"{name}: tier proven but no probe (proven means observed — add a probe or change the tier)")
        if tier in ("gated", "planned") and plist:
            errs.append(f"{name}: tier {tier} must claim no probe (it has one — promote it to proven)")
        if tier == "planned" and pending:
            errs.append(f"{name}: tier planned has no handler for a pending probe to run against")
    # Every probe on disk must be claimed by exactly one service — a NEW probe forces a registry entry.
    for pr in sorted(probes):
        if pr not in claimed:
            errs.append(f"probe/aws-shim-{pr}.sh is not claimed by any service in shim-services.yaml "
                        f"(add it to the service it proves, so the list + count stay honest)")
    return errs


# A probe's denial check: AWS's access-denied error (or the probe library's deny verdict) asserted in a
# line that fails the probe without it — the code before the `fail`, so a fail MESSAGE that mentions a
# denial is not mistaken for a check of one.
DENIAL_RE = re.compile(r"AccessDenied|AuthorizationError|UnauthorizedOperation|NotAuthorized|"
                       r"not authorized to perform|=\s*deny\b")
NO_POLICY_PROBE = os.path.join(HERE, "iam-no-policy.sh")
# The one router service a principal with no policy may call: sts:GetCallerIdentity, as on AWS.
NO_POLICY_ALLOWED = {"sts"}


def denial_checks(text):
    """The line numbers of a probe that assert an access denial."""
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("#"):
            continue
        m = DENIAL_RE.search(s)
        if not m:
            continue
        f = s.find("fail")
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if (0 <= f and m.start() < f) or (f < 0 and s.endswith("\\") and nxt.startswith("|| fail")):
            out.append(i + 1)
    return out


def no_policy_calls(text):
    """The signing names probe/iam-no-policy.sh calls as a principal with no policy (its CALL table)."""
    m = re.search(r"declare -A CALL=\((.*?)\n\)", text, re.S)
    return set(re.findall(r"^\s*\[([a-z0-9-]+)\]=", m.group(1), re.M)) if m else set()


def validate_denials(services, read_probe, router_keys, no_policy_text):
    """Every proven service is proven to DENY, live: one of its probes asserts AWS's access-denied, or the
    service carries `denialPending` — why not yet, shown in the docs — which fails once a probe does. And
    the no-policy probe calls every service the router serves (sts excepted, as AWS excepts
    GetCallerIdentity), so a new front door is denied to a principal with no policy, live, from its first run."""
    errs = []
    for s in services:
        name, pending_why = s.get("name", "<unnamed>"), s.get("denialPending")
        if s.get("tier") != "proven":
            if pending_why:
                errs.append(f"{name}: denialPending on a {s.get('tier')} service (only a proven one is held to a denial)")
            continue
        proving = [p for p in s.get("probes") or [] if denial_checks(read_probe(p))]
        if proving and pending_why:
            errs.append(f"{name}: denialPending, but {', '.join(f'aws-shim-{p}.sh' for p in proving)} asserts a denial "
                        f"now — remove denialPending")
        elif not proving and not pending_why:
            errs.append(f"{name}: proven, but none of its probes asserts a denial (AccessDenied or the service's own "
                        f"access-denied code, before the `|| fail`). Add a denied call to its probe — a principal "
                        f"without the action is refused — or, until that runs live, say why under denialPending")
    calls = no_policy_calls(no_policy_text)
    if not calls:
        errs.append("probe/iam-no-policy.sh: no CALL table found (the no-policy probe calls every service the router serves)")
    for k in sorted(router_keys):
        if k not in calls and k not in NO_POLICY_ALLOWED:
            errs.append(f"the router serves {k!r} but probe/iam-no-policy.sh calls nothing of it: add [{k}]=\"<a "
                        f"read-only call>\" to its CALL table, so a principal with no policy is shown denied there")
    for k in sorted(calls - set(router_keys)):
        errs.append(f"probe/iam-no-policy.sh calls {k!r}, which the router no longer serves — remove it from CALL")
    return errs


def read_probe(name):
    return open(os.path.join(HERE, f"aws-shim-{name}.sh"), encoding="utf-8").read()


def proven(services):
    return [s for s in services if s.get("tier") == "proven"]


def _name(s):
    tag = " (experimental)" if s.get("experimental") else ""
    return f"**{s['name']}**{tag}"


# --- renderers: each returns the INNER text for a marked block ---

def render_readme_matrix(services):
    ps = proven(services)
    n = num2word(len(ps)).capitalize()
    cells = [f"{_name(s)} {s['cell']}" for s in ps]
    # pad to a multiple of 3 for a clean 3-column table
    while len(cells) % 3:
        cells.append("")
    lines = [
        f"**{n} services are fronted, and every one is proven by a real-AWS-SDK compatibility probe** "
        f"(`probe/aws-shim-*.sh`, exit 0 live) — not asserted, observed:",
        "",
        "| | | |",
        "|---|---|---|",
    ]
    for i in range(0, len(cells), 3):
        lines.append("| " + " | ".join(cells[i:i + 3]) + " |")
    return "\n".join(lines)


def render_docs_list(services):
    ps = proven(services)
    n = num2word(len(ps))
    items = ", ".join(f"{_name(s)} {s['cell']}" for s in ps)
    gated = [s for s in services if s.get("tier") == "gated"]
    out = [
        f"**{n.capitalize()} services are fronted and each is proven by a real-AWS-SDK compatibility "
        f"probe** (`probe/aws-shim-*.sh`, exit 0 live): {items}.",
    ]
    for s in gated:
        out.append("")
        out.append(f"**{s['name']} — written but gated.** {s.get('note', s['cell'])}")
    return "\n".join(out)


def render_denials(services):
    """The proven services whose probes do not yet assert a denial, with why (denialPending)."""
    pend = [s for s in proven(services) if s.get("denialPending")]
    head = (f"{len(proven(services)) - len(pend)} of the {len(proven(services))} probe-proven AWS APIs have a probe "
            f"that asserts AWS's access-denied, live; every one the router serves is also called, and must be "
            f"denied, by a principal with no policy (`probe/iam-no-policy.sh`).")
    if not pend:
        return head
    lines = [head + " The rest:", "", "| AWS API | Why its own probe asserts no denial yet |", "|---|---|"]
    for s in pend:
        lines.append(f"| {s['name']} | {s['denialPending']} |")
    return "\n".join(lines)


def render_docs_501(services):
    planned = [s["name"] for s in services if s.get("tier") == "planned"]
    lst = ", ".join(planned)
    return (f"**Still not fronted** (honest `501`, never a silent fake, until built + probed): "
            f"{lst}, and the rest of the AWS surface.")


SRC_SERVICES = "probe/shim-services.yaml"
SRC_COVERAGE = "the coverage registry (probe/registry/)"
SRC_SURFACE = "the customer-surface registry (probe/surface.py, probe/registry/)"

# file -> list of (marker, renderer(services, reg, surface), source). A shim-services block renders the
# proof registry; a coverage block the joined coverage registry; a surface block the customer surface.
TARGETS = {
    os.path.join(ROOT, "README.md"): [
        ("readme-matrix", lambda s, r, x: render_readme_matrix(s), SRC_SERVICES),
        ("readme-coverage", lambda s, r, x: coverage.render_readme_coverage(r), SRC_COVERAGE),
    ],
    os.path.join(ROOT, "docs", "aws-shim.md"): [
        ("docs-list", lambda s, r, x: render_docs_list(s), SRC_SERVICES),
        ("docs-501", lambda s, r, x: render_docs_501(s), SRC_SERVICES),
        ("docs-operations", lambda s, r, x: coverage.render_shim_operations(r), SRC_COVERAGE),
    ],
    os.path.join(ROOT, "docs", "cloudformation.md"): [
        ("cfn-namespaces", lambda s, r, x: coverage.render_cfn_namespaces(r), SRC_COVERAGE),
    ],
    os.path.join(ROOT, "docs", "aws-coverage.md"): [
        ("coverage-summary", lambda s, r, x: coverage.render_coverage_summary(r), SRC_COVERAGE),
        ("coverage-gate", lambda s, r, x: coverage.render_coverage_gate(r), SRC_COVERAGE),
        ("coverage-breadth", lambda s, r, x: coverage.render_coverage_breadth(r), SRC_COVERAGE),
        ("coverage-types", lambda s, r, x: coverage.render_coverage_types(r), SRC_COVERAGE),
    ],
    os.path.join(ROOT, "docs", "customer-surface.md"): [
        (marker, (lambda render: lambda s, r, x: render(x))(render), SRC_SURFACE)
        for marker, render in surface.BLOCKS
    ] + [("surface-denials", lambda s, r, x: render_denials(s), SRC_SERVICES)],
}

REGISTRY_JSON = os.path.join(HERE, "registry", "registry.json")

# The Go tests that read the registry's halves from code (run with UPDATE_REGISTRY=1 to rewrite them):
# (module dir, package, test).
GO_HALVES = [
    ("cfn", ".", "TestCoverageRegistryCFNTypes"),
    ("console-api", "./cmd/aws-shim", "TestCoverageRegistryShimRouter"),
    ("console-api", "./internal/awsaction", "TestIAMActionsRegistryIsCurrent"),
    ("console-api", "./cmd/server", "TestConsoleRouteRegistryIsCurrent"),
]


def apply_block(text, marker, inner, source=SRC_SERVICES):
    begin = (f"<!-- BEGIN shimgen:{marker} — generated by probe/shimgen.py from "
             f"{source}; do not edit -->")
    end = f"<!-- END shimgen:{marker} -->"
    block = f"{begin}\n{inner}\n{end}"
    pat = re.compile(r"<!-- BEGIN shimgen:" + re.escape(marker) + r".*?-->.*?<!-- END shimgen:"
                     + re.escape(marker) + r" -->", re.S)
    if not pat.search(text):
        raise SystemExit(f"marker shimgen:{marker} not found — add the BEGIN/END comment pair to the file")
    return pat.sub(lambda _: block, text)


def refresh_go_halves():
    """Re-read the registry's two halves from code (write mode only). Without Go, the committed halves
    are used — and their own CI jobs fail if those are stale."""
    gobin = shutil.which("go")
    if not gobin:
        print("note: no `go` on PATH — using the committed probe/registry/cfn-types.json, shim-router.json, "
              "iam-actions.json and console-routes.json (the cfn and console-api CI jobs fail if they are stale)")
        return True
    env = dict(os.environ, UPDATE_REGISTRY="1")
    for mod, pkg, test in GO_HALVES:
        r = subprocess.run([gobin, "test", pkg, "-run", "^" + test + "$", "-count=1"], cwd=os.path.join(ROOT, mod),
                           env=env, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL: {mod}: go test -run {test} could not refresh its half of the registry:\n{r.stdout}{r.stderr}")
            return False
    return True


def build_coverage(services):
    """Join the coverage registry; returns (registry, errors)."""
    inp = coverage.load_inputs(ROOT)
    inp["services"] = services
    errs = coverage.validate_sigv4(services, inp["shim"])
    reg, gate = coverage.build(inp)
    errs += gate
    cfn_doc = os.path.join(ROOT, "docs", "cloudformation.md")
    errs += coverage.check_cfn_doc_claims(open(cfn_doc, encoding="utf-8").read(), reg["types"])
    return reg, errs


def main():
    check = "--check" in sys.argv
    services = load_registry()
    errs = validate(services, probe_basenames())
    if errs:
        print("FAIL: probe/shim-services.yaml is inconsistent with probe/:")
        for e in errs:
            print("  - " + e)
        return 1

    if not check and "--no-go" not in sys.argv and not refresh_go_halves():
        return 1
    reg, errs = build_coverage(services)
    if errs:
        print("FAIL: the AWS coverage registry gate (probe/coverage.py):")
        for e in errs:
            print("  - " + e)
        return 1

    errs = validate_denials(services, read_probe, reg["services"].keys(),
                            open(NO_POLICY_PROBE, encoding="utf-8").read())
    if errs:
        print("FAIL: a proven service is not proven to deny (probe/shim-services.yaml, probe/iam-no-policy.sh):")
        for e in errs:
            print("  - " + e)
        return 1

    surf, errs = surface.build(surface.load_inputs(ROOT))
    if errs:
        print("FAIL: the customer-surface gate (probe/surface.py): a customer-reachable capability has no "
              "AWS-shaped registry entry, or probe/registry/surface.yaml no longer matches the code:")
        for e in errs:
            print("  - " + e)
        return 1
    surf_json = surface.write(surf)
    cur = open(surface.SURFACE_JSON, encoding="utf-8").read() if os.path.exists(surface.SURFACE_JSON) else ""
    if cur != surf_json:
        if check:
            print("FAIL: probe/registry/customer-surface.json does not list what a customer can reach — run "
                  "probe/shimgen.py, review the entries, and commit them:")
            names = surface.unregistered(surf, cur) or ["(formatting only)"]
            for e in names[:60]:
                print("  - " + e)
            if len(names) > 60:
                print(f"  … and {len(names) - 60} more")
            return 1
        open(surface.SURFACE_JSON, "w", encoding="utf-8").write(surf_json)

    stale = []
    reg_json = coverage.write_registry(reg)
    cur = open(REGISTRY_JSON, encoding="utf-8").read() if os.path.exists(REGISTRY_JSON) else ""
    if cur != reg_json:
        if check:
            stale.append(os.path.relpath(REGISTRY_JSON, ROOT))
        else:
            open(REGISTRY_JSON, "w", encoding="utf-8").write(reg_json)
    for path, blocks in TARGETS.items():
        cur = open(path, encoding="utf-8").read()
        new = cur
        for marker, render, source in blocks:
            new = apply_block(new, marker, render(services, reg, surf), source)
        if check:
            if new != cur:
                stale.append(os.path.relpath(path, ROOT))
        else:
            if new != cur:
                open(path, "w", encoding="utf-8").write(new)

    n = len(proven(services))
    s = reg["summary"]
    cov = (f"{s['deployable']} CloudFormation types a stack can create: {s['covered']} served by their own "
           f"front door, {s['excepted']} listed exceptions")
    ss = surf["summary"]
    cov += (f"; customer surface: {ss['kinds']['total']} kinds, {ss['fields']['total']} fields, "
            f"{ss['routes']['total']} console routes, {ss['screens']['total']} screens, "
            f"{ss['services']['total']} AWS APIs, every one with its AWS-shaped entry")
    if check:
        if stale:
            print("FAIL: generated aws-shim / coverage docs are STALE — run probe/shimgen.py: " + ", ".join(stale))
            return 1
        print(f"OK: aws-shim service docs current ({n} probe-proven services); coverage gate passes ({cov}).")
        return 0
    print(f"wrote aws-shim service + coverage blocks — {n} probe-proven services; {cov}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
