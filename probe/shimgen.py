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

  probe/shimgen.py            # refresh the Go-read halves (when Go is on PATH), rewrite every generated block
  probe/shimgen.py --no-go    # the same, from the committed halves
  probe/shimgen.py --check    # fail if a generated block or registry.json is stale, the registry ⇄
                              # probe/ ⇄ router drifted, or the coverage gate fails
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
        if tier not in ("proven", "gated", "planned"):
            errs.append(f"{name}: tier must be proven|gated|planned (got {tier!r})")
        for pr in plist:
            if pr in claimed:
                errs.append(f"probe {pr!r} claimed by both {claimed[pr]!r} and {name!r}")
            claimed[pr] = name
            if pr not in probes:
                errs.append(f"{name}: probes names {pr!r} but probe/aws-shim-{pr}.sh does not exist")
        if tier == "proven" and not plist:
            errs.append(f"{name}: tier proven but no probe (proven means observed — add a probe or change the tier)")
        if tier in ("gated", "planned") and plist:
            errs.append(f"{name}: tier {tier} must claim no probe (it has one — promote it to proven)")
    # Every probe on disk must be claimed by exactly one service — a NEW probe forces a registry entry.
    for pr in sorted(probes):
        if pr not in claimed:
            errs.append(f"probe/aws-shim-{pr}.sh is not claimed by any service in shim-services.yaml "
                        f"(add it to the service it proves, so the list + count stay honest)")
    return errs


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


def render_docs_501(services):
    planned = [s["name"] for s in services if s.get("tier") == "planned"]
    lst = ", ".join(planned)
    return (f"**Still not fronted** (honest `501`, never a silent fake, until built + probed): "
            f"{lst}, and the rest of the AWS surface.")


SRC_SERVICES = "probe/shim-services.yaml"
SRC_COVERAGE = "the coverage registry (probe/registry/)"

# file -> list of (marker, renderer(services, reg), source). A shim-services block renders the proof
# registry; a coverage block renders the joined coverage registry.
TARGETS = {
    os.path.join(ROOT, "README.md"): [
        ("readme-matrix", lambda s, r: render_readme_matrix(s), SRC_SERVICES),
        ("readme-coverage", lambda s, r: coverage.render_readme_coverage(r), SRC_COVERAGE),
    ],
    os.path.join(ROOT, "docs", "aws-shim.md"): [
        ("docs-list", lambda s, r: render_docs_list(s), SRC_SERVICES),
        ("docs-501", lambda s, r: render_docs_501(s), SRC_SERVICES),
        ("docs-operations", lambda s, r: coverage.render_shim_operations(r), SRC_COVERAGE),
    ],
    os.path.join(ROOT, "docs", "cloudformation.md"): [
        ("cfn-namespaces", lambda s, r: coverage.render_cfn_namespaces(r), SRC_COVERAGE),
    ],
    os.path.join(ROOT, "docs", "aws-coverage.md"): [
        ("coverage-summary", lambda s, r: coverage.render_coverage_summary(r), SRC_COVERAGE),
        ("coverage-gate", lambda s, r: coverage.render_coverage_gate(r), SRC_COVERAGE),
        ("coverage-breadth", lambda s, r: coverage.render_coverage_breadth(r), SRC_COVERAGE),
        ("coverage-types", lambda s, r: coverage.render_coverage_types(r), SRC_COVERAGE),
    ],
}

REGISTRY_JSON = os.path.join(HERE, "registry", "registry.json")

# The Go tests that read the two halves of the coverage registry from code (run with UPDATE_REGISTRY=1
# to rewrite them): (module dir, package, test).
GO_HALVES = [
    ("cfn", ".", "TestCoverageRegistryCFNTypes"),
    ("console-api", "./cmd/aws-shim", "TestCoverageRegistryShimRouter"),
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
        print("note: no `go` on PATH — using the committed probe/registry/cfn-types.json and shim-router.json "
              "(the cfn and console-api CI jobs fail if they are stale)")
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
            new = apply_block(new, marker, render(services, reg), source)
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
