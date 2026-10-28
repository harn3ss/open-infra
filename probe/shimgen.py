#!/usr/bin/env python3
"""Generate the aws-shim service list + count in README.md and docs/aws-shim.md from the single
source of truth, probe/shim-services.yaml, cross-checked against the probe/ directory.

The list and count used to be hand-typed in two places and drifted — a service could be built AND
probe-proven yet still documented as "not fronted" (the EKS bug). Now the docs are rendered from the
registry, and --check fails CI if the committed docs are stale OR the registry disagrees with the
filesystem. Same shape as docs/openapi/generate.py and tools/chaosdoc: one source, generated output,
a drift gate.

  probe/shimgen.py            # rewrite the generated blocks in README.md and docs/aws-shim.md
  probe/shimgen.py --check    # fail if a generated block is stale, or the registry ⇄ probe/ drifted
"""
import glob
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
REGISTRY = os.path.join(HERE, "shim-services.yaml")
PROBE_GLOB = os.path.join(HERE, "aws-shim-*.sh")

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


# file -> list of (marker, renderer)
TARGETS = {
    os.path.join(ROOT, "README.md"): [
        ("readme-matrix", render_readme_matrix),
    ],
    os.path.join(ROOT, "docs", "aws-shim.md"): [
        ("docs-list", render_docs_list),
        ("docs-501", render_docs_501),
    ],
}


def apply_block(text, marker, inner):
    begin = (f"<!-- BEGIN shimgen:{marker} — generated by probe/shimgen.py from "
             f"probe/shim-services.yaml; do not edit -->")
    end = f"<!-- END shimgen:{marker} -->"
    block = f"{begin}\n{inner}\n{end}"
    pat = re.compile(r"<!-- BEGIN shimgen:" + re.escape(marker) + r".*?-->.*?<!-- END shimgen:"
                     + re.escape(marker) + r" -->", re.S)
    if not pat.search(text):
        raise SystemExit(f"marker shimgen:{marker} not found — add the BEGIN/END comment pair to the file")
    return pat.sub(lambda _: block, text)


def main():
    check = "--check" in sys.argv
    services = load_registry()
    errs = validate(services, probe_basenames())
    if errs:
        print("FAIL: probe/shim-services.yaml is inconsistent with probe/:")
        for e in errs:
            print("  - " + e)
        return 1

    stale = []
    for path, blocks in TARGETS.items():
        cur = open(path, encoding="utf-8").read()
        new = cur
        for marker, render in blocks:
            new = apply_block(new, marker, render(services))
        if check:
            if new != cur:
                stale.append(os.path.relpath(path, ROOT))
        else:
            if new != cur:
                open(path, "w", encoding="utf-8").write(new)

    n = len(proven(services))
    if check:
        if stale:
            print("FAIL: aws-shim service docs are STALE — run probe/shimgen.py: " + ", ".join(stale))
            return 1
        print(f"OK: aws-shim service docs current ({n} probe-proven services).")
        return 0
    print(f"wrote aws-shim service blocks — {n} probe-proven services")
    return 0


if __name__ == "__main__":
    sys.exit(main())
