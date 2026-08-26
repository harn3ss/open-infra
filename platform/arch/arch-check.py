#!/usr/bin/env python3
"""
#41 Phase 2 — declared-vs-actual architecture check.

Reads the declared architecture registry (kind-architectures.yaml) and verifies every
first-party-image-backed kind against the image's REAL published manifest, so the declaration
can never silently drift from what ships:

  - declared `supported`   for an arch -> that arch MUST be in the image manifest (else the
    claim over-promises and would ImagePullBackOff on that arch).
  - declared `unsupported` for an arch while the image HAS gained it -> STALE: the image is now
    multi-arch but the registry still says unsupported (under-promises; probably wants updating,
    and enforcement pinning to the other arch is now needlessly restrictive).

Kinds with no `image` (no first-party data plane) are not checked here — they inherit their arch
from upstream and stay `untested` until run on real hardware.

Usage: arch-check.py [path-to-registry]   (default: alongside this script)
Exit 0 = consistent, 1 = drift found, 2 = could not inspect an image (inconclusive, not a pass).
"""
import json, os, subprocess, sys, yaml

ARCHES = ("amd64", "arm64")


def image_arches(ref):
    """Return the set of real (non-attestation) architectures in the image's manifest, or None."""
    r = f"{ref}:latest"
    try:
        out = subprocess.run(["docker", "manifest", "inspect", r],
                             capture_output=True, text=True, timeout=60)
    except Exception as e:
        print(f"  ! docker manifest inspect failed for {r}: {e}")
        return None
    if out.returncode != 0:
        print(f"  ! cannot inspect {r}: {out.stderr.strip()[:160]}")
        return None
    try:
        d = json.loads(out.stdout)
    except Exception:
        return None
    arches = set()
    for m in d.get("manifests", [d]):
        a = m.get("platform", {}).get("architecture")
        if a and a != "unknown":
            arches.add(a)
    return arches


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "kind-architectures.yaml")
    cm = yaml.safe_load(open(path))
    kinds = yaml.safe_load(cm["data"]["kinds.yaml"])

    drift, inconclusive, checked = [], [], 0
    for kind, spec in kinds.items():
        img = spec.get("image")
        if not img:
            continue
        checked += 1
        actual = image_arches(img)
        if actual is None:
            inconclusive.append(kind)
            continue
        for arch in ARCHES:
            declared = spec.get(arch)
            has = arch in actual
            if declared == "supported" and not has:
                drift.append(f"{kind}: declares {arch}=supported but {img} has no {arch} manifest {sorted(actual)}")
            if declared == "unsupported" and has:
                drift.append(f"{kind}: declares {arch}=unsupported but {img} now HAS {arch} (stale — update the registry) {sorted(actual)}")
        print(f"  ok  {kind:16s} {img.split('/')[-1]:26s} actual={sorted(actual)}")

    print(f"\nchecked {checked} first-party-backed kinds")
    if drift:
        print("DRIFT:")
        for d in drift:
            print("  ✗ " + d)
        sys.exit(1)
    if inconclusive:
        print("INCONCLUSIVE (could not inspect): " + ", ".join(inconclusive))
        sys.exit(2)
    print("declared architecture matches every published manifest.")


if __name__ == "__main__":
    main()
