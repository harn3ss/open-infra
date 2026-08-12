#!/usr/bin/env python3
"""Convention guard for the nightly-chaos scenarios.

Every scenario-*.sh must carry the EXIT_INCONCLUSIVE=42 vocabulary so that a fault which never
fired — or a sandbox that could not stand up — is graded INCONCLUSIVE (the workflow maps 42 to a
warning: neither red nor green), NOT a hard red. A scenario missing it can only ever lie green or
fail hard on a non-fired fault, which is precisely the false-red / false-green drift the suite
exists to refuse. (Five legacy scripts — clockskew, cnpgfailover, concurrent, sinkkill, storage —
used to map "the fault did not land" to exit 1; this guard keeps them, and any new scenario, honest.)
"""
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    scripts = sorted(glob.glob(os.path.join(HERE, "scenario-*.sh")))
    if not scripts:
        print("FAIL: no scenario-*.sh found")
        return 1
    missing = []
    for path in scripts:
        with open(path, encoding="utf-8") as f:
            if "EXIT_INCONCLUSIVE=42" not in f.read():
                missing.append(os.path.basename(path))
    if missing:
        print("FAIL: these scenario scripts do not declare EXIT_INCONCLUSIVE=42:")
        for m in missing:
            print("  -", m)
        print(
            "\nA scenario must map 'the fault never fired / the sandbox never stood up' to\n"
            "  exit \"$EXIT_INCONCLUSIVE\"   (42, INCONCLUSIVE), not a hard red.\n"
            "See scenario-partition.sh for the pattern."
        )
        return 1
    print(f"OK: all {len(scripts)} scenario scripts carry the EXIT_INCONCLUSIVE=42 convention.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
