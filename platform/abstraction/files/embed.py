#!/usr/bin/env python3
"""Embed files/windows-launch-agent.ps1 into the VM composition's launch Secret (the block between the
BEGIN/END windows-launch-agent.ps1 markers), indented as the YAML literal block it sits in.

  python3 platform/abstraction/files/embed.py           # rewrite the composition
  python3 platform/abstraction/files/embed.py --check   # exit 1 if the embedded copy is stale
"""
import pathlib, re, sys

HERE = pathlib.Path(__file__).resolve().parent
AGENT = HERE / "windows-launch-agent.ps1"
COMPOSITION = HERE.parent / "vm-composition.yaml"
BEGIN, END = "# BEGIN windows-launch-agent.ps1", "# END windows-launch-agent.ps1"


def embedded(text: str, agent: str) -> str:
    m = re.search(r"^( *)" + re.escape(BEGIN) + r"\n.*?^\1" + re.escape(END) + r"$", text, re.S | re.M)
    if not m:
        sys.exit("vm-composition.yaml has no windows-launch-agent.ps1 markers")
    pad = m.group(1)
    body = "".join((pad + line if line.strip() else "") + "\n" for line in agent.splitlines())
    return text[: m.start()] + pad + BEGIN + "\n" + body + pad + END + text[m.end():]


def main() -> int:
    text, agent = COMPOSITION.read_text(), AGENT.read_text()
    if "{{" in agent or "}}" in agent:
        sys.exit("windows-launch-agent.ps1 must not contain {{ or }} (the composition is a Go template)")
    want = embedded(text, agent)
    if "--check" in sys.argv:
        if want != text:
            print("STALE: run python3 platform/abstraction/files/embed.py", file=sys.stderr)
            return 1
        print("OK: the composition embeds windows-launch-agent.ps1")
        return 0
    COMPOSITION.write_text(want)
    return 0


if __name__ == "__main__":
    sys.exit(main())
