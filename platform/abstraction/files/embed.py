#!/usr/bin/env python3
"""Embed the VM composition's copied blocks, indented as the YAML literal block each sits in:

  - files/windows-launch-agent.ps1 into the launch Secret (between the BEGIN/END windows-launch-agent.ps1
    markers);
  - the metadata agent the Linux guests run (its cloud-init write_files entry,
    /usr/local/lib/openinfra/metadata-agent.py, the one source) into the instance metadata Secret a Windows
    instance's pod serves from (between the BEGIN/END metadata-agent.py markers).

  python3 platform/abstraction/files/embed.py           # rewrite the composition
  python3 platform/abstraction/files/embed.py --check   # exit 1 if an embedded copy is stale
"""
import pathlib, re, sys

HERE = pathlib.Path(__file__).resolve().parent
AGENT = HERE / "windows-launch-agent.ps1"
COMPOSITION = HERE.parent / "vm-composition.yaml"
METADATA_AGENT_PATH = "/usr/local/lib/openinfra/metadata-agent.py"


def embedded(text: str, name: str, body_text: str) -> str:
    begin, end = "# BEGIN " + name, "# END " + name
    m = re.search(r"^( *)" + re.escape(begin) + r"\n.*?^\1" + re.escape(end) + r"$", text, re.S | re.M)
    if not m:
        sys.exit("vm-composition.yaml has no %s markers" % name)
    pad = m.group(1)
    body = "".join((pad + line if line.strip() else "") + "\n" for line in body_text.splitlines())
    return text[: m.start()] + pad + begin + "\n" + body + pad + end + text[m.end():]


def write_file_block(text: str, path: str) -> str:
    """The dedented `content: |` body of the cloud-init write_files entry for path (as test/vm-creds reads it)."""
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if ln.strip() != "- path: " + path:
            continue
        for j in range(i + 1, min(i + 4, len(lines))):
            if lines[j].strip() != "content: |":
                continue
            key_indent = len(lines[j]) - len(lines[j].lstrip(" "))
            out = []
            for b in lines[j + 1:]:
                if not b.strip():
                    out.append("")
                    continue
                if len(b) - len(b.lstrip(" ")) <= key_indent:
                    break
                out.append(b[key_indent + 2:])
            while out and out[-1] == "":
                out.pop()
            return "\n".join(out) + "\n"
    sys.exit("vm-composition.yaml has no write_files entry for %s" % path)


def main() -> int:
    text, agent = COMPOSITION.read_text(), AGENT.read_text()
    if "{{" in agent or "}}" in agent:
        sys.exit("windows-launch-agent.ps1 must not contain {{ or }} (the composition is a Go template)")
    want = embedded(text, "windows-launch-agent.ps1", agent)
    metadata_agent = write_file_block(want, METADATA_AGENT_PATH)
    if "{{" in metadata_agent or "}}" in metadata_agent:
        sys.exit("the metadata agent must not contain {{ or }} (the composition is a Go template)")
    want = embedded(want, "metadata-agent.py", metadata_agent)
    if "--check" in sys.argv:
        if want != text:
            print("STALE: run python3 platform/abstraction/files/embed.py", file=sys.stderr)
            return 1
        print("OK: the composition embeds windows-launch-agent.ps1 and the metadata agent")
        return 0
    COMPOSITION.write_text(want)
    return 0


if __name__ == "__main__":
    sys.exit(main())
