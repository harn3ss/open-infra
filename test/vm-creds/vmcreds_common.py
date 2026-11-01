# Shared helpers for the VM credentials / instance metadata tests (stdlib only, Python 3.6+).
#
# The instance metadata agent ships INSIDE the VM composition (cloud-init write_files), so these tests
# extract it from platform/abstraction/vm-composition.yaml and run that exact text. The config they run
# it with is testdata/metadata-agent.golden.json, which test/render pins to what the composition renders.

import importlib.util
import json
import os
import re
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
COMPOSITION = os.path.join(REPO, "platform", "abstraction", "vm-composition.yaml")
GOLDEN_CONFIG = os.path.join(HERE, "testdata", "metadata-agent.golden.json")
AGENT_GUEST_PATH = "/usr/local/lib/openinfra/metadata-agent.py"


def write_file_block(text, path):
    """The dedented `content: |` body of the cloud-init write_files entry for `path`."""
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
    raise SystemExit("FAIL: no write_files entry for %s in %s" % (path, COMPOSITION))


def agent_source():
    src = write_file_block(open(COMPOSITION).read(), AGENT_GUEST_PATH)
    if "{{" in src:
        raise SystemExit("FAIL: the agent body in vm-composition.yaml contains a template action; "
                         "it must render verbatim")
    return src


def write_agent(directory):
    path = os.path.join(directory, "metadata-agent.py")
    with open(path, "w") as fh:
        fh.write(agent_source())
    return path


def load_agent_module(directory):
    path = write_agent(directory)
    spec = importlib.util.spec_from_file_location("openinfra_metadata_agent", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def golden_config():
    with open(GOLDEN_CONFIG) as fh:
        return json.load(fh)


def composition_env():
    """The container-credentials env the composition renders: {var: value}. Fails on a token env var."""
    text = open(COMPOSITION).read()
    if re.search(r"AWS_CONTAINER_\w*TOKEN", text):
        raise SystemExit("FAIL: vm-composition.yaml renders an AWS_CONTAINER_*TOKEN* env var; the agent "
                         "authenticates to the shim itself and the token is root-only (#347 item 13)")
    m_port = re.search(r'\$credsPort\s*:=\s*"(\d+)"', text)
    m_uri = re.search(r'\$credsURI\s*:=\s*printf\s+"(http://127\.0\.0\.1:%s/\S+?)"', text)
    if not (m_port and m_uri) or "AWS_CONTAINER_CREDENTIALS_FULL_URI={{ $credsURI }}" not in text:
        raise SystemExit("FAIL: could not extract AWS_CONTAINER_CREDENTIALS_FULL_URI from vm-composition.yaml")
    return {"AWS_CONTAINER_CREDENTIALS_FULL_URI": m_uri.group(1) % m_port.group(1)}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(host, port, timeout=15.0, proc=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            raise SystemExit("FAIL: the agent exited early (rc=%s)" % proc.returncode)
        try:
            socket.create_connection((host, port), 0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise SystemExit("FAIL: nothing listening on %s:%d after %.0fs" % (host, port, timeout))


def say(*a):
    print(*a)
    sys.stdout.flush()
