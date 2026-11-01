#!/usr/bin/env python3
# The instance metadata agent's real network path, end to end in the kernel (#347 item 14): the agent
# (the exact text in vm-composition.yaml, with the composition's production network settings) builds its
# metadata namespace and serves 169.254.169.254:80 from it, and we prove from a "guest" and from a
# "container" one forwarding hop behind it that:
#
#   * port 80 in the guest stays free for the workload (a wildcard :80 bind succeeds while IMDS serves);
#   * the IMDSv2 PUT response hop limit behaves as on EC2: with hop limit 1 a guest process gets a token
#     and the container does not (its token response dies at the guest's forwarding hop, the client times
#     out); with hop limit 2 the container gets one too; IMDSv1 GETs are not hop-limited — both for a
#     routed container and (when iptables is available) one behind docker-style MASQUERADE;
#   * stopping the agent removes the namespace, and a restart over a stale namespace (after SIGKILL) works.
#
# Needs root in an ISOLATED network namespace — it creates interfaces, routes and namespaces. Run it as
#     sudo unshare --net --mount --fork python3 test/vm-creds/metadata_agent_netns_test.py
# It refuses to run in a namespace that has any interface besides lo.

import http.client
import http.server
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

import vmcreds_common as common
from vmcreds_common import say

CTR_NS = "oi-test-ctr"
CTR_HOST_IF, CTR_PEER_IF = "oi-test-c0", "oi-test-c1"
CTR_GW, CTR_IP = "198.18.0.1", "198.18.0.2"  # RFC 2544 benchmarking range, never routed
IMDS = "169.254.169.254"
CREDS = {"AccessKeyId": "ASIANETNSTEST0000001", "SecretAccessKey": "s", "Token": "t", "Expiration": "2099-01-01T00:00:00Z"}

CLIENT = r"""
import http.client, sys
method, path, ttl = sys.argv[1], sys.argv[2], sys.argv[3]
c = http.client.HTTPConnection("169.254.169.254", 80, timeout=3)
try:
    c.request(method, path, headers={"X-aws-ec2-metadata-token-ttl-seconds": ttl} if method == "PUT" else {})
    r = c.getresponse()
    print(r.status)
except Exception as e:
    print("TIMEOUT" if "timed out" in str(e) else "ERROR " + str(e))
"""


def sh(*cmd):
    p = subprocess.run(list(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if p.returncode != 0:
        raise SystemExit("FAIL: %s: %s" % (" ".join(cmd), p.stderr.strip()))
    return p.stdout


def preflight():
    if os.geteuid() != 0:
        raise SystemExit("SKIP-REFUSED: needs root (run under `sudo unshare --net --mount --fork`)")
    links = [l.split(":")[1].strip().split("@")[0] for l in sh("ip", "-o", "link", "show").splitlines()]
    if [l for l in links if l != "lo"]:
        raise SystemExit("REFUSED: this network namespace has real interfaces %s — run the test inside "
                         "`unshare --net --mount --fork` so it cannot touch a real network" % links)
    sh("ip", "link", "set", "lo", "up")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:  # the guest routes for its "containers"
        fh.write("1\n")
    # A "container": its own namespace on a veth, one forwarding hop behind the guest.
    sh("ip", "netns", "add", CTR_NS)
    sh("ip", "link", "add", CTR_HOST_IF, "type", "veth", "peer", "name", CTR_PEER_IF)
    sh("ip", "link", "set", CTR_PEER_IF, "netns", CTR_NS)
    sh("ip", "addr", "add", CTR_GW + "/30", "dev", CTR_HOST_IF)
    sh("ip", "link", "set", CTR_HOST_IF, "up")
    sh("ip", "-n", CTR_NS, "link", "set", "lo", "up")
    sh("ip", "-n", CTR_NS, "addr", "add", CTR_IP + "/30", "dev", CTR_PEER_IF)
    sh("ip", "-n", CTR_NS, "link", "set", CTR_PEER_IF, "up")
    sh("ip", "-n", CTR_NS, "route", "add", "default", "via", CTR_GW)


class Shim(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = json.dumps(CREDS).encode()
        self.send_response(200 if self.headers.get("Authorization") == "netns-test-token" else 401)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def start_agent(tmp, agent_path, shim_port, hop_limit):
    cfg = common.golden_config()  # production network settings: netns openinfra-imds, 169.254.169.254:80
    cfg["imds"]["hopLimit"] = hop_limit
    cfg["credentialsUrl"] = "http://127.0.0.1:%d/v1/vm-credentials" % shim_port
    cfg["tokenFile"] = os.path.join(tmp, "token")
    cfg["userDataFile"] = ""
    path = os.path.join(tmp, "agent-%d.json" % hop_limit)
    with open(path, "w") as fh:
        json.dump(cfg, fh)
    log = open(os.path.join(tmp, "agent-%d.log" % hop_limit), "w")
    proc = subprocess.Popen([sys.executable, agent_path, path], stdout=log, stderr=log)
    proc.log_path = log.name
    common.wait_port(IMDS, 80, timeout=20, proc=proc)
    return proc


def guest(method, path, ttl="60"):
    c = http.client.HTTPConnection(IMDS, 80, timeout=3)
    try:
        c.request(method, path, headers={"X-aws-ec2-metadata-token-ttl-seconds": ttl} if method == "PUT" else {})
        r = c.getresponse()
        return str(r.status), r.read().decode()
    finally:
        c.close()


def container(method, path, ttl="60"):
    return sh("ip", "netns", "exec", CTR_NS, sys.executable, "-c", CLIENT, method, path, ttl).strip()


MASQ = ["-t", "nat", "POSTROUTING", "-s", CTR_IP + "/32", "!", "-o", CTR_HOST_IF, "-j", "MASQUERADE"]


def masquerade(on):
    """Docker's default bridge rule: container traffic leaving the bridge is SNAT'd to the egress
    interface's address (here oi-imds0's 169.254.169.1). Returns False when iptables is unavailable."""
    if not shutil.which("iptables"):
        return False
    rule = MASQ[:2] + ["-A" if on else "-D"] + MASQ[2:]
    sh("iptables", *rule)
    return True


def stop(proc, sig=signal.SIGTERM):
    proc.send_signal(sig)
    proc.wait(15)


def main():
    preflight()
    tmp = tempfile.mkdtemp(prefix="oi-netns-test-")
    with open(os.path.join(tmp, "token"), "w") as fh:
        fh.write("netns-test-token\n")
    agent_path = common.write_agent(tmp)
    shim = http.server.HTTPServer(("127.0.0.1", 0), Shim)
    threading.Thread(target=shim.serve_forever, daemon=True).start()
    failures = []

    def check(name, ok, detail=""):
        say("%s: %s%s" % (name, "ok" if ok else "FAILED", (" (" + detail + ")") if detail and not ok else ""))
        if not ok:
            failures.append(name)

    proc = start_agent(tmp, agent_path, shim.server_address[1], hop_limit=1)
    try:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", 80))
            s.listen(1)
            free = True
        except OSError as e:
            free, err = False, str(e)
        finally:
            s.close()
        check("guest port 80 stays free for the workload while IMDS serves", free, "" if free else err)
        st, _ = guest("PUT", "/latest/api/token")
        check("hop limit 1: a guest process gets a token", st == "200", st)
        st, body = guest("GET", "/latest/meta-data/iam/security-credentials/app-role")
        check("guest gets role credentials over IMDS", st == "200" and json.loads(body).get("AccessKeyId") == CREDS["AccessKeyId"], st)
        got = container("PUT", "/latest/api/token")
        check("hop limit 1: a container one hop away gets NO token (response dies in transit)", got == "TIMEOUT", got)
        got = container("GET", "/latest/meta-data/instance-id")
        check("IMDSv1 GET from the container is not hop-limited", got == "200", got)
        if masquerade(True):
            got = container("PUT", "/latest/api/token")
            check("hop limit 1: a MASQUERADEd (docker-style) container gets NO token", got == "TIMEOUT", got)
            masquerade(False)
        else:
            say("(iptables not available: docker-style MASQUERADE path not exercised)")
        stop(proc, signal.SIGKILL)  # leave a stale namespace behind

        proc = start_agent(tmp, agent_path, shim.server_address[1], hop_limit=2)
        check("restart over a stale namespace works", guest("GET", "/latest/meta-data/instance-id")[0] == "200")
        got = container("PUT", "/latest/api/token")
        check("hop limit 2: the container one hop away gets a token", got == "200", got)
        if masquerade(True):
            got = container("PUT", "/latest/api/token")
            check("hop limit 2: a MASQUERADEd (docker-style) container gets a token", got == "200", got)
            got = container("GET", "/latest/meta-data/iam/security-credentials/app-role")
            check("a MASQUERADEd container gets role credentials", got == "200", got)
            masquerade(False)
        stop(proc)
        netns = sh("ip", "netns", "list")
        links = sh("ip", "-o", "link", "show")
        check("SIGTERM removes the metadata namespace and its veth", "openinfra-imds" not in netns and "oi-imds0" not in links,
              netns + links)
    finally:
        if proc.poll() is None:
            stop(proc)
        shim.shutdown()
    if failures:
        for name in sorted(os.listdir(tmp)):
            if name.endswith(".log"):
                say("---- %s ----\n%s" % (name, open(os.path.join(tmp, name)).read()))
        raise SystemExit("FAIL: " + "; ".join(failures))
    say("PASS: metadata namespace, port-80 coexistence and EC2 hop-limit semantics hold in the kernel")


if __name__ == "__main__":
    main()
