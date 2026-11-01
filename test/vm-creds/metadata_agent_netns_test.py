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
#   * a "LAN host" that routes 169.254.169.254 through the guest (a guest forwarding as a router, VPN or NAT
#     instance would) is dropped on the guest's NIC, while the guest and its containers keep IMDS;
#   * credentials come from a TLS shim the agent verifies against a test root (as a guest does the shim);
#   * stopping the agent removes the namespace and the drop rule, and a restart over a stale namespace
#     (after SIGKILL) works.
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
import time

import vmcreds_common as common
from vmcreds_common import say

CTR_NS = "oi-test-ctr"
CTR_HOST_IF, CTR_PEER_IF = "oi-test-c0", "oi-test-c1"
CTR_GW, CTR_IP = "198.18.0.1", "198.18.0.2"  # RFC 2544 benchmarking range, never routed
LAN_NS = "oi-test-lan"
LAN_HOST_IF, LAN_PEER_IF = "oi-test-l0", "oi-test-l1"  # oi-test-l0 plays the guest's NIC
LAN_GW, LAN_IP = "198.18.0.5", "198.18.0.6"
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
    # A private /run in this mount namespace: `ip netns` files (/run/netns) and the agent's ruleset file
    # would otherwise be created in the host's /run and outlive the test.
    sh("mount", "--make-rprivate", "/")
    sh("mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", "/run")
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
    # A "LAN host" on the guest's NIC, which sends its 169.254.169.254 traffic through the guest.
    sh("ip", "netns", "add", LAN_NS)
    sh("ip", "link", "add", LAN_HOST_IF, "type", "veth", "peer", "name", LAN_PEER_IF)
    sh("ip", "link", "set", LAN_PEER_IF, "netns", LAN_NS)
    sh("ip", "addr", "add", LAN_GW + "/30", "dev", LAN_HOST_IF)
    sh("ip", "link", "set", LAN_HOST_IF, "up")
    sh("ip", "-n", LAN_NS, "link", "set", "lo", "up")
    sh("ip", "-n", LAN_NS, "addr", "add", LAN_IP + "/30", "dev", LAN_PEER_IF)
    sh("ip", "-n", LAN_NS, "link", "set", LAN_PEER_IF, "up")
    sh("ip", "-n", LAN_NS, "route", "add", "default", "via", LAN_GW)


class Shim(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = json.dumps(CREDS).encode()
        self.send_response(200 if self.headers.get("Authorization") == "netns-test-token" else 401)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def start_agent(tmp, agent_path, shim_port, hop_limit, ca_file, guard=LAN_HOST_IF):
    cfg = common.golden_config()  # production network settings: netns openinfra-imds, 169.254.169.254:80
    cfg["imds"]["hopLimit"] = hop_limit
    cfg["imds"]["guardInterfaces"] = [guard]  # this namespace has no device-backed NIC to detect
    cfg["credentialsUrl"] = "https://127.0.0.1:%d/v1/vm-credentials" % shim_port
    cfg["caFile"] = ca_file
    cfg["tokenFile"] = os.path.join(tmp, "token")
    cfg["userDataFile"] = ""
    cfg["trustPlatformCA"] = False  # a netns does not isolate the filesystem: never touch the host trust store
    cfg["caBundleLink"] = ""        # ... nor /etc/openinfra
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


def lan_host(method, path, ttl="60"):
    return sh("ip", "netns", "exec", LAN_NS, sys.executable, "-c", CLIENT, method, path, ttl).strip()


def guard_tool():
    return "nft" if shutil.which("nft") else ("iptables" if shutil.which("iptables") else "")


def guard_present():
    if shutil.which("nft") and subprocess.run(["nft", "list", "table", "ip", "openinfra_imds"],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        return True
    return bool(shutil.which("iptables")) and subprocess.run(
        ["iptables", "-w", "-t", "raw", "-S", "OPENINFRA-IMDS"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


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
    if not shutil.which("openssl"):
        raise SystemExit("FAIL: openssl is needed to mint the TLS shim's test certificates")
    pki = common.make_test_pki(os.path.join(tmp, "pki"))
    shim = common.tls_server(Shim, pki["server"], pki["server-key"])
    failures = []

    def check(name, ok, detail=""):
        say("%s: %s%s" % (name, "ok" if ok else "FAILED", (" (" + detail + ")") if detail and not ok else ""))
        if not ok:
            failures.append(name)

    tool = guard_tool()
    if tool:
        # Control: with the drop rule on some other interface, the LAN host DOES reach IMDS through the
        # forwarding guest, so the check below measures the guard, not the topology.
        proc = start_agent(tmp, agent_path, shim.server_address[1], hop_limit=1, ca_file=pki["root"], guard="oi-test-none")
        got = lan_host("GET", "/latest/meta-data/instance-id")
        check("control: without the guard on its NIC, a LAN host reaches IMDS through the guest", got == "200", got)
        stop(proc)
    proc = start_agent(tmp, agent_path, shim.server_address[1], hop_limit=1, ca_file=pki["root"])
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
        if tool:
            check("IMDSv1 GET from the container is not hop-limited", got == "200", got)
        else:
            say("(no nft/iptables: the route fallback leaves a routed container without IMDS, as documented)")
        got = lan_host("GET", "/latest/meta-data/iam/security-credentials/app-role")
        check("a LAN host routing through the guest is dropped (%s)" % (tool or "route fallback"), got == "TIMEOUT", got)
        got = lan_host("PUT", "/latest/api/token")
        check("... and gets no IMDSv2 token either", got == "TIMEOUT", got)
        if tool:
            check("the forwarded-metadata drop rule is installed", guard_present())
        if masquerade(True):
            got = container("PUT", "/latest/api/token")
            check("hop limit 1: a MASQUERADEd (docker-style) container gets NO token", got == "TIMEOUT", got)
            masquerade(False)
        else:
            say("(iptables not available: docker-style MASQUERADE path not exercised)")
        stop(proc, signal.SIGKILL)  # leave a stale namespace behind

        proc = start_agent(tmp, agent_path, shim.server_address[1], hop_limit=2, ca_file=pki["root"])
        check("restart over a stale namespace works", guest("GET", "/latest/meta-data/instance-id")[0] == "200")
        got = lan_host("GET", "/latest/meta-data/instance-id")
        check("after the restart the LAN host is still dropped", got == "TIMEOUT", got)
        if tool:  # the route fallback answers only the guest's own address: a routed container is out of reach
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
        check("SIGTERM removes the forwarded-metadata drop rule", not guard_present())
    finally:
        if proc.poll() is None:
            stop(proc)
        shim.shutdown()
    if failures:
        for name in sorted(os.listdir(tmp)):
            if name.endswith(".log"):
                say("---- %s ----\n%s" % (name, open(os.path.join(tmp, name)).read()))
        raise SystemExit("FAIL: " + "; ".join(failures))
    say("PASS: metadata namespace, port-80 coexistence, EC2 hop-limit semantics and the forwarded-traffic drop hold in the kernel")


if __name__ == "__main__":
    main()
