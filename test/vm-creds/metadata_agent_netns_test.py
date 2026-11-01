#!/usr/bin/env python3
# The instance metadata agent's real network path, end to end in the kernel (#347 items 14 + 5): the agent
# (the exact text in vm-composition.yaml, with the composition's production network settings) builds its
# metadata namespace and serves 169.254.169.254:80 from it, and we prove from a "guest", from "containers"
# and from "LAN hosts" the guest forwards for that:
#
#   * port 80 in the guest stays free for the workload (a wildcard :80 bind succeeds while IMDS serves);
#   * the IMDSv2 PUT response hop limit behaves as on EC2: with hop limit 1 a guest process gets a token
#     and the container does not (its token response dies at the guest's forwarding hop, the client times
#     out); with hop limit 2 the container gets one too; IMDSv1 GETs are not hop-limited — both for a
#     routed container and (when iptables is available) one behind docker-style MASQUERADE;
#   * only the guest's own containers reach it: a routed container (veth) and one on a bridge whose ports
#     are containers do; a LAN host behind a VLAN, and one on a bridge whose port is a VLAN (a NIC, a tap),
#     are dropped — whatever interface a forwarding guest (router, VPN, NAT instance) receives them on;
#   * an interface named in guardInterfaces is refused even if it looks like a container's;
#   * the guard comes back by itself after `nft flush ruleset` (or `iptables -t raw -F`);
#   * with iptables only (no nft), the guard names the container interfaces and still drops the LAN hosts;
#   * credentials come from a TLS shim the agent verifies against a test root (as a guest does the shim);
#   * stopping the agent removes the namespace and the guard, and a restart over a stale namespace
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

IMDS = "169.254.169.254"
# RFC 2544 benchmarking range, never routed.
CTR_NS, CTR_HOST_IF, CTR_PEER_IF, CTR_GW, CTR_IP = "oi-test-ctr", "oi-test-c0", "oi-test-c1", "198.18.0.1", "198.18.0.2"
# A "LAN host" on a VLAN of the guest's network, which sends its 169.254.169.254 traffic through the guest.
LAN_NS, LAN_HOST_IF, LAN_PEER_IF = "oi-test-lan", "oi-test-l0", "oi-test-l1"
LAN_VLAN, LAN_GW, LAN_IP = "7", "198.18.0.5", "198.18.0.6"
# A bridge in the guest with two ports: a VLAN to another LAN host, and a container's veth.
BR = "oi-test-br"
BR_GW = "198.18.0.17"
BRLAN_NS, BRLAN_HOST_IF, BRLAN_PEER_IF, BRLAN_VLAN, BRLAN_IP = "oi-test-blan", "oi-test-b0", "oi-test-b1", "8", "198.18.0.18"
BRCTR_NS, BRCTR_HOST_IF, BRCTR_PEER_IF, BRCTR_IP = "oi-test-bctr", "oi-test-c2", "oi-test-c3", "198.18.0.19"
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


def quiet(*cmd):
    return subprocess.run(list(cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def netns_host(ns, host_if, peer_if, ip, gw, prefix):
    """Namespace `ns` on a veth pair: `peer_if` inside with `ip`/`prefix` (default route via `gw`)."""
    sh("ip", "netns", "add", ns)
    sh("ip", "link", "add", host_if, "type", "veth", "peer", "name", peer_if)
    sh("ip", "link", "set", peer_if, "netns", ns)
    sh("ip", "-n", ns, "link", "set", "lo", "up")
    if ip:
        sh("ip", "-n", ns, "addr", "add", "%s/%s" % (ip, prefix), "dev", peer_if)
    sh("ip", "-n", ns, "link", "set", peer_if, "up")
    if ip:
        sh("ip", "-n", ns, "route", "add", "default", "via", gw)


def vlan_pair(ns, host_if, peer_if, vid, guest_ip, peer_ip, prefix):
    """VLAN `vid` on both ends of host_if/peer_if; the peer's address on its VLAN. Returns the guest's VLAN."""
    g, p = "%s.%s" % (host_if, vid), "%s.%s" % (peer_if, vid)
    sh("ip", "link", "add", "link", host_if, "name", g, "type", "vlan", "id", vid)
    sh("ip", "-n", ns, "link", "add", "link", peer_if, "name", p, "type", "vlan", "id", vid)
    if guest_ip:
        sh("ip", "addr", "add", "%s/%s" % (guest_ip, prefix), "dev", g)
    sh("ip", "link", "set", host_if, "up")
    sh("ip", "link", "set", g, "up")
    sh("ip", "-n", ns, "addr", "add", "%s/%s" % (peer_ip, prefix), "dev", p)
    sh("ip", "-n", ns, "link", "set", p, "up")
    sh("ip", "-n", ns, "route", "add", "default", "via", guest_ip or BR_GW)
    return g


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
    with open("/proc/sys/net/ipv4/ip_forward", "w") as fh:  # the guest routes for its containers and LAN hosts
        fh.write("1\n")
    # A routed "container": its own namespace on a veth, one forwarding hop behind the guest.
    netns_host(CTR_NS, CTR_HOST_IF, CTR_PEER_IF, CTR_IP, CTR_GW, 30)
    sh("ip", "addr", "add", CTR_GW + "/30", "dev", CTR_HOST_IF)
    sh("ip", "link", "set", CTR_HOST_IF, "up")
    # A LAN host on VLAN 7 of the guest's network (the guest's interface is a VLAN, not a container's).
    netns_host(LAN_NS, LAN_HOST_IF, LAN_PEER_IF, "", "", 0)
    vlan_pair(LAN_NS, LAN_HOST_IF, LAN_PEER_IF, LAN_VLAN, LAN_GW, LAN_IP, 30)
    # A bridge holding a VLAN port (to another LAN host) and a container's veth.
    sh("ip", "link", "add", BR, "type", "bridge")
    sh("ip", "addr", "add", BR_GW + "/28", "dev", BR)
    sh("ip", "link", "set", BR, "up")
    netns_host(BRLAN_NS, BRLAN_HOST_IF, BRLAN_PEER_IF, "", "", 0)
    port = vlan_pair(BRLAN_NS, BRLAN_HOST_IF, BRLAN_PEER_IF, BRLAN_VLAN, "", BRLAN_IP, 28)
    sh("ip", "link", "set", port, "master", BR)
    netns_host(BRCTR_NS, BRCTR_HOST_IF, BRCTR_PEER_IF, BRCTR_IP, BR_GW, 28)
    sh("ip", "link", "set", BRCTR_HOST_IF, "master", BR)
    sh("ip", "link", "set", BRCTR_HOST_IF, "up")


class Shim(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = json.dumps(CREDS).encode()
        self.send_response(200 if self.headers.get("Authorization") == "netns-test-token" else 401)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def start_agent(tmp, agent_path, shim_port, hop_limit, ca_file, extra=(), check_seconds=1, path=None, tag=""):
    cfg = common.golden_config()  # production network settings: netns openinfra-imds, 169.254.169.254:80
    cfg["imds"]["hopLimit"] = hop_limit
    cfg["imds"]["guardInterfaces"] = list(extra)
    cfg["imds"]["guardCheckSeconds"] = check_seconds
    cfg["credentialsUrl"] = "https://127.0.0.1:%d/v1/vm-credentials" % shim_port
    cfg["caFile"] = ca_file
    cfg["tokenFile"] = os.path.join(tmp, "token")
    cfg["userDataFile"] = ""
    cfg["trustPlatformCA"] = False  # a netns does not isolate the filesystem: never touch the host trust store
    cfg["caBundleLink"] = ""        # ... nor /etc/openinfra
    name = "agent-%d%s" % (hop_limit, tag)
    cfg_path = os.path.join(tmp, name + ".json")
    with open(cfg_path, "w") as fh:
        json.dump(cfg, fh)
    log = open(os.path.join(tmp, name + ".log"), "w")
    env = dict(os.environ)
    if path is not None:
        env["PATH"] = path
    proc = subprocess.Popen([sys.executable, agent_path, cfg_path], stdout=log, stderr=log, env=env)
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


def from_ns(ns, method, path, ttl="60"):
    return sh("ip", "netns", "exec", ns, sys.executable, "-c", CLIENT, method, path, ttl).strip()


def container(method, path, ttl="60"):
    return from_ns(CTR_NS, method, path, ttl)


def lan_host(method, path, ttl="60"):
    return from_ns(LAN_NS, method, path, ttl)


def nft_tables():
    if not shutil.which("nft"):
        return []
    return [f for f in ("ip", "bridge") if quiet("nft", "list", "table", f, "openinfra_imds") == 0]


def ipt_guard():
    return bool(shutil.which("iptables")) and quiet("iptables", "-w", "-t", "raw", "-S", "OPENINFRA-IMDS") == 0


def guard_present():
    return bool(nft_tables()) or ipt_guard()


def wait_for(cond, seconds=8):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.25)
    return cond()


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


def iptables_only_path(tmp):
    """A PATH with iptables but no nft: the agent's iptables fallback."""
    d = os.path.join(tmp, "iptables-only")
    os.makedirs(d, exist_ok=True)
    # A symlink named iptables: the xtables multi-binary dispatches on its own name.
    if not os.path.exists(os.path.join(d, "iptables")):
        os.symlink(shutil.which("iptables"), os.path.join(d, "iptables"))
    return d


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
    port = shim.server_address[1]
    failures = []

    def check(name, ok, detail=""):
        say("%s: %s%s" % (name, "ok" if ok else "FAILED", (" (" + detail + ")") if detail and not ok else ""))
        if not ok:
            failures.append(name)

    has_nft, has_ipt = bool(shutil.which("nft")), bool(shutil.which("iptables"))
    proc = None
    try:
        if has_nft:
            # Control: with the guard removed (and the watchdog asleep), both LAN hosts DO reach IMDS through
            # the forwarding guest, so the checks below measure the guard, not the topology.
            proc = start_agent(tmp, agent_path, port, hop_limit=1, ca_file=pki["root"], check_seconds=3600, tag="-control")
            check("the guard is installed by interface kind (tables ip + bridge)", nft_tables() == ["ip", "bridge"], str(nft_tables()))
            quiet("nft", "delete", "table", "ip", "openinfra_imds")
            quiet("nft", "delete", "table", "bridge", "openinfra_imds")
            got = lan_host("GET", "/latest/meta-data/instance-id")
            check("control: without the guard, a LAN host on a VLAN reaches IMDS through the guest", got == "200", got)
            got = from_ns(BRLAN_NS, "GET", "/latest/meta-data/instance-id")
            check("control: without the guard, a LAN host behind a bridge port reaches IMDS", got == "200", got)
            stop(proc)

        proc = start_agent(tmp, agent_path, port, hop_limit=1, ca_file=pki["root"])
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
        tool = "nft" if has_nft else ("iptables" if has_ipt else "")
        if tool:
            got = container("GET", "/latest/meta-data/instance-id")
            check("IMDSv1 GET from a routed container (veth) is not hop-limited", got == "200", got)
        else:
            say("(no nft/iptables: the route fallback leaves a routed container without IMDS, as documented)")
        if has_nft:
            got = from_ns(BRCTR_NS, "GET", "/latest/meta-data/instance-id")
            check("a container on a bridge reaches IMDS (its bridge port is a veth)", got == "200", got)
        got = lan_host("GET", "/latest/meta-data/iam/security-credentials/app-role")
        check("a LAN host on a VLAN is dropped (%s)" % (tool or "route fallback"), got == "TIMEOUT", got)
        got = lan_host("PUT", "/latest/api/token")
        check("... and gets no IMDSv2 token either", got == "TIMEOUT", got)
        got = from_ns(BRLAN_NS, "GET", "/latest/meta-data/iam/security-credentials/app-role")
        check("a LAN host behind a bridge port (a VLAN, not a container) is dropped", got == "TIMEOUT", got)
        if tool:
            check("the forwarded-metadata guard is installed", guard_present())
        if has_nft:
            quiet("nft", "flush", "ruleset")
            check("after `nft flush ruleset` the watchdog puts the guard back", wait_for(lambda: nft_tables() == ["ip", "bridge"]))
            got = lan_host("GET", "/latest/meta-data/instance-id")
            check("... and the LAN host is dropped again", got == "TIMEOUT", got)
        if masquerade(True):
            got = container("PUT", "/latest/api/token")
            check("hop limit 1: a MASQUERADEd (docker-style) container gets NO token", got == "TIMEOUT", got)
            masquerade(False)
        else:
            say("(iptables not available: docker-style MASQUERADE path not exercised)")
        stop(proc, signal.SIGKILL)  # leave a stale namespace behind

        proc = start_agent(tmp, agent_path, port, hop_limit=2, ca_file=pki["root"])
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
        check("SIGTERM removes the forwarded-metadata guard", not guard_present(), str(nft_tables()))

        if tool:
            proc = start_agent(tmp, agent_path, port, hop_limit=1, ca_file=pki["root"], extra=[CTR_HOST_IF], tag="-extra")
            got = container("GET", "/latest/meta-data/instance-id")
            check("an interface in guardInterfaces is refused even though it is a container's veth", got == "TIMEOUT", got)
            stop(proc)

        if has_ipt and has_nft:  # (without nft, the main run above already was the iptables path)
            proc = start_agent(tmp, agent_path, port, hop_limit=1, ca_file=pki["root"], path=iptables_only_path(tmp), tag="-iptables")
            check("iptables only: the guard is an iptables chain, no nft table", ipt_guard() and not nft_tables(), str(nft_tables()))
            got = container("GET", "/latest/meta-data/instance-id")
            check("iptables only: the routed container (veth) reaches IMDS", got == "200", got)
            got = lan_host("GET", "/latest/meta-data/instance-id")
            check("iptables only: the LAN host on a VLAN is dropped", got == "TIMEOUT", got)
            got = from_ns(BRLAN_NS, "GET", "/latest/meta-data/instance-id")
            check("iptables only: the LAN host behind the bridge is dropped", got == "TIMEOUT", got)
            got = from_ns(BRCTR_NS, "GET", "/latest/meta-data/instance-id")
            check("iptables only: a container on a bridge that also holds a VLAN port is refused too (documented)",
                  got == "TIMEOUT", got)
            quiet("iptables", "-w", "-t", "raw", "-F", "PREROUTING")
            check("after `iptables -t raw -F PREROUTING` the watchdog puts the jump back",
                  wait_for(lambda: quiet("iptables", "-w", "-t", "raw", "-C", "PREROUTING", "-d", IMDS + "/32",
                                         "-j", "OPENINFRA-IMDS") == 0))
            got = lan_host("GET", "/latest/meta-data/instance-id")
            check("... and the LAN host is dropped again", got == "TIMEOUT", got)
            stop(proc)
            check("SIGTERM removes the iptables guard", not ipt_guard())
    finally:
        if proc is not None and proc.poll() is None:
            stop(proc)
        shim.shutdown()
    if failures:
        for name in sorted(os.listdir(tmp)):
            if name.endswith(".log"):
                say("---- %s ----\n%s" % (name, open(os.path.join(tmp, name)).read()))
        raise SystemExit("FAIL: " + "; ".join(failures))
    say("PASS: metadata namespace, port-80 coexistence, EC2 hop-limit semantics, and the forwarded-traffic guard "
        "(by interface kind, re-applied when removed) hold in the kernel")


if __name__ == "__main__":
    main()
