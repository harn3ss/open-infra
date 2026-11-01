#!/usr/bin/env python3
# #347 items 13 + 14: real aws CLIs get a VM's role credentials from the in-guest metadata agent the VM
# composition ships, through both paths a guest uses:
#
#   1. Container credentials with AWS_CONTAINER_CREDENTIALS_FULL_URI ALONE (the only env the composition
#      renders — no token variable). The agent adds the Authorization header to the shim itself, so even
#      an SDK that predates AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE gets credentials.
#   2. EC2 instance metadata, with NO container-credentials env: the CLI's instance-profile provider
#      fetches an IMDSv2 token and the role credentials. CI runners have their own cloud's metadata
#      service at 169.254.169.254, so the agent listens on loopback here and the CLI is pointed at it
#      with AWS_EC2_METADATA_SERVICE_ENDPOINT. A second run with httpTokens=required proves the CLI
#      completed the IMDSv2 handshake (token-less IMDSv1 GETs are refused).
#   3. The platform CA (#347 item 15): aws-cli v2 ships its OWN CA store and ignores the system's, so the
#      composition also renders AWS_CA_BUNDLE naming the path the agent keeps pointing at the FULL system
#      bundle. Against a TLS stub whose certificate a throwaway test root signs, the CLI succeeds with
#      AWS_CA_BUNDLE -> (system bundle + that root, linked by the agent's own code) and fails without it.
#
# The agent is the exact text extracted from platform/abstraction/vm-composition.yaml, run as a real
# process with the golden config (pinned to the composition's render by test/render) re-pointed at a stub
# that plays the aws-shim's /v1/vm-credentials endpoint over TLS, which the agent verifies against a
# throwaway test root as a guest verifies the shim against the platform root (the stub refuses any request
# whose Authorization is not the VM token), and STS (it records which access key signed the call).
#
# aws-cli v2 is the hard gate. A distro aws CLI (older botocore) is run too and must pass the
# container-credentials path; its IMDS result is reported (an old botocore may not honor
# AWS_EC2_METADATA_SERVICE_ENDPOINT, which only this test needs).

import http.client
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading

import vmcreds_common as common
from vmcreds_common import say

TOKEN_VALUE = "oidc-test-token-A1B2C3.notarealjwt.payload"
CREDS = {
    "AccessKeyId": "ASIAVMCREDSCLITEST01",
    "SecretAccessKey": "secretExampleKey",
    "Token": "sessionExampleToken",
    "Expiration": "2099-01-01T00:00:00Z",
}


class Stub(http.server.BaseHTTPRequestHandler):
    shim_calls = []  # Authorization header of every /v1/vm-credentials request
    sts_calls = []   # (Authorization, X-Amz-Security-Token) of every signed STS call

    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype):
        b = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path != "/v1/vm-credentials":
            return self._send(404, "not found", "text/plain")
        auth = self.headers.get("Authorization")
        Stub.shim_calls.append(auth)
        if auth != TOKEN_VALUE:
            return self._send(401, "missing credential token", "text/plain")
        self._send(200, json.dumps(CREDS), "application/json")

    def do_POST(self):  # the signed STS GetCallerIdentity call
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        Stub.sts_calls.append((self.headers.get("Authorization") or "", self.headers.get("X-Amz-Security-Token")))
        self._send(200, '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
                        "<GetCallerIdentityResult><Arn>arn:aws:sts::open-infra:assumed-role/app-role/vm</Arn>"
                        "<UserId>AROAEXAMPLE:vm</UserId><Account>open-infra</Account>"
                        "</GetCallerIdentityResult></GetCallerIdentityResponse>", "text/xml")


class AgentProcess(object):
    def __init__(self, tmp, agent_path, tls, http_tokens, relay):
        cfg = common.golden_config()
        self.relay = (cfg["relay"]["address"], int(cfg["relay"]["port"]))
        self.imds_port = common.free_port()
        # The shim's /v1/vm-credentials over TLS, verified against the (test) platform root only.
        cfg["credentialsUrl"] = "https://127.0.0.1:%d/v1/vm-credentials" % tls.port
        cfg["caFile"] = tls.ca
        cfg["tokenFile"] = os.path.join(tmp, "token")
        cfg["userDataFile"] = os.path.join(tmp, "user-data")
        cfg["imds"].update({"netns": "", "address": "127.0.0.1", "port": self.imds_port, "httpTokens": http_tokens})
        cfg["relay"]["enabled"] = relay
        cfg["trustPlatformCA"] = False  # never touch the runner's trust store (metadata_agent_test covers it)
        cfg["caBundleLink"] = ""        # nor /etc/openinfra (the TLS check links a temp path itself)
        self.cfg_path = os.path.join(tmp, "agent-%s.json" % http_tokens)
        with open(self.cfg_path, "w") as fh:
            json.dump(cfg, fh)
        self.log_path = os.path.join(tmp, "agent-%s.log" % http_tokens)
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen([sys.executable, agent_path, self.cfg_path], stdout=self.log, stderr=self.log)
        common.wait_port("127.0.0.1", self.imds_port, proc=self.proc)
        if relay:
            common.wait_port(self.relay[0], self.relay[1], proc=self.proc)

    def imds(self, method, path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.imds_port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            r = conn.getresponse()
            return r.status, r.read().decode()
        finally:
            conn.close()

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()

    def dump(self):
        with open(self.log_path) as fh:
            say("---- agent log ----\n" + fh.read() + "-------------------")


def find_clis():
    """Installed aws CLIs as [(path, "v1"|"v2")]: PATH order can let an apt v1 shadow a v2, so probe the
    usual locations explicitly. Dedup by resolved path."""
    out, seen = [], set()
    for p in filter(None, [shutil.which("aws"), "/usr/local/bin/aws", "/usr/bin/aws"]):
        rp = os.path.realpath(p)
        if not os.path.exists(p) or rp in seen:
            continue
        seen.add(rp)
        ver = subprocess.run([p, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        text = ver.stdout + ver.stderr
        out.append((p, "v2" if "aws-cli/2" in text else "v1", text.strip().split(" ")[0]))
    return out


def run_cli(aws_bin, env, stub_port, endpoint=None):
    """`aws sts get-caller-identity` -> (ok, detail, stderr). ok = exit 0 AND signed with the role creds."""
    del Stub.sts_calls[:]
    endpoint = endpoint or "http://127.0.0.1:%d" % stub_port
    p = subprocess.run([aws_bin, "sts", "get-caller-identity", "--endpoint-url", endpoint],
                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=90)
    signed = any(("Credential=%s/" % CREDS["AccessKeyId"]) in a and t == CREDS["Token"] for a, t in Stub.sts_calls)
    ok = p.returncode == 0 and signed
    detail = "exit=%d signed-with-role-creds=%s" % (p.returncode, signed)
    if not ok:
        detail += "\n    stderr: " + p.stderr.strip()[-600:]
    return ok, detail, p.stderr


def openssl(*args):
    subprocess.run(["openssl"] + list(args), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class TLSStub(object):
    """The same stub over HTTPS, with a server certificate for 127.0.0.1 signed by a throwaway test root."""

    def __init__(self, tmp):
        d = os.path.join(tmp, "tls")
        os.makedirs(d)
        self.ca = os.path.join(d, "test-root.crt")
        key, csr, crt, ext = (os.path.join(d, n) for n in ("server.key", "server.csr", "server.crt", "server.ext"))
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", os.path.join(d, "test-root.key"), "-out", self.ca, "-days", "2",
                "-subj", "/CN=vm-creds test root CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", key,
                "-out", csr, "-subj", "/CN=127.0.0.1")
        with open(ext, "w") as fh:
            fh.write("subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n"
                     "basicConstraints=critical,CA:FALSE\n")
        openssl("x509", "-req", "-in", csr, "-CA", self.ca, "-CAkey", os.path.join(d, "test-root.key"),
                "-CAcreateserial", "-out", crt, "-days", "2", "-extfile", ext)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), Stub)
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def publish_bundle(self, agent_mod, tmp):
        """What the guest ends up with: the distro's full system bundle once the trust-store tool has added
        the platform root (simulated: this host's system bundle + the test root), and the agent's own
        publish_ca_bundle() pointing the AWS_CA_BUNDLE path at it. Returns (link, public roots kept)."""
        store = agent_mod.trust_store()
        system = agent_mod.system_bundle(store[0] if store else None)
        public = open(system).read() if system else ""
        full = os.path.join(tmp, "tls", "system-bundle.pem")
        with open(full, "w") as fh:
            fh.write(public.rstrip("\n") + "\n" + open(self.ca).read() if public else open(self.ca).read())
        link = os.path.join(tmp, "openinfra", "ca-bundle.pem")
        if agent_mod.publish_ca_bundle(link, bundle=lambda family: full) not in ("linked", "unchanged"):
            raise SystemExit("FAIL: the agent could not link %s" % link)
        return link, public.count("BEGIN CERTIFICATE")

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def main():
    env_all = common.composition_env()
    full_uri = env_all["AWS_CONTAINER_CREDENTIALS_FULL_URI"]
    env_rendered = {"AWS_CONTAINER_CREDENTIALS_FULL_URI": full_uri}
    golden = common.golden_config()
    relay_uri = "http://%s:%d/v1/vm-credentials" % (golden["relay"]["address"], golden["relay"]["port"])
    say("composition renders %s (and no token variable)" % ", ".join("%s=%s" % kv for kv in sorted(env_all.items())))
    if full_uri != relay_uri:
        sys.exit("FAIL: FULL_URI %s is not the agent's credentials endpoint %s" % (full_uri, relay_uri))
    if env_all["AWS_CA_BUNDLE"] != golden["caBundleLink"]:
        sys.exit("FAIL: AWS_CA_BUNDLE %s is not the path the agent maintains (%s)" % (env_all["AWS_CA_BUNDLE"], golden["caBundleLink"]))

    clis = find_clis()
    for path, tag, ver in clis:
        say("found %s (%s) at %s" % (ver, tag, path))
    if not any(tag == "v2" for _, tag, _ in clis):
        sys.exit("FAIL: aws-cli v2 not found — the CI job must provide it")

    tmp = tempfile.mkdtemp(prefix="vm-creds-cli-")
    with open(os.path.join(tmp, "token"), "w") as fh:
        fh.write(TOKEN_VALUE + "\n")  # the agent strips whitespace before sending it
    with open(os.path.join(tmp, "user-data"), "w") as fh:
        fh.write("#!/bin/bash\necho hello\n")
    agent_path = common.write_agent(tmp)

    stub = http.server.HTTPServer(("127.0.0.1", 0), Stub)
    stub_port = stub.server_address[1]
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    if not shutil.which("openssl"):
        sys.exit("FAIL: openssl is needed to mint the TLS stub's test certificates")
    tls = TLSStub(tmp)  # the shim's in-cluster TLS port, and a platform-CA endpoint for the CLI checks

    base = {"PATH": os.environ.get("PATH", ""), "HOME": tmp, "AWS_REGION": "us-east-1",
            "AWS_DEFAULT_REGION": "us-east-1", "AWS_PAGER": ""}
    failures, notes = [], []

    agent = AgentProcess(tmp, agent_path, tls, "optional", relay=True)
    try:
        # --- the raw IMDSv2 contract, against the running agent ---
        checks = [
            ("PUT token without TTL header -> 400", agent.imds("PUT", "/latest/api/token")[0] == 400),
            ("PUT token with X-Forwarded-For -> 403",
             agent.imds("PUT", "/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "60",
                                                     "X-Forwarded-For": "203.0.113.7"})[0] == 403),
        ]
        st, token = agent.imds("PUT", "/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
        checks.append(("PUT token -> 200", st == 200 and len(token) > 20))
        st, body = agent.imds("GET", "/latest/meta-data/iam/security-credentials/", {"X-aws-ec2-metadata-token": token})
        checks.append(("role listed under iam/security-credentials/", (st, body) == (200, golden["role"])))
        st, body = agent.imds("GET", "/latest/meta-data/iam/security-credentials/" + golden["role"],
                              {"X-aws-ec2-metadata-token": token})
        doc = json.loads(body) if st == 200 else {}
        checks.append(("role credentials in the EC2 shape",
                       doc.get("Code") == "Success" and doc.get("Type") == "AWS-HMAC"
                       and doc.get("AccessKeyId") == CREDS["AccessKeyId"]))
        checks.append(("user-data served", agent.imds("GET", "/latest/user-data")[1] == "#!/bin/bash\necho hello\n"))
        checks.append(("IMDSv1 GET allowed with httpTokens=optional",
                       agent.imds("GET", "/latest/meta-data/instance-id") == (200, golden["instanceId"])))
        for name, ok in checks:
            say("[imds] %s: %s" % (name, "ok" if ok else "FAILED"))
            if not ok:
                failures.append("imds: " + name)

        # --- the CLIs, through both credential paths ---
        for aws_bin, tag, ver in clis:
            env = dict(base)
            env.update(env_rendered)                 # FULL_URI only — exactly what the guest gets
            env["AWS_EC2_METADATA_DISABLED"] = "true"  # so only the container provider can answer
            ok, detail, _ = run_cli(aws_bin, env, stub_port)
            say("[%s %s] container credentials via FULL_URI alone: %s" % (ver, aws_bin, detail))
            if not ok:
                failures.append("%s: container credentials via FULL_URI alone" % ver)

            env = dict(base)
            env["AWS_EC2_METADATA_SERVICE_ENDPOINT"] = "http://127.0.0.1:%d/" % agent.imds_port
            ok, detail, _ = run_cli(aws_bin, env, stub_port)
            say("[%s %s] instance metadata (IMDS), no container env: %s" % (ver, aws_bin, detail))
            if not ok:
                (failures if tag == "v2" else notes).append("%s: IMDS credentials" % ver)

        # --- the platform CA: AWS_CA_BUNDLE -> the full system bundle (#347 item 15) ---
        link, public = tls.publish_bundle(common.load_agent_module(tmp), tmp)
        say("[tls] AWS_CA_BUNDLE path %s -> system bundle (%d public roots) + the test root" % (link, public))
        if public == 0:
            notes.append("no system CA bundle on this host: public roots not exercised")
        for aws_bin, tag, ver in clis:
            env = dict(base, AWS_EC2_METADATA_DISABLED="true", **env_rendered)
            https = "https://127.0.0.1:%d" % tls.port
            ok, detail, _ = run_cli(aws_bin, dict(env, AWS_CA_BUNDLE=link), stub_port, endpoint=https)
            say("[%s %s] TLS to a platform-CA endpoint with AWS_CA_BUNDLE: %s" % (ver, aws_bin, detail))
            if not ok:
                failures.append("%s: TLS with AWS_CA_BUNDLE" % ver)
            bad, detail, err = run_cli(aws_bin, env, stub_port, endpoint=https)
            refused = not bad and ("CERTIFICATE_VERIFY_FAILED" in err or "SSL" in err)
            say("[%s %s] ... and without it the CLI's own CA store refuses it: %s"
                % (ver, aws_bin, "yes" if refused else "NO (" + detail + ")"))
            if not refused:
                (failures if tag == "v2" else notes).append("%s: TLS without AWS_CA_BUNDLE was not refused" % ver)
    finally:
        agent.stop()
    if failures:
        agent.dump()

    # --- httpTokens=required: IMDSv1 is refused, the CLI still succeeds (so it used IMDSv2) ---
    agent = AgentProcess(tmp, agent_path, tls, "required", relay=False)
    try:
        ok = agent.imds("GET", "/latest/meta-data/instance-id")[0] == 401
        say("[imds required] token-less GET -> 401: %s" % ("ok" if ok else "FAILED"))
        if not ok:
            failures.append("imds required: token-less GET not refused")
        for aws_bin, tag, ver in clis:
            env = dict(base)
            env["AWS_EC2_METADATA_SERVICE_ENDPOINT"] = "http://127.0.0.1:%d/" % agent.imds_port
            ok, detail, _ = run_cli(aws_bin, env, stub_port)
            say("[%s %s] IMDS with httpTokens=required (IMDSv2 handshake): %s" % (ver, aws_bin, detail))
            if not ok:
                (failures if tag == "v2" else notes).append("%s: IMDSv2 with httpTokens=required" % ver)
    finally:
        agent.stop()
        stub.shutdown()
        tls.stop()

    bad_auth = [a for a in Stub.shim_calls if a != TOKEN_VALUE]
    say("shim saw %d credential requests; Authorization was the VM token on all of them: %s"
        % (len(Stub.shim_calls), not bad_auth))
    if not Stub.shim_calls or bad_auth:
        failures.append("the agent must authenticate to the shim with the VM token (saw %r)" % bad_auth[:3])

    for n in notes:
        say("NOTE (best-effort, distro CLI): " + n)
    if failures:
        agent.dump()
        sys.exit("FAIL:\n  " + "\n  ".join(failures))
    say("PASS: aws CLIs resolve VM role credentials from the composition's metadata agent "
        "(FULL_URI alone, and IMDSv2) and trust the platform CA through AWS_CA_BUNDLE")
    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
