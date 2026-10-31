#!/usr/bin/env python3
# #347 Phase 2.12 (§3.4): prove the container-credentials env the VM composition renders actually
# works with REAL aws CLIs — the class of bug #11 fixed (a wrong env-var name no unit test catches).
#
# We extract the EXACT env the composition writes (var names + the loopback port + the token path)
# from platform/abstraction/vm-composition.yaml, stand up a stub that plays both the shim's
# /v1/vm-credentials endpoint and an STS GetCallerIdentity endpoint, then run each installed aws CLI
# with that env and assert it fetched credentials with the token as its Authorization header.
#
# Drift guard: the env var names come from the composition. If the token-file var regresses to a name
# the SDK doesn't honor (e.g. the old AWS_CONTAINER_CREDENTIALS_TOKEN_FILE), the CLI sends no auth and
# the stub assertion fails — exactly the #11 regression.
#
# aws-cli v2 is a HARD gate. A distro v1 (older botocore) is run best-effort and reported: old SDKs
# that don't support AUTHORIZATION_TOKEN_FILE are the motivation for the #13 relay-injects-header
# follow-on, so we document v1's result rather than failing on an SDK-age limitation.

import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
COMPOSITION = os.path.join(REPO, "platform", "abstraction", "vm-composition.yaml")
TOKEN_VALUE = "oidc-test-token-A1B2C3.notarealjwt.payload"  # single line, no whitespace


def extract_env_from_composition():
    """Pull the rendered container-credentials env out of the VM composition."""
    text = open(COMPOSITION).read()
    m_tok = re.search(r"(AWS_CONTAINER_\w*TOKEN_FILE)=(\S+?)(?:\\n|\s|\")", text)
    if not m_tok:
        sys.exit("FAIL: no AWS_CONTAINER_*TOKEN_FILE assignment found in vm-composition.yaml")
    token_var, token_path = m_tok.group(1), m_tok.group(2)
    if not re.search(r"AWS_CONTAINER_CREDENTIALS_FULL_URI", text):
        sys.exit("FAIL: no AWS_CONTAINER_CREDENTIALS_FULL_URI in vm-composition.yaml")
    m_port = re.search(r'\$credsPort\s*:=\s*"(\d+)"', text)
    if not m_port:
        sys.exit("FAIL: could not extract $credsPort from vm-composition.yaml")
    m_path = re.search(r'printf\s+"http://127\.0\.0\.1:%s(/\S+?)"', text)
    cred_path = m_path.group(1) if m_path else "/v1/vm-credentials"
    return token_var, token_path, int(m_port.group(1)), cred_path


class Stub(http.server.BaseHTTPRequestHandler):
    cred_auth_seen = None  # the Authorization header the CLI sent on the creds request
    cred_path = "/v1/vm-credentials"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == self.cred_path:
            Stub.cred_auth_seen = self.headers.get("Authorization")
            body = json.dumps({
                "AccessKeyId": "AKIAEXAMPLE",
                "SecretAccessKey": "secretExampleKey",
                "Token": "sessionExampleToken",
                "Expiration": "2099-01-01T00:00:00Z",
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):  # the signed STS GetCallerIdentity call lands here
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        body = (b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
                b"<GetCallerIdentityResult><Arn>arn:aws:iam::000000000000:role/vm</Arn>"
                b"<UserId>AROAEXAMPLE</UserId><Account>000000000000</Account>"
                b"</GetCallerIdentityResult></GetCallerIdentityResponse>")
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_cli(aws_bin, env, port):
    Stub.cred_auth_seen = None
    proc = subprocess.run(
        [aws_bin, "sts", "get-caller-identity", "--endpoint-url", f"http://127.0.0.1:{port}"],
        env=env, capture_output=True, text=True, timeout=60,
    )
    return proc, Stub.cred_auth_seen


def main():
    token_var, token_path, port, cred_path = extract_env_from_composition()
    Stub.cred_path = cred_path
    print(f"composition renders: FULL_URI port={port} path={cred_path}  token-file var={token_var}")

    # Hard-fail if the token-file var regressed to a name the SDKs don't honor.
    if token_var != "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE":
        sys.exit(f"FAIL: token-file env var is {token_var}, but the AWS SDKs only honor "
                 f"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE (#347 Phase 2.11 regression)")

    tmp = tempfile.mkdtemp()
    tok = os.path.join(tmp, "token")
    with open(tok, "w") as fh:
        fh.write(TOKEN_VALUE)  # no trailing newline, as the composition materializes it

    srv = http.server.HTTPServer(("127.0.0.1", port), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # wait for the listener
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)

    base_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": tmp,
        "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": f"http://127.0.0.1:{port}{cred_path}",
        token_var: tok,
    }

    # Discover installed CLIs by probing the usual locations (PATH order can let an apt v1 shadow the
    # preinstalled v2, so we check both explicitly). aws-cli v2 is the hard gate; a distro v1 is
    # best-effort. Dedup by resolved path.
    candidates = []
    seen = set()
    for p in filter(None, [shutil.which("aws"), "/usr/local/bin/aws", "/usr/bin/aws"]):
        rp = os.path.realpath(p)
        if not os.path.exists(p) or rp in seen:
            continue
        seen.add(rp)
        ver = subprocess.run([p, "--version"], capture_output=True, text=True)
        tag = "v2" if "aws-cli/2" in (ver.stderr + ver.stdout) else "v1"
        candidates.append(("aws", p, tag))

    if not any(c[2] == "v2" for c in candidates):
        sys.exit("FAIL: aws-cli v2 not found on PATH — the CI job must install it")

    hard_ok = False
    for label, aws_bin, tag in candidates:
        env = dict(base_env)
        proc, auth = run_cli(aws_bin, env, port)
        got_creds = auth is not None
        auth_ok = auth == TOKEN_VALUE
        ok = proc.returncode == 0 and auth_ok
        print(f"[{label} {tag} {aws_bin}] exit={proc.returncode} creds-fetched={got_creds} "
              f"auth-matches-token={auth_ok}")
        if not ok and proc.returncode != 0:
            print("  stderr:", proc.stderr.strip()[:400])
        if tag == "v2":
            if not ok:
                sys.exit(f"FAIL: aws-cli v2 did not resolve container credentials with the "
                         f"composition env (creds-fetched={got_creds}, auth-matches={auth_ok}). "
                         f"This is the end-to-end check for the #11 env-var fix.")
            hard_ok = True
        else:
            if ok:
                print("  v1 honors AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE too.")
            else:
                print("  NOTE: this distro v1 did not authenticate via the token file — an old-SDK "
                      "limitation that the #13 relay-injects-Authorization follow-on addresses. "
                      "Not failing the gate on SDK age.")

    srv.shutdown()
    print("PASS: aws-cli v2 resolves VM container credentials with the composition's rendered env"
          if hard_ok else "FAIL")
    sys.exit(0 if hard_ok else 1)


if __name__ == "__main__":
    main()
