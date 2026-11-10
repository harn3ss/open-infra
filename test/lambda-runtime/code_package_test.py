#!/usr/bin/env python3
# Tests for the Lambda runtime bootstraps' stored-deployment-package code source (OPENINFRA_CODE_URL,
# #402): the platform keeps a function's .zip and the function's pod fetches it from the aws-shim with
# its own identity token, checks its SHA-256 and unpacks it into the task dir. Each first-party bootstrap
# — lambda-runtime/python/bootstrap.py, lambda-runtime/nodejs/bootstrap.js and lambda-runtime/dotnet
# (dotnet8) — is run as its image runs it, as a process, against a stub aws-shim on loopback.
#
# Covered, per runtime: the package unpacks into the task dir and its handler serves; a SHA-256 mismatch,
# a refusal (401, a redirect), a package over 64 MiB, an entry that would unpack outside the task dir,
# both code sources at once, and a missing SHA-256 or token each fail start (exit 2) with nothing
# unpacked; a 503 and a download cut short are retried, and five failed attempts fail start. The token is
# sent as a bearer and never logged, no proxy is used, and the temp file is always removed. The python
# bootstrap never imports boto3 on this path.
#
# stdlib only, Python 3.6-compatible, no root, no cluster. The python runtime always runs (this
# interpreter); node (with the system unzip it uses) and dotnet run when they are on PATH, and are
# skipped, saying so, when not. OPENINFRA_TASK_DIR (each image's own ENV) points the task dir at a temp dir.
#
#   python3 test/lambda-runtime/code_package_test.py
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler

try:
    from http.server import ThreadingHTTPServer
except ImportError:  # Python 3.6
    import socketserver
    from http.server import HTTPServer

    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUNTIMES = os.path.join(REPO, "lambda-runtime")
CAP = 64 * 1024 * 1024
TOKEN = "eyJhbGciOiJSUzI1NiJ9.token-sentinel-never-logged.c2lnbmF0dXJl"
TMP = tempfile.mkdtemp(prefix="oi-code-pkg-test-")


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class StubShim:
    """The aws-shim's /v1/function-code, scripted: each request takes the next step (the last repeats).
    A step is (status, body) or (status, body, mode): mode "truncate" declares the full length and sends
    half; "declare" sends only headers declaring `body` (an int) bytes; "stream" sends `body` (an int)
    bytes with no length, closing the connection to end them."""

    def __init__(self):
        self.script = []
        self.requests = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                stub.requests.append({"path": self.path, "authorization": self.headers.get("Authorization")})
                step = stub.script.pop(0) if len(stub.script) > 1 else stub.script[0]
                status, body = step[0], step[1]
                mode = step[2] if len(step) > 2 else ""
                try:
                    self.send_response(status)
                    if status in (301, 302, 307, 308):
                        self.send_header("Location", "/elsewhere")
                    if mode == "declare":
                        self.send_header("Content-Length", str(body))
                        self.end_headers()
                    elif mode == "stream":
                        self.end_headers()
                        chunk = b"\0" * (1024 * 1024)
                        left = body
                        while left > 0:
                            self.wfile.write(chunk[:min(left, len(chunk))])
                            left -= len(chunk)
                    elif mode == "truncate":
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body[: len(body) // 2])
                    else:
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the bootstrap gave up on the body, as it should

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d/v1/function-code" % self.httpd.server_address[1]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Run:
    def __init__(self, returncode, stderr, served, invoked):
        self.returncode, self.stderr, self.served, self.invoked = returncode, stderr, served, invoked


def run_bootstrap(cmd, env, timeout=60):
    """Run a bootstrap until it exits or serves. When it serves, invoke it once (direct) and stop it."""
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            universal_newlines=True)
    lines, serving = [], threading.Event()

    def read():
        for line in proc.stderr:
            lines.append(line)
            if "open-infra-runtime: serving " in line:
                serving.set()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    deadline = time.time() + timeout
    while time.time() < deadline and proc.poll() is None and not serving.is_set():
        time.sleep(0.02)
    hung = proc.poll() is None and not serving.is_set()
    invoked = None
    if serving.is_set() and proc.poll() is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request("http://127.0.0.1:%s/" % env["PORT"], data=b'{"k":"v"}',
                                     headers={"X-Openinfra-Invoke": "direct", "Content-Type": "application/json"})
        for _ in range(100):  # the listener opens just after the "serving" line
            try:
                with opener.open(req, timeout=10) as r:
                    invoked = json.loads(r.read().decode())
                break
            except OSError:
                time.sleep(0.05)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    reader.join(10)
    proc.stderr.close()
    if hung:
        raise AssertionError("bootstrap neither served nor exited in %ss:\n%s" % (timeout, "".join(lines)))
    return Run(proc.returncode, "".join(lines), serving.is_set(), invoked)


class CodePackageCases:
    """The stored-package cases, run against one runtime. A subclass sets the runtime up in setUpClass:
    cls.cmd (the bootstrap command), cls.handler (OPENINFRA_HANDLER) and cls.handler_entries (the zip
    entries that make a package whose handler returns {"from": "package", "event": <event>})."""

    cmd = None
    handler = None
    handler_entries = None

    def setUp(self):
        self.stub = StubShim()
        self.addCleanup(self.stub.close)
        self.work = tempfile.mkdtemp(dir=TMP)
        self.task = os.path.join(self.work, "task")
        self.tmpdir = os.path.join(self.work, "tmp")
        os.makedirs(self.task)
        os.makedirs(self.tmpdir)
        self.token_file = os.path.join(self.work, "token")
        with open(self.token_file, "w") as f:
            f.write(TOKEN + "\n")  # projected tokens are trimmed before use

    def package(self, extra=()):
        return make_zip(list(self.handler_entries) + [("lib/data.txt", b"from the package\n")] + list(extra))

    def env(self, sha, **over):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("OPENINFRA_", "AWS_")) and k.lower() not in ("no_proxy", "http_proxy", "https_proxy")}
        env.update({
            "OPENINFRA_HANDLER": self.handler,
            "OPENINFRA_TASK_DIR": self.task,
            "OPENINFRA_OPT_DIR": os.path.join(self.work, "opt"),
            "OPENINFRA_CODE_URL": self.stub.url,
            "OPENINFRA_CODE_SHA256": sha,
            "OPENINFRA_CODE_TOKEN_FILE": self.token_file,
            "PORT": str(free_port()),
            "TMPDIR": self.tmpdir,
            # As the .NET image runs its host (lambda-runtime/dotnet/Dockerfile): no diagnostics IPC, whose
            # pipes and socket .NET 10 would otherwise leave in TMPDIR beside the runtime's own temp files.
            "DOTNET_EnableDiagnostics": "0",
            # A dead proxy: a bootstrap that sent the token through a proxy could not reach the stub at all.
            "HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",  # as the python image sets it: stderr is block-buffered on a pipe before 3.9
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        })
        env.update(self.extra_env())
        for k, v in over.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
        return env

    def extra_env(self):
        return {}

    def run_with(self, script, sha, **over):
        self.stub.script = list(script)
        r = run_bootstrap(self.cmd, self.env(sha, **over))
        self.assertNotIn(TOKEN, r.stderr, "the identity token must never be logged")
        self.assertEqual(os.listdir(self.tmpdir), [], "the downloaded package's temp file is removed")
        for req in self.stub.requests:
            self.assertEqual(req["path"], "/v1/function-code")
            self.assertEqual(req["authorization"], "Bearer " + TOKEN, "the token is sent as a bearer, trimmed")
        return r

    def assertFailedStart(self, r, *phrases):
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertFalse(r.served, r.stderr)
        for p in phrases:
            self.assertIn(p, r.stderr)
        self.assertNotIn("unpacked the deployment package", r.stderr)

    def assertServedFromPackage(self, r, pkg):
        self.assertTrue(r.served, r.stderr)
        self.assertIn("open-infra-runtime: unpacked the deployment package (%s, %d bytes) into %s\n"
                      % (sha256(pkg)[:12], len(pkg), self.task), r.stderr)
        with open(os.path.join(self.task, "lib", "data.txt"), "rb") as f:
            self.assertEqual(f.read(), b"from the package\n")
        self.assertEqual(r.invoked, {"from": "package", "event": {"k": "v"}}, r.stderr)

    # --- success --------------------------------------------------------------------------------------

    def test_package_unpacks_into_the_task_dir_and_serves(self):
        pkg = self.package()
        r = self.run_with([(200, pkg)], sha256(pkg))
        self.assertServedFromPackage(r, pkg)
        self.assertEqual(len(self.stub.requests), 1)

    # --- retried ------------------------------------------------------------------------------------

    def test_a_503_is_retried_then_the_package_serves(self):
        pkg = self.package()
        r = self.run_with([(503, b"the shim is restarting"), (200, pkg)], sha256(pkg))
        self.assertServedFromPackage(r, pkg)
        self.assertEqual(len(self.stub.requests), 2)
        self.assertIn("retrying in 1s (attempt 1 of 5)", r.stderr)

    def test_a_download_cut_short_is_retried(self):
        pkg = self.package()
        r = self.run_with([(200, pkg, "truncate"), (200, pkg)], sha256(pkg))
        self.assertServedFromPackage(r, pkg)
        self.assertEqual(len(self.stub.requests), 2)

    def test_five_failed_attempts_fail_start(self):
        pkg = self.package()
        r = self.run_with([(503, b"still restarting")], sha256(pkg))
        self.assertFailedStart(r, "in 5 attempts", "HTTP 503")
        self.assertEqual(len(self.stub.requests), 5, "5 attempts in all, then start fails")
        for delay, attempt in ((1, 1), (2, 2), (4, 3), (8, 4)):
            self.assertIn("retrying in %ds (attempt %d of 5)" % (delay, attempt), r.stderr)
        self.assertEqual(os.listdir(self.task), [])

    # --- refused, at once -----------------------------------------------------------------------------

    def test_a_401_fails_start_without_a_retry(self):
        pkg = self.package()
        body = b'{"__type":"AccessDeniedException","message":"not this function\'s package"}' + b"x" * 400
        r = self.run_with([(401, body), (200, pkg)], sha256(pkg))
        self.assertFailedStart(r, "HTTP 401", "AccessDeniedException")
        self.assertEqual(len(self.stub.requests), 1, "a refusal is not retried")
        self.assertNotIn("x" * 200, r.stderr, "only the first 200 characters of the body are logged")
        self.assertEqual(os.listdir(self.task), [])

    def test_a_redirect_is_not_followed(self):
        pkg = self.package()
        r = self.run_with([(302, b""), (200, pkg)], sha256(pkg))
        self.assertFailedStart(r, "HTTP 302")
        self.assertEqual(len(self.stub.requests), 1, "the token is never carried to a redirect's target")

    def test_a_sha256_mismatch_fails_start(self):
        pkg = self.package()
        r = self.run_with([(200, pkg)], sha256(b"some other package"))
        self.assertFailedStart(r, "the deployment package does not match its recorded SHA-256")
        self.assertEqual(len(self.stub.requests), 1)
        self.assertEqual(os.listdir(self.task), [], "a package that fails its check is never unpacked")

    def test_a_package_declared_over_64_mib_fails_start(self):
        r = self.run_with([(200, CAP + 1, "declare")], sha256(b"x"))
        self.assertFailedStart(r, "64 MiB")
        self.assertEqual(len(self.stub.requests), 1)

    def test_a_package_streamed_over_64_mib_fails_start(self):
        r = self.run_with([(200, CAP + 1, "stream")], sha256(b"x"))
        self.assertFailedStart(r, "64 MiB")
        self.assertEqual(len(self.stub.requests), 1)

    def test_an_entry_with_dotdot_is_refused(self):
        pkg = self.package(extra=[("../escape.txt", b"outside")])
        r = self.run_with([(200, pkg)], sha256(pkg))
        self.assertFailedStart(r, "refused", "../escape.txt")
        self.assertFalse(os.path.exists(os.path.join(self.work, "escape.txt")))
        self.assertEqual(os.listdir(self.task), [], "the whole package is refused, not part of it")

    def test_an_absolute_entry_is_refused(self):
        target = os.path.join(self.work, "abs-escape.txt")
        pkg = self.package(extra=[(target, b"outside")])
        r = self.run_with([(200, pkg)], sha256(pkg))
        self.assertFailedStart(r, "refused")
        self.assertFalse(os.path.exists(target))
        self.assertEqual(os.listdir(self.task), [])

    # --- configuration: fails start before any request -----------------------------------------------

    def test_url_and_bucket_together_fail_start(self):
        pkg = self.package()
        r = self.run_with([(200, pkg)], sha256(pkg), OPENINFRA_CODE_BUCKET="fn-artifacts", OPENINFRA_CODE_KEY="f.zip")
        self.assertFailedStart(r, "OPENINFRA_CODE_URL and OPENINFRA_CODE_BUCKET are both set")
        self.assertEqual(self.stub.requests, [])

    def test_a_missing_or_malformed_sha256_fails_start(self):
        pkg = self.package()
        for sha in (None, "", sha256(pkg).upper(), sha256(pkg)[:63]):
            self.stub.requests[:] = []
            r = self.run_with([(200, pkg)], sha256(pkg), OPENINFRA_CODE_SHA256=sha)
            self.assertFailedStart(r, "OPENINFRA_CODE_SHA256")
            self.assertEqual(self.stub.requests, [], "sha=%r" % sha)

    def test_a_missing_or_empty_token_fails_start(self):
        pkg = self.package()
        empty = os.path.join(self.work, "empty-token")
        with open(empty, "w") as f:
            f.write("\n")
        for tf in (None, os.path.join(self.work, "no-such-token"), empty):
            self.stub.requests[:] = []
            r = self.run_with([(200, pkg)], sha256(pkg), OPENINFRA_CODE_TOKEN_FILE=tf)
            self.assertFailedStart(r, "OPENINFRA_CODE_TOKEN_FILE")
            self.assertEqual(self.stub.requests, [], "token file=%r" % tf)


def which(name):
    return shutil.which(name)


class PythonRuntime(CodePackageCases, unittest.TestCase):
    handler = "app.handler"
    handler_entries = [("app.py", b"def handler(event, context):\n    return {'from': 'package', 'event': event}\n")]

    @classmethod
    def setUpClass(cls):
        cls.cmd = [sys.executable, os.path.join(RUNTIMES, "python", "bootstrap.py")]
        # A boto3 that cannot be imported, first on the path: the stored-package path must never import it.
        cls.no_boto3 = os.path.join(TMP, "no-boto3")
        os.makedirs(os.path.join(cls.no_boto3, "boto3"), exist_ok=True)
        with open(os.path.join(cls.no_boto3, "boto3", "__init__.py"), "w") as f:
            f.write("raise ImportError('boto3 imported on the stored-package path')\n")

    def extra_env(self):
        return {"PYTHONPATH": self.no_boto3}

    def test_the_no_boto3_guard_bites(self):
        # Prove-red for the guard above: the bucket path, which does import boto3, trips it.
        r = run_bootstrap(self.cmd, self.env("", OPENINFRA_CODE_URL=None, OPENINFRA_CODE_SHA256=None,
                                             OPENINFRA_CODE_BUCKET="fn-artifacts", OPENINFRA_CODE_KEY="f.zip"))
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("boto3 imported on the stored-package path", r.stderr)


class NodeRuntime(CodePackageCases, unittest.TestCase):
    handler = "index.handler"
    handler_entries = [("index.js", b"exports.handler = async function (event) { return { from: 'package', event: event }; };\n")]

    @classmethod
    def setUpClass(cls):
        if not which("node") or not which("unzip"):
            raise unittest.SkipTest("node and unzip are not both on PATH")
        cls.cmd = ["node", os.path.join(RUNTIMES, "nodejs", "bootstrap.js")]


HANDLER_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <NetVersion Condition="'$(NetVersion)' == ''">8.0</NetVersion>
    <TargetFramework>net$(NetVersion)</TargetFramework>
    <AssemblyName>Handler</AssemblyName>
  </PropertyGroup>
</Project>
"""
HANDLER_CS = """namespace Pkg
{
    public static class Fn
    {
        public static string Handle(string e) { return "{\\"from\\":\\"package\\",\\"event\\":" + e + "}"; }
    }
}
"""


# DOTNET_VERSION is the .NET the host and the handler are built for: 8.0 (dotnet8), or 10.0 (dotnet10) with
# OPENINFRA_TEST_DOTNET=10.0, as each runtime's image builds its host (NetVersion, bootstrap.csproj).
DOTNET_VERSION = os.environ.get("OPENINFRA_TEST_DOTNET", "8.0")


def dotnet_publish(project, out):
    r = subprocess.run(["dotnet", "publish", project, "-c", "Release", "-p:NetVersion=" + DOTNET_VERSION, "-o", out, "--nologo"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                       env=dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1"))
    if r.returncode != 0:
        raise AssertionError("dotnet publish %s failed:\n%s" % (project, r.stdout))


class DotnetRuntime(CodePackageCases, unittest.TestCase):
    handler = "Handler::Pkg.Fn::Handle"

    @classmethod
    def setUpClass(cls):
        if not which("dotnet"):
            raise unittest.SkipTest("dotnet is not on PATH")
        work = tempfile.mkdtemp(dir=TMP)
        # Built from a copy, as the image's Dockerfile builds it, so no bin/ or obj/ lands in the repository.
        src = os.path.join(work, "bootstrap-src")
        shutil.copytree(os.path.join(RUNTIMES, "dotnet"), src, ignore=shutil.ignore_patterns("bin", "obj", "Dockerfile"))
        dotnet_publish(os.path.join(src, "bootstrap.csproj"), os.path.join(work, "bootstrap"))
        hsrc = os.path.join(work, "handler-src")
        os.makedirs(hsrc)
        with open(os.path.join(hsrc, "Handler.csproj"), "w") as f:
            f.write(HANDLER_CSPROJ)
        with open(os.path.join(hsrc, "Fn.cs"), "w") as f:
            f.write(HANDLER_CS)
        dotnet_publish(os.path.join(hsrc, "Handler.csproj"), os.path.join(work, "handler"))
        with open(os.path.join(work, "handler", "Handler.dll"), "rb") as f:
            cls.handler_entries = [("Handler.dll", f.read())]
        cls.cmd = ["dotnet", os.path.join(work, "bootstrap", "bootstrap.dll")]


if __name__ == "__main__":
    unittest.main(verbosity=2)
