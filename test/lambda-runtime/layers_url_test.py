#!/usr/bin/env python3
# Tests for a function's layers as the first-party runtimes fetch them with the function's own identity
# (OPENINFRA_LAYERS_URL): layer i of OPENINFRA_LAYERS is GET {OPENINFRA_LAYERS_URL}?layer={i} from the
# aws-shim, sent the token in OPENINFRA_LAYERS_TOKEN_FILE as a bearer, and unpacked, in order, into /opt, as
# Lambda extracts a function's layers. lambda-runtime/python/bootstrap.py, lambda-runtime/nodejs/bootstrap.js
# and lambda-runtime/dotnet (dotnet8) are each run as their image runs them, as a process, against a stub
# aws-shim on loopback.
#
# Covered, per runtime: the layers unpack into the opt dir in order (a later layer's file over an earlier
# one's) and the handler imports and reads them; the token is sent as a bearer, trimmed, re-read for each
# request and never logged, no proxy is used, the S3 keys and endpoint are never used for a layer (and the
# python bootstrap never imports boto3 for one), and the temp files are removed; a 403 for a layer fails start
# (exit 2) at once, naming the layer, with no retry; a 503 is retried; a layer entry that would unpack outside
# the opt dir fails start; a missing or unreadable token file fails start before any request. Without
# OPENINFRA_LAYERS_URL a layer still comes from S3 with the bucket's keys, as before.
#
# stdlib only, no root, no cluster. node (with the system unzip it uses) and dotnet run when they are on
# PATH, and are skipped, saying so, when not; the python S3 case needs boto3, and is skipped without it.
#
#   python3 test/lambda-runtime/layers_url_test.py
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import code_package_test as cp  # noqa: E402  (run_bootstrap, make_zip, ThreadingHTTPServer)
import context_test as ct  # noqa: E402  (free_port, write_task, dotnet_publish, DOTNET_CSPROJ)

RUNTIMES = ct.RUNTIMES
TMP = tempfile.mkdtemp(prefix="oi-layers-url-test-")
TOKEN = "eyJhbGciOiJSUzI1NiJ9.layer-token-sentinel-never-logged.c2lnbmF0dXJl"
S3_KEY_ID = "AKIDEXAMPLELAYERS01"
S3_SECRET = "layers-s3-secret-example-never-used"
WANT = {"module": "layer-0", "shared": "from layer 1", "only1": "layer 1 only"}


def tearDownModule():
    for d in (TMP, cp.TMP, ct.TMP):
        shutil.rmtree(d, ignore_errors=True)


class Stub:
    """A loopback HTTP server answering GETs by route(path, query) -> (status, body); it records each
    request's path, query and Authorization header."""

    def __init__(self, route):
        self.requests = []
        stub = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                stub.requests.append({"path": u.path, "query": u.query, "authorization": self.headers.get("Authorization")})
                status, body = route(u.path, urllib.parse.parse_qs(u.query))
                try:
                    self.send_response(status)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        self.httpd = cp.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class LayerShim(Stub):
    """The aws-shim's /v1/function-code?layer=<i>, scripted per layer: script[i] is a list of steps
    (status, body), each request taking the next (the last repeats)."""

    def __init__(self):
        self.script = {}
        lock = threading.Lock()

        def route(path, q):
            i = int(q.get("layer", ["-1"])[0])
            with lock:
                steps = self.script.get(i) or [(404, b"the function declares no layer %d" % i)]
                return steps.pop(0) if len(steps) > 1 else steps[0]

        super().__init__(route)
        self.url = self.base + "/v1/function-code"

    def layer_requests(self):
        return [r["query"] for r in self.requests]


class LayerCases:
    """Each runtime class sets cmd, handler, task (a task dir holding the handler) and layer0_entries (the
    runtime's own layer contents: a module the handler imports, or a file it reads, giving "layer-0")."""

    cmd = handler = task = None
    layer0_entries = ()

    def setUp(self):
        self.shim = LayerShim()
        self.addCleanup(self.shim.close)
        self.s3 = Stub(lambda path, q: (500, b"the S3 endpoint must not be used for a layer"))
        self.addCleanup(self.s3.close)
        self.work = tempfile.mkdtemp(dir=TMP)
        self.opt = os.path.join(self.work, "opt")
        self.tmpdir = os.path.join(self.work, "tmp")
        os.makedirs(self.tmpdir)
        self.token_file = os.path.join(self.work, "token")
        with open(self.token_file, "w") as f:
            f.write(TOKEN + "\n")  # projected tokens are trimmed before use

    def layers(self):
        layer0 = cp.make_zip(list(self.layer0_entries) + [("shared.txt", b"from layer 0")])
        layer1 = cp.make_zip([("shared.txt", b"from layer 1"), ("only1.txt", b"layer 1 only")])
        return layer0, layer1

    def env(self, **over):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("OPENINFRA_", "AWS_")) and k.lower() not in ("no_proxy", "http_proxy", "https_proxy")}
        env.update({
            "OPENINFRA_HANDLER": self.handler,
            "OPENINFRA_TASK_DIR": self.task,
            "OPENINFRA_OPT_DIR": self.opt,
            "OPENINFRA_LAYERS": json.dumps([{"bucket": "layers-bucket", "key": "layer0.zip"},
                                            {"bucket": "layers-bucket", "key": "layer1.zip"}]),
            "OPENINFRA_LAYERS_URL": self.shim.url,
            "OPENINFRA_LAYERS_TOKEN_FILE": self.token_file,
            # Keys and an S3 endpoint that a layer must never be fetched with: the endpoint refuses every request.
            "AWS_ACCESS_KEY_ID": S3_KEY_ID, "AWS_SECRET_ACCESS_KEY": S3_SECRET,
            "AWS_ENDPOINT_URL_S3": self.s3.base, "AWS_REGION": "us-east-1",
            "PORT": str(ct.free_port()),
            "TMPDIR": self.tmpdir,
            # A dead proxy: a bootstrap that sent the token through a proxy could not reach the stub at all.
            "HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
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

    def run_with(self, script, **over):
        self.shim.script = {i: list(steps) for i, steps in script.items()}
        r = cp.run_bootstrap(self.cmd, self.env(**over))
        self.assertNotIn(TOKEN, r.stderr, "the identity token must never be logged")
        self.assertEqual(os.listdir(self.tmpdir), [], "the downloaded layers' temp files are removed")
        self.assertEqual(self.s3.requests, [], "a layer is never fetched from S3 with keys when OPENINFRA_LAYERS_URL is set")
        for req in self.shim.requests:
            self.assertEqual(req["path"], "/v1/function-code")
            self.assertEqual(req["authorization"], "Bearer " + TOKEN, "the token is sent as a bearer, trimmed")
        return r

    def assertFailedStart(self, r, *phrases):
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertFalse(r.served, r.stderr)
        for p in phrases:
            self.assertIn(p, r.stderr)

    def test_the_layers_unpack_into_opt_in_order_and_the_handler_reads_them(self):
        layer0, layer1 = self.layers()
        r = self.run_with({0: [(200, layer0)], 1: [(200, layer1)]})
        self.assertTrue(r.served, r.stderr)
        self.assertEqual(r.invoked, WANT, r.stderr)
        self.assertEqual(self.shim.layer_requests(), ["layer=0", "layer=1"], "each layer once, in order")
        self.assertIn("open-infra-runtime: unpacked layer 0 (%d bytes) into %s\n" % (len(layer0), self.opt), r.stderr)
        self.assertIn("open-infra-runtime: unpacked layer 1 (%d bytes) into %s\n" % (len(layer1), self.opt), r.stderr)
        with open(os.path.join(self.opt, "shared.txt"), "rb") as f:
            self.assertEqual(f.read(), b"from layer 1", "a later layer's file is over an earlier one's")

    def test_a_403_fails_start_naming_the_layer_without_a_retry(self):
        layer0, layer1 = self.layers()
        body = b'{"__type":"AccessDeniedException","message":"the function\'s account may not read layer 1"}'
        r = self.run_with({0: [(200, layer0)], 1: [(403, body), (200, layer1)]})
        self.assertFailedStart(r, "layer 1", "HTTP 403", "AccessDeniedException")
        self.assertEqual(self.shim.layer_requests(), ["layer=0", "layer=1"], "a refusal is not retried")
        failure = [l for l in r.stderr.splitlines() if "HTTP 403" in l]
        self.assertTrue(failure and failure[-1].startswith("open-infra-runtime: cannot load layer 1 into "), r.stderr)

    def test_a_503_is_retried_then_the_layers_unpack(self):
        layer0, layer1 = self.layers()
        r = self.run_with({0: [(503, b"the shim is restarting"), (200, layer0)], 1: [(200, layer1)]})
        self.assertTrue(r.served, r.stderr)
        self.assertEqual(r.invoked, WANT, r.stderr)
        self.assertEqual(self.shim.layer_requests(), ["layer=0", "layer=0", "layer=1"])
        self.assertIn("open-infra-runtime: fetching layer 0: ", r.stderr)
        self.assertIn("retrying in 1s (attempt 1 of 5)", r.stderr)

    def test_an_entry_outside_opt_fails_start(self):
        _, layer1 = self.layers()
        bad = cp.make_zip(list(self.layer0_entries) + [("../escape.txt", b"outside")])
        r = self.run_with({0: [(200, bad)], 1: [(200, layer1)]})
        self.assertFailedStart(r, "layer 0", "refused", "../escape.txt")
        self.assertFalse(os.path.exists(os.path.join(self.work, "escape.txt")))
        self.assertEqual(self.shim.layer_requests(), ["layer=0"])

    def test_a_missing_or_unreadable_token_fails_start(self):
        layer0, layer1 = self.layers()
        empty = os.path.join(self.work, "empty-token")
        with open(empty, "w") as f:
            f.write("\n")
        for tf in (None, os.path.join(self.work, "no-such-token"), empty):
            self.shim.requests[:] = []
            r = self.run_with({0: [(200, layer0)], 1: [(200, layer1)]}, OPENINFRA_LAYERS_TOKEN_FILE=tf)
            self.assertFailedStart(r, "OPENINFRA_LAYERS_TOKEN_FILE")
            self.assertEqual(self.shim.requests, [], "token file=%r" % tf)

    def test_without_a_layers_url_the_layers_come_from_s3_with_the_keys(self):
        layer0, layer1 = self.layers()
        objects = {"/layers-bucket/layer0.zip": layer0, "/layers-bucket/layer1.zip": layer1}
        s3 = Stub(lambda path, q: (200, objects[path]) if path in objects else (404, b"NoSuchKey"))
        self.addCleanup(s3.close)
        self.s3_layers_supported()
        # No dead proxy here: the AWS SDKs the S3 path uses honour HTTP_PROXY, as they always have.
        no_proxy = {k: None for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")}
        r = cp.run_bootstrap(self.cmd, self.env(OPENINFRA_LAYERS_URL=None, AWS_ENDPOINT_URL_S3=s3.base, **no_proxy))
        self.assertTrue(r.served, r.stderr)
        self.assertEqual(r.invoked, WANT, r.stderr)
        self.assertEqual(self.shim.requests, [])
        self.assertEqual([q["path"] for q in s3.requests], ["/layers-bucket/layer0.zip", "/layers-bucket/layer1.zip"])
        for q in s3.requests:
            self.assertIn("Credential=" + S3_KEY_ID + "/", q["authorization"] or "", "signed with the bucket's keys")

    def s3_layers_supported(self):
        pass


class PythonLayers(LayerCases, unittest.TestCase):
    handler = "index.handler"
    layer0_entries = [("python/layermod.py", b"WHO = 'layer-0'\n")]

    @classmethod
    def setUpClass(cls):
        cls.cmd = [sys.executable, os.path.join(RUNTIMES, "python", "bootstrap.py")]
        cls.task = ct.write_task({"index.py": (
            "import os\n"
            "import layermod\n\n"
            "def handler(event, context):\n"
            "    opt = os.environ['OPENINFRA_OPT_DIR']\n"
            "    read = lambda n: open(os.path.join(opt, n)).read()\n"
            "    return {'module': layermod.WHO, 'shared': read('shared.txt'), 'only1': read('only1.txt')}\n")})
        # A boto3 that cannot be imported, first on the path: the layers URL path must never import it.
        cls.no_boto3 = os.path.join(TMP, "no-boto3")
        os.makedirs(os.path.join(cls.no_boto3, "boto3"), exist_ok=True)
        with open(os.path.join(cls.no_boto3, "boto3", "__init__.py"), "w") as f:
            f.write("raise ImportError('boto3 imported on the layers URL path')\n")

    def extra_env(self):
        return {"PYTHONPATH": self.no_boto3}

    def s3_layers_supported(self):
        if importlib.util.find_spec("boto3") is None:
            self.skipTest("boto3 is not installed: the python bootstrap's S3 layer path needs it")

    def env(self, **over):
        env = super().env(**over)
        if "OPENINFRA_LAYERS_URL" not in env:
            env.pop("PYTHONPATH", None)  # the S3 path imports the real boto3
        return env


@unittest.skipUnless(shutil.which("node") and shutil.which("unzip"), "node and unzip are not both on PATH")
class NodeLayers(LayerCases, unittest.TestCase):
    handler = "index.handler"
    layer0_entries = [("nodejs/node_modules/layermod/index.js", b"module.exports = { who: 'layer-0' };\n")]

    @classmethod
    def setUpClass(cls):
        cls.cmd = ["node", os.path.join(RUNTIMES, "nodejs", "bootstrap.js")]
        cls.task = ct.write_task({"index.js": (
            "const fs = require('fs');\n"
            "const path = require('path');\n"
            "const layermod = require('layermod');\n"
            "exports.handler = async () => {\n"
            "  const read = (n) => fs.readFileSync(path.join(process.env.OPENINFRA_OPT_DIR, n), 'utf8');\n"
            "  return { module: layermod.who, shared: read('shared.txt'), only1: read('only1.txt') };\n"
            "};\n")})


DOTNET_HANDLER = """using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
namespace Pkg
{
    public static class Fn
    {
        public static string Handle(string e)
        {
            var opt = Environment.GetEnvironmentVariable("OPENINFRA_OPT_DIR");
            string Read(string n) => File.ReadAllText(Path.Combine(opt, n));
            return JsonSerializer.Serialize(new Dictionary<string, string> {
                ["module"] = Read(Path.Combine("dotnet", "layermod.txt")), ["shared"] = Read("shared.txt"), ["only1"] = Read("only1.txt") });
        }
    }
}
"""


@unittest.skipUnless(shutil.which("dotnet"), "dotnet is not on PATH")
class DotnetLayers(LayerCases, unittest.TestCase):
    handler = "Handler::Pkg.Fn::Handle"
    layer0_entries = [("dotnet/layermod.txt", b"layer-0")]

    @classmethod
    def setUpClass(cls):
        work = tempfile.mkdtemp(dir=TMP)
        # Built from a copy, as the image's Dockerfile builds it, so no bin/ or obj/ lands in the repository.
        src = os.path.join(work, "bootstrap-src")
        shutil.copytree(os.path.join(RUNTIMES, "dotnet"), src, ignore=shutil.ignore_patterns("bin", "obj", "Dockerfile"))
        ct.dotnet_publish(os.path.join(src, "bootstrap.csproj"), os.path.join(work, "bootstrap"))
        hsrc = os.path.join(work, "handler-src")
        os.makedirs(hsrc)
        with open(os.path.join(hsrc, "Handler.csproj"), "w") as f:
            f.write(ct.DOTNET_CSPROJ)
        with open(os.path.join(hsrc, "Fn.cs"), "w") as f:
            f.write(DOTNET_HANDLER)
        ct.dotnet_publish(os.path.join(hsrc, "Handler.csproj"), os.path.join(work, "handler"))
        cls.task = os.path.join(work, "handler")
        cls.cmd = ["dotnet", os.path.join(work, "bootstrap", "bootstrap.dll")]


if __name__ == "__main__":
    unittest.main(verbosity=2)
