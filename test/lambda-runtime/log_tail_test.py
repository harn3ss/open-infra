#!/usr/bin/env python3
# Tests for an invocation's log tail (#407), as the first-party runtimes answer it to Invoke with LogType
# Tail: lambda-runtime/nodejs/bootstrap.js, lambda-runtime/python/bootstrap.py and lambda-runtime/dotnet
# (dotnet8), each run as its image runs it, as a process on loopback.
#
# Covered, per runtime:
#   - X-Amz-Log-Result is base64 of Lambda's lines around what the invocation printed: START (the request ID
#     the aws-shim passes, and the version), the output, END and REPORT;
#   - it is at most 4 KB, the end of the log, when the invocation printed more;
#   - a handler that raises has its error in the tail;
#   - no tail unless the invocation asked for one;
#   - two concurrent invocations each get their own output, never the other's.
#
# stdlib only, no root, no cluster. node and dotnet run when they are on PATH, and are skipped, saying so,
# when not.
#
#   python3 test/lambda-runtime/log_tail_test.py
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context_test as ct  # noqa: E402  (the runtime process harness)

RUNTIMES = ct.RUNTIMES
TMP = tempfile.mkdtemp(prefix="oi-log-tail-test-")
RID = "8f507cfc-1d2e-4697-b07a-ac58fc914c95"


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)
    shutil.rmtree(ct.TMP, ignore_errors=True)


def invoke(rt, event, headers=None, timeout=60):
    """One direct invoke: (response headers, body)."""
    rt.invoke({}, timeout=timeout)  # waits for the listener (the warm-up invocation prints nothing)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    h = {"X-Openinfra-Invoke": "direct", "Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request("http://127.0.0.1:%d/" % rt.port, data=json.dumps(event).encode(), headers=h)
    with opener.open(req, timeout=timeout) as r:
        return r.headers, r.read().decode()


def tail(headers):
    v = headers.get("X-Amz-Log-Result")
    return base64.b64decode(v).decode("utf-8", "replace") if v else None


class Cases:
    def runtime(self):
        rt = self.start({"AWS_REGION": "us-east-1", "OPENINFRA_MEMORY_MB": "256"})
        self.addCleanup(rt.close)
        return rt

    def test_the_tail_is_the_invocations_output_between_lambdas_lines(self):
        rt = self.runtime()
        headers, _ = invoke(rt, {"m": "one"}, {"X-Amz-Log-Type": "Tail", "X-Openinfra-Request-Id": RID,
                                               "X-Openinfra-Function-Version": "3"})
        log = tail(headers)
        self.assertIsNotNone(log, "a Tail invoke answers X-Amz-Log-Result")
        lines = log.splitlines()
        self.assertEqual(lines[0], "START RequestId: %s Version: 3" % RID)
        self.assertIn("marker-one", log)
        self.assertIn("after-one", log)
        self.assertLess(log.index("marker-one"), log.index("END RequestId: " + RID))
        self.assertTrue(lines[-1].startswith("REPORT RequestId: %s\tDuration: " % RID), lines[-1])
        self.assertIn("\tMemory Size: 256 MB\tMax Memory Used: ", lines[-1])

    def test_no_tail_unless_asked(self):
        rt = self.runtime()
        headers, _ = invoke(rt, {"m": "quiet"})
        self.assertIsNone(headers.get("X-Amz-Log-Result"))

    def test_the_tail_is_at_most_4_kb(self):
        rt = self.runtime()
        headers, _ = invoke(rt, {"m": "big", "big": True}, {"X-Amz-Log-Type": "Tail"})
        raw = base64.b64decode(headers["X-Amz-Log-Result"])
        self.assertLessEqual(len(raw), 4096)
        self.assertGreater(len(raw), 4000, "the tail is the last 4 KB, not less")
        self.assertIn(b"REPORT RequestId: ", raw, "the end of the log is kept")

    def test_a_raised_error_is_in_the_tail(self):
        rt = self.runtime()
        headers, _ = invoke(rt, {"m": "bad", "fail": True}, {"X-Amz-Log-Type": "Tail"})
        self.assertEqual(headers.get("X-Amz-Function-Error"), "Unhandled")
        self.assertIn("boom-bad", tail(headers))

    def test_concurrent_invocations_never_share_output(self):
        rt = self.runtime()
        invoke(rt, {"m": "warm"})
        out = {}

        def run(m):
            out[m] = invoke(rt, {"m": m, "wait": 400}, {"X-Amz-Log-Type": "Tail"})[0]

        threads = [threading.Thread(target=run, args=(m,)) for m in ("left", "right")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        for mine, other in (("left", "right"), ("right", "left")):
            log = tail(out[mine])
            self.assertIn("marker-" + mine, log)
            self.assertIn("after-" + mine, log)
            self.assertNotIn(other, log, "an invocation's tail holds only its own output")


NODE_HANDLER = """exports.handler = async (e) => {
  if (!e.m) return {};
  console.log("marker-" + e.m);
  await new Promise((r) => setTimeout(r, e.wait || 0));
  console.error("after-" + e.m);
  if (e.big) for (let i = 0; i < 200; i++) console.log("line " + i + " " + "x".repeat(60));
  if (e.fail) throw new Error("boom-" + e.m);
  return { ok: e.m };
};
"""

PYTHON_HANDLER = """import sys
import time

def handler(e, context):
    if not e.get("m"):
        return {}
    print("marker-" + e["m"])
    time.sleep(e.get("wait", 0) / 1000.0)
    sys.stderr.write("after-" + e["m"] + "\\n")
    if e.get("big"):
        for i in range(200):
            print("line %d %s" % (i, "x" * 60))
    if e.get("fail"):
        raise RuntimeError("boom-" + e["m"])
    return {"ok": e["m"]}
"""

DOTNET_HANDLER = """using System;
using System.Text.Json;
using System.Threading.Tasks;
namespace Pkg
{
    public static class Fn
    {
        public static async Task<string> Handle(string e)
        {
            var doc = JsonDocument.Parse(e).RootElement;
            if (!doc.TryGetProperty("m", out var mv)) return "{}";
            var m = mv.GetString();
            Console.WriteLine("marker-" + m);
            await Task.Delay(doc.TryGetProperty("wait", out var w) ? w.GetInt32() : 0);
            Console.Error.WriteLine("after-" + m);
            if (doc.TryGetProperty("big", out _)) for (int i = 0; i < 200; i++) Console.WriteLine("line " + i + " " + new string('x', 60));
            if (doc.TryGetProperty("fail", out _)) throw new InvalidOperationException("boom-" + m);
            return "{\\"ok\\":\\"" + m + "\\"}";
        }
    }
}
"""


@unittest.skipUnless(shutil.which("node"), "node is not on PATH")
class NodeLogTail(Cases, unittest.TestCase):
    def start(self, env):
        return ct.Runtime(["node", os.path.join(RUNTIMES, "nodejs", "bootstrap.js")], "index.handler",
                          ct.write_task({"index.js": NODE_HANDLER}), env)


class PythonLogTail(Cases, unittest.TestCase):
    def start(self, env):
        return ct.Runtime([sys.executable, os.path.join(RUNTIMES, "python", "bootstrap.py")], "index.handler",
                          ct.write_task({"index.py": PYTHON_HANDLER}), env)


@unittest.skipUnless(shutil.which("dotnet"), "dotnet is not on PATH")
class DotnetLogTail(Cases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = tempfile.mkdtemp(dir=TMP)
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

    def start(self, env):
        return ct.Runtime(self.cmd, "Handler::Pkg.Fn::Handle", self.task, env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
