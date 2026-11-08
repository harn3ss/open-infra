#!/usr/bin/env python3
# Tests for a function's Timeout as the first-party runtimes enforce it (#413): lambda-runtime/nodejs/bootstrap.js,
# lambda-runtime/python/bootstrap.py and lambda-runtime/dotnet (dotnet8), each run as its image runs it, as a
# process on loopback. The function's timeout reaches the runtime in OPENINFRA_TIMEOUT_S; its clock starts when
# the invocation reaches the bootstrap, so a cold start is not counted, as on Lambda.
#
# Covered, per runtime:
#   - a handler still waiting at its deadline is answered then: 504, application/json, no X-Amz-Function-Error,
#     the body {"errorType":"Sandbox.Timedout","errorMessage":"RequestId: <id> Error: Task timed out after
#     1.00 seconds"}, in a direct invoke and through the API-Gateway proxy mapping alike;
#   - a handler that blocks (Python time.sleep and a busy loop, .NET Thread.Sleep and a busy loop) is answered at
#     the deadline, not when it finishes; Node.js: a handler that holds the event loop past the deadline and
#     then returns is answered with the timeout, not its result;
#   - a fast handler is unaffected, its remaining time about the timeout;
#   - after a timed-out invocation the instance answers the next ones normally, concurrently with the timed-out
#     handler still running, and that handler's late output, result or error never reaches them;
#   - the log tail of a timed-out invocation: START, the output so far, "<UTC time> <id> Task timed out after
#     1.00 seconds", END, and REPORT ending "Status: timeout"; the same line is written to stdout;
#   - OPENINFRA_TIMEOUT_S unset, not a whole number or out of 1-900 means 300 seconds (the remaining time says so).
#
# stdlib only, Python 3.6-compatible, no root, no cluster. node and dotnet run when they are on PATH, and are
# skipped, saying so, when not.
#
#   python3 test/lambda-runtime/timeout_test.py
import base64
import calendar
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context_test as ct  # noqa: E402  (free_port, write_task, dotnet_publish)

RUNTIMES = ct.RUNTIMES
TMP = tempfile.mkdtemp(prefix="oi-timeout-test-")
RID = "3d0c8f6e-5b7a-4c1e-9f2d-6a8b0e4c7d21"
RID2 = "a7e4b2c9-1f3d-4e6a-8b5c-2d9f0a1e3c47"
RID3 = "c1f9e3a5-7d2b-4a8e-b6c4-0e5d9f2a8b13"


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)
    shutil.rmtree(ct.TMP, ignore_errors=True)


class Answer:
    def __init__(self, status, headers, body, took):
        self.status, self.headers, self.body, self.took = status, headers, body, took

    def tail(self):
        v = self.headers.get("X-Amz-Log-Result")
        return base64.b64decode(v).decode("utf-8", "replace") if v else None


class Runtime:
    """One runtime process serving the handler in a task dir, with env added to the platform's. Unlike
    context_test's, it keeps the process's stdout too: the timed-out line is written there."""

    def __init__(self, cmd, handler, task, env):
        self.port = ct.free_port()
        full = {k: v for k, v in os.environ.items() if not k.startswith(("OPENINFRA_", "AWS_"))}
        full.update({"OPENINFRA_HANDLER": handler, "OPENINFRA_TASK_DIR": task, "OPENINFRA_OPT_DIR": os.path.join(task, "opt"),
                     "OPENINFRA_FUNCTION_NAME": "timeout-fn", "PORT": str(self.port), "PYTHONUNBUFFERED": "1",
                     "PYTHONDONTWRITEBYTECODE": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
                     # A local time far from UTC: the timed-out line must still be stamped in UTC.
                     "TZ": "OIT-14"})
        full.update(env)
        self.proc = subprocess.Popen(cmd, env=full, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.out, self.logs = [], []
        for stream, into in ((self.proc.stdout, self.out), (self.proc.stderr, self.logs)):
            threading.Thread(target=lambda s=stream, i=into: [i.append(l) for l in s], daemon=True).start()
        self.wait_ready()

    def wait_ready(self, timeout=60):
        start, last = time.time(), None
        while time.time() - start < timeout:
            if self.proc.poll() is not None:
                break
            try:
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
                conn.request("GET", "/_openinfra_health")
                if conn.getresponse().status == 200:
                    conn.close()
                    return
            except OSError as e:  # the listener opens just after the "serving" line
                last = e
            time.sleep(0.05)
        raise AssertionError("the runtime did not start: %s\n%s" % (last, "".join(self.logs)))

    def call(self, event, rid=RID, direct=True, tail=False, timeout=30):
        h = {"Content-Type": "application/json", "X-Openinfra-Request-Id": rid}
        if direct:
            h["X-Openinfra-Invoke"] = "direct"
        if tail:
            h["X-Amz-Log-Type"] = "Tail"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        start = time.time()
        conn.request("POST", "/", body=json.dumps(event).encode(), headers=h)
        r = conn.getresponse()
        body = r.read().decode()
        took = time.time() - start
        conn.close()
        return Answer(r.status, r.msg, body, took)

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()
        self.proc.stderr.close()


def timed_out_body(rid, secs):
    return '{"errorType":"Sandbox.Timedout","errorMessage":"RequestId: %s Error: Task timed out after %.2f seconds"}' % (rid, secs)


def timed_out_line(rid, secs):
    """The line Lambda logs for a timeout: '<ISO 8601 UTC, milliseconds>Z <id> Task timed out after N.NN seconds'."""
    return re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d{3}Z %s Task timed out after %s seconds$"
                      % (re.escape(rid), re.escape("%.2f" % secs)), re.M)


class Cases:
    """Each runtime class sets start(env) -> Runtime, and blocking: the events of its handler's blocking modes."""

    blocking = ()

    def runtime(self, timeout="1"):
        env = {"AWS_REGION": "us-east-1"}
        if timeout is not None:
            env["OPENINFRA_TIMEOUT_S"] = timeout
        rt = self.start(env)
        self.addCleanup(rt.close)
        rt.call({"mode": "warm"})  # loads (and, for .NET, compiles) the invoke path; its answer is not checked
        return rt

    def assertTimedOut(self, a, rid=RID, secs=1):
        self.assertEqual(a.status, 504, a.body)
        self.assertEqual(a.headers.get("Content-Type"), "application/json")
        self.assertIsNone(a.headers.get("X-Amz-Function-Error"), "a timeout is a 504 with no function error")
        self.assertEqual(a.body, timed_out_body(rid, secs))

    def assertAtTheDeadline(self, a, secs=1):
        self.assertGreaterEqual(a.took, secs - 0.05, "never answered before the deadline")
        self.assertLess(a.took, secs + 2.0, "answered at the deadline, not when the handler finishes")

    def test_a_handler_past_its_timeout_is_answered_at_the_deadline(self):
        rt = self.runtime("1")
        for direct in (True, False):  # Invoke, and the API-Gateway proxy mapping
            a = rt.call({"mode": "sleep", "s": 6, "m": "slow"}, direct=direct)
            self.assertTimedOut(a)
            self.assertAtTheDeadline(a)

    def test_a_blocking_handler_is_answered_at_the_deadline(self):
        if not self.blocking:
            self.skipTest("no blocking handler mode for this runtime")
        rt = self.runtime("1")
        for ev in self.blocking:
            a = rt.call(ev)
            self.assertTimedOut(a)
            self.assertAtTheDeadline(a)
        a = rt.call({"mode": "remaining"}, rid=RID2)
        self.assertEqual(a.status, 200, "the instance still answers while the blocked handlers run on: " + a.body)

    def test_a_fast_handler_is_unaffected(self):
        rt = self.runtime("7")
        a = rt.call({"mode": "remaining", "m": "quick"})
        self.assertEqual(a.status, 200, a.body)
        self.assertIsNone(a.headers.get("X-Amz-Function-Error"))
        remaining = json.loads(a.body)["remaining"]
        self.assertLessEqual(remaining, 7000)
        self.assertGreater(remaining, 6000, "the remaining time counts from the invocation's start: %d" % remaining)
        a = rt.call({"mode": "done", "m": "quick"}, direct=False)
        self.assertEqual((a.status, json.loads(a.body)), (200, {"done": "quick"}))

    def test_the_next_invocations_after_a_timeout_are_answered_normally(self):
        rt = self.runtime("2")
        for fail in (False, True):  # the timed-out handler's late result, then its late error
            first = rt.call({"mode": "sleep", "s": 3, "m": "first", "fail": fail}, tail=True)
            self.assertTimedOut(first, secs=2)
            # Runs while the first handler is still running (it ends 1 s in), and past its end.
            second = rt.call({"mode": "sleep", "s": 1.5, "m": "second"}, rid=RID2, tail=True)
            self.assertEqual(second.status, 200, second.body)
            self.assertEqual(json.loads(second.body), {"done": "second"})
            self.assertIsNone(second.headers.get("X-Amz-Function-Error"))
            log = second.tail()
            self.assertIn("marker-second", log)
            self.assertIn("after-second", log)
            self.assertNotIn("first", log, "the timed-out invocation's late output is its own, never the next one's")
            self.assertNotIn("Status: timeout", log)
            third = rt.call({"mode": "remaining"}, rid=RID3)
            self.assertEqual(third.status, 200, third.body)
            self.assertGreater(json.loads(third.body)["remaining"], 1000)
        self.assertIsNone(rt.proc.poll(), "the process was never exited")
        self.assertNotIn("late-first", "".join(rt.logs), "the timed-out handler's late error is discarded")

    def test_the_tail_and_stdout_of_a_timed_out_invocation(self):
        rt = self.runtime("1")
        a = rt.call({"mode": "sleep", "s": 6, "m": "tailed"}, tail=True)
        self.assertTimedOut(a)
        log = a.tail()
        self.assertIsNotNone(log, "a Tail invoke that times out answers X-Amz-Log-Result")
        lines = log.splitlines()
        self.assertEqual(lines[0], "START RequestId: %s Version: $LATEST" % RID)
        m = timed_out_line(RID, 1).search(log)
        self.assertIsNotNone(m, log)
        self.assertLess(log.index("marker-tailed"), m.start(), "the output so far comes first")
        self.assertLess(m.end(), log.index("END RequestId: " + RID))
        self.assertNotIn("after-tailed", log)
        self.assertTrue(lines[-1].startswith("REPORT RequestId: %s\tDuration: " % RID), lines[-1])
        self.assertIn("\tMax Memory Used: ", lines[-1])
        self.assertTrue(lines[-1].endswith("\tStatus: timeout"), repr(lines[-1]))
        # The same line on stdout (CloudWatch Logs reads stdout), stamped in UTC.
        deadline = time.time() + 5
        while time.time() < deadline and not timed_out_line(RID, 1).search("".join(rt.out)):
            time.sleep(0.05)
        out = timed_out_line(RID, 1).search("".join(rt.out))
        self.assertIsNotNone(out, "stdout: %r" % "".join(rt.out))
        stamped = calendar.timegm(time.strptime(out.group(1), "%Y-%m-%dT%H:%M:%S"))
        self.assertLess(abs(stamped - time.time()), 30, "the line is stamped in UTC: %s" % out.group(0))

    def test_an_unset_or_invalid_timeout_is_300_seconds(self):
        for value in (None, "", "abc", "0", "901", "3.5", "-5", "1e3"):
            rt = self.runtime(value)
            a = rt.call({"mode": "remaining"})
            self.assertEqual(a.status, 200, a.body)
            remaining = json.loads(a.body)["remaining"]
            self.assertTrue(299000 < remaining <= 300000, "OPENINFRA_TIMEOUT_S=%r: remaining %d" % (value, remaining))
            rt.close()
        rt = self.runtime("900")
        remaining = json.loads(rt.call({"mode": "remaining"}).body)["remaining"]
        self.assertTrue(899000 < remaining <= 900000, "OPENINFRA_TIMEOUT_S=900: remaining %d" % remaining)


NODE_HANDLER = """exports.handler = async (e, context) => {
  const m = e.m || "";
  if (m) console.log("marker-" + m);
  if (e.mode === "remaining") return { remaining: context.getRemainingTimeInMillis() };
  if (e.mode === "sleep") await new Promise((r) => setTimeout(r, e.s * 1000));
  if (e.mode === "busy") { const end = Date.now() + e.s * 1000; while (Date.now() < end) {} }
  if (m) console.log("after-" + m);
  if (e.fail) throw new Error("late-" + m);
  return { done: m };
};
"""

PYTHON_HANDLER = """import time

def handler(e, context):
    m = e.get("m", "")
    if m:
        print("marker-" + m)
    mode = e.get("mode")
    if mode == "remaining":
        return {"remaining": context.get_remaining_time_in_millis()}
    if mode == "sleep":
        time.sleep(e["s"])
    elif mode == "busy":
        end = time.time() + e["s"]
        while time.time() < end:
            pass
    if m:
        print("after-" + m)
    if e.get("fail"):
        raise RuntimeError("late-" + m)
    return {"done": m}
"""

# The handler declares the Amazon.Lambda.Core interface it reads (the runtime binds it by name), so the test
# needs no package feed.
DOTNET_HANDLER = """using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
namespace Amazon.Lambda.Core
{
    public interface ILambdaContext { string AwsRequestId { get; } TimeSpan RemainingTime { get; } }
}
namespace Pkg
{
    public static class Fn
    {
        public static async Task<string> Handle(string e, Amazon.Lambda.Core.ILambdaContext c)
        {
            var doc = JsonDocument.Parse(e).RootElement;
            var m = doc.TryGetProperty("m", out var mv) ? mv.GetString() : "";
            var mode = doc.TryGetProperty("mode", out var mo) ? mo.GetString() : "";
            var s = doc.TryGetProperty("s", out var sv) ? sv.GetDouble() : 0;
            if (m != "") Console.WriteLine("marker-" + m);
            if (mode == "remaining") return "{\\"remaining\\":" + (long)c.RemainingTime.TotalMilliseconds + "}";
            if (mode == "sleep") await Task.Delay(TimeSpan.FromSeconds(s));
            if (mode == "block") Thread.Sleep(TimeSpan.FromSeconds(s));
            if (mode == "busy") { var end = DateTime.UtcNow.AddSeconds(s); while (DateTime.UtcNow < end) { } }
            if (m != "") Console.WriteLine("after-" + m);
            if (doc.TryGetProperty("fail", out var f) && f.GetBoolean()) throw new InvalidOperationException("late-" + m);
            return "{\\"done\\":\\"" + m + "\\"}";
        }
    }
}
"""


@unittest.skipUnless(shutil.which("node"), "node is not on PATH")
class NodeTimeout(Cases, unittest.TestCase):
    def start(self, env):
        return Runtime(["node", os.path.join(RUNTIMES, "nodejs", "bootstrap.js")], "index.handler",
                       ct.write_task({"index.js": NODE_HANDLER}), env)

    def test_a_handler_holding_the_event_loop_past_its_deadline_is_answered_with_the_timeout(self):
        # Nothing on the event loop can answer while a synchronous handler holds it: the timeout is answered
        # the moment it gives the loop back, and its result is discarded.
        rt = self.runtime("1")
        a = rt.call({"mode": "busy", "s": 2.5, "m": "spin"}, tail=True)
        self.assertTimedOut(a)
        self.assertGreaterEqual(a.took, 2.4)
        self.assertLess(a.took, 5)
        self.assertNotIn("done", a.body)
        log = a.tail()
        self.assertIsNotNone(timed_out_line(RID, 1).search(log), log)
        self.assertTrue(log.splitlines()[-1].endswith("\tStatus: timeout"), log)
        b = rt.call({"mode": "done", "m": "next"}, rid=RID2)
        self.assertEqual((b.status, json.loads(b.body)), (200, {"done": "next"}))


class PythonTimeout(Cases, unittest.TestCase):
    blocking = ({"mode": "sleep", "s": 6, "m": "sleeping"}, {"mode": "busy", "s": 6, "m": "spinning"})

    def start(self, env):
        return Runtime([sys.executable, os.path.join(RUNTIMES, "python", "bootstrap.py")], "index.handler",
                       ct.write_task({"index.py": PYTHON_HANDLER}), env)


@unittest.skipUnless(shutil.which("dotnet"), "dotnet is not on PATH")
class DotnetTimeout(Cases, unittest.TestCase):
    blocking = ({"mode": "block", "s": 6, "m": "sleeping"}, {"mode": "busy", "s": 6, "m": "spinning"})

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

    def start(self, env):
        return Runtime(self.cmd, "Handler::Pkg.Fn::Handle", self.task, env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
