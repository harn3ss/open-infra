#!/usr/bin/env python3
# Tests for CloudFormation's response module as open-infra provides it beside inline custom-resource code
# (#404): cfn/cfnresponse/cfn-response.js (Node.js) and cfnresponse.py (Python), run in the first-party
# bootstraps (lambda-runtime/nodejs/bootstrap.js, lambda-runtime/python/bootstrap.py) as their images run
# them, against a stub ResponseURL on loopback.
#
# Covered, per runtime: a handler written as AWS documents it — Node.js's callback-less
# `function (event, context) { response.send(...) }`, an async one that awaits send, and Python's
# `cfnresponse.send(event, context, ...)` — PUTs AWS's response body (Status, Reason, PhysicalResourceId,
# StackId, RequestId, LogicalResourceId, NoEcho, Data) to the ResponseURL, the invocation then ends (it
# does not hang until its timeout), a FAILED response is sent as FAILED, and PhysicalResourceId defaults to
# the log stream name. `require("cfn-response")` resolves the file beside index.js, as on Lambda.
#
# stdlib only, no root, no cluster. node runs when it is on PATH, and is skipped, saying so, when not.
#
#   python3 test/lambda-runtime/cfn_response_test.py
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
MODULES = os.path.join(REPO, "cfn", "cfnresponse")
TMP = tempfile.mkdtemp(prefix="oi-cfn-response-test-")


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ResponseURL:
    """A stub ResponseURL: records each PUT's path, headers and JSON body."""

    def __init__(self):
        self.puts = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_PUT(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.puts.append({"path": self.path, "body": json.loads(self.rfile.read(n).decode())})
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d/v1/cfn-response/tok123" % self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def event(url, status="SUCCESS"):
    return {"RequestType": "Create", "ResponseURL": url, "StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/s/1",
            "RequestId": "s/Custom", "ResourceType": "Custom::Thing", "LogicalResourceId": "Custom",
            "ResourceProperties": {"Want": status}}


class Cases:
    cmd = None
    files = None  # {name: source}: the inline handler and the module beside it
    handler = "index.handler"

    def run_handler(self, ev, timeout=30):
        task = tempfile.mkdtemp(dir=TMP)
        for name, src in self.files.items():
            with open(os.path.join(task, name), "w") as f:
                f.write(src)
        port = free_port()
        env = {k: v for k, v in os.environ.items() if not k.startswith(("OPENINFRA_", "AWS_"))}
        env.update({"OPENINFRA_HANDLER": self.handler, "OPENINFRA_TASK_DIR": task, "OPENINFRA_OPT_DIR": os.path.join(task, "opt"),
                    "OPENINFRA_FUNCTION_NAME": "custom-fn", "PORT": str(port), "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"})
        proc = subprocess.Popen(self.cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, universal_newlines=True)
        logs = []
        threading.Thread(target=lambda: [logs.append(l) for l in proc.stderr], daemon=True).start()
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            req = urllib.request.Request("http://127.0.0.1:%d/" % port, data=json.dumps(ev).encode(),
                                         headers={"X-Openinfra-Invoke": "direct", "Content-Type": "application/json"})
            start, last = time.time(), None
            while time.time() - start < timeout:
                try:
                    with opener.open(req, timeout=timeout) as r:
                        return r.status, r.read().decode(), time.time() - start
                except OSError as e:  # the listener opens just after the "serving" line
                    last = e
                    if proc.poll() is not None:
                        break
                    time.sleep(0.05)
            raise AssertionError("no answer: %s\n%s" % (last, "".join(logs)))
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            proc.stderr.close()

    def setUp(self):
        self.url = ResponseURL()
        self.addCleanup(self.url.close)

    def check(self, status):
        code, _, took = self.run_handler(event(self.url.url, status))
        self.assertEqual(code, 200)
        self.assertLess(took, 20, "the invocation must end once the response is sent, not at its timeout")
        self.assertEqual(len(self.url.puts), 1, "one PUT to the ResponseURL")
        put = self.url.puts[0]
        self.assertEqual(put["path"], "/v1/cfn-response/tok123")
        b = put["body"]
        self.assertEqual(b["Status"], status)
        self.assertEqual((b["StackId"], b["RequestId"], b["LogicalResourceId"]),
                         ("arn:aws:cloudformation:us-east-1:123456789012:stack/s/1", "s/Custom", "Custom"))
        self.assertEqual(b["Data"], {"Greeting": "hello"})
        self.assertIn("/[$LATEST]", b["PhysicalResourceId"], "PhysicalResourceId defaults to the log stream name")
        self.assertIn("See the details in CloudWatch Log Stream: ", b["Reason"])
        self.assertIs(b["NoEcho"], False)

    def test_success(self):
        self.check("SUCCESS")

    def test_failed(self):
        self.check("FAILED")


NODE_CALLBACKLESS = """var response = require('cfn-response');
exports.handler = function (event, context) {
  var status = event.ResourceProperties.Want === 'FAILED' ? response.FAILED : response.SUCCESS;
  response.send(event, context, status, { Greeting: 'hello' });
};
"""

NODE_ASYNC = """const response = require('cfn-response');
exports.handler = async (event, context) => {
  const status = event.ResourceProperties.Want === 'FAILED' ? response.FAILED : response.SUCCESS;
  await response.send(event, context, status, { Greeting: 'hello' });
};
"""

PYTHON = """import cfnresponse

def handler(event, context):
    status = cfnresponse.FAILED if event['ResourceProperties']['Want'] == 'FAILED' else cfnresponse.SUCCESS
    cfnresponse.send(event, context, status, {'Greeting': 'hello'})
"""


def module(name):
    with open(os.path.join(MODULES, name)) as f:
        return f.read()


@unittest.skipUnless(shutil.which("node"), "node is not on PATH")
class NodeCallbacklessHandler(Cases, unittest.TestCase):
    cmd = ["node", os.path.join(RUNTIMES, "nodejs", "bootstrap.js")]
    files = {"index.js": NODE_CALLBACKLESS, "cfn-response.js": module("cfn-response.js")}


@unittest.skipUnless(shutil.which("node"), "node is not on PATH")
class NodeAsyncHandler(Cases, unittest.TestCase):
    cmd = ["node", os.path.join(RUNTIMES, "nodejs", "bootstrap.js")]
    files = {"index.js": NODE_ASYNC, "cfn-response.js": module("cfn-response.js")}


class PythonHandler(Cases, unittest.TestCase):
    cmd = [sys.executable, os.path.join(RUNTIMES, "python", "bootstrap.py")]
    files = {"index.py": PYTHON, "cfnresponse.py": module("cfnresponse.py")}


if __name__ == "__main__":
    unittest.main(verbosity=2)
