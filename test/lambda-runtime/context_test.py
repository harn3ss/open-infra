#!/usr/bin/env python3
# Tests for the context a first-party runtime gives a handler (#406): lambda-runtime/nodejs/bootstrap.js,
# lambda-runtime/python/bootstrap.py and lambda-runtime/dotnet (dotnet8), each run as its image runs it, as
# a process on loopback, with a handler that answers what its context says.
#
# Covered, per runtime:
#   - the invoked function ARN: the one the caller (the aws-shim) passes, with a version or alias qualifier;
#     one naming another function is not taken, and the function's own ARN (its region and its role's
#     account) is given instead; "" with neither;
#   - the function version: the version that runs (a published version's number), else $LATEST;
#   - the ClientContext the caller passed (base64 JSON): its client, custom and env;
#   - the log group; Node.js's callbackWaitsForEmptyEventLoop (true, Lambda's default) and
#     AWS_EXECUTION_ENV completed to Lambda's identifier (AWS_Lambda_nodejs22.x).
#
# stdlib only, no root, no cluster. node and dotnet run when they are on PATH, and are skipped, saying so,
# when not.
#
#   python3 test/lambda-runtime/context_test.py
import base64
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

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUNTIMES = os.path.join(REPO, "lambda-runtime")
TMP = tempfile.mkdtemp(prefix="oi-context-test-")

FN = "ctx-fn"
OWN = "arn:aws:lambda:us-east-1:123456789012:function:" + FN
ROLE = "arn:aws:iam::210987654321:role/exec"
CLIENT_CONTEXT = {"client": {"app_title": "Orders", "installation_id": "inst-1"}, "custom": {"k": "v"}, "env": {"locale": "en"}}


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Runtime:
    """One runtime process serving the handler in a task dir, with env added to the platform's."""

    def __init__(self, cmd, handler, task, env):
        self.port = free_port()
        full = {k: v for k, v in os.environ.items() if not k.startswith(("OPENINFRA_", "AWS_"))}
        full.update({"OPENINFRA_HANDLER": handler, "OPENINFRA_TASK_DIR": task, "OPENINFRA_OPT_DIR": os.path.join(task, "opt"),
                     "OPENINFRA_FUNCTION_NAME": FN, "PORT": str(self.port), "PYTHONUNBUFFERED": "1",
                     "PYTHONDONTWRITEBYTECODE": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1"})
        full.update(env)
        self.proc = subprocess.Popen(cmd, env=full, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, universal_newlines=True)
        self.logs = []
        threading.Thread(target=lambda: [self.logs.append(l) for l in self.proc.stderr], daemon=True).start()

    def invoke(self, headers=None, timeout=60):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        h = {"X-Openinfra-Invoke": "direct", "Content-Type": "application/json"}
        h.update(headers or {})
        req = urllib.request.Request("http://127.0.0.1:%d/" % self.port, data=b"{}", headers=h)
        start, last = time.time(), None
        while time.time() - start < timeout:
            try:
                with opener.open(req, timeout=timeout) as r:
                    return json.loads(r.read().decode())
            except OSError as e:  # the listener opens just after the "serving" line
                last = e
                if self.proc.poll() is not None:
                    break
                time.sleep(0.05)
        raise AssertionError("no answer: %s\n%s" % (last, "".join(self.logs)))

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc.stderr.close()


class Cases:
    """Each runtime class sets start(env) -> Runtime."""

    extra = {}  # runtime-specific expectations: {field: value}

    def runtime(self, env):
        rt = self.start(env)
        self.addCleanup(rt.close)
        return rt

    def test_the_arn_and_version_the_caller_passes(self):
        rt = self.runtime({"AWS_REGION": "us-east-1", "AWS_ROLE_ARN": ROLE})
        c = rt.invoke({"X-Openinfra-Invoked-Function-Arn": OWN + ":live", "X-Openinfra-Function-Version": "2"})
        self.assertEqual(c["arn"], OWN + ":live")
        self.assertEqual(c["version"], "2")
        self.assertEqual(c["logGroup"], "/aws/lambda/" + FN)
        for k, v in self.extra.items():
            self.assertEqual(c[k], v, k)
        c = rt.invoke({"X-Openinfra-Invoked-Function-Arn": OWN})
        self.assertEqual((c["arn"], c["version"]), (OWN, "$LATEST"))

    def test_an_arn_of_another_function_is_not_taken(self):
        rt = self.runtime({"AWS_REGION": "eu-west-1", "AWS_ROLE_ARN": ROLE})
        own = "arn:aws:lambda:eu-west-1:210987654321:function:" + FN
        for given in ("arn:aws:lambda:us-east-1:123456789012:function:other", "nonsense", ""):
            c = rt.invoke({"X-Openinfra-Invoked-Function-Arn": given, "X-Openinfra-Function-Version": "v1"} if given else {})
            self.assertEqual(c["arn"], own, given)
            self.assertEqual(c["version"], "$LATEST", given)

    def test_no_arn_without_a_role(self):
        rt = self.runtime({"AWS_REGION": "us-east-1"})
        self.assertEqual(rt.invoke()["arn"], "")

    def test_client_context(self):
        rt = self.runtime({"AWS_REGION": "us-east-1"})
        c = rt.invoke({"X-Amz-Client-Context": base64.b64encode(json.dumps(CLIENT_CONTEXT).encode()).decode()})
        self.assertEqual(c["clientContext"], {"appTitle": "Orders", "installationId": "inst-1", "custom": "v", "env": "en"})
        self.assertIsNone(rt.invoke()["clientContext"], "no ClientContext passed: none in the context")


NODE_HANDLER = """exports.handler = async (event, context) => {
  const cc = context.clientContext;
  return {
    arn: context.invokedFunctionArn, version: context.functionVersion, logGroup: context.logGroupName,
    waits: context.callbackWaitsForEmptyEventLoop, executionEnv: process.env.AWS_EXECUTION_ENV,
    clientContext: cc ? { appTitle: cc.client.app_title, installationId: cc.client.installation_id, custom: cc.custom.k, env: cc.env.locale } : null,
  };
};
"""

PYTHON_HANDLER = """import os

def handler(event, context):
    cc = context.client_context
    return {
        "arn": context.invoked_function_arn, "version": context.function_version, "logGroup": context.log_group_name,
        "clientContext": {"appTitle": cc.client.app_title, "installationId": cc.client.installation_id,
                          "custom": cc.custom["k"], "env": cc.env["locale"]} if cc else None,
    }
"""

# The handler declares the Amazon.Lambda.Core interfaces it reads (the runtime binds them by name), so the
# test needs no package feed.
DOTNET_CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <NetVersion Condition="'$(NetVersion)' == ''">8.0</NetVersion>
    <TargetFramework>net$(NetVersion)</TargetFramework>
    <AssemblyName>Handler</AssemblyName>
  </PropertyGroup>
</Project>
"""
DOTNET_HANDLER = """using System.Collections.Generic;
using System.Text.Json;
namespace Amazon.Lambda.Core
{
    public interface IClientApplication { string AppPackageName { get; } string AppTitle { get; } string AppVersionCode { get; } string AppVersionName { get; } string InstallationId { get; } }
    public interface IClientContext { IDictionary<string, string> Environment { get; } IClientApplication Client { get; } IDictionary<string, string> Custom { get; } }
    public interface ILambdaContext
    {
        string AwsRequestId { get; } IClientContext ClientContext { get; } string FunctionName { get; } string FunctionVersion { get; }
        string InvokedFunctionArn { get; } string LogGroupName { get; } string LogStreamName { get; } int MemoryLimitInMB { get; }
        System.TimeSpan RemainingTime { get; }
    }
}
namespace Pkg
{
    public static class Fn
    {
        public static string Handle(string e, Amazon.Lambda.Core.ILambdaContext c)
        {
            var cc = c.ClientContext;
            object client = cc == null ? null : new Dictionary<string, string> {
                ["appTitle"] = cc.Client.AppTitle, ["installationId"] = cc.Client.InstallationId,
                ["custom"] = cc.Custom["k"], ["env"] = cc.Environment["locale"] };
            return JsonSerializer.Serialize(new Dictionary<string, object> {
                ["arn"] = c.InvokedFunctionArn, ["version"] = c.FunctionVersion, ["logGroup"] = c.LogGroupName, ["clientContext"] = client });
        }
    }
}
"""


def write_task(files):
    task = tempfile.mkdtemp(dir=TMP)
    for name, src in files.items():
        with open(os.path.join(task, name), "w") as f:
            f.write(src)
    return task


@unittest.skipUnless(shutil.which("node"), "node is not on PATH")
class NodeContext(Cases, unittest.TestCase):
    extra = {"waits": True, "executionEnv": "AWS_Lambda_nodejs22.x"}

    def start(self, env):
        env = dict(env, AWS_EXECUTION_ENV="AWS_Lambda_nodejs22")
        return Runtime(["node", os.path.join(RUNTIMES, "nodejs", "bootstrap.js")], "index.handler",
                       write_task({"index.js": NODE_HANDLER}), env)


class PythonContext(Cases, unittest.TestCase):
    def start(self, env):
        return Runtime([sys.executable, os.path.join(RUNTIMES, "python", "bootstrap.py")], "index.handler",
                       write_task({"index.py": PYTHON_HANDLER}), env)


# DOTNET_VERSION is the .NET the host and the handler are built for: 8.0 (dotnet8), or 10.0 (dotnet10) with
# OPENINFRA_TEST_DOTNET=10.0, as each runtime's image builds its host (NetVersion, bootstrap.csproj).
DOTNET_VERSION = os.environ.get("OPENINFRA_TEST_DOTNET", "8.0")


def dotnet_publish(project, out):
    r = subprocess.run(["dotnet", "publish", project, "-c", "Release", "-p:NetVersion=" + DOTNET_VERSION, "-o", out, "--nologo"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,
                       env=dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1"))
    if r.returncode != 0:
        raise AssertionError("dotnet publish %s failed:\n%s" % (project, r.stdout))


@unittest.skipUnless(shutil.which("dotnet"), "dotnet is not on PATH")
class DotnetContext(Cases, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = tempfile.mkdtemp(dir=TMP)
        # Built from a copy, as the image's Dockerfile builds it, so no bin/ or obj/ lands in the repository.
        src = os.path.join(work, "bootstrap-src")
        shutil.copytree(os.path.join(RUNTIMES, "dotnet"), src, ignore=shutil.ignore_patterns("bin", "obj", "Dockerfile"))
        dotnet_publish(os.path.join(src, "bootstrap.csproj"), os.path.join(work, "bootstrap"))
        hsrc = os.path.join(work, "handler-src")
        os.makedirs(hsrc)
        with open(os.path.join(hsrc, "Handler.csproj"), "w") as f:
            f.write(DOTNET_CSPROJ)
        with open(os.path.join(hsrc, "Fn.cs"), "w") as f:
            f.write(DOTNET_HANDLER)
        dotnet_publish(os.path.join(hsrc, "Handler.csproj"), os.path.join(work, "handler"))
        cls.task = os.path.join(work, "handler")
        cls.cmd = ["dotnet", os.path.join(work, "bootstrap", "bootstrap.dll")]

    def start(self, env):
        return Runtime(self.cmd, "Handler::Pkg.Fn::Handle", self.task, env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
