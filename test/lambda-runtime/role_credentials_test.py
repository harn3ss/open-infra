#!/usr/bin/env python3
# Tests for the execution role's credentials as the first-party runtimes hand them to a function, as Lambda
# does: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN are in the environment before the
# handler's module loads. lambda-runtime/python/bootstrap.py, lambda-runtime/nodejs/bootstrap.js and
# lambda-runtime/dotnet (dotnet8) are each run as their image runs them, as a process on loopback, against a
# stub STS endpoint (AWS_ENDPOINT_URL_STS) answering sts:AssumeRoleWithWebIdentity in STS's XML.
#
# Covered, per runtime:
#   - at cold start the bootstrap asks STS for the role's session (AssumeRoleWithWebIdentity, Version
#     2011-06-15, RoleArn, RoleSessionName, the trimmed web identity token, DurationSeconds 43200, as a form
#     POST to the endpoint's /) and the handler's module sees the three variables as it loads, with
#     AWS_CREDENTIAL_EXPIRATION; AWS_ROLE_ARN is kept; the session name falls back to
#     AWS_LAMBDA_FUNCTION_NAME, then "lambda";
#   - a role whose maximum session is shorter: STS's refusal naming DurationSeconds is asked again without it;
#   - an STS refusal, an unreachable STS and one that never answers leave the function serving without the
#     variables, said in one line; nothing is set or asked when keys are already given or the role is not;
#   - credentials near their expiry are refreshed before an invocation (and only then: no call otherwise); a
#     failed refresh keeps the current ones, said once, and is not tried again at once;
#   - no credential value and no token is ever logged, and no proxy is used.
#
# stdlib only, no root, no cluster. node and dotnet run when they are on PATH, and are skipped, saying so,
# when not.
#
#   python3 test/lambda-runtime/role_credentials_test.py
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import code_package_test as cp  # noqa: E402  (ThreadingHTTPServer)
import context_test as ct  # noqa: E402  (Runtime, write_task, dotnet_publish, DOTNET_CSPROJ)

RUNTIMES = ct.RUNTIMES
TMP = tempfile.mkdtemp(prefix="oi-role-credentials-test-")
ROLE = "arn:aws:iam::111122223333:role/fn-exec"
TOKEN = "eyJhbGciOiJSUzI1NiJ9.web-identity-sentinel-never-logged.c2lnbmF0dXJl"
KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_CREDENTIAL_EXPIRATION", "AWS_ROLE_ARN")
STS_NS = "https://sts.amazonaws.com/doc/2011-06-15/"


def tearDownModule():
    for d in (TMP, cp.TMP, ct.TMP):
        shutil.rmtree(d, ignore_errors=True)


class Creds:
    """A role session STS answers: invented values; the session token has characters STS escapes in XML."""

    def __init__(self, tag, expires_in):
        self.akid = "AKIDEXAMPLE" + tag.upper()
        self.secret = "secret-example-%s+/Zq=" % tag
        self.session = "session-example-%s+/A&B=" % tag
        self.expiration = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + expires_in))

    def xml(self):
        return ('<?xml version="1.0" encoding="UTF-8"?>\n<AssumeRoleWithWebIdentityResponse xmlns="%s">'
                "<AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId>"
                "<SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration>"
                "</Credentials><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/fn-exec/creds-fn</Arn>"
                "<AssumedRoleId>fn-exec:creds-fn</AssumedRoleId></AssumedRoleUser>"
                "<SubjectFromWebIdentityToken>system:serviceaccount:example:creds-fn</SubjectFromWebIdentityToken>"
                "</AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>0c4f5e8a-1b2d-4c3e-9f6a-7b8c9d0e1f2a"
                "</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>"
                % (STS_NS, self.akid, self.secret, self.session.replace("&", "&amp;"), self.expiration)).encode()

    def env(self):
        return {"AWS_ACCESS_KEY_ID": self.akid, "AWS_SECRET_ACCESS_KEY": self.secret, "AWS_SESSION_TOKEN": self.session,
                "AWS_CREDENTIAL_EXPIRATION": self.expiration, "AWS_ROLE_ARN": ROLE}

    def values(self):
        return (self.akid, self.secret, self.session)


def sts_error(status, code, message):
    return (status, ('<ErrorResponse xmlns="%s"><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error>'
                     "<RequestId>5e1d2c3b-4a59-4687-b6c5-d4e3f2a1b0c9</RequestId></ErrorResponse>"
                     % (STS_NS, code, message)).encode())


class STS:
    """A stub STS endpoint: each POST takes the next step of script (the last repeats); a step is
    (status, body), or a function of the request's form giving one. It records each request."""

    def __init__(self):
        self.script = []
        self.requests = []
        lock = threading.Lock()
        stub = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                form = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
                with lock:
                    stub.requests.append({"path": self.path, "type": self.headers.get("Content-Type"), "form": form})
                    step = stub.script.pop(0) if len(stub.script) > 1 else stub.script[0]
                status, body = step(form) if callable(step) else step
                self.send_response(status)
                self.send_header("Content-Type", "text/xml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = cp.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class Silent:
    """An endpoint that accepts connections and never answers."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.conns = []
        threading.Thread(target=self._accept, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.sock.getsockname()[1]

    def _accept(self):
        while True:
            try:
                self.conns.append(self.sock.accept()[0])
            except OSError:
                return

    def close(self):
        for c in self.conns:
            c.close()
        self.sock.close()


class Cases:
    """Each runtime class sets start(env) -> ct.Runtime, serving a handler that answers {"load": <KEYS as
    its module saw them when it loaded>, "now": <KEYS as it sees them now>}."""

    def setUp(self):
        self.sts = STS()
        self.addCleanup(self.sts.close)
        self.work = tempfile.mkdtemp(dir=TMP)
        self.token_file = os.path.join(self.work, "token")
        with open(self.token_file, "w") as f:
            f.write(TOKEN + "\n")  # projected tokens are trimmed before use
        self.secrets = [TOKEN]

    def runtime(self, script, **over):
        self.sts.script = list(script)
        env = {"AWS_REGION": "us-east-1", "AWS_ROLE_ARN": ROLE, "AWS_ROLE_SESSION_NAME": "creds-fn",
               "AWS_WEB_IDENTITY_TOKEN_FILE": self.token_file, "AWS_ENDPOINT_URL_STS": self.sts.url,
               "AWS_LAMBDA_FUNCTION_NAME": "creds-fn-name", "OPENINFRA_TIMEOUT_S": "3",
               # A dead proxy: a bootstrap that sent the token through a proxy could not reach the stub at all.
               "HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9",
               "HTTPS_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9"}
        for k, v in over.items():
            if v is None:
                env.pop(k, None)
            else:
                env[k] = v
        rt = self.start(env)
        self.addCleanup(rt.close)
        self.addCleanup(self.assertNothingSecretLogged, rt)
        return rt

    def assertNothingSecretLogged(self, rt):
        logs = "".join(rt.logs)
        for s in self.secrets:
            self.assertNotIn(s, logs, "a credential value or the token was logged")

    def expect(self, *creds):
        for c in creds:
            self.secrets += list(c.values())
        return creds

    def none(self):
        return {k: (ROLE if k == "AWS_ROLE_ARN" else None) for k in KEYS}

    def lines(self, rt, phrase):
        return [l for l in "".join(rt.logs).splitlines() if phrase in l]

    def assertAssumeRequest(self, req, duration=True, session="creds-fn"):
        self.assertEqual(req["path"], "/")
        self.assertEqual((req["type"] or "").split(";")[0], "application/x-www-form-urlencoded")
        want = {"Action": "AssumeRoleWithWebIdentity", "Version": "2011-06-15", "RoleArn": ROLE,
                "RoleSessionName": session, "WebIdentityToken": TOKEN}
        if duration:
            want["DurationSeconds"] = "43200"
        self.assertEqual(req["form"], want)

    def test_the_credentials_are_in_the_environment_when_the_handler_loads(self):
        (a,) = self.expect(Creds("first", 12 * 3600))
        rt = self.runtime([(200, a.xml())])
        got = rt.invoke()
        self.assertEqual(got["load"], a.env(), "the module saw the role's credentials as it loaded")
        self.assertEqual(got["now"], a.env())
        self.assertEqual(rt.invoke()["now"], a.env())
        self.assertEqual(len(self.sts.requests), 1, "one call at cold start, none while they are far from expiry")
        self.assertAssumeRequest(self.sts.requests[0])
        self.assertEqual(len(self.lines(rt, "open-infra-runtime: the execution role's credentials are in the environment")), 1,
                         "".join(rt.logs))

    def test_the_session_name_falls_back_to_the_function_name_then_lambda(self):
        (a,) = self.expect(Creds("named", 12 * 3600))
        rt = self.runtime([(200, a.xml())], AWS_ROLE_SESSION_NAME=None)
        self.assertEqual(rt.invoke()["load"], a.env())
        self.assertAssumeRequest(self.sts.requests[0], session="creds-fn-name")
        rt.close()
        self.sts.requests[:] = []
        rt = self.runtime([(200, a.xml())], AWS_ROLE_SESSION_NAME=None, AWS_LAMBDA_FUNCTION_NAME=None)
        self.assertEqual(rt.invoke()["load"], a.env())
        self.assertAssumeRequest(self.sts.requests[0], session="lambda")

    def test_a_shorter_maximum_session_is_asked_again_without_duration_seconds(self):
        (a,) = self.expect(Creds("onehour", 3600))
        refusal = sts_error(400, "ValidationError", "The requested DurationSeconds exceeds the MaxSessionDuration set for this role.")
        rt = self.runtime([lambda form: refusal if "DurationSeconds" in form else (200, a.xml())])
        self.assertEqual(rt.invoke()["load"], a.env())
        self.assertEqual(len(self.sts.requests), 2)
        self.assertAssumeRequest(self.sts.requests[0], duration=True)
        self.assertAssumeRequest(self.sts.requests[1], duration=False)

    def test_an_sts_refusal_leaves_the_function_serving_without_the_keys(self):
        rt = self.runtime([sts_error(403, "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")])
        got = rt.invoke()
        self.assertEqual(got["load"], self.none())
        self.assertEqual(got["now"], self.none())
        self.assertEqual(rt.invoke()["now"], self.none())
        self.assertEqual(len(self.sts.requests), 1, "a cold start's failure is not tried again at every invocation")
        said = self.lines(rt, "open-infra-runtime: the execution role's credentials are not in the environment")
        self.assertEqual(len(said), 1, "".join(rt.logs))
        self.assertIn("AccessDenied", said[0])

    def test_an_unreachable_or_silent_sts_leaves_the_function_serving(self):
        silent = Silent()
        self.addCleanup(silent.close)
        for url in ("http://127.0.0.1:%d" % ct.free_port(), silent.url):
            start = time.time()
            rt = self.runtime([(500, b"")], AWS_ENDPOINT_URL_STS=url)
            got = rt.invoke()
            self.assertLess(time.time() - start, 20, "the STS call has a short timeout: %s" % url)
            self.assertEqual(got["load"], self.none(), url)
            self.assertEqual(len(self.lines(rt, "the execution role's credentials are not in the environment")), 1,
                             "".join(rt.logs))
            rt.close()

    def test_nothing_is_asked_when_keys_are_given_or_the_role_is_not_set(self):
        given = {"AWS_ACCESS_KEY_ID": "AKIDEXAMPLEGIVEN", "AWS_SECRET_ACCESS_KEY": "given-secret-example"}
        (a,) = self.expect(Creds("unused", 12 * 3600))
        rt = self.runtime([(200, a.xml())], **given)
        got = rt.invoke()
        self.assertEqual(got["load"]["AWS_ACCESS_KEY_ID"], "AKIDEXAMPLEGIVEN", "keys already given stay the function's")
        self.assertIsNone(got["load"]["AWS_SESSION_TOKEN"])
        rt.close()
        for unset in ("AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ENDPOINT_URL_STS"):
            rt = self.runtime([(200, a.xml())], **{unset: None})
            self.assertIsNone(rt.invoke()["load"]["AWS_ACCESS_KEY_ID"], unset)
            rt.close()
        self.assertEqual(self.sts.requests, [])

    def test_credentials_near_their_expiry_are_refreshed_before_an_invocation(self):
        a, b = self.expect(Creds("expiring", 120), Creds("fresh", 12 * 3600))
        rt = self.runtime([(200, a.xml()), (200, b.xml())])
        got = rt.invoke()
        self.assertEqual(got["load"], a.env(), "the module loaded with the first session")
        self.assertEqual(got["now"], b.env(), "refreshed before the invocation: they expired within 5 minutes of its end")
        self.assertEqual(len(self.sts.requests), 2)
        self.assertAssumeRequest(self.sts.requests[1])
        self.assertEqual(rt.invoke()["now"], b.env())
        self.assertEqual(len(self.sts.requests), 2, "no call while the fresh session is far from expiry")
        self.assertEqual(len(self.lines(rt, "open-infra-runtime: refreshed the execution role's credentials")), 1,
                         "".join(rt.logs))

    def test_a_failed_refresh_keeps_the_current_credentials(self):
        (a,) = self.expect(Creds("kept", 120))
        rt = self.runtime([(200, a.xml()), sts_error(503, "ServiceUnavailable", "the shim is restarting")])
        self.assertEqual(rt.invoke()["now"], a.env())
        self.assertEqual(rt.invoke()["now"], a.env())
        self.assertEqual(len(self.sts.requests), 2, "a failed refresh is not tried again at once")
        said = self.lines(rt, "could not refresh the execution role's credentials")
        self.assertEqual(len(said), 1, "".join(rt.logs))
        self.assertIn("ServiceUnavailable", said[0])
        self.assertIn("the current ones are kept", said[0])


NODE_HANDLER = """const KEYS = %s;
const pick = () => { const o = {}; for (const k of KEYS) o[k] = process.env[k] === undefined ? null : process.env[k]; return o; };
const atLoad = pick();
exports.handler = async () => ({ load: atLoad, now: pick() });
""" % json.dumps(list(KEYS))

PYTHON_HANDLER = """import os

KEYS = %r
AT_LOAD = {k: os.environ.get(k) for k in KEYS}


def handler(event, context):
    return {"load": AT_LOAD, "now": {k: os.environ.get(k) for k in KEYS}}
""" % (KEYS,)

# An instance handler: the runtime constructs it as it loads the handler, as Lambda's .NET runtime does.
DOTNET_HANDLER = """using System;
using System.Collections.Generic;
using System.Text.Json;
namespace Pkg
{
    public class Fn
    {
        static readonly string[] Keys = { %s };
        readonly Dictionary<string, string> _atLoad = Pick();
        static Dictionary<string, string> Pick()
        {
            var d = new Dictionary<string, string>();
            foreach (var k in Keys) d[k] = Environment.GetEnvironmentVariable(k);
            return d;
        }
        public string Handle(string e) =>
            JsonSerializer.Serialize(new Dictionary<string, object> { ["load"] = _atLoad, ["now"] = Pick() });
    }
}
""" % ", ".join('"%s"' % k for k in KEYS)


@unittest.skipUnless(shutil.which("node"), "node is not on PATH")
class NodeCredentials(Cases, unittest.TestCase):
    def start(self, env):
        return ct.Runtime(["node", os.path.join(RUNTIMES, "nodejs", "bootstrap.js")], "index.handler",
                          ct.write_task({"index.js": NODE_HANDLER}), env)


class PythonCredentials(Cases, unittest.TestCase):
    def start(self, env):
        return ct.Runtime([sys.executable, os.path.join(RUNTIMES, "python", "bootstrap.py")], "index.handler",
                          ct.write_task({"index.py": PYTHON_HANDLER}), env)


@unittest.skipUnless(shutil.which("dotnet"), "dotnet is not on PATH")
class DotnetCredentials(Cases, unittest.TestCase):
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
        return ct.Runtime(self.cmd, "Handler::Pkg.Fn::Handle", self.task, env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
