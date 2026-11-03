#!/usr/bin/env python3
# Unit tests for the metadata agent's SSM Run Command half (#347 item 22, CommandRunner), run against the
# EXACT agent text the VM composition ships. stdlib only, Python 3.6-compatible, no root needed.
#
# Covered: an AWS-RunShellScript command runs with its workingDirectory and executionTimeout, its exit
# status decides Success/Failed/TimedOut, each stream keeps 24,000 characters, nothing is left on disk;
# the channel to the shim sends the instance token only over TLS verified against the platform root
# (never in plain text, never to an impostor), long-polls with the guest's platform details, reports to
# /v1/vm-commands/<command id>, and a refusal carries its status so the agent backs off.

import http.server
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.parse

import vmcreds_common as common

TMP = tempfile.mkdtemp(prefix="oi-cmd-test-")
agent = common.load_agent_module(TMP)
PKI = common.get_test_pki(TMP)


def command(cid, *lines, **params):
    p = {"commands": list(lines)}
    if "workdir" in params:
        p["workingDirectory"] = [params["workdir"]]
    if "timeout" in params:
        p["executionTimeout"] = [str(params["timeout"])]
    return {"CommandId": cid, "DocumentName": "AWS-RunShellScript", "Parameters": p}


class ExecuteTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(dir=TMP)
        self.runner = agent.CommandRunner("https://shim.invalid/v1/vm-commands", "/nonexistent", "/nonexistent",
                                          work_dir=os.path.join(self.work, "commands"))

    def test_success_runs_every_line_and_keeps_both_streams(self):
        r = self.runner.execute(command("c-1", "echo one", "echo two", "echo err >&2"))
        self.assertEqual(r["Status"], "Success")
        self.assertEqual(r["ResponseCode"], 0)
        self.assertEqual(r["StandardOutputContent"], "one\ntwo\n")
        self.assertEqual(r["StandardErrorContent"], "err\n")
        self.assertEqual(os.listdir(os.path.join(self.work, "commands")), [], "the command's files are removed")

    def test_exit_status_fails_it_as_aws_reports(self):
        r = self.runner.execute(command("c-2", "echo partial", "exit 3"))
        self.assertEqual(r["Status"], "Failed")
        self.assertEqual(r["ResponseCode"], 3)
        self.assertEqual(r["StandardOutputContent"], "partial\n")
        self.assertTrue(r["StandardErrorContent"].endswith("failed to run commands: exit status 3"), r["StandardErrorContent"])

    def test_working_directory(self):
        d = tempfile.mkdtemp(dir=TMP)
        r = self.runner.execute(command("c-3", "pwd", workdir=d))
        self.assertEqual(r["StandardOutputContent"].strip(), os.path.realpath(d))
        r = self.runner.execute(command("c-4", "pwd", workdir=os.path.join(d, "missing")))
        self.assertEqual(r["Status"], "Failed")
        self.assertIn("failed to run commands", r["StandardErrorContent"])

    def test_execution_timeout_kills_the_whole_group(self):
        marker = os.path.join(TMP, "survivor")
        start = time.time()
        r = self.runner.execute(command("c-5", "(sleep 3; touch %s) &" % marker, "sleep 30", timeout=1))
        self.assertLess(time.time() - start, 10)
        self.assertEqual(r["Status"], "TimedOut")
        self.assertEqual(r["ResponseCode"], -1)
        self.assertIn("timed out", r["StandardErrorContent"])
        time.sleep(3.5)
        self.assertFalse(os.path.exists(marker), "a background child of the command must be killed with it")

    def test_output_is_capped(self):
        r = self.runner.execute(command("c-6", "head -c 30000 /dev/zero | tr '\\0' x"))
        self.assertEqual(len(r["StandardOutputContent"]), agent.OUTPUT_CAP)

    def test_a_hostile_command_id_stays_in_the_work_dir(self):
        r = self.runner.execute(command("../../etc/x", "pwd"))
        self.assertTrue(os.path.realpath(r["StandardOutputContent"].strip()).startswith(os.path.realpath(self.work)), r)


class StubShim(http.server.BaseHTTPRequestHandler):
    seen = []
    poll_status = 200
    commands = []
    report_status = 200

    def log_message(self, *a):
        pass

    def _send(self, status, body):
        b = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        StubShim.seen.append(("GET", self.path, self.headers.get("Authorization"), None))
        if StubShim.poll_status != 200:
            self._send(StubShim.poll_status, {"message": "refused"})
            return
        cmds, StubShim.commands = StubShim.commands, []
        self._send(200, {"InstanceId": "i-0123456789abcdef0", "Commands": cmds})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        StubShim.seen.append(("POST", self.path, self.headers.get("Authorization"), json.loads(self.rfile.read(n).decode())))
        self._send(StubShim.report_status, {})


@unittest.skipIf(PKI is None, "no openssl CLI and no OPENINFRA_TEST_PKI: TLS paths not exercised")
class ChannelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = common.tls_server(StubShim, PKI["server"], PKI["server-key"])
        cls.url = "https://127.0.0.1:%d/v1/vm-commands" % cls.srv.server_address[1]
        cls.rogue = common.tls_server(StubShim, PKI["rogue-server"], PKI["rogue-server-key"])
        cls.rogue_url = "https://127.0.0.1:%d/v1/vm-commands" % cls.rogue.server_address[1]
        cls.tok = os.path.join(TMP, "token")
        with open(cls.tok, "w") as fh:
            fh.write("header.payload.sig\n")

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.rogue.shutdown()

    def setUp(self):
        StubShim.seen, StubShim.poll_status, StubShim.commands, StubShim.report_status = [], 200, [], 200
        self.runner = agent.CommandRunner(self.url, self.tok, PKI["root"], work_dir=os.path.join(tempfile.mkdtemp(dir=TMP), "c"))

    def test_poll_sends_the_token_and_platform_details(self):
        StubShim.commands = [command("c-1", "echo hi")]
        got = self.runner.poll(wait=0)
        self.assertEqual([c["CommandId"] for c in got], ["c-1"])
        method, path, auth, _ = StubShim.seen[0]
        self.assertEqual((method, auth), ("GET", "header.payload.sig"))
        q = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
        self.assertEqual(q["wait"], ["0"])
        self.assertEqual(q["platformType"], ["Linux"])
        self.assertIn("agentVersion", q)

    def test_handle_runs_and_reports_its_own_command(self):
        self.runner.handle(command("c-9", "echo done"))
        method, path, auth, body = StubShim.seen[-1]
        self.assertEqual((method, path, auth), ("POST", "/v1/vm-commands/c-9", "header.payload.sig"))
        self.assertEqual(body["Status"], "Success")
        self.assertEqual(body["StandardOutputContent"], "done\n")
        self.assertEqual(self.runner.running, set())

    def test_a_report_the_shim_no_longer_expects_is_not_retried(self):
        StubShim.report_status = 409
        self.runner.handle(command("c-10", "true"), retry_wait=0.01)
        self.assertEqual(len([s for s in StubShim.seen if s[0] == "POST"]), 1)

    def test_a_refusal_carries_its_status(self):
        StubShim.poll_status = 403
        with self.assertRaises(agent.CredentialsError) as ctx:
            self.runner.poll(wait=0)
        self.assertEqual(ctx.exception.status, 403)

    def test_the_token_never_travels_in_clear_or_to_an_impostor(self):
        for url in (self.url.replace("https://", "http://"), self.rogue_url):
            runner = agent.CommandRunner(url, self.tok, PKI["root"])
            with self.assertRaises(agent.CredentialsError):
                runner.poll(wait=0)
        self.assertEqual(StubShim.seen, [], "nothing reaches a server the platform root does not vouch for")

    def test_run_forever_runs_each_command_once(self):
        StubShim.commands = [command("c-20", "echo a"), command("c-20", "echo a")]
        stop = threading.Event()
        t = threading.Thread(target=self.runner.run_forever, args=(stop,), daemon=True)
        t.start()
        deadline = time.time() + 5
        while time.time() < deadline and not [s for s in StubShim.seen if s[0] == "POST"]:
            time.sleep(0.05)
        stop.set()
        t.join(10)  # the poll in flight answers at once (the stub does not long-poll)
        self.assertFalse(t.is_alive())
        posts = [s for s in StubShim.seen if s[0] == "POST"]
        self.assertEqual([p[1] for p in posts], ["/v1/vm-commands/c-20"])


class AgentWiringTest(unittest.TestCase):
    def test_only_an_instance_with_a_role_is_managed(self):
        cfg = common.golden_config()
        self.assertTrue(cfg["commandsUrl"].endswith("/v1/vm-commands"))
        a = agent.Agent(agent.load_config(common.GOLDEN_CONFIG), fetch=lambda: None)
        self.assertIsNotNone(a.commands)
        path = os.path.join(TMP, "norole.json")
        cfg["role"] = ""
        with open(path, "w") as fh:
            json.dump(cfg, fh)
        self.assertIsNone(agent.Agent(agent.load_config(path)).commands)


if __name__ == "__main__":
    unittest.main(verbosity=2)
