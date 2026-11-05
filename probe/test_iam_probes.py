#!/usr/bin/env python3
"""Self-tests for the IAM probes (probe/iam-*.sh, probe/aws-shim-organizations.sh) against fakes: no
cluster, no shim, no console. They pin what a live run relies on:

  - the decision readers tell an IAM denial from anything else: the console gate's 403 naming the asked
    action is a deny, a downstream 403 or a 404 for a made-up resource is not; AWS's denial codes from the
    API are a deny, a NotFound is not; an unreachable door is "unknown" (the probe ends inconclusive,
    never passes or fails on it);
  - the console route table parses to every fixed-action route (a route-table move fails here, not
    silently in a live run);
  - the no-policy probe has an API call for every service the shim's router fronts;
  - every probe parses (bash -n).

    python3 probe/test_iam_probes.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LIB = os.path.join(HERE, "iam-lib.sh")


def read(path):
    with open(path) as f:
        return f.read()


def run_lib(snippet, fakes):
    """Source iam-lib.sh with fake executables first on PATH and run snippet; returns stdout."""
    with tempfile.TemporaryDirectory() as bindir:
        for name, body in fakes.items():
            p = os.path.join(bindir, name)
            with open(p, "w") as f:
                f.write("#!/usr/bin/env bash\n" + body)
            os.chmod(p, 0o755)
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
                   CONSOLE_ENDPOINT="http://console.test", SHIM_ENDPOINT="http://shim.test")
        out = subprocess.run(["bash", "-c", f'. "{LIB}"; {snippet}'], env=env,
                             capture_output=True, text=True, timeout=60)
        return out.stdout.strip(), out.returncode


def fake_curl(code, body):
    """A curl that writes body to the -o file and prints the status code for -w."""
    return (
        'out=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;; *) shift;; esac; done\n'
        f'printf %s {json.dumps(body)!s} > "$out"\n'
        f'printf %s "{code}"\n'
    )


def fake_aws(rc, stderr):
    return f'printf %s {json.dumps(stderr)} >&2\nexit {rc}\n'


class ConsoleDecision(unittest.TestCase):
    def decide(self, code, body, action="s3:DeleteBucket"):
        out, _ = run_lib(f'console_decision /dev/null DELETE /api/buckets/x "{action}"',
                         {"curl": fake_curl(code, body)})
        return out

    def test_the_gate_naming_the_action_is_a_deny(self):
        body = json.dumps({"errorCode": "AccessDeniedException", "action": "s3:DeleteBucket", "error": "…"})
        self.assertEqual(self.decide(403, body), "deny")

    def test_a_403_naming_another_action_is_not_this_decision(self):
        body = json.dumps({"errorCode": "AccessDeniedException", "action": "s3:ListBucket"})
        self.assertEqual(self.decide(403, body), "allow")

    def test_a_downstream_403_is_not_an_iam_deny(self):
        body = json.dumps({"errorCode": "AccessDeniedException", "error": "rewritten Kubernetes forbidden"})
        self.assertEqual(self.decide(403, body), "allow")

    def test_a_made_up_resource_404_is_allowed(self):
        self.assertEqual(self.decide(404, '{"errorCode":"ResourceNotFoundException"}'), "allow")

    def test_a_prefix_action(self):
        body = json.dumps({"errorCode": "AccessDeniedException", "action": "openinfra-operator:GetSecret"})
        self.assertEqual(self.decide(403, body, "openinfra-operator:Get*"), "deny")

    def test_an_expired_session_or_no_answer_is_unknown(self):
        self.assertEqual(self.decide(401, "{}"), "unknown")
        self.assertEqual(self.decide("000", ""), "unknown")

    def test_a_request_carries_the_console_header(self):
        # The console refuses a mutation without X-Openinfra-Console before its IAM gate runs: a probe that
        # left it off read that refusal as an allow (the cutover canary's rds:DeleteDBSnapshot).
        gate = json.dumps({"errorCode": "AccessDeniedException", "action": "rds:DeleteDBSnapshot"})
        curl = (
            'out=""; hdr=no; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;;'
            ' -H) [ "$2" = "X-Openinfra-Console: 1" ] && hdr=yes; shift 2;; *) shift;; esac; done\n'
            f'if [ $hdr = yes ]; then printf %s {json.dumps(gate)} > "$out"; else printf %s \'{{"error":"missing X-Openinfra-Console"}}\' > "$out"; fi\n'
            'printf 403\n'
        )
        out, _ = run_lib('console_decision /dev/null DELETE "/api/snapshots?id=x" rds:DeleteDBSnapshot', {"curl": curl})
        self.assertEqual(out, "deny")

    def test_a_refusal_before_the_gate_is_unknown(self):
        self.assertEqual(self.decide(403, '{"error":"missing X-Openinfra-Console"}'), "unknown")
        self.assertEqual(self.decide(403, '{"code":"PasswordResetRequired","error":"you must change your password"}'), "unknown")


class ShimDecision(unittest.TestCase):
    def decide(self, rc, stderr):
        out, _ = run_lib("shim_decision AK SK s3api list-buckets", {"aws": fake_aws(rc, stderr)})
        return out

    def test_success_is_allow(self):
        self.assertEqual(self.decide(0, ""), "allow")

    def test_aws_denials_are_deny(self):
        for err in ["An error occurred (AccessDenied) when calling the ListBuckets operation",
                    "An error occurred (AccessDeniedException) when calling the ListTables operation",
                    "An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation",
                    "An error occurred (AuthorizationError) when calling the ListTopics operation"]:
            self.assertEqual(self.decide(254, err), "deny", err)

    def test_not_found_is_allow(self):
        self.assertEqual(self.decide(254, "An error occurred (ResourceNotFoundException) …"), "allow")

    def test_an_unreachable_shim_is_unknown(self):
        self.assertEqual(self.decide(255, 'Could not connect to the endpoint URL: "http://shim.test/"'), "unknown")


class Decided(unittest.TestCase):
    def test_unknown_ends_inconclusive(self):
        _, rc = run_lib('echo why > "$PROBE_TMP/why"; decided unknown; echo after', {})
        self.assertEqual(rc, 42)

    def test_a_decision_continues(self):
        out, rc = run_lib("decided deny; echo after", {})
        self.assertEqual((out, rc), ("after", 0))


class LoginWaitsForThePrincipalsMode(unittest.TestCase):
    """iamp_login reads the session's own mode from /api/auth/me. A User made a moment ago reads as the
    platform's mode until the console's 30 s policy cache reloads, so it asks until IAMP_SETTLED_AT — the
    canary's no-policy and managed-policy probes asked once and ended inconclusive on that."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.counter = os.path.join(self.tmp.name, "n")

    def tearDown(self):
        self.tmp.cleanup()

    def curl(self, modes):
        # sign-in: 200 to -o; /api/auth/me: the next mode of `modes` on stdout (a counter file keeps state).
        return (
            'out=""; url=""; while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2;;'
            ' -c|-b|-m|-w|-d|-H|-X) shift 2;; *) url="$1"; shift;; esac; done\n'
            'case "$url" in\n'
            '  */api/auth/login) printf "{}" > "$out"; printf 200;;\n'
            f'  */api/auth/me) n=$(cat "{self.counter}" 2>/dev/null || echo 0); modes=({" ".join(modes)});'
            f' m=${{modes[$n]:-${{modes[-1]}}}}; echo $((n+1)) > "{self.counter}"; printf \'{{"iamAuthz":"%s"}}\' "$m";;\n'
            'esac\n'
        )

    def test_it_waits_for_enforce(self):
        out, rc = run_lib('IAMP_SETTLED_AT=$(( $(date +%s) + 20 )); iamp_login u pw /dev/null; echo signed-in',
                          {"curl": self.curl(["shadow", "shadow", "enforce"]), "sleep": "exit 0\n"})
        self.assertEqual((out, rc), ("signed-in", 0))

    def test_past_the_settle_time_it_is_inconclusive(self):
        _, rc = run_lib('IAMP_SETTLED_AT=0; iamp_login u pw /dev/null; echo signed-in',
                        {"curl": self.curl(["shadow"]), "sleep": "exit 0\n"})
        self.assertEqual(rc, 42)

    def test_settle_waits_out_the_shims_cache(self):
        out, rc = run_lib('IAMP_SETTLED_AT=$(( $(date +%s) + 7 )); iamp_settle; echo settled',
                          {"sleep": 'echo "slept $1" >&2; exit 0\n'})
        self.assertEqual((out, rc), ("settled", 0))


class ConsoleRoutes(unittest.TestCase):
    def test_every_fixed_action_route_parses(self):
        routes = os.path.join(REPO, "console-api", "cmd", "server", "routes.go")
        out, rc = run_lib(f'iamp_console_routes "{routes}" nope', {})
        self.assertEqual(rc, 0)
        lines = [ln for ln in out.splitlines() if ln]
        src = read(routes)
        registered = re.findall(r'\bh\((?:get|post|put|patch|del), "', src)
        self.assertGreaterEqual(len(lines), 80, "the route table has moved or changed shape")
        self.assertLessEqual(len(lines), len(registered))
        for ln in lines:
            method, path, action = ln.split(" ")
            self.assertIn(method, {"GET", "POST", "PUT", "PATCH", "DELETE"})
            self.assertTrue(path.startswith("/api/") and "{" not in path, path)
            self.assertRegex(action, r"^[a-z0-9-]+:[A-Za-z*]+$")


class NoPolicyCallsEveryService(unittest.TestCase):
    def test_every_router_service_has_a_call(self):
        router = json.loads(read(os.path.join(HERE, "registry", "shim-router.json")))["services"]
        script = read(os.path.join(HERE, "iam-no-policy.sh"))
        calls = set(re.findall(r'^\s+\[([a-z0-9-]+)\]="', script, re.M))
        missing = sorted(set(router) - calls - {"sts"})
        self.assertEqual(missing, [], "probe/iam-no-policy.sh has no call for these fronted services")


class LoginProfileProbe(unittest.TestCase):
    """probe/aws-shim-iam-login-profile.sh run whole against a fake shim, console and cluster
    (probe/fake_login_world.py): it passes against a faithful one, fails on each broken behaviour, ends
    inconclusive when IAM policy does not decide, and cleans up what it made either way."""

    def run_probe(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            os.mkdir(bindir)
            world = os.path.join(HERE, "fake_login_world.py")
            for tool in ("aws", "kubectl", "curl"):
                p = os.path.join(bindir, tool)
                with open(p, "w") as f:
                    f.write(f'#!/usr/bin/env bash\nexec "{sys.executable}" "{world}" {tool} "$@"\n')
                os.chmod(p, 0o755)
            p = os.path.join(bindir, "sleep")
            with open(p, "w") as f:
                f.write("#!/usr/bin/env bash\nexit 0\n")
            os.chmod(p, 0o755)
            state = os.path.join(tmp, "state.json")
            env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
                       CONSOLE_ENDPOINT="http://console.test", SHIM_ENDPOINT="http://shim.test",
                       FAKE_STATE=state, FAKE_MODE=mode)
            env.pop("PRINCIPAL_MODE", None)
            r = subprocess.run(["bash", os.path.join(HERE, "aws-shim-iam-login-profile.sh")], env=env,
                               capture_output=True, text=True, timeout=120)
            calls = []
            if os.path.exists(state + ".log"):
                calls = [json.loads(ln) for ln in read(state + ".log").splitlines()]
            return r.returncode, r.stdout + r.stderr, calls

    def assertCleanedUp(self, calls, out):
        deletes = [c for c in calls if c[0] == "kubectl" and "delete" in c]
        users = [c for c in deletes if "users.iam.openinfra.dev" in c]
        keys = [c for c in deletes if "secret" in c and any(a.startswith("iam-ak-") for a in c)]
        self.assertEqual(len(users), 2, out)  # the admin and the throwaway User
        self.assertEqual(len(keys), 2, out)   # their access keys

    def test_passes_against_a_faithful_shim_and_console(self):
        rc, out, calls = self.run_probe("good")
        self.assertEqual(rc, 0, out)
        self.assertIn("✓ PASS", out)
        for step in ["→ EntityAlreadyExists", "create-login-profile for root → NoSuchEntity",
                     "→ PasswordPolicyViolation", "refused with no grant (AccessDenied)",
                     "a wrong old password is refused (InvalidUserType)", "refused by openinfra-login-profile-guard"]:
            self.assertIn(step, out)
        self.assertCleanedUp(calls, out)
        self.assertFalse([c for c in calls if c[0] == "aws" and "update-account-password-policy" in c],
                         "the probe must never set the account password policy (it governs every user)")

    def test_a_wrong_old_password_accepted_fails(self):
        rc, out, calls = self.run_probe("wrong-old-accepted")
        self.assertEqual(rc, 1, out)
        self.assertIn("accepted a wrong old password", out)
        self.assertCleanedUp(calls, out)

    def test_a_hash_in_the_console_namespace_fails(self):
        rc, out, _ = self.run_probe("console-ns")
        self.assertEqual(rc, 1, out)
        self.assertIn("must be in the credential store", out)

    def test_a_missing_admission_guard_fails(self):
        rc, out, _ = self.run_probe("no-guard")
        self.assertEqual(rc, 1, out)
        self.assertIn("unlabelled iam-login-* Secret was admitted", out)

    def test_iam_policy_not_deciding_is_inconclusive(self):
        rc, out, calls = self.run_probe("iam-not-deciding")
        self.assertEqual(rc, 42, out)
        self.assertIn("IAM policy does not decide", out)
        self.assertCleanedUp(calls, out)


class Parses(unittest.TestCase):
    def test_bash_n(self):
        for name in ["iam-lib.sh", "iam-parity.sh", "iam-no-policy.sh", "iam-managed-policies.sh",
                     "aws-shim-organizations.sh", "aws-shim-iam-login-profile.sh"]:
            r = subprocess.run(["bash", "-n", os.path.join(HERE, name)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr}")
        cut = os.path.join(REPO, "hack", "iam-cutover.sh")
        if os.path.exists(cut):
            r = subprocess.run(["bash", "-n", cut], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
