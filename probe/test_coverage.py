#!/usr/bin/env python3
"""Tests for the AWS coverage registry gate (probe/coverage.py, run by probe/shimgen.py --check).

The gate must be shown to go RED, not just green: a CloudFormation type a stack can create with no
front door for its own API fails it — through the module, and end to end through the exact CI command
on a copy of the repository with one such type added. Also: a front door that serves no call reading
the type, an exception that is malformed, a wildcard or stale, a router service the proof registry
does not claim, and a hand-written doc table that claims more than the code.

  python3 probe/test_coverage.py
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import coverage  # noqa: E402

BAD_TYPE = "AWS::Route53::RecordSet"  # the router serves no route53 front door


def deployable(status="partial", kind="SomeKind"):
    return {"status": status, "kind": kind, "translator": True, "deployable": True}


class CoverageGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = coverage.load_inputs(ROOT)

    def inputs(self):
        return copy.deepcopy(self.base)

    def gate(self, inp):
        reg, errs = coverage.build(inp)
        return reg, errs + coverage.validate_sigv4(inp["services"], inp["shim"])

    # --- green: the committed registry passes ---

    def test_committed_registry_passes(self):
        reg, errs = self.gate(self.inputs())
        self.assertEqual(errs, [])
        self.assertEqual(reg["summary"]["violations"], 0)
        self.assertGreater(reg["summary"]["covered"], 0)

    def test_queue_is_covered_by_its_own_front_door(self):
        reg, _ = self.gate(self.inputs())
        q = reg["types"]["AWS::SQS::Queue"]
        self.assertEqual(q["verdict"], "ok")
        self.assertEqual(q["frontDoor"], ["sqs"])
        self.assertIn("GetQueueUrl", q["readCalls"])

    # --- red: a type a stack can create, with no front door for its API ---

    def test_red_deployable_type_without_front_door(self):
        inp = self.inputs()
        self.assertNotIn("route53", inp["shim"])
        inp["cfn"][BAD_TYPE] = deployable()
        reg, errs = self.gate(inp)
        self.assertEqual(reg["types"][BAD_TYPE]["verdict"], "violation")
        self.assertTrue(any(BAD_TYPE in e and "front door" in e for e in errs), errs)

    def test_red_unknown_namespace(self):
        inp = self.inputs()
        inp["cfn"]["AWS::Bogus::Widget"] = deployable()
        _, errs = self.gate(inp)
        self.assertTrue(any("AWS::Bogus" in e and "no signing name" in e for e in errs), errs)

    def test_red_front_door_serves_no_read_call(self):
        inp = self.inputs()
        inp["cfn"]["AWS::SQS::Widget"] = deployable()  # sqs is routed, but nothing reads a Widget
        reg, errs = self.gate(inp)
        self.assertEqual(reg["types"]["AWS::SQS::Widget"]["problem"], "read")
        self.assertTrue(any("AWS::SQS::Widget" in e and "serves no call" in e for e in errs), errs)

    def test_not_deployable_type_is_not_gated(self):
        inp = self.inputs()
        inp["cfn"][BAD_TYPE] = {"status": "unsupported", "translator": False, "deployable": False}
        _, errs = self.gate(inp)
        self.assertEqual(errs, [])

    # --- exceptions: they excuse, and only while they apply ---

    def test_exception_excuses_the_violation(self):
        inp = self.inputs()
        inp["cfn"][BAD_TYPE] = deployable()
        inp["facts"]["exceptions"].append({"types": [BAD_TYPE], "check": "front-door", "reason": "r", "issue": "i"})
        reg, errs = self.gate(inp)
        self.assertEqual(errs, [])
        self.assertEqual(reg["types"][BAD_TYPE]["verdict"], "excepted")

    def test_exception_for_the_wrong_check_fails(self):
        inp = self.inputs()
        inp["cfn"][BAD_TYPE] = deployable()
        inp["facts"]["exceptions"].append({"types": [BAD_TYPE], "check": "read", "reason": "r", "issue": "i"})
        _, errs = self.gate(inp)
        self.assertTrue(any(BAD_TYPE in e and "update the exception" in e for e in errs), errs)

    def test_stale_exception_fails(self):
        inp = self.inputs()
        inp["facts"]["exceptions"].append({"types": ["AWS::SQS::Queue"], "check": "front-door", "reason": "r", "issue": "i"})
        _, errs = self.gate(inp)
        self.assertTrue(any("AWS::SQS::Queue" in e and "remove the exception" in e for e in errs), errs)

    def test_exception_for_unknown_type_fails(self):
        inp = self.inputs()
        inp["facts"]["exceptions"].append({"types": ["AWS::Nope::Thing"], "check": "front-door", "reason": "r", "issue": "i"})
        _, errs = self.gate(inp)
        self.assertTrue(any("AWS::Nope::Thing" in e and "remove it" in e for e in errs), errs)

    def test_wildcard_exception_rejected(self):
        inp = self.inputs()
        inp["facts"]["exceptions"].append({"types": ["AWS::Route53::*"], "check": "front-door", "reason": "r", "issue": "i"})
        _, errs = self.gate(inp)
        self.assertTrue(any("wildcard" in e for e in errs), errs)

    def test_exception_needs_reason_and_issue(self):
        inp = self.inputs()
        inp["cfn"][BAD_TYPE] = deployable()
        inp["facts"]["exceptions"].append({"types": [BAD_TYPE], "check": "front-door"})
        _, errs = self.gate(inp)
        self.assertTrue(any("needs 'reason'" in e for e in errs), errs)
        self.assertTrue(any("needs 'issue'" in e for e in errs), errs)

    def test_committed_exceptions_all_have_reason_and_issue(self):
        for e in self.base["facts"]["exceptions"]:
            self.assertTrue(e.get("reason") and e.get("issue"), e)
            for t in e["types"]:
                self.assertNotRegex(t, r"[*?\[]")

    # --- the proof registry must agree with the router ---

    def test_router_service_nobody_claims_fails(self):
        inp = self.inputs()
        inp["shim"]["widgets"] = {"handler": "widgetHandler", "operations": ["DescribeWidgets"]}
        _, errs = self.gate(inp)
        self.assertTrue(any("'widgets'" in e and "no service in probe/shim-services.yaml claims it" in e for e in errs), errs)
        self.assertTrue(any("'widgets'" in e and "no CloudFormation namespace" in e for e in errs), errs)

    def test_proven_service_without_a_route_fails(self):
        inp = self.inputs()
        del inp["shim"]["kinesis"]
        _, errs = self.gate(inp)
        self.assertTrue(any("Kinesis" in e and "serves no 'kinesis'" in e for e in errs), errs)

    def test_planned_service_that_is_routed_fails(self):
        inp = self.inputs()
        inp["shim"]["route53"] = {"handler": "r53Handler", "operations": ["ListHostedZones"]}
        _, errs = self.gate(inp)
        self.assertTrue(any("Route 53" in e and "promote it" in e for e in errs), errs)

    # --- hand-written docs may not claim more than the code ---

    def test_doc_claiming_supported_for_a_partial_type_fails(self):
        reg, _ = self.gate(self.inputs())
        text = ("\n### Supported — a faithful backing kind\n\n| CloudFormation | open-infra |\n|---|---|\n"
                "| `AWS::EC2::Instance` | `kind: VirtualMachine` |\n\n"
                "### Partial — a backing kind exists, but the mapping is lossy\n\n| a | b | c |\n|---|---|---|\n\n"
                "Today's create translators (live-verified on the cluster):\n\n| a | b | c |\n|---|---|---|\n"
                "| `AWS::EC2::NatGateway` | `kind: NatGateway` | maps |\n")
        errs = coverage.check_cfn_doc_claims(text, reg["types"])
        self.assertTrue(any("AWS::EC2::Instance" in e and "supported" in e for e in errs), errs)
        self.assertTrue(any("AWS::EC2::NatGateway" in e and "create-deployable" in e for e in errs), errs)

    def test_committed_cfn_doc_claims_hold(self):
        reg, _ = self.gate(self.inputs())
        text = coverage.read_text(os.path.join(ROOT, "docs", "cloudformation.md"))
        self.assertEqual(coverage.check_cfn_doc_claims(text, reg["types"]), [])

    # --- the read-call default ---

    def test_read_call_default(self):
        ops = {"GetQueueUrl", "ListQueues", "DescribeRepositories", "ListAliases", "CreateThing"}
        self.assertEqual(coverage.read_calls("AWS::SQS::Queue", ops, {}), ["GetQueueUrl", "ListQueues"])
        self.assertEqual(coverage.read_calls("AWS::ECR::Repository", ops, {}), ["DescribeRepositories"])
        self.assertEqual(coverage.read_calls("AWS::KMS::Alias", ops, {}), ["ListAliases"])
        self.assertEqual(coverage.read_calls("AWS::X::Thing", ops, {}), [])
        self.assertEqual(coverage.read_calls("AWS::X::Thing", ops, {"AWS::X::Thing": ["ListQueues"]}), ["ListQueues"])


class ProofRegistry(unittest.TestCase):
    """shimgen.validate: the registry ⇄ probe/ contract. A pending probe (written, not yet run live) is
    claimed like any other, so a new probe still needs its entry, but it is never proof."""

    @classmethod
    def setUpClass(cls):
        import shimgen  # noqa: E402  (probe/shimgen.py)
        cls.shimgen = shimgen

    def validate(self, services, probes):
        return self.shimgen.validate(services, set(probes))

    def test_committed_registry_passes(self):
        self.assertEqual(self.shimgen.validate(self.shimgen.load_registry(), self.shimgen.probe_basenames()), [])

    def test_pending_probe_is_claimed(self):
        svc = [{"name": "IAM", "tier": "proven", "probes": ["iam"], "pending": ["iam-new"]}]
        self.assertEqual(self.validate(svc, ["iam", "iam-new"]), [])

    def test_unclaimed_probe_fails(self):
        svc = [{"name": "IAM", "tier": "proven", "probes": ["iam"]}]
        errs = self.validate(svc, ["iam", "iam-new"])
        self.assertTrue(any("aws-shim-iam-new.sh is not claimed" in e for e in errs), errs)

    def test_pending_is_not_proof(self):
        svc = [{"name": "Widgets", "tier": "proven", "pending": ["widgets"]}]
        errs = self.validate(svc, ["widgets"])
        self.assertTrue(any("Widgets: tier proven but no probe" in e for e in errs), errs)

    def test_pending_probe_must_exist(self):
        svc = [{"name": "IAM", "tier": "proven", "probes": ["iam"], "pending": ["iam-gone"]}]
        errs = self.validate(svc, ["iam"])
        self.assertTrue(any("pending names 'iam-gone'" in e for e in errs), errs)

    def test_probe_both_proven_and_pending_fails(self):
        svc = [{"name": "IAM", "tier": "proven", "probes": ["iam"], "pending": ["iam"]}]
        errs = self.validate(svc, ["iam"])
        self.assertTrue(any("claimed by both" in e for e in errs), errs)

    def test_gated_may_hold_a_pending_probe_planned_may_not(self):
        self.assertEqual(self.validate([{"name": "G", "tier": "gated", "pending": ["g"]}], ["g"]), [])
        errs = self.validate([{"name": "P", "tier": "planned", "pending": ["p"]}], ["p"])
        self.assertTrue(any("P: tier planned" in e for e in errs), errs)


class EndToEndRed(unittest.TestCase):
    """The exact CI command, `probe/shimgen.py --check`, on a copy of the repository: green as committed,
    red once one CloudFormation type a stack can create — with no front door for its API — is added to
    the engine's half of the registry."""

    def run_check(self, tree):
        return subprocess.run([sys.executable, os.path.join(tree, "probe", "shimgen.py"), "--check"],
                              capture_output=True, text=True)

    def copy_tree(self):
        tmp = tempfile.mkdtemp(prefix="coverage-red-")
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copytree(os.path.join(ROOT, "probe"), os.path.join(tmp, "probe"))
        shutil.copytree(os.path.join(ROOT, "docs"), os.path.join(tmp, "docs"))
        shutil.copytree(os.path.join(ROOT, "cfn", "testdata"), os.path.join(tmp, "cfn", "testdata"))
        if os.path.isdir(os.path.join(ROOT, "examples")):
            shutil.copytree(os.path.join(ROOT, "examples"), os.path.join(tmp, "examples"))
        shutil.copy(os.path.join(ROOT, "README.md"), os.path.join(tmp, "README.md"))
        return tmp

    def test_ci_command_green_then_red(self):
        tree = self.copy_tree()
        green = self.run_check(tree)
        self.assertEqual(green.returncode, 0, green.stdout + green.stderr)

        path = os.path.join(tree, "probe", "registry", "cfn-types.json")
        data = json.loads(coverage.read_text(path))
        data["types"][BAD_TYPE] = deployable()
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2) + "\n")

        red = self.run_check(tree)
        self.assertEqual(red.returncode, 1, red.stdout + red.stderr)
        self.assertIn("coverage registry gate", red.stdout)
        self.assertIn(BAD_TYPE, red.stdout)
        self.assertIn("serves no AWS::Route53 front door", red.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
