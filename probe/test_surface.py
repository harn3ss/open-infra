#!/usr/bin/env python3
"""Tests for the customer-surface gate (probe/surface.py) and the denial gate (probe/shimgen.py), both run
by `probe/shimgen.py --check`.

The gates must be shown to go RED, not just green: a claim kind with no row in the kinds table, a claim
field the committed registry does not list, a console route with no AWS action (or one AWS does not
document), a console screen that belongs to no service, a platform extra without the operator's ruling,
and a proven AWS API without a live denial each fail them — through the module, and end to end through the
exact CI command on a copy of the repository with one such capability added.

  python3 probe/test_surface.py
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
import shimgen  # noqa: E402
import surface  # noqa: E402


class SurfaceGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = surface.load_inputs(ROOT)

    def inputs(self):
        return copy.deepcopy(self.base)

    def gate(self, inp):
        return surface.build(inp)

    def assertError(self, errs, *needles):
        self.assertTrue(any(all(n in e for n in needles) for e in errs), errs)

    # --- green ---

    def test_committed_surface_passes(self):
        surf, errs = self.gate(self.inputs())
        self.assertEqual(errs, [])
        s = surf["summary"]
        self.assertGreaterEqual(s["kinds"]["total"], 50)
        self.assertGreaterEqual(s["fields"]["total"], 300)
        self.assertGreaterEqual(s["routes"]["total"], 100)
        self.assertGreaterEqual(s["screens"]["total"], 150)
        self.assertEqual(s["services"]["total"], len(self.base["shim"]))

    def test_committed_registry_is_current(self):
        surf, _ = self.gate(self.inputs())
        cur = surface.read_text(surface.SURFACE_JSON)
        self.assertEqual(surface.unregistered(surf, cur), [])
        self.assertEqual(surface.write(surf), cur)

    def test_classes(self):
        surf, _ = self.gate(self.inputs())
        self.assertEqual(surf["kinds"]["Bucket"]["class"], "aws")
        self.assertEqual(surf["kinds"]["Bucket"]["actions"]["create"], "s3:CreateBucket")
        self.assertEqual(surf["kinds"]["DataFlow"]["class"], "extra")
        self.assertEqual(surf["kinds"]["Account"]["class"], "operator")
        self.assertEqual(surf["fields"]["Function.image"]["actions"], ["lambda:UpdateFunctionCode"])
        self.assertEqual(surf["routes"]["GET /api/nodes/disk"]["class"], "operator")
        self.assertEqual(surf["routes"]["DELETE /api/buckets/{bucket}"]["resource"], "arn:aws:s3:::{bucket}")
        self.assertEqual(surf["screens"]["/workloads"]["class"], "operator")
        self.assertEqual(surf["screens"]["/buckets/$bucket"]["service"], ["s3"])

    # --- red: claim kinds ---

    def test_red_kind_without_a_row(self):
        inp = self.inputs()
        inp["xrds"]["Frobnicator"] = {"group": "openinfra.dev", "plural": "frobnicators", "fields": ["size"],
                                      "file": "platform/abstraction/frobnicator-xrd.yaml", "claim": True}
        _, errs = self.gate(inp)
        self.assertError(errs, "kind Frobnicator", "no row in the kinds table")

    def test_red_kind_in_another_group(self):
        inp = self.inputs()
        inp["xrds"]["Widget"] = {"group": "widgets.openinfra.dev", "plural": "widgets", "fields": [],
                                 "file": "platform/x.yaml", "claim": False}
        _, errs = self.gate(inp)
        self.assertError(errs, "kind Widget", "operatorKinds")

    def test_red_extra_without_a_ruling(self):
        inp = self.inputs()
        del inp["facts"]["extras"]["kinds"]["DataFlow"]
        _, errs = self.gate(inp)
        self.assertError(errs, "kind DataFlow", "platform extra", "no operator ruling")

    def test_red_extra_ruling_needs_reason_and_approval(self):
        inp = self.inputs()
        inp["facts"]["extras"]["kinds"]["DataFlow"] = {}
        _, errs = self.gate(inp)
        self.assertError(errs, "extras.kinds.DataFlow", "'reason'")
        self.assertError(errs, "extras.kinds.DataFlow", "'approval'")

    def test_red_kind_action_aws_does_not_document(self):
        inp = self.inputs()
        inp["kinds"]["Bucket"]["actions"]["delete"] = "s3:Obliterate"
        _, errs = self.gate(inp)
        self.assertError(errs, "kind Bucket", "s3:Obliterate", "does not document")

    def test_red_stale_rulings(self):
        inp = self.inputs()
        inp["facts"]["extras"]["kinds"]["Bucket"] = {"reason": "r", "approval": "a"}
        inp["facts"]["operatorKinds"]["Gone"] = {"reason": "r"}
        inp["facts"]["screens"]["Frobnicators"] = {"service": "s3"}
        inp["facts"]["perRequest"]["/api/gone"] = {"class": "aws", "how": "h"}
        inp["facts"]["kubernetesFields"]["Bucket.namespaceGone"] = {"disposition": "pending", "reason": "r"}
        _, errs = self.gate(inp)
        self.assertError(errs, "extras.kinds.Bucket", "AWS-shaped now")
        self.assertError(errs, "operatorKinds.Gone", "remove the entry")
        self.assertError(errs, "screens.Frobnicators", "remove the entry")
        self.assertError(errs, "perRequest./api/gone", "remove the entry")
        self.assertError(errs, "kubernetesFields.Bucket.namespaceGone", "remove the entry")

    # --- red: claim fields ---

    def test_red_field_in_kubernetes_vocabulary(self):
        inp = self.inputs()
        inp["xrds"]["Bucket"]["fields"] = sorted(inp["xrds"]["Bucket"]["fields"] + ["nodeSelector"])
        _, errs = self.gate(inp)
        self.assertError(errs, "Bucket spec.nodeSelector", "Kubernetes vocabulary")

    def test_red_unregistered_field_is_named(self):
        inp = self.inputs()
        inp["xrds"]["Bucket"]["fields"] = sorted(inp["xrds"]["Bucket"]["fields"] + ["retentionDays"])
        surf, errs = self.gate(inp)
        self.assertEqual(errs, [])
        names = surface.unregistered(surf, surface.read_text(surface.SURFACE_JSON))
        self.assertTrue(any("claim field Bucket.retentionDays" in n and "not in the committed registry" in n
                            and "s3:PutBucketPolicy" in n for n in names), names)

    # --- red: console routes ---

    def test_red_route_with_an_undocumented_action(self):
        inp = self.inputs()
        inp["routes"]["routes"].append({"method": "GET", "path": "/api/frobnicate", "action": "frob:DoThing", "resource": "*"})
        _, errs = self.gate(inp)
        self.assertError(errs, "console route GET /api/frobnicate", "frob:DoThing", "not an action AWS documents")

    def test_red_route_on_an_unapproved_extra(self):
        inp = self.inputs()
        inp["routes"]["routes"].append({"method": "POST", "path": "/api/frobnicate", "action": "openinfra:Frobnicate"})
        _, errs = self.gate(inp)
        self.assertError(errs, "console route POST /api/frobnicate", "no operator ruling")

    def test_red_per_request_route_without_a_ruling(self):
        inp = self.inputs()
        inp["routes"]["perRequest"].append({"method": "GET", "path": "/api/raw", "decided": "whatever the body says"})
        _, errs = self.gate(inp)
        self.assertError(errs, "console route GET /api/raw", "perRequest")

    def test_red_unregistered_route_is_named(self):
        inp = self.inputs()
        inp["routes"]["routes"].append({"method": "GET", "path": "/api/buckets/{bucket}/tags", "action": "s3:ListBucket",
                                        "resource": "arn:aws:s3:::{bucket}"})
        surf, errs = self.gate(inp)
        self.assertEqual(errs, [])
        names = surface.unregistered(surf, surface.read_text(surface.SURFACE_JSON))
        self.assertTrue(any("console route GET /api/buckets/{bucket}/tags" in n for n in names), names)

    # --- red: console screens ---

    def test_red_screen_with_no_service(self):
        inp = self.inputs()
        inp["screens"].append("/frobnicators")
        _, errs = self.gate(inp)
        self.assertError(errs, "console screen /frobnicators", "no entry")

    def test_red_screen_with_an_unknown_service(self):
        inp = self.inputs()
        inp["facts"]["screens"]["Buckets"] = {"service": "frobnicate"}
        _, errs = self.gate(inp)
        self.assertError(errs, "console screen /buckets", "'frobnicate'", "not AWS-shaped")

    def test_red_operator_screen_shown_to_everyone(self):
        inp = self.inputs()
        for s in inp["nav"]:
            if s["label"] == "Workloads":
                s["requires"] = None
        _, errs = self.gate(inp)
        self.assertError(errs, "console screen /workloads", "shows it to everyone")

    def test_red_gated_screen_classified_aws(self):
        inp = self.inputs()
        inp["facts"]["screens"]["Nodes"] = {"service": "ec2"}
        _, errs = self.gate(inp)
        self.assertError(errs, "console screen /nodes", "operator's in the console")

    # --- red: removed ---

    def test_red_removed_but_still_reachable(self):
        inp = self.inputs()
        inp["facts"]["removed"] = [{"capability": "Bucket", "section": "kinds", "reason": "r"}]
        _, errs = self.gate(inp)
        self.assertError(errs, "removed[0]", "still reachable")

    # --- the screen resolver ---

    def test_screen_resolution(self):
        nav = self.base["nav"]
        self.assertEqual(surface.screen_service("/buckets/$bucket", nav)[0], "Buckets")
        self.assertEqual(surface.screen_service("/vms/images", nav)[0], "Virtual Machines / Images")
        self.assertEqual(surface.screen_service("/vms/$namespace/$name", nav)[0], "Virtual Machines / Instances")
        self.assertEqual(surface.screen_service("/executions/$namespace/$name", nav)[0], "State Machines")
        self.assertEqual(surface.screen_service("/", nav), (None, None))


class DenialGate(unittest.TestCase):
    """shimgen.validate_denials: a proven AWS API is proven to deny, live."""

    def test_denial_checks(self):
        yes = ['grep -qiE "AccessDenied" "$f" || fail "wrong error"',
               'case "$(field error)" in AccessDenied*) ;; *) fail "x" ;; esac',
               '[ "$d" = deny ] || fail "allowed"',
               'grep -q UnauthorizedOperation "$TMP/deny" || fail "x"',
               'grep -qE AuthorizationError "$out" \\\n  || fail "x"']
        no = ['# a reader is AccessDenied',
              'aws sts get-caller-identity || fail "if AccessDenied, the shim lacks RBAC"',
              'grep -q SignatureDoesNotMatch "$f" || fail "x"',
              'log "denied"']
        for text in yes:
            self.assertTrue(shimgen.denial_checks(text), text)
        for text in no:
            self.assertFalse(shimgen.denial_checks(text), text)

    def committed(self):
        services = shimgen.load_registry()
        keys = json.loads(surface.read_text(os.path.join(HERE, "registry", "shim-router.json")))["services"].keys()
        return services, keys, surface.read_text(shimgen.NO_POLICY_PROBE)

    def test_committed_passes(self):
        services, keys, np = self.committed()
        self.assertEqual(shimgen.validate_denials(services, shimgen.read_probe, keys, np), [])

    def test_red_proven_service_without_a_denial(self):
        services, keys, np = self.committed()
        services = services + [{"name": "Widgets", "tier": "proven", "probes": ["widgets"]}]
        errs = shimgen.validate_denials(services, lambda p: "aws widgets list || fail x" if p == "widgets"
                                        else shimgen.read_probe(p), keys, np)
        self.assertTrue(any("Widgets: proven, but none of its probes asserts a denial" in e for e in errs), errs)

    def test_red_stale_denial_pending(self):
        services, keys, np = self.committed()
        for s in services:
            if s["name"] == "SQS":
                s["denialPending"] = "not yet"
        errs = shimgen.validate_denials(services, shimgen.read_probe, keys, np)
        self.assertTrue(any("SQS: denialPending, but aws-shim-sqs.sh asserts a denial" in e for e in errs), errs)

    def test_red_router_service_the_no_policy_probe_does_not_call(self):
        services, keys, np = self.committed()
        errs = shimgen.validate_denials(services, shimgen.read_probe, list(keys) + ["widgets"], np)
        self.assertTrue(any("'widgets'" in e and "iam-no-policy.sh calls nothing" in e for e in errs), errs)
        errs = shimgen.validate_denials(services, shimgen.read_probe, [k for k in keys if k != "kms"], np)
        self.assertTrue(any("calls 'kms', which the router no longer serves" in e for e in errs), errs)


def write_file(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def copy_repo(test):
    """The inputs `probe/shimgen.py --check` reads, copied to a throwaway tree."""
    tmp = tempfile.mkdtemp(prefix="surface-red-")
    test.addCleanup(shutil.rmtree, tmp)
    for d in ("probe", "docs", "platform", os.path.join("cfn", "testdata"), "examples"):
        if os.path.isdir(os.path.join(ROOT, d)):
            shutil.copytree(os.path.join(ROOT, d), os.path.join(tmp, d))
    for f in ("README.md", os.path.join("ui", "src", "router.tsx"),
              os.path.join("ui", "src", "components", "layout", "nav-items.ts"),
              os.path.join("console-api", "internal", "awsaction", "testdata", "aws-actions.txt")):
        os.makedirs(os.path.dirname(os.path.join(tmp, f)) or tmp, exist_ok=True)
        shutil.copy(os.path.join(ROOT, f), os.path.join(tmp, f))
    return tmp


class EndToEndRed(unittest.TestCase):
    """The exact CI command, `probe/shimgen.py --check`, on a copy of the repository: green as committed,
    red once one unregistered capability is added — a claim kind, a claim field, a console route, a console
    screen, a front door without a denial."""

    def run_check(self, tree):
        return subprocess.run([sys.executable, os.path.join(tree, "probe", "shimgen.py"), "--check"],
                              capture_output=True, text=True)

    def red(self, mutate, *needles):
        tree = copy_repo(self)
        mutate(tree)
        r = self.run_check(tree)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        for n in needles:
            self.assertIn(n, r.stdout)

    def test_green_as_committed(self):
        r = self.run_check(copy_repo(self))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("customer surface:", r.stdout)

    def test_red_new_claim_kind(self):
        def mutate(tree):
            with open(os.path.join(tree, "platform", "abstraction", "frobnicator-xrd.yaml"), "w") as f:
                f.write("apiVersion: apiextensions.crossplane.io/v1\nkind: CompositeResourceDefinition\n"
                        "metadata: {name: xfrobnicators.openinfra.dev}\nspec:\n  group: openinfra.dev\n"
                        "  names: {kind: XFrobnicator, plural: xfrobnicators}\n"
                        "  claimNames: {kind: Frobnicator, plural: frobnicators}\n  versions:\n  - name: v1\n"
                        "    schema:\n      openAPIV3Schema:\n        properties:\n          spec:\n"
                        "            properties: {size: {type: integer}}\n")
        self.red(mutate, "customer-surface gate", "kind Frobnicator", "no row in the kinds table")

    def test_red_new_claim_field(self):
        def mutate(tree):
            import yaml
            path = os.path.join(tree, "platform", "abstraction", "bucket-xrd.yaml")
            with open(path, encoding="utf-8") as f:
                xrd = yaml.safe_load(f)
            for v in xrd["spec"]["versions"]:
                v["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["retentionDays"] = {"type": "integer"}
            with open(path, "w", encoding="utf-8") as f:
                yaml.safe_dump(xrd, f)
        self.red(mutate, "customer-surface.json does not list", "claim field Bucket.retentionDays",
                 "not in the committed registry")

    def test_red_new_console_route(self):
        def mutate(tree):
            path = os.path.join(tree, "probe", "registry", "console-routes.json")
            data = json.loads(surface.read_text(path))
            data["routes"].append({"method": "POST", "path": "/api/frobnicate", "action": "frob:DoThing", "resource": "*"})
            write_file(path, json.dumps(data, indent=1) + "\n")
        self.red(mutate, "customer-surface gate", "console route POST /api/frobnicate", "frob:DoThing")

    def test_red_new_console_screen(self):
        def mutate(tree):
            path = os.path.join(tree, "ui", "src", "router.tsx")
            text = surface.read_text(path)
            text += ('\nconst frobRoute = createRoute({ getParentRoute: () => rootRoute, path: "/frobnicators", '
                     'component: FrobPage });\n')
            write_file(path, text)
        self.red(mutate, "customer-surface gate", "console screen /frobnicators")

    def test_red_front_door_without_a_denial(self):
        def mutate(tree):
            path = os.path.join(tree, "probe", "shim-services.yaml")
            text = surface.read_text(path)
            text = text.replace("    pending: [dynamodb-deny]\n", "")
            text = "\n".join(l for l in text.splitlines() if "aws-shim-dynamodb-deny.sh asserts" not in l) + "\n"
            write_file(path, text)
            os.remove(os.path.join(tree, "probe", "aws-shim-dynamodb-deny.sh"))
        self.red(mutate, "not proven to deny", "DynamoDB: proven, but none of its probes asserts a denial")


if __name__ == "__main__":
    unittest.main(verbosity=2)
