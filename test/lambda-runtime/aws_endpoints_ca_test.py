#!/usr/bin/env python3
# The AWS endpoints CA in a Python function's TLS trust (#335). The platform answers AWS's own hostnames with its
# own AWS front door, under a certificate from a CA of its own that the function's pod mounts
# (OPENINFRA_AWS_ENDPOINTS_CA). botocore verifies TLS against AWS_CA_BUNDLE alone, so before the handler loads the
# runtime points AWS_CA_BUNDLE at the system's roots and this CA together. A function that names its own bundle
# keeps it; a function without the CA is unchanged.
#
#   python3 test/lambda-runtime/aws_endpoints_ca_test.py
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import context_test as ct  # noqa: E402

HANDLER = """import os
def handler(event, context):
    path = os.environ.get("AWS_CA_BUNDLE")
    return {"bundle": path, "content": open(path).read() if path and os.path.exists(path) else None}
"""
SYSTEM = "-----BEGIN CERTIFICATE-----\nSYSTEMROOTS\n-----END CERTIFICATE-----\n"
AWS_CA = "-----BEGIN CERTIFICATE-----\nAWSENDPOINTSCA\n-----END CERTIFICATE-----\n"


class AWSEndpointsCA(unittest.TestCase):
    def run_with(self, env):
        task = ct.write_task({"index.py": HANDLER})
        rt = ct.Runtime([sys.executable, os.path.join(ct.RUNTIMES, "python", "bootstrap.py")], "index.handler", task,
                        dict(env, TMPDIR=tempfile.mkdtemp(dir=ct.TMP)))
        try:
            return rt.invoke()
        finally:
            rt.close()

    def files(self):
        d = tempfile.mkdtemp(dir=ct.TMP)
        system, ca = os.path.join(d, "system.pem"), os.path.join(d, "ca.crt")
        with open(system, "w") as f:
            f.write(SYSTEM)
        with open(ca, "w") as f:
            f.write(AWS_CA)
        return system, ca

    def test_botocore_gets_the_system_roots_and_the_ca(self):
        system, ca = self.files()
        r = self.run_with({"OPENINFRA_AWS_ENDPOINTS_CA": ca, "OPENINFRA_SYSTEM_CA_BUNDLE": system})
        self.assertTrue(r["bundle"], r)
        self.assertIn("SYSTEMROOTS", r["content"])
        self.assertIn("AWSENDPOINTSCA", r["content"])

    def test_a_functions_own_bundle_is_kept(self):
        system, ca = self.files()
        r = self.run_with({"OPENINFRA_AWS_ENDPOINTS_CA": ca, "OPENINFRA_SYSTEM_CA_BUNDLE": system, "AWS_CA_BUNDLE": system})
        self.assertEqual(r["bundle"], system)

    def test_no_ca_no_change(self):
        r = self.run_with({})
        self.assertIsNone(r["bundle"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
