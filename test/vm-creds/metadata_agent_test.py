#!/usr/bin/env python3
# Unit tests for the in-guest instance metadata agent (#347 items 13 + 14), run against the EXACT
# agent text the VM composition ships (extracted from platform/abstraction/vm-composition.yaml) and
# the config shape it renders (testdata/metadata-agent.golden.json, pinned by test/render).
#
# stdlib only and Python 3.6-compatible, like the agent: CI also runs this file under python:3.6 (the
# RHEL 8 platform-python floor). No root needed — the network-namespace path is covered by
# metadata_agent_netns_test.py.

import http.client
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

import vmcreds_common as common

TMP = tempfile.mkdtemp(prefix="oi-agent-test-")
agent = common.load_agent_module(TMP)

CREDS = {
    "AccessKeyId": "ASIAUNITTESTKEY00001",
    "SecretAccessKey": "unit-test-secret",
    "Token": "unit-test-session-token",
    "Expiration": "2099-01-01T00:00:00Z",
}


class FakeClock(object):
    def __init__(self, t=1000000.0):
        self.t = t

    def __call__(self):
        return self.t


def make_config(**over):
    """The golden (composition-rendered) config, re-pointed at loopback test listeners."""
    cfg = common.golden_config()
    cfg["imds"].update({"netns": "", "address": "127.0.0.1", "port": 0})
    cfg["relay"].update({"port": 0})
    cfg["trustPlatformCA"] = False  # never touch this host's trust store (PlatformCATest covers it)
    cfg["caBundleLink"] = ""        # nor /etc/openinfra (CABundleLinkTest covers it)
    ud = os.path.join(TMP, "user-data")
    with open(ud, "w") as fh:
        fh.write("#!/bin/bash\necho hi\n")
    cfg["userDataFile"] = ud
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    path = os.path.join(TMP, "config-%d.json" % id(cfg))
    with open(path, "w") as fh:
        json.dump(cfg, fh)
    return agent.load_config(path)


class Running(object):
    """An Agent with in-process listeners on ephemeral loopback ports."""

    def __init__(self, cfg, fetch=None):
        self.fetches = []

        def default_fetch():
            self.fetches.append(1)
            return dict(CREDS)

        self.agent = agent.Agent(cfg, fetch=fetch or default_fetch, warm_timeout=0)

    def __enter__(self):
        self.agent.start()
        self.imds = self.relay = None
        for srv in self.agent.servers:
            if srv.RequestHandlerClass is agent.IMDSHandler:
                self.imds = srv
            else:
                self.relay = srv
        return self

    def __exit__(self, *exc):
        self.agent.shutdown()

    def request(self, srv, method, path, headers=None):
        host, port = srv.server_address[:2]
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            r = conn.getresponse()
            return r.status, r.read().decode("utf-8", "replace"), dict((k.lower(), v) for k, v in r.getheaders())
        finally:
            conn.close()

    def get(self, path, headers=None):
        return self.request(self.imds, "GET", path, headers)

    def put_token(self, ttl="21600", extra=None):
        h = {} if ttl is None else {agent.TOKEN_TTL_HEADER: ttl}
        h.update(extra or {})
        return self.request(self.imds, "PUT", "/latest/api/token", h)


class ConfigTest(unittest.TestCase):
    def test_golden_config_loads_with_composition_defaults(self):
        cfg = make_config()
        self.assertEqual(cfg["imds"]["hopLimit"], 2)
        self.assertEqual(cfg["imds"]["httpTokens"], "optional")
        self.assertEqual(cfg["region"], "us-east-1")
        self.assertEqual(cfg["availabilityZone"], "us-east-1a")
        self.assertTrue(cfg["relay"]["enabled"])

    def test_bad_values_fall_back_safely(self):
        cfg = make_config(imds={"hopLimit": 99, "httpTokens": "sometimes"})
        self.assertEqual(cfg["imds"]["hopLimit"], 2)
        self.assertEqual(cfg["imds"]["httpTokens"], "required")  # unknown -> fail closed

    def test_defaults_are_not_mutated(self):
        p = os.path.join(TMP, "minimal.json")
        with open(p, "w") as fh:
            json.dump({"imds": {"hopLimit": 7}}, fh)
        agent.load_config(p)
        self.assertEqual(agent.DEFAULTS["imds"]["hopLimit"], 2)


class TimestampTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(agent.parse_timestamp("1970-01-01T00:01:00Z"), 60)
        self.assertEqual(agent.parse_timestamp("1970-01-01T01:00:00+01:00"), 0)
        self.assertEqual(agent.parse_timestamp("1970-01-01T00:00:00.123Z"), 0)
        self.assertEqual(agent.iso8601(60), "1970-01-01T00:01:00Z")
        with self.assertRaises(ValueError):
            agent.parse_timestamp("tomorrow")


class TokenTest(unittest.TestCase):
    def test_issue_validate_expire(self):
        clock = FakeClock()
        issuer = agent.TokenIssuer(clock=clock)
        tok = issuer.issue(10)
        self.assertTrue(issuer.valid(tok))
        clock.t += 11
        self.assertFalse(issuer.valid(tok), "a token must expire after its TTL")

    def test_rejects_forged_and_foreign_tokens(self):
        a, b = agent.TokenIssuer(), agent.TokenIssuer()
        tok = a.issue(60)
        self.assertFalse(b.valid(tok), "a token from another agent instance (key) must not validate")
        self.assertFalse(a.valid(tok[:-4] + "AAAA"))
        for junk in ("", "x", "not base64 !!", "éé"):
            self.assertFalse(a.valid(junk))


class CredentialCacheTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock(1000000.0)
        self.calls = 0
        self.fail = None

    def fetch(self):
        self.calls += 1
        if self.fail:
            raise agent.CredentialsError("shim down", self.fail)
        c = dict(CREDS)
        c["Expiration"] = agent.iso8601(self.clock.t + 3600)  # the shim's default 1h session
        c["AccessKeyId"] = "ASIA%016d" % self.calls
        return c

    def test_caches_then_refreshes_early(self):
        cache = agent.CredentialCache(self.fetch, clock=self.clock)
        first = cache.get()
        self.assertEqual(cache.get(), first)
        self.assertEqual(self.calls, 1, "a second get() inside the validity window must not refetch")
        # A 1h session refreshes 20 min before expiry: at +39 min still cached, and the cached
        # credentials then always have > 15 min left (the botocore refresh window never fires).
        self.clock.t += 39 * 60
        self.assertEqual(cache.get(), first)
        self.assertGreater(cache.next_wait(), 0)
        self.clock.t += 2 * 60
        served = cache.get()  # past the refresh point: still served at once, refresh is backgrounded
        self.assertEqual(served, first)
        self.assertTrue(cache._wake.is_set(), "past the refresh point the background refresher is woken")
        cache.refresh()
        self.assertNotEqual(cache.get()["AccessKeyId"], first["AccessKeyId"])

    def test_failed_refresh_keeps_serving_valid_credentials(self):
        cache = agent.CredentialCache(self.fetch, clock=self.clock)
        first = cache.get()
        self.clock.t += 45 * 60
        self.fail = 503
        with self.assertRaises(agent.CredentialsError):
            cache.refresh()
        self.assertEqual(cache.get(), first, "still-valid credentials keep being served while the shim is down")
        self.clock.t += 20 * 60  # now expired
        with self.assertRaises(agent.CredentialsError):
            cache.get()

    def test_no_credentials_raises_with_status(self):
        self.fail = 403
        cache = agent.CredentialCache(self.fetch, clock=self.clock)
        with self.assertRaises(agent.CredentialsError) as ctx:
            cache.get()
        self.assertEqual(ctx.exception.status, 403)


class StubShim(http.server.BaseHTTPRequestHandler):
    status = 200
    body = json.dumps(CREDS)
    seen_auth = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        StubShim.seen_auth.append(self.headers.get("Authorization"))
        b = self.body.encode()
        self.send_response(self.status)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


class FetchFromShimTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), StubShim)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d/v1/vm-credentials" % cls.srv.server_address[1]
        cls.tok = os.path.join(TMP, "token")
        with open(cls.tok, "w") as fh:
            fh.write("header.payload.sig\n")  # a trailing newline must not reach the header

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        StubShim.status, StubShim.body, StubShim.seen_auth = 200, json.dumps(CREDS), []

    def test_sends_the_token_as_authorization_and_ignores_proxies(self):
        old = os.environ.get("http_proxy")
        os.environ["http_proxy"] = "http://127.0.0.1:1"  # would break the request if honored
        try:
            creds = agent.fetch_from_shim(self.url, self.tok)
        finally:
            if old is None:
                del os.environ["http_proxy"]
            else:
                os.environ["http_proxy"] = old
        self.assertEqual(creds, CREDS)
        self.assertEqual(StubShim.seen_auth, ["header.payload.sig"])

    def test_shim_refusal_carries_status(self):
        StubShim.status, StubShim.body = 403, "role not assumable by this instance"
        with self.assertRaises(agent.CredentialsError) as ctx:
            agent.fetch_from_shim(self.url, self.tok)
        self.assertEqual(ctx.exception.status, 403)
        self.assertIn("role not assumable", str(ctx.exception))
        self.assertIn("spec.trust", str(ctx.exception), "a 403 tells the operator what to fix (journal)")

    def test_bad_document_and_missing_token(self):
        StubShim.body = '{"AccessKeyId": "x"}'
        with self.assertRaises(agent.CredentialsError):
            agent.fetch_from_shim(self.url, self.tok)
        with self.assertRaises(agent.CredentialsError):
            agent.fetch_from_shim(self.url, os.path.join(TMP, "no-such-token"))


class IMDSTest(unittest.TestCase):
    def test_imdsv2_token_handshake(self):
        with Running(make_config()) as r:
            st, tok, hdrs = r.put_token("21600")
            self.assertEqual(st, 200)
            self.assertEqual(hdrs.get(agent.TOKEN_TTL_HEADER.lower()), "21600")
            st, body, _ = r.get("/latest/meta-data/instance-id", {agent.TOKEN_HEADER: tok})
            self.assertEqual((st, body), (200, common.golden_config()["instanceId"]))
            st, _, _ = r.get("/latest/meta-data/instance-id", {agent.TOKEN_HEADER: "bogus"})
            self.assertEqual(st, 401, "an invalid token is refused even when tokens are optional")

    def test_token_put_validation(self):
        with Running(make_config()) as r:
            for ttl in (None, "0", "21601", "abc", "-5", ""):
                self.assertEqual(r.put_token(ttl)[0], 400, "TTL %r must be a 400" % (ttl,))
            self.assertEqual(r.put_token("1")[0], 200)
            # EC2 refuses a token PUT that came through a proxy (open-proxy / SSRF guard).
            self.assertEqual(r.put_token("60", {"X-Forwarded-For": "203.0.113.9"})[0], 403)
            self.assertEqual(r.request(r.imds, "PUT", "/latest/meta-data/", {agent.TOKEN_TTL_HEADER: "60"})[0], 405)
            self.assertEqual(r.request(r.imds, "POST", "/latest/api/token")[0], 405)

    def test_hop_limit_is_the_token_response_ip_ttl(self):
        for hops in (1, 2, 5):
            with Running(make_config(imds={"hopLimit": hops})) as r:
                self.assertEqual(r.put_token("60")[0], 200)
                self.assertEqual(r.imds.last_put_ttl, hops,
                                 "the PUT token response must leave with IP TTL = hop limit")
                r.imds.last_put_ttl = None
                r.get("/latest/meta-data/")
                self.assertIsNone(r.imds.last_put_ttl, "only the token PUT response is hop-limited")

    def test_apply_hop_limit_sets_ip_ttl(self):
        s = socket.socket()
        try:
            self.assertEqual(agent.apply_hop_limit(s, 3), 3)
            self.assertEqual(s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL), 3)
        finally:
            s.close()

    def test_http_tokens_required_refuses_imdsv1(self):
        with Running(make_config(imds={"httpTokens": "required"})) as r:
            self.assertEqual(r.get("/latest/meta-data/instance-id")[0], 401)
            tok = r.put_token("60")[1]
            self.assertEqual(r.get("/latest/meta-data/instance-id", {agent.TOKEN_HEADER: tok})[0], 200)

    def test_http_tokens_optional_allows_imdsv1(self):
        with Running(make_config()) as r:
            self.assertEqual(r.get("/latest/meta-data/instance-id")[0], 200)

    def test_listings(self):
        with Running(make_config()) as r:
            st, body, _ = r.get("/")
            self.assertEqual(st, 200)
            self.assertIn("latest", body.split("\n"))
            self.assertEqual(r.get("/latest")[1].split("\n"), ["dynamic", "meta-data", "user-data"])
            md = r.get("/latest/meta-data/")[1].split("\n")
            for entry in ("ami-id", "hostname", "iam/", "instance-id", "local-hostname", "local-ipv4",
                          "placement/", "security-groups", "services/"):
                self.assertIn(entry, md)
            self.assertEqual(r.get("/latest/meta-data")[1].split("\n"), md, "a trailing slash is optional")
            self.assertEqual(r.get("/latest/meta-data/iam/")[1].split("\n"), ["info", "security-credentials/"])
            self.assertEqual(r.get("/latest/meta-data/placement/region")[1], "us-east-1")
            self.assertEqual(r.get("/latest/meta-data/placement/availability-zone")[1], "us-east-1a")
            self.assertEqual(r.get("/latest/meta-data/security-groups")[1], "web")
            self.assertEqual(r.get("/latest/meta-data/hostname")[1], socket.gethostname())
            self.assertEqual(r.get("/2009-04-04/meta-data/instance-id")[0], 200, "dated versions resolve too")
            self.assertEqual(r.get("/latest/meta-data/nope")[0], 404)
            self.assertEqual(r.get("/latest/meta-data/instance-id/extra")[0], 404)
            self.assertEqual(r.get("/1999-01-01/meta-data/")[0], 404)

    def test_role_credentials_in_ec2_shape(self):
        with Running(make_config()) as r:
            st, body, _ = r.get("/latest/meta-data/iam/security-credentials/")
            self.assertEqual((st, body), (200, "app-role"))
            st, body, _ = r.get("/latest/meta-data/iam/security-credentials/app-role")
            self.assertEqual(st, 200)
            doc = json.loads(body)
            self.assertEqual(doc["Code"], "Success")
            self.assertEqual(doc["Type"], "AWS-HMAC")
            for k in ("AccessKeyId", "SecretAccessKey", "Token", "Expiration"):
                self.assertEqual(doc[k], CREDS[k])
            agent.parse_timestamp(doc["LastUpdated"])
            self.assertEqual(r.get("/latest/meta-data/iam/security-credentials/other-role")[0], 404)
            info = json.loads(r.get("/latest/meta-data/iam/info")[1])
            self.assertEqual(info["Code"], "Success")
            self.assertEqual(info["InstanceProfileArn"], "arn:aws:iam::open-infra:instance-profile/app-role")
            self.assertTrue(info["InstanceProfileId"].startswith("AIPA"))
            self.assertEqual(len(r.fetches), 1, "credentials are fetched once (at start) and then cached")

    def test_role_refusal_is_reported_in_ec2_shape(self):
        def refused():
            raise agent.CredentialsError("role not assumable by this instance", 403)

        with Running(make_config(), fetch=refused) as r:
            st, body, _ = r.get("/latest/meta-data/iam/security-credentials/app-role")
            self.assertEqual(st, 200)
            doc = json.loads(body)
            self.assertEqual(doc["Code"], "AssumeRoleUnauthorizedAccess")
            self.assertNotIn("AccessKeyId", doc)

    def test_identity_document_and_user_data(self):
        golden = common.golden_config()
        with Running(make_config()) as r:
            doc = json.loads(r.get("/latest/dynamic/instance-identity/document")[1])
            self.assertEqual(doc["instanceId"], golden["instanceId"])
            self.assertEqual(doc["imageId"], golden["imageId"])
            self.assertEqual(doc["accountId"], "open-infra")
            self.assertEqual(doc["region"], "us-east-1")
            self.assertEqual(doc["availabilityZone"], "us-east-1a")
            self.assertEqual(doc["pendingTime"], "2026-10-31T12:00:00Z")
            self.assertIn(doc["architecture"], ("x86_64", "arm64"))
            self.assertIn("privateIp", doc)
            self.assertEqual(r.get("/latest/dynamic/")[1], "instance-identity/")
            self.assertEqual(r.get("/latest/user-data")[1], "#!/bin/bash\necho hi\n")
        with Running(make_config(userDataFile="")) as r:
            self.assertEqual(r.get("/latest/user-data")[0], 404, "no user-data -> 404, as on EC2")
            self.assertNotIn("user-data", r.get("/latest/")[1].split("\n"))

    def test_no_role_serves_no_iam(self):
        with Running(make_config(role="", relay={"enabled": False})) as r:
            self.assertIsNone(r.relay, "no role -> no credentials endpoint")
            self.assertNotIn("iam/", r.get("/latest/meta-data/")[1].split("\n"))
            self.assertEqual(r.get("/latest/meta-data/iam/security-credentials/")[0], 404)
            self.assertEqual(r.get("/latest/meta-data/instance-id")[0], 200)


class RelayTest(unittest.TestCase):
    def test_container_credentials_without_authorization(self):
        with Running(make_config()) as r:
            st, body, hdrs = r.request(r.relay, "GET", "/v1/vm-credentials")  # no Authorization header
            self.assertEqual(st, 200)
            self.assertEqual(json.loads(body), CREDS)
            self.assertEqual(r.request(r.relay, "GET", "/latest/meta-data/")[0], 404)

    def test_shim_refusal_and_outage(self):
        for status, want in ((403, 403), (401, 401), (None, 502), (500, 502)):
            def fetch(status=status):
                raise agent.CredentialsError("nope", status)

            with Running(make_config(), fetch=fetch) as r:
                self.assertEqual(r.request(r.relay, "GET", "/v1/vm-credentials")[0], want)


# Public, test-only certificates (no keys anywhere): a self-signed root with basicConstraints CA:TRUE,
# and a self-signed leaf with CA:FALSE.
TEST_CA = b"""-----BEGIN CERTIFICATE-----
MIIB4DCCAYWgAwIBAgIUbyqT2isHCS4bhb9aiZOu3ZIR0zYwCgYIKoZIzj0EAwIw
PDEYMBYGA1UECgwPb3Blbi1pbmZyYSB0ZXN0MSAwHgYDVQQDDBdvcGVuLWluZnJh
IHRlc3Qgcm9vdCBDQTAgFw0yNjExMDEwMTQxNDBaGA8yMTI2MTAwODAxNDE0MFow
PDEYMBYGA1UECgwPb3Blbi1pbmZyYSB0ZXN0MSAwHgYDVQQDDBdvcGVuLWluZnJh
IHRlc3Qgcm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGMFSZXYGp5J
Lh+qAJjZDH7ksnsUc6XC0BooXIfGzHHcANObPL2EyjT6EhwyI+GyzD6k8o2egyzE
oXJrCYdUYuejYzBhMB0GA1UdDgQWBBQ7wRnjrWL4yv0PBp78pSoz9+2HvTAfBgNV
HSMEGDAWgBQ7wRnjrWL4yv0PBp78pSoz9+2HvTAPBgNVHRMBAf8EBTADAQH/MA4G
A1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNJADBGAiEA35GyhQLO/z0kouYdIHiB
2hauQxRq3LuG3Q1aoJrUkSgCIQCPEpq8zT3Ujmr8mt01Y4FM/fQs6/peKnz19YIc
E47Mmw==
-----END CERTIFICATE-----
"""
TEST_LEAF = b"""-----BEGIN CERTIFICATE-----
MIIBkjCCATigAwIBAgIULgH6EFz3cRvvlbbzl6QFF8PoNGowCgYIKoZIzj0EAwIw
HzEdMBsGA1UEAwwUb3Blbi1pbmZyYSB0ZXN0IGxlYWYwIBcNMjYxMTAxMDE0MTQw
WhgPMjEyNjEwMDgwMTQxNDBaMB8xHTAbBgNVBAMMFG9wZW4taW5mcmEgdGVzdCBs
ZWFmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyhusPyTvECumNTGLrzxnnluM
T14Ru/KMdGgPFuvGv1mbVEtlkaTWqLVTvRjLgZOwWnGKzptCD28WAwALeO1mGaNQ
ME4wHQYDVR0OBBYEFBA5F5PCn9JrNb/cxE4bdcqWVbCuMB8GA1UdIwQYMBaAFBA5
F5PCn9JrNb/cxE4bdcqWVbCuMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAw
RQIgIi2VxwUScD+um64biyKS+h/GjZqvSVLQVLtxzhNuZOwCIQDabg5iz76cuChN
Jnl0Af5d6agHsdOfBE4u7mjR5635Kw==
-----END CERTIFICATE-----
"""


class FakeRun(object):
    def __init__(self, rc=0):
        self.rc, self.calls = rc, []

    def __call__(self, cmd, check=True):
        self.calls.append(list(cmd))

        class P(object):
            returncode, stdout, stderr = self.rc, "", "refresh failed" if self.rc else ""
        return P()


class PlatformCATest(unittest.TestCase):
    """#347 item 15: the guest trusts the platform root CA (fetched from the shim) at boot."""

    def test_validate_accepts_only_ca_certificates(self):
        pem = agent.validate_ca_pem(TEST_CA)
        self.assertTrue(pem.startswith("-----BEGIN CERTIFICATE-----\n"))
        self.assertEqual(pem.count("BEGIN CERTIFICATE"), 1)
        self.assertEqual(agent.validate_ca_pem(TEST_CA + TEST_CA), pem, "duplicates collapse")
        self.assertEqual(agent.validate_ca_pem(TEST_CA.replace(b"\n", b"\r\n")), pem, "CRLF PEM is accepted")
        key = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n"
        junk_der = b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"
        for name, data in (
            ("a non-CA (leaf) certificate", TEST_LEAF),
            ("a private key", key),
            ("a CA bundled with a key", TEST_CA + key),
            ("text outside the PEM blocks", b"hello\n" + TEST_CA),
            ("not PEM at all", b"<html>404</html>"),
            ("empty", b""),
            ("non-ASCII", "é".encode("utf-8")),
            ("bad base64", b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"),
            ("base64 that is not X.509", junk_der),
        ):
            with self.assertRaises(ValueError, msg=name):
                agent.validate_ca_pem(data)

    def test_trust_store_detection(self):
        def detect(tools, dirs):
            return agent.trust_store(which=lambda t: "/usr/sbin/" + t if t in tools else None,
                                     isdir=lambda d: d in dirs)

        rhel = detect({"update-ca-trust"}, {"/etc/pki/ca-trust/source/anchors"})
        self.assertEqual(rhel, ("rhel", "/etc/pki/ca-trust/source/anchors", ["/usr/sbin/update-ca-trust", "extract"]))
        suse = detect({"update-ca-certificates"}, {"/etc/pki/trust/anchors"})
        self.assertEqual(suse[:2], ("suse", "/etc/pki/trust/anchors"))
        deb = detect({"update-ca-certificates"}, {"/usr/local/share/ca-certificates"})
        self.assertEqual(deb, ("debian", "/usr/local/share/ca-certificates", ["/usr/sbin/update-ca-certificates"]))
        self.assertIsNone(detect({"update-ca-certificates"}, set()), "the tool without its anchor directory is not a store")
        self.assertIsNone(detect(set(), {"/usr/local/share/ca-certificates"}), "the directory without its tool is not a store")

    def test_install_is_idempotent(self):
        d = tempfile.mkdtemp(dir=TMP)
        store = ("debian", d, ["update-ca-certificates"])
        pem = agent.validate_ca_pem(TEST_CA)
        run = FakeRun()
        self.assertEqual(agent.install_ca(pem, store, run_cmd=run), "installed")
        path = os.path.join(d, agent.CA_FILE_NAME)
        with open(path) as fh:
            self.assertEqual(fh.read(), pem)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
        self.assertEqual(run.calls, [["update-ca-certificates"]])
        self.assertEqual(agent.install_ca(pem, store, run_cmd=run), "unchanged")
        self.assertEqual(len(run.calls), 1, "an unchanged CA is neither rewritten nor re-refreshed")
        with open(path, "w") as fh:
            fh.write("an older root\n")
        self.assertEqual(agent.install_ca(pem, store, run_cmd=run), "installed", "a changed CA is replaced")
        self.assertEqual(len(run.calls), 2)
        os.remove(path)
        with self.assertRaises(RuntimeError):
            agent.install_ca(pem, store, run_cmd=FakeRun(rc=1))
        self.assertFalse(os.path.exists(path), "a failed refresh removes the anchor so the next start retries")
        self.assertFalse(os.path.exists(path + ".tmp"))

    def test_trust_platform_ca_outcomes(self):
        store = ("debian", "/nonexistent", ["update-ca-certificates"])
        installed = []

        def install(pem, st):
            installed.append(pem)
            return "installed"

        def fetching(*results):
            seq = list(results)

            def fetch(url):
                r = seq.pop(0)
                if isinstance(r, Exception):
                    raise r
                return r
            return fetch

        clock = FakeClock(0.0)

        def sleep(s):
            clock.t += s

        run = lambda fetch, st=store: agent.trust_platform_ca("http://shim/v1/ca-bundle", budget=15, store=st, fetch=fetch,
                                                              install=install, sleep=sleep, clock=clock)
        self.assertEqual(run(fetching(TEST_CA)), "installed")
        self.assertEqual(len(installed), 1)
        self.assertEqual(run(fetching(None)), "absent", "a platform without a CA (404) installs nothing")
        self.assertEqual(run(fetching(TEST_LEAF)), "invalid", "a non-CA certificate is never installed")
        self.assertEqual(len(installed), 1)
        # A briefly unreachable shim is retried within the budget...
        down = agent.CAFetchError("connection refused")
        self.assertEqual(run(fetching(down, down, TEST_CA)), "installed")
        # ...but the boot never waits past it,
        clock.t = 0.0
        self.assertEqual(run(fetching(*([down] * 50))), "unavailable")
        self.assertLessEqual(clock.t, 15)
        # and a shim whose name does not resolve (the aws-shim component is not installed) gives up fast.
        clock.t = 0.0
        nx = agent.CAFetchError("name does not resolve", dns=True)
        self.assertEqual(run(fetching(nx, nx, TEST_CA)), "unavailable")
        self.assertLessEqual(clock.t, 2)
        orig = agent.trust_store
        agent.trust_store = lambda: None  # a guest with no supported trust-store tool
        try:
            self.assertEqual(agent.trust_platform_ca("u", fetch=fetching(TEST_CA), install=install), "unsupported")
        finally:
            agent.trust_store = orig

        def broken(pem, st):
            raise RuntimeError("update-ca-certificates failed")
        self.assertEqual(agent.trust_platform_ca("u", store=store, fetch=fetching(TEST_CA), install=broken), "failed")

    def test_fetch_ca_bundle(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                status = {"/ok": 200, "/absent": 404}.get(self.path, 503)
                body = TEST_CA if status == 200 else b"nope"
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        try:
            self.assertEqual(agent.fetch_ca_bundle(base + "/ok"), TEST_CA)
            self.assertIsNone(agent.fetch_ca_bundle(base + "/absent"))
            with self.assertRaises(agent.CAFetchError) as ctx:
                agent.fetch_ca_bundle(base + "/unavailable")
            self.assertFalse(ctx.exception.dns)
        finally:
            srv.shutdown()
            srv.server_close()
        with self.assertRaises(agent.CAFetchError) as ctx:
            agent.fetch_ca_bundle("http://aws-shim.example.invalid:4566/v1/ca-bundle", timeout=3)
        self.assertTrue(ctx.exception.dns, "an unresolvable shim name is reported as such")

    def test_boot_only_mode_when_metadata_is_disabled(self):
        calls = []
        orig = agent.trust_platform_ca
        agent.trust_platform_ca = lambda url, **kw: calls.append(url) or "installed"
        try:
            cfg = make_config(imds={"enabled": False}, relay={"enabled": False}, trustPlatformCA=True,
                              caBundleUrl="http://shim/v1/ca-bundle")
            a = agent.Agent(cfg, fetch=lambda: dict(CREDS), warm_timeout=0)
            a.start()  # no listener wanted: must not raise
            self.assertEqual(a.servers, [])
            self.assertEqual(calls, ["http://shim/v1/ca-bundle"], "the platform CA is still trusted at boot")
            a.shutdown()
        finally:
            agent.trust_platform_ca = orig
        # The real process exits 0 after its boot-time step, so Restart=on-failure leaves it stopped.
        p = os.path.join(TMP, "boot-only.json")
        c = common.golden_config()
        c["imds"]["enabled"], c["relay"]["enabled"], c["trustPlatformCA"] = False, False, False
        with open(p, "w") as fh:
            json.dump(c, fh)
        rc = subprocess.call([sys.executable, os.path.join(TMP, "metadata-agent.py"), p],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        self.assertEqual(rc, 0)


class CABundleLinkTest(unittest.TestCase):
    """#347 item 15: /etc/openinfra/ca-bundle.pem (AWS_CA_BUNDLE) -> the distro's FULL system bundle."""

    def test_system_bundle_per_distro(self):
        every = set(agent.FAMILY_BUNDLES.values()) | set(agent.SYSTEM_BUNDLES)
        for family, bundle in (("debian", "/etc/ssl/certs/ca-certificates.crt"),
                               ("rhel", "/etc/pki/tls/certs/ca-bundle.crt"),
                               ("suse", "/etc/ssl/ca-bundle.pem")):
            self.assertEqual(agent.system_bundle(family, isfile=lambda p: p in every), bundle,
                             "%s links its own full bundle even when others exist" % family)
        self.assertEqual(agent.system_bundle(None, isfile=lambda p: p == "/etc/ssl/cert.pem"), "/etc/ssl/cert.pem",
                         "an undetected family falls back to the well-known locations")
        self.assertIsNone(agent.system_bundle("debian", isfile=lambda p: False))

    def test_link_is_atomic_and_idempotent(self):
        d = tempfile.mkdtemp(dir=TMP)
        a, b = os.path.join(d, "a.crt"), os.path.join(d, "b.crt")
        for p in (a, b):
            with open(p, "w") as fh:
                fh.write("bundle\n")
        link = os.path.join(d, "openinfra", "ca-bundle.pem")  # the parent is created
        self.assertEqual(agent.link_ca_bundle(a, link), "linked")
        self.assertEqual(os.readlink(link), a)
        self.assertEqual(agent.link_ca_bundle(a, link), "unchanged")
        self.assertEqual(agent.link_ca_bundle(b, link), "linked", "a different target is re-pointed")
        self.assertEqual(os.readlink(link), b)
        os.remove(link)
        with open(link, "w") as fh:
            fh.write("a stale regular file\n")
        self.assertEqual(agent.link_ca_bundle(a, link), "linked", "a regular file at the path is replaced")
        self.assertTrue(os.path.islink(link))
        self.assertFalse(os.path.lexists(link + ".tmp"))

    def test_publish_never_raises(self):
        d = tempfile.mkdtemp(dir=TMP)
        target = os.path.join(d, "ca-certificates.crt")
        with open(target, "w") as fh:
            fh.write("bundle\n")
        link = os.path.join(d, "ca-bundle.pem")
        self.assertEqual(agent.publish_ca_bundle(link, "debian", bundle=lambda f: target), "linked")
        self.assertEqual(agent.publish_ca_bundle(link, "debian", bundle=lambda f: None), "missing")
        blocker = os.path.join(d, "a-file")
        with open(blocker, "w") as fh:
            fh.write("x")
        self.assertEqual(agent.publish_ca_bundle(os.path.join(blocker, "ca-bundle.pem"), "debian",
                                                 bundle=lambda f: target), "failed")

    def test_agent_links_after_the_ca_step_and_always(self):
        """The link is published AFTER the platform-CA step (so the bundle already carries the root), and
        also when that step did not install it: AWS_CA_BUNDLE replaces an SDK's roots, so a path that does
        not resolve would fail every TLS call, public endpoints included."""
        order = []
        orig = (agent.trust_platform_ca, agent.publish_ca_bundle, agent.trust_store)
        agent.trust_store = lambda: ("debian", "/x", ["update-ca-certificates"])
        agent.publish_ca_bundle = lambda link, family=None, platform_ca=True, **kw: order.append(("link", link, family, platform_ca))
        try:
            for outcome, trusted in (("installed", True), ("unchanged", True), ("unavailable", False), ("failed", False)):
                del order[:]
                agent.trust_platform_ca = lambda url, outcome=outcome, **kw: order.append(("ca", url)) or outcome
                cfg = make_config(imds={"enabled": False}, relay={"enabled": False}, trustPlatformCA=True,
                                  caBundleUrl="http://shim/v1/ca-bundle", caBundleLink="/etc/openinfra/ca-bundle.pem")
                agent.Agent(cfg, warm_timeout=0).start()
                self.assertEqual(order, [("ca", "http://shim/v1/ca-bundle"),
                                         ("link", "/etc/openinfra/ca-bundle.pem", "debian", trusted)], outcome)
            del order[:]
            cfg = make_config(imds={"enabled": False}, relay={"enabled": False}, trustPlatformCA=False,
                              caBundleLink="/etc/openinfra/ca-bundle.pem")
            agent.Agent(cfg, warm_timeout=0).start()
            self.assertEqual(order, [("link", "/etc/openinfra/ca-bundle.pem", "debian", False)],
                             "with trust opted out the path still resolves (to the public roots)")
        finally:
            agent.trust_platform_ca, agent.publish_ca_bundle, agent.trust_store = orig


class NetnsPlanTest(unittest.TestCase):
    """The namespace plumbing, without root: record the ip(8) commands instead of running them."""

    def test_setup_commands(self):
        ran = []
        orig_run, orig_ip = agent.run, agent.ip_binary
        agent.run = lambda cmd, check=True: ran.append(cmd)
        agent.ip_binary = lambda: "ip"
        try:
            agent.setup_netns("openinfra-imds", "169.254.169.254", "169.254.169.1")
        finally:
            agent.run, agent.ip_binary = orig_run, orig_ip
        flat = [" ".join(c) for c in ran]
        self.assertEqual(flat[:2], ["ip netns delete openinfra-imds", "ip link delete oi-imds0"],
                         "setup starts from a clean slate (idempotent restarts)")
        for want in (
            "ip netns add openinfra-imds",
            "ip link add oi-imds0 type veth peer name oi-imds1",
            "ip link set oi-imds1 netns openinfra-imds",
            "ip -n openinfra-imds addr add 169.254.169.254/32 dev oi-imds1",
            "ip -n openinfra-imds route add default via 169.254.169.1 dev oi-imds1",
            "ip route replace 169.254.169.254/32 dev oi-imds0 src 169.254.169.1",
        ):
            self.assertIn(want, flat)
        self.assertFalse(any(" lo" in c and "addr" in c for c in flat),
                         "169.254.169.254 must NOT go on the guest's lo (that would take port 80 from the workload)")


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
