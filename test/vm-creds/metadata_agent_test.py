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
        self.assertEqual(cfg["imds"]["hopLimit"], 1)
        self.assertEqual(cfg["imds"]["httpTokens"], "optional")
        self.assertEqual(cfg["region"], "us-east-1")
        self.assertEqual(cfg["availabilityZone"], "us-east-1a")
        self.assertTrue(cfg["relay"]["enabled"])

    def test_bad_values_fall_back_safely(self):
        cfg = make_config(imds={"hopLimit": 99, "httpTokens": "sometimes"})
        self.assertEqual(cfg["imds"]["hopLimit"], 1)
        self.assertEqual(cfg["imds"]["httpTokens"], "required")  # unknown -> fail closed

    def test_defaults_are_not_mutated(self):
        p = os.path.join(TMP, "minimal.json")
        with open(p, "w") as fh:
            json.dump({"imds": {"hopLimit": 7}}, fh)
        agent.load_config(p)
        self.assertEqual(agent.DEFAULTS["imds"]["hopLimit"], 1)


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


PKI = common.get_test_pki(TMP)


@unittest.skipIf(PKI is None, "no openssl CLI and no OPENINFRA_TEST_PKI: TLS paths not exercised")
class FetchFromShimTest(unittest.TestCase):
    """Credentials come from the shim over TLS verified against the platform root ALONE; the token is
    written only after the handshake verifies."""

    @classmethod
    def setUpClass(cls):
        cls.srv = common.tls_server(StubShim, PKI["server"], PKI["server-key"])
        cls.url = "https://127.0.0.1:%d/v1/vm-credentials" % cls.srv.server_address[1]
        cls.rogue = common.tls_server(StubShim, PKI["rogue-server"], PKI["rogue-server-key"])
        cls.rogue_url = "https://127.0.0.1:%d/v1/vm-credentials" % cls.rogue.server_address[1]
        cls.ca = PKI["root"]
        cls.tok = os.path.join(TMP, "token")
        with open(cls.tok, "w") as fh:
            fh.write("header.payload.sig\n")  # a trailing newline must not reach the header

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.rogue.shutdown()

    def setUp(self):
        StubShim.status, StubShim.body, StubShim.seen_auth = 200, json.dumps(CREDS), []

    def test_sends_the_token_over_verified_tls_and_ignores_proxies(self):
        old = dict((k, os.environ.get(k)) for k in ("http_proxy", "https_proxy"))
        os.environ["http_proxy"] = os.environ["https_proxy"] = "http://127.0.0.1:1"  # would break the request if honored
        try:
            creds = agent.fetch_from_shim(self.url, self.tok, self.ca)
        finally:
            for k, v in old.items():
                if v is None:
                    del os.environ[k]
                else:
                    os.environ[k] = v
        self.assertEqual(creds, CREDS)
        self.assertEqual(StubShim.seen_auth, ["header.payload.sig"])

    def test_an_impostor_never_receives_the_token(self):
        """A server that answers for the shim's address with a certificate the platform root did not sign
        (a LAN DHCP/DNS server, say) fails verification before any HTTP is written."""
        with self.assertRaises(agent.CredentialsError) as ctx:
            agent.fetch_from_shim(self.rogue_url, self.tok, self.ca)
        self.assertIn("not the aws-shim", str(ctx.exception))
        self.assertIn("token was not sent", str(ctx.exception))
        self.assertEqual(StubShim.seen_auth, [], "the impostor must see no request at all")

    def test_never_plaintext_and_never_without_the_root(self):
        plain = self.url.replace("https://", "http://")
        for url, ca, why in ((plain, self.ca, "http:// URL"), (self.url, os.path.join(TMP, "no-root.pem"), "missing root"),
                             (self.url, "", "no caFile")):
            with self.assertRaises(agent.CredentialsError, msg=why):
                agent.fetch_from_shim(url, self.tok, ca)
        self.assertEqual(StubShim.seen_auth, [], "nothing is sent when the shim cannot be verified")
        # The public roots are not enough: only the platform root verifies the shim.
        with self.assertRaises(agent.CredentialsError):
            agent.fetch_from_shim(self.url, self.tok, PKI["rogue-root"])
        self.assertEqual(StubShim.seen_auth, [])

    def test_shim_refusal_carries_status(self):
        StubShim.status, StubShim.body = 403, "role not assumable by this instance"
        with self.assertRaises(agent.CredentialsError) as ctx:
            agent.fetch_from_shim(self.url, self.tok, self.ca)
        self.assertEqual(ctx.exception.status, 403)
        self.assertIn("role not assumable", str(ctx.exception))
        self.assertIn("spec.trust", str(ctx.exception), "a 403 tells the operator what to fix (journal)")

    def test_bad_document_and_missing_token(self):
        StubShim.body = '{"AccessKeyId": "x"}'
        with self.assertRaises(agent.CredentialsError):
            agent.fetch_from_shim(self.url, self.tok, self.ca)
        with self.assertRaises(agent.CredentialsError):
            agent.fetch_from_shim(self.url, os.path.join(TMP, "no-such-token"), self.ca)


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
            self.assertEqual(info["InstanceProfileArn"], "arn:aws:iam::000000000000:instance-profile/app-role")
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
            self.assertEqual(doc["accountId"], "000000000000")
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
    """#347 item 15: the guest trusts the platform root CA (from its own spec) at boot."""

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
        """The root comes from the VM's spec (caFile, written by cloud-init); nothing is fetched."""
        store = ("debian", "/nonexistent", ["update-ca-certificates"])
        installed = []

        def install(pem, st):
            installed.append(pem)
            return "installed"

        d = tempfile.mkdtemp(dir=TMP)

        def ca_file(data):
            path = os.path.join(d, "ca-%d.pem" % len(os.listdir(d)))
            with open(path, "wb") as fh:
                fh.write(data)
            return path

        self.assertEqual(agent.trust_platform_ca(ca_file(TEST_CA), store=store, install=install), "installed")
        self.assertEqual(len(installed), 1)
        for name, path in (("no file", os.path.join(d, "absent.pem")), ("empty file", ca_file(b"")),
                           ("blank file", ca_file(b"\n \n")), ("caFile unset", "")):
            self.assertEqual(agent.trust_platform_ca(path, store=store, install=install), "absent", name)
        self.assertEqual(agent.trust_platform_ca(ca_file(TEST_LEAF), store=store, install=install), "invalid",
                         "a non-CA certificate is never installed")
        self.assertEqual(len(installed), 1)
        orig = agent.trust_store
        agent.trust_store = lambda: None  # a guest with no supported trust-store tool
        try:
            self.assertEqual(agent.trust_platform_ca(ca_file(TEST_CA), install=install), "unsupported")
        finally:
            agent.trust_store = orig

        def broken(pem, st):
            raise RuntimeError("update-ca-certificates failed")
        self.assertEqual(agent.trust_platform_ca(ca_file(TEST_CA), store=store, install=broken), "failed")

    def test_the_agent_fetches_no_ca_over_the_network(self):
        for gone in ("fetch_ca_bundle", "CAFetchError"):
            self.assertFalse(hasattr(agent, gone), "%s must not exist: the root never comes from the network" % gone)
        self.assertNotIn("caBundleUrl", agent.DEFAULTS)

    def test_boot_only_mode_when_metadata_is_disabled(self):
        calls = []
        orig = agent.trust_platform_ca
        agent.trust_platform_ca = lambda path, **kw: calls.append(path) or "installed"
        try:
            cfg = make_config(imds={"enabled": False}, relay={"enabled": False}, trustPlatformCA=True,
                              caFile="/etc/openinfra/platform-root-ca.pem")
            a = agent.Agent(cfg, fetch=lambda: dict(CREDS), warm_timeout=0)
            a.start()  # no listener wanted: must not raise
            self.assertEqual(a.servers, [])
            self.assertEqual(calls, ["/etc/openinfra/platform-root-ca.pem"], "the platform CA is still trusted at boot")
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
            for outcome, trusted in (("installed", True), ("unchanged", True), ("absent", False), ("failed", False)):
                del order[:]
                agent.trust_platform_ca = lambda path, outcome=outcome, **kw: order.append(("ca", path)) or outcome
                cfg = make_config(imds={"enabled": False}, relay={"enabled": False}, trustPlatformCA=True,
                                  caFile="/etc/openinfra/platform-root-ca.pem", caBundleLink="/etc/openinfra/ca-bundle.pem")
                agent.Agent(cfg, warm_timeout=0).start()
                self.assertEqual(order, [("ca", "/etc/openinfra/platform-root-ca.pem"),
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

    # The guest's interfaces as `ip -d -j link` reports them: (name, kind, master).
    LINKS = [
        ("lo", "", ""), ("eth0", "", ""), ("eth0.7", "vlan", ""), ("bond0", "bond", ""),
        ("wg0", "wireguard", ""), ("tun0", "tun", ""), ("vxlan.calico", "vxlan", ""),
        ("docker0", "bridge", ""), ("veth1a2b", "veth", "docker0"),            # containers on docker's bridge
        ("br-lan", "bridge", ""), ("eth1", "", "br-lan"), ("veth9", "veth", "br-lan"),  # a bridge with a NIC
        ("br-tap", "bridge", ""), ("tap0", "tun", "br-tap"),                    # OpenVPN bridged clients
        ("cali123", "veth", ""), ("nk0", "netkit", ""), ("virbr-empty", "bridge", ""),
        (agent.NETNS_HOST_IF, "veth", ""), ('bad"name', "veth", ""),
    ]

    def test_container_interfaces_are_veth_netkit_and_all_container_bridges(self):
        self.assertEqual(agent.container_interfaces(self.LINKS),
                         ["cali123", "docker0", "nk0", "veth1a2b", "veth9", "virbr-empty"],
                         "containers only: never a NIC, VLAN, bond, tunnel, a bridge holding a NIC or tap, the "
                         "metadata veth, or a name that cannot be quoted into a rule")
        self.assertNotIn("cali123", agent.container_interfaces(self.LINKS, extra=["cali123"]),
                         "an always-refused interface is never admitted")

    def test_guest_links_parses_ip_json(self):
        out = json.dumps([{"ifname": "eth0"}, {"ifname": "docker0", "linkinfo": {"info_kind": "bridge"}},
                          {"ifname": "veth1", "master": "docker0", "linkinfo": {"info_kind": "veth", "info_slave_kind": "bridge"}}])

        def run_cmd(cmd, check=True):
            class P(object):
                returncode, stdout, stderr = 0, out, ""
            return P()

        orig = agent.ip_binary
        agent.ip_binary = lambda: "ip"
        try:
            self.assertEqual(agent.guest_links(run_cmd), [("eth0", "", ""), ("docker0", "bridge", ""), ("veth1", "veth", "docker0")])

            def failing(cmd, check=True):
                class P(object):
                    returncode, stdout, stderr = 255, "", "Option \"-j\" is unknown"
                return P()
            self.assertIsNone(agent.guest_links(failing), "an ip without JSON: unknown, not an empty list")
        finally:
            agent.ip_binary = orig

    def guard_with(self, tools, refuse=(), extra=(), links=None):
        """Run guard_forwarded_imds with fake tools. refuse: substrings of a command or of the nft ruleset
        it loads that make that command fail."""
        ran = []
        ruleset = os.path.join(tempfile.mkdtemp(dir=TMP), "guard.nft")

        def run_cmd(cmd, check=True):
            ran.append(list(cmd))
            text = " ".join(cmd)
            if cmd[-2:] == ["-f", ruleset] and os.path.exists(ruleset):
                with open(ruleset) as fh:
                    text += "\n" + fh.read()
            failed = any(r in text for r in refuse) or "-C" in cmd  # -C (check) answers "absent"

            class P(object):
                returncode = 1 if failed else 0
                stdout, stderr = "", "refused" if failed else ""
            return P()

        orig_ip = agent.ip_binary
        agent.ip_binary = lambda: "ip"
        try:
            mode, allowed = agent.guard_forwarded_imds("openinfra-imds", "169.254.169.254", list(extra),
                                                       which=lambda t: "/usr/sbin/" + t if t in tools else None,
                                                       run_cmd=run_cmd, ruleset_path=ruleset,
                                                       links=self.LINKS if links is None else links)
        finally:
            agent.ip_binary = orig_ip
        script = ""
        if os.path.exists(ruleset):
            with open(ruleset) as fh:
                script = fh.read()
        return mode, allowed, [" ".join(c) for c in ran], script

    def test_guard_prefers_nft_by_interface_kind(self):
        mode, allowed, ran, script = self.guard_with({"nft", "iptables"}, extra=["cali123"])
        self.assertEqual((mode, allowed), ("nft-kind", None))
        self.assertIn("/usr/sbin/nft -f ", "\n".join(ran))
        ip_table, bridge_table = script.split("table bridge openinfra_imds {}\n")
        self.assertTrue(ip_table.startswith("table ip openinfra_imds {}\ndelete table ip openinfra_imds\n"),
                        "the ruleset replaces itself atomically (idempotent restarts)")
        for want in ('iifname { "cali123" } ip daddr 169.254.169.254 drop',
                     'ip daddr 169.254.169.254 meta iifkind { "veth", "netkit", "bridge" } accept',
                     "ip daddr 169.254.169.254 drop"):
            self.assertIn(want, ip_table)
        self.assertIn("type filter hook prerouting priority -300; policy accept;", ip_table, "raw priority, before conntrack/DNAT")
        self.assertLess(ip_table.index("iifname"), ip_table.index("} accept"), "an always-refused interface is dropped first")
        self.assertLess(ip_table.index("} accept"), ip_table.rindex("ip daddr 169.254.169.254 drop"), "everything else is dropped")
        self.assertIn('ip daddr 169.254.169.254 meta iifkind { "veth", "netkit" } accept', bridge_table,
                      "a bridged frame is admitted only from a container's port")
        self.assertTrue(bridge_table.rstrip().endswith("ip daddr 169.254.169.254 drop\n  }\n}"), bridge_table)
        self.assertFalse(any("route del default" in c for c in ran), "with a firewall tool the namespace keeps its routes")

    def test_guard_names_the_containers_when_nft_cannot_match_kinds(self):
        mode, allowed, ran, script = self.guard_with({"nft", "iptables"}, refuse=("iifkind",))
        self.assertEqual(mode, "nft-names")
        self.assertEqual(allowed, agent.container_interfaces(self.LINKS))
        self.assertIn('ip daddr 169.254.169.254 iifname { "cali123", "docker0", "nk0", "veth1a2b", "veth9", "virbr-empty" } accept',
                      script)
        self.assertNotIn("table bridge", script)
        self.assertTrue(script.rstrip().endswith("ip daddr 169.254.169.254 drop\n  }\n}"))
        mode, allowed, _, script = self.guard_with({"nft"}, refuse=("iifkind",), links=[("eth0", "", "")])
        self.assertEqual((mode, allowed), ("nft-names", []))
        self.assertNotIn("} accept", script, "no container interface: everything for IMDS is dropped")

    def test_guard_iptables_and_route_fallback(self):
        mode, allowed, ran, _ = self.guard_with({"iptables"}, extra=["wg9"])
        self.assertEqual(mode, "iptables")
        for want in ("/usr/sbin/iptables -w -t raw -N OPENINFRA-IMDS",
                     "/usr/sbin/iptables -w -t raw -A OPENINFRA-IMDS -i wg9 -j DROP",
                     "/usr/sbin/iptables -w -t raw -A OPENINFRA-IMDS -i docker0 -j RETURN",
                     "/usr/sbin/iptables -w -t raw -A OPENINFRA-IMDS -i cali123 -j RETURN",
                     "/usr/sbin/iptables -w -t raw -A OPENINFRA-IMDS -j DROP",
                     "/usr/sbin/iptables -w -t raw -I PREROUTING 1 -d 169.254.169.254/32 -j OPENINFRA-IMDS"):
            self.assertIn(want, ran)
        self.assertLess(ran.index("/usr/sbin/iptables -w -t raw -A OPENINFRA-IMDS -i docker0 -j RETURN"),
                        ran.index("/usr/sbin/iptables -w -t raw -A OPENINFRA-IMDS -j DROP"))
        self.assertFalse(any("-i eth0" in c or "-i wg0 -j RETURN" in c or "-i br-lan" in c for c in ran),
                         "NICs, tunnels and a bridge with a NIC are never admitted")
        mode, _, ran, _ = self.guard_with(set())
        self.assertEqual(mode, "routes", "no nft/iptables: the namespace answers only the guest itself")
        self.assertIn("ip -n openinfra-imds route del default", ran)
        mode, _, _, _ = self.guard_with({"nft", "iptables"}, refuse=("-f ", "iptables", "route del", "route show"))
        self.assertEqual(mode, "failed", "every mechanism refused: reported, never raised")

    def test_remove_guard(self):
        ran = []

        def run_cmd(cmd, check=True):
            ran.append(" ".join(cmd))

            class P(object):
                returncode, stdout, stderr = (1 if "-D" in cmd else 0), "", ""
            return P()

        agent.remove_imds_guard(which=lambda t: "/usr/sbin/" + t, run_cmd=run_cmd)
        for want in ("/usr/sbin/nft delete table ip openinfra_imds", "/usr/sbin/nft delete table bridge openinfra_imds",
                     "/usr/sbin/iptables -w -t raw -D PREROUTING -d 169.254.169.254/32 -j OPENINFRA-IMDS",
                     "/usr/sbin/iptables -w -t raw -D PREROUTING -j OPENINFRA-IMDS",  # an older agent's jump
                     "/usr/sbin/iptables -w -t raw -X OPENINFRA-IMDS"):
            self.assertIn(want, ran)

    def test_guard_in_place(self):
        def fake(answers):
            def run_cmd(cmd, check=True):
                text = " ".join(cmd)
                rc, out = 1, ""
                for key, (r, o) in answers.items():
                    if key in text:
                        rc, out = r, o

                class P(object):
                    returncode, stdout, stderr = rc, out, ""
                return P()
            return run_cmd

        which = lambda t: "/usr/sbin/" + t
        rule = "ip daddr 169.254.169.254 drop"
        both = fake({"list table ip": (0, rule), "list table bridge": (0, rule)})
        self.assertTrue(agent.guard_in_place("nft-kind", "169.254.169.254", "ns", which, both))
        self.assertFalse(agent.guard_in_place("nft-kind", "169.254.169.254", "ns", which, fake({"list table ip": (0, rule)})),
                         "kind mode needs its bridge table too")
        self.assertTrue(agent.guard_in_place("nft-names", "169.254.169.254", "ns", which, fake({"list table ip": (0, rule)})))
        self.assertFalse(agent.guard_in_place("nft-names", "169.254.169.254", "ns", which, fake({})), "flushed ruleset")
        self.assertFalse(agent.guard_in_place("nft-names", "169.254.169.254", "ns", which, fake({"list table ip": (0, "table ip openinfra_imds {}")})),
                         "an emptied table is not a guard")
        self.assertTrue(agent.guard_in_place("iptables", "169.254.169.254", "ns", which, fake({"-C": (0, "")})))
        self.assertFalse(agent.guard_in_place("iptables", "169.254.169.254", "ns", which, fake({})))
        self.assertFalse(agent.guard_in_place("failed", "169.254.169.254", "ns", which, both))
        orig = agent.ip_binary
        agent.ip_binary = lambda: "ip"
        try:
            self.assertTrue(agent.guard_in_place("routes", "169.254.169.254", "ns", which, fake({"route show default": (0, "")})))
            self.assertFalse(agent.guard_in_place("routes", "169.254.169.254", "ns", which,
                                                  fake({"route show default": (0, "default via 169.254.169.1")})))
        finally:
            agent.ip_binary = orig


class GuardFailClosedTest(unittest.TestCase):
    """Without a forwarded-traffic guard the metadata service serves nothing; the watchdog re-applies a
    removed guard and lifts the 503 once one is back."""

    def test_no_guard_no_metadata(self):
        with Running(make_config()) as r:
            self.assertEqual(r.get("/latest/meta-data/instance-id")[0], 200)
            r.agent.guard_ok = False
            self.assertEqual(r.get("/latest/meta-data/instance-id")[0], 503)
            self.assertEqual(r.put_token()[0], 503, "no IMDSv2 token either")
            self.assertEqual(r.get("/latest/meta-data/iam/security-credentials/app-role")[0], 503)
            r.agent.guard_ok = True
            self.assertEqual(r.get("/latest/meta-data/instance-id")[0], 200)

    def test_watchdog_reapplies_a_removed_guard_and_fails_closed_meanwhile(self):
        a = agent.Agent(make_config(imds={"netns": "openinfra-imds"}), fetch=lambda: dict(CREDS), warm_timeout=0)
        state = {"in_place": True, "modes": ["failed", "nft-kind"], "links": [("docker0", "bridge", "")]}
        calls = []
        orig = (agent.guard_in_place, agent.guard_forwarded_imds, agent.guest_links)

        def fake_apply(netns, addr, extra=()):
            calls.append(("apply", list(extra)))
            mode = state["modes"].pop(0) if state["modes"] else "nft-kind"
            state["in_place"] = mode != "failed"
            return mode, (["docker0"] if mode == "iptables" else None)

        agent.guard_in_place = lambda mode, addr, netns, *a_: state["in_place"]
        agent.guard_forwarded_imds = fake_apply
        agent.guest_links = lambda *a_: state["links"]
        try:
            a.guard_mode, a.guard_ok = "nft-kind", True
            a.check_guard()
            self.assertEqual(calls, [], "a guard in place is left alone")
            state["in_place"] = False  # nft flush ruleset
            a.check_guard()
            self.assertEqual((a.guard_mode, a.guard_ok), ("failed", False), "re-applying failed: fail closed")
            a.check_guard()
            self.assertEqual((a.guard_mode, a.guard_ok), ("nft-kind", True), "the next check restores it")
            # Name-based: a new container interface re-applies the guard so the container is admitted.
            state["modes"] = ["iptables"]
            state["in_place"] = False
            a.check_guard()
            self.assertEqual((a.guard_mode, a.guard_allowed), ("iptables", ["docker0"]))
            n = len(calls)
            a.check_guard()
            self.assertEqual(len(calls), n, "unchanged interfaces: nothing re-applied")
            state["links"] = [("docker0", "bridge", ""), ("cali9", "veth", "")]
            state["modes"] = ["iptables"]
            a.check_guard()
            self.assertEqual(len(calls), n + 1, "a new container interface re-applies the name-based guard")
        finally:
            agent.guard_in_place, agent.guard_forwarded_imds, agent.guest_links = orig


class ContainerConfigTest(unittest.TestCase):
    """Containers do not inherit the guest's environment: the agent makes Docker and Podman add the guest's AWS
    endpoint and CA to every container (#347 item A)."""

    def setUp(self):
        self.d = tempfile.mkdtemp(dir=TMP)
        self.json = os.path.join(self.d, "docker", "daemon.json")
        self.calls = []

    def run_cmd(self, active):
        def f(cmd, check=True):
            self.calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0 if (cmd[1] != "is-active" or active) else 3, "", "")
        return f

    def read(self):
        with open(self.json) as fh:
            return json.load(fh)

    def test_fresh_guest_gets_the_wrapper_as_default_runtime(self):
        self.assertEqual(agent.configure_docker("/w", path=self.json, run_cmd=self.run_cmd(False)), "configured")
        self.assertEqual(self.read(), {"default-runtime": "openinfra-aws", "runtimes": {"openinfra-aws": {"path": "/w"}}})
        self.assertNotIn(["systemctl", "reload", "docker"], self.calls, "Docker not running: nothing to reload")

    def test_a_running_daemon_is_reloaded_and_other_keys_are_kept(self):
        os.makedirs(os.path.dirname(self.json))
        with open(self.json, "w") as fh:
            json.dump({"log-driver": "json-file", "runtimes": {"nvidia": {"path": "/usr/bin/nvidia-container-runtime"}}}, fh)
        self.assertEqual(agent.configure_docker("/w", path=self.json, run_cmd=self.run_cmd(True)), "configured")
        d = self.read()
        self.assertEqual(d["log-driver"], "json-file")
        self.assertEqual(sorted(d["runtimes"]), ["nvidia", "openinfra-aws"])
        self.assertEqual(d["default-runtime"], "openinfra-aws")
        self.assertIn(["systemctl", "reload", "docker"], self.calls)
        self.assertEqual(agent.configure_docker("/w", path=self.json, run_cmd=self.run_cmd(True)), "unchanged")

    def test_a_default_runtime_the_guest_chose_is_kept(self):
        os.makedirs(os.path.dirname(self.json))
        with open(self.json, "w") as fh:
            json.dump({"default-runtime": "nvidia"}, fh)
        self.assertEqual(agent.configure_docker("/w", path=self.json, run_cmd=self.run_cmd(False)), "kept")
        d = self.read()
        self.assertEqual(d["default-runtime"], "nvidia")
        self.assertEqual(d["runtimes"]["openinfra-aws"], {"path": "/w"}, "still offered as --runtime openinfra-aws")

    def test_an_unreadable_daemon_json_is_left_alone(self):
        os.makedirs(os.path.dirname(self.json))
        with open(self.json, "w") as fh:
            fh.write("{not json")
        self.assertEqual(agent.configure_docker("/w", path=self.json, run_cmd=self.run_cmd(False)), "error")
        with open(self.json) as fh:
            self.assertEqual(fh.read(), "{not json")

    def test_podman_dropin(self):
        env = ["AWS_ENDPOINT_URL=https://shim:4567", "AWS_CA_BUNDLE=/etc/openinfra/ca-bundle.pem"]
        text = agent.podman_dropin(env, "/etc/openinfra/ca-bundle.pem")
        self.assertIn("[containers]\n", text)
        self.assertIn('env = ["AWS_ENDPOINT_URL=https://shim:4567", "AWS_CA_BUNDLE=/etc/openinfra/ca-bundle.pem"]', text)
        self.assertIn('volumes = ["/etc/openinfra/ca-bundle.pem:/etc/openinfra/ca-bundle.pem:ro"]', text)

    def test_configure_containers_follows_the_golden_config(self):
        cfg = agent.load_config(common.GOLDEN_CONFIG)
        podman = os.path.join(self.d, "containers.conf.d", "50-openinfra-aws.conf")
        out = agent.configure_containers(cfg, docker_json=self.json, podman_path=podman, run_cmd=self.run_cmd(False))
        self.assertEqual(out, {"docker": "configured", "podman": "configured"})
        self.assertEqual(self.read()["runtimes"]["openinfra-aws"]["path"], agent.OCI_WRAPPER)
        with open(podman) as fh:
            self.assertIn("AWS_ENDPOINT_URL=", fh.read())
        cfg["containers"] = {"env": [], "caBundle": ""}
        self.assertEqual(agent.configure_containers(cfg, docker_json=self.json + ".2", podman_path=podman + ".2"), {})
        self.assertFalse(os.path.exists(self.json + ".2"), "no container env (no platform CA): Docker untouched")


class OCIWrapperTest(unittest.TestCase):
    """The OCI runtime wrapper Docker runs every container through: env + CA mount, then the real runc."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(dir=TMP)
        cls.wrapper_path = common.write_oci_wrapper(cls.d)
        cls.w = common.load_oci_wrapper_module(tempfile.mkdtemp(dir=TMP))
        cls.ca = os.path.join(cls.d, "ca-bundle.pem")
        with open(cls.ca, "w") as fh:
            fh.write("-----BEGIN CERTIFICATE-----\n")
        cls.cfg = os.path.join(cls.d, "agent.json")
        with open(cls.cfg, "w") as fh:
            json.dump({"containers": {"env": ["AWS_ENDPOINT_URL=https://shim:4567", "AWS_CA_BUNDLE=%s" % cls.ca],
                                      "caBundle": cls.ca}}, fh)
        # A fake runc: records its arguments and the config.json it was handed.
        cls.fake = os.path.join(cls.d, "fake-runc")
        with open(cls.fake, "w") as fh:
            fh.write("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_OUT.args\"\n"
                     "for a; do [ \"$prev\" = --bundle ] && cp \"$a/config.json\" \"$FAKE_OUT.json\"; prev=$a; done\nexit 0\n")
        os.chmod(cls.fake, 0o755)

    def test_bundle_parsing_matches_what_containerd_passes(self):
        args = ["--root", "/var/run/docker/runtime-runc/moby", "--log", "/run/x/log.json", "--log-format", "json",
                "--systemd-cgroup", "create", "--bundle", "/run/b", "--pid-file", "/run/p", "cid"]
        self.assertEqual(self.w.bundle_of(args), ("create", "/run/b"))
        self.assertEqual(self.w.bundle_of(["run", "--bundle=/run/c", "cid"]), ("run", "/run/c"))
        self.assertEqual(self.w.bundle_of(["--root", "/r", "start", "cid"]), ("start", None))
        self.assertEqual(self.w.bundle_of(["state", "cid"]), ("state", None))

    def test_inject_adds_only_what_the_container_does_not_set(self):
        spec = {"process": {"env": ["PATH=/bin", "AWS_ENDPOINT_URL=http://mine"]}, "mounts": []}
        self.assertTrue(self.w.inject(spec, ["AWS_ENDPOINT_URL=https://shim", "AWS_CA_BUNDLE=" + self.ca], self.ca))
        self.assertEqual(spec["process"]["env"], ["PATH=/bin", "AWS_ENDPOINT_URL=http://mine", "AWS_CA_BUNDLE=" + self.ca])
        self.assertEqual([m["destination"] for m in spec["mounts"]], [self.ca])
        self.assertIn("ro", spec["mounts"][0]["options"])
        self.assertFalse(self.w.inject(spec, ["AWS_ENDPOINT_URL=https://shim"], self.ca), "already done: unchanged")

    def test_opt_out_and_no_ca_leave_the_container_alone(self):
        spec = {"process": {"env": ["OPENINFRA_AWS_ENV=off"]}}
        self.assertFalse(self.w.inject(spec, ["AWS_ENDPOINT_URL=https://shim"], self.ca))
        spec = {"process": {"env": []}}
        self.assertFalse(self.w.inject(spec, ["AWS_ENDPOINT_URL=https://shim"], self.ca + ".missing"))
        self.assertEqual(spec, {"process": {"env": []}})

    def run_wrapper(self, config_json, tag):
        bundle = tempfile.mkdtemp(dir=self.d)
        with open(os.path.join(bundle, "config.json"), "w") as fh:
            fh.write(config_json)
        out = os.path.join(self.d, tag)
        env = dict(os.environ, OPENINFRA_RUNC=self.fake, OPENINFRA_METADATA_CONFIG=self.cfg, FAKE_OUT=out)
        p = subprocess.run([sys.executable, self.wrapper_path, "--root", "/r", "--log", "/l", "create", "--bundle", bundle, "cid"],
                           env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
        with open(out + ".args") as fh:
            args = fh.read().split()
        handed = None
        if os.path.exists(out + ".json"):
            with open(out + ".json") as fh:
                handed = fh.read()
        return p, args, handed

    def test_end_to_end_the_real_runc_gets_the_same_args_and_the_injected_spec(self):
        p, args, handed = self.run_wrapper(json.dumps({"process": {"env": ["PATH=/bin"]}, "mounts": []}), "e2e")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(args[:5], ["--root", "/r", "--log", "/l", "create"])
        spec = json.loads(handed)
        self.assertIn("AWS_ENDPOINT_URL=https://shim:4567", spec["process"]["env"])
        self.assertEqual(spec["mounts"][-1]["destination"], self.ca)

    def test_a_broken_spec_still_runs_the_container_unchanged(self):
        p, args, handed = self.run_wrapper("{not json", "broken")
        self.assertEqual(p.returncode, 0)
        self.assertIn("container left unchanged", p.stderr)
        self.assertEqual(handed, "{not json")


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
