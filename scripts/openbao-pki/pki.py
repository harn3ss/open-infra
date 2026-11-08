#!/usr/bin/env python3
"""The platform's CAs into OpenBao (#359): run once, in the openbao-pki pod (scripts/openbao-pki.sh).

  setup        The intermediates of openinfra/pki-platform and openinfra/pki-aws-endpoints: OpenBao generates
               each key and never exports it; its CSR is signed by its root through a temporary, namespaced
               cert-manager Issuer in cert-manager (the root key is never read); the signed certificate and its
               root are set in OpenBao as the mount's default issuer. openinfra/pki-acm: the ACM intermediate is
               imported as it is (same certificate, same validated-domain constraint), its key moved by pipe,
               never shown; its signing role gets the CA's own permitted domains. Each mount then signs a
               throwaway certificate, checked to chain to the same root. Idempotent: a mount with an issuer
               is left as it is.
  rotate NAME  A new intermediate for openinfra/pki-NAME (platform or aws-endpoints), signed the same way, made
               the mount's default issuer; the previous one keeps verifying what it signed.

Needs a root token (BAO_TOKEN, from Secret openbao-bootstrap) and kubectl with: CertificateRequests and Issuers
in cert-manager, the ClusterIssuers, EnvironmentConfig openinfra-platform-ca (the published roots), the ACM
Certificate and its Secret (the one key that moves), ConfigMap openinfra-roots in cert-manager. Prints no
key, token or certificate body; a status file (/run/pki/status.json) holds what was done, public data only.
"""
import base64, datetime, json, os, ssl, subprocess, sys, time, urllib.error, urllib.request

E = os.environ.get
ADDR = E("BAO_ADDR", "https://openbao-active.openbao.svc:8200")
CA = E("BAO_CACERT", "/etc/openbao-ca/ca.crt")
TOKEN = E("BAO_TOKEN", "")
KUBECTL = E("KUBECTL", "kubectl").split()
CM_NS = "cert-manager"
STATUS_FILE = E("PKI_STATUS", "/run/pki/status.json")
# name: (mount, role, the issuer whose root signs it, the root's Secret, intermediate common name)
CAS = {
    "platform": ("openinfra/pki-platform", "platform", "openinfra-ca", "open-infra platform intermediate"),
    "aws-endpoints": ("openinfra/pki-aws-endpoints", "aws-endpoints", "openinfra-aws-endpoints", "open-infra AWS endpoints intermediate"),
}
STATUS = {"steps": []}


def note(msg, **kw):
    print(msg, flush=True)
    STATUS["steps"].append(dict(msg=msg, **kw))
    os.makedirs(os.path.dirname(STATUS_FILE), exist_ok=True)
    with open(STATUS_FILE, "w") as f:
        json.dump(STATUS, f)


def bao(method, path, body=None):
    ctx = ssl.create_default_context(cafile=CA) if ADDR.startswith("https") else None
    req = urllib.request.Request(ADDR + "/v1/" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Vault-Token": TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise SystemExit("OpenBao %s %s: %s" % (method, path, "; ".join(json.loads(e.read() or b"{}").get("errors", [])) or e.code))


def kubectl(*args, stdin=None, check=True):
    r = subprocess.run(KUBECTL + list(args), input=stdin, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit("kubectl %s: %s" % (" ".join(args[:4]), r.stderr.strip()[-300:]))
    return r.stdout


def kget(*args):
    return json.loads(kubectl("get", *args, "-o", "json"))


def pem_first(pem):
    end = "-----END CERTIFICATE-----"
    return pem[: pem.index(end) + len(end)] + "\n" if end in pem else pem


def issuers(mount):
    try:
        return bao("LIST", mount + "/issuers").get("data", {}).get("keys", [])
    except SystemExit:
        return []


PUBLISHED = {"openinfra-ca": "platformRootCA", "openinfra-aws-endpoints": "awsEndpointsCA"}


def root_of(issuer):
    """(the root's Secret name, its certificate). The certificate is read where the platform publishes it
    (EnvironmentConfig openinfra-platform-ca, public), so no Secret holding a root key is ever read here."""
    ci = kget("clusterissuer", issuer)
    secret = ci["spec"].get("ca", {}).get("secretName")
    if not secret:
        raise SystemExit("ClusterIssuer %s is not a CA issuer (already moved?)" % issuer)
    pem = kget("environmentconfig", "openinfra-platform-ca").get("data", {}).get(PUBLISHED[issuer], "")
    if "BEGIN CERTIFICATE" not in pem:
        raise SystemExit("the root of %s is not published (EnvironmentConfig openinfra-platform-ca)" % issuer)
    return secret, pem


def sign_intermediate(name, csr_pem, root_secret):
    """Sign an intermediate CSR with the root, through a temporary namespaced Issuer: returns (cert, root)."""
    issuer = "openbao-root-signer-" + name
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    cr = "openbao-%s-intermediate-%s" % (name, stamp)
    kubectl("apply", "-f", "-", stdin=json.dumps({
        "apiVersion": "cert-manager.io/v1", "kind": "Issuer",
        "metadata": {"name": issuer, "namespace": CM_NS, "labels": {"app.kubernetes.io/managed-by": "openbao-pki"}},
        "spec": {"ca": {"secretName": root_secret}}}))
    try:
        kubectl("apply", "-f", "-", stdin=json.dumps({
            "apiVersion": "cert-manager.io/v1", "kind": "CertificateRequest",
            "metadata": {"name": cr, "namespace": CM_NS, "labels": {"app.kubernetes.io/managed-by": "openbao-pki"}},
            "spec": {"request": base64.b64encode(csr_pem.encode()).decode(), "isCA": True, "duration": "43800h",
                     "usages": ["digital signature", "cert sign", "crl sign"],
                     "issuerRef": {"name": issuer, "kind": "Issuer", "group": "cert-manager.io"}}}))
        for _ in range(60):
            st = kget("-n", CM_NS, "certificaterequest", cr).get("status", {})
            ready = [c for c in st.get("conditions", []) if c["type"] == "Ready"]
            if ready and ready[0]["status"] == "True":
                return base64.b64decode(st["certificate"]).decode(), base64.b64decode(st["ca"]).decode()
            if ready and ready[0].get("reason") in ("Failed", "Denied"):
                raise SystemExit("CertificateRequest %s: %s" % (cr, ready[0].get("message")))
            time.sleep(2)
        raise SystemExit("CertificateRequest %s was not signed within 120s" % cr)
    finally:
        kubectl("-n", CM_NS, "delete", "issuer", issuer, "--ignore-not-found", check=False)


def new_intermediate(name, key_name):
    mount, role, issuer, cn = CAS[name]
    root_secret, root_pem = root_of(issuer)
    csr = bao("POST", mount + "/intermediate/generate/internal",
              {"common_name": cn, "key_type": "ec", "key_bits": 256, "key_name": key_name})["data"]["csr"]
    cert, ca = sign_intermediate(name, csr, root_secret)
    if pem_first(ca).strip() != pem_first(root_pem).strip():
        raise SystemExit("the root that signed %s is not the root its issuer holds" % name)
    res = bao("POST", mount + "/intermediate/set-signed", {"certificate": cert.strip() + "\n" + pem_first(ca)})["data"]
    imported = res.get("imported_issuers") or []
    mine = [i for i in imported if bao("GET", "%s/issuer/%s" % (mount, i))["data"].get("key_id")]
    if len(mine) != 1:
        raise SystemExit("set-signed on %s imported no issuer with this key" % mount)
    bao("POST", mount + "/issuer/" + mine[0], {"issuer_name": key_name})
    bao("POST", mount + "/config/issuers", {"default": mine[0]})
    return mine[0], cert, pem_first(ca)


def throwaway(mount, role, cn, root_pem):
    """Issue a short-lived certificate through the role and check it chains to root_pem (openssl, if any)."""
    r = bao("POST", "%s/issue/%s" % (mount, role), {"common_name": cn, "ttl": "5m", "key_type": "ec", "key_bits": 256})["data"]
    chain = r["certificate"].strip() + "\n" + "\n".join(c.strip() for c in r.get("ca_chain", [])) + "\n"
    serial = r["serial_number"]
    del r
    bao("POST", mount + "/revoke", {"serial_number": serial})
    ok = None
    if subprocess.run(["sh", "-c", "command -v openssl"], capture_output=True).returncode == 0:
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            open(d + "/root.pem", "w").write(root_pem)
            open(d + "/chain.pem", "w").write(chain)
            leaf = pem_first(chain)
            open(d + "/leaf.pem", "w").write(leaf)
            open(d + "/rest.pem", "w").write(chain[len(leaf):])
            ok = subprocess.run(["openssl", "verify", "-CAfile", d + "/root.pem", "-untrusted", d + "/rest.pem", d + "/leaf.pem"],
                                capture_output=True).returncode == 0
    return serial, chain, ok


def roots_configmap(platform_root, aws_root):
    """The roots, public, for what publishes them once their Certificates are gone (platform-ca-publisher)."""
    data = {"platformRootCA": platform_root}
    if aws_root:
        data["awsEndpointsCA"] = aws_root
    kubectl("apply", "-f", "-", stdin=json.dumps({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "openinfra-roots", "namespace": CM_NS, "labels": {"app.kubernetes.io/managed-by": "openbao-pki"}},
        "data": data}))


def setup():
    if "root" not in bao("GET", "auth/token/lookup-self")["data"]["policies"]:
        raise SystemExit("BAO_TOKEN is not a root token")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
    roots = {}
    for name, (mount, role, issuer, cn) in CAS.items():
        if issuers(mount):
            note("%s: %s already has an issuer, left as it is" % (name, mount))
            roots[name] = bao("GET", mount + "/issuer/default")["data"].get("ca_chain", [""])[-1]
            continue
        iid, cert, root = new_intermediate(name, "%s-%s" % (name, stamp))
        roots[name] = root
        note("%s: intermediate generated in OpenBao, signed by its root, default issuer of %s" % (name, mount),
             mount=mount, issuer_id=iid)
    # ACM: the existing intermediate, imported as it is.
    mount = "openinfra/pki-acm"
    acm = kget("clusterissuer", "openinfra-acm") if kubectl("get", "clusterissuer", "openinfra-acm", "--ignore-not-found", "-o", "name").strip() else None
    if acm and not issuers(mount):
        secret = acm["spec"].get("ca", {}).get("secretName")
        if not secret:
            raise SystemExit("ClusterIssuer openinfra-acm is not a CA issuer (already moved?)")
        data = kget("-n", CM_NS, "secret", secret)["data"]
        bundle = (base64.b64decode(data["tls.key"]).decode().strip() + "\n" + base64.b64decode(data["tls.crt"]).decode().strip()
                  + "\n" + base64.b64decode(data.get("ca.crt", "")).decode().strip() + "\n")
        res = bao("POST", mount + "/issuers/import/bundle", {"pem_bundle": bundle})["data"]
        del bundle, data
        keyed = [i for i in (res.get("imported_issuers") or []) if bao("GET", "%s/issuer/%s" % (mount, i))["data"].get("key_id")]
        if len(keyed) != 1:
            raise SystemExit("the ACM import produced no issuer with its key")
        imported = bao("GET", "%s/issuer/%s" % (mount, keyed[0]))["data"]["certificate"]
        current = base64.b64decode(kget("-n", CM_NS, "secret", secret)["data"]["tls.crt"]).decode()
        if pem_first(imported).strip() != pem_first(current).strip():
            raise SystemExit("the imported ACM certificate differs from the one in use")
        bao("POST", mount + "/issuer/" + keyed[0], {"issuer_name": "acm"})
        bao("POST", mount + "/config/issuers", {"default": keyed[0]})
        domains = []
        for c in kget("-n", CM_NS, "certificates")["items"]:
            if c["spec"].get("secretName") == secret:
                domains = c["spec"].get("nameConstraints", {}).get("permitted", {}).get("dnsDomains", [])
        if not domains:
            raise SystemExit("no validated domains found for the ACM CA")
        bao("POST", mount + "/roles/acm", {"allowed_domains": ",".join(domains), "allow_subdomains": True, "allow_bare_domains": True,
                                           "allow_wildcard_certificates": True, "allow_ip_sans": False, "server_flag": True,
                                           "client_flag": False, "key_type": "any", "max_ttl": "8760h", "require_cn": False})
        note("acm: the existing intermediate imported as it is (same certificate), default issuer of %s; its role allows %d validated domain(s)"
             % (mount, len(domains)), mount=mount)
    elif acm:
        note("acm: %s already has an issuer, left as it is" % mount)
    roots_configmap(roots["platform"], roots.get("aws-endpoints"))
    note("the roots' certificates (public) are in configmap %s/openinfra-roots" % CM_NS)
    for name, cn in (("platform", "pki-check.svc.cluster.local"), ("aws-endpoints", "pki-check.amazonaws.com")):
        mount, role = CAS[name][0], CAS[name][1]
        serial, chain, ok = throwaway(mount, role, cn, roots[name])
        note("%s: a throwaway certificate issued and revoked (%s); chains to its root: %s"
             % (name, serial, {True: "yes", False: "NO", None: "checked outside this pod"}[ok]),
             chained=ok, chain=chain, root=roots[name])


def rotate(name):
    if name not in CAS:
        raise SystemExit("rotate: platform or aws-endpoints")
    mount = CAS[name][0]
    before = bao("GET", mount + "/issuer/default")["data"]
    iid, cert, root = new_intermediate(name, "%s-%s" % (name, datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M")))
    note("%s: rotated: new intermediate %s is the default issuer; the previous one (%s) keeps verifying"
         % (name, iid, before.get("issuer_id")), new=iid, previous=before.get("issuer_id"))


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("BAO_TOKEN (a root token) is required")
    cmd = sys.argv[1:] or ["setup"]
    {"setup": lambda: setup(), "rotate": lambda: rotate(cmd[1] if len(cmd) > 1 else "")}[cmd[0]]()
