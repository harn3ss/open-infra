#!/usr/bin/env bash
# The platform's root CA keys, offline (#359; docs/openbao.md, "The platform's CAs"). Once the platform's
# issuers sign through OpenBao intermediates (openbao.platformCAs: true), the root keys are needed only to sign
# a new intermediate. They leave the cluster for a file encrypted with the operator's passphrase, kept off the
# cluster and away from any agent-reachable path, and come back only for that ceremony.
#
#   scripts/openbao-offline-roots.sh export FILE    encrypt the roots into FILE, check FILE against the cluster,
#                                                   then (after "yes") delete the root keys from the cluster
#   scripts/openbao-offline-roots.sh check FILE     decrypt FILE in memory and show what it holds (public data)
#   scripts/openbao-offline-roots.sh restore FILE   put the roots back in cert-manager, for a rotation
#   scripts/openbao-offline-roots.sh unrestore      delete the restored roots again
#
# Run it yourself, in your own terminal: it asks for the passphrase and never prints a key. FILE is OpenPGP
# symmetric encryption (AES-256, an iterated and salted SHA-512 passphrase key, integrity-protected), so any
# gpg (Gpg4win on Windows) opens it; the passphrase is not cached. Losing both FILE and the passphrase means a
# new root, which every client has to trust again.
set -euo pipefail
KUBECTL="${KUBECTL:-kubectl}"
NS=cert-manager
# The two roots: the platform root (networking/cluster-ca-root.yaml) and the guest AWS-endpoints root
# (aws-shim/guest-aws-endpoints-ca.yaml), each by its Secret's name.
ROOTS="${ROOTS:-openinfra-root-ca-2 openinfra-aws-endpoints-ca-1}"
FORMAT=openinfra-offline-roots/1
RESTORED_LABEL=openinfra.dev/offline-root-restored

die() { echo "$*" >&2; exit 1; }
command -v gpg >/dev/null || die "gpg is needed (apt install gnupg)"
command -v python3 >/dev/null || die "python3 is needed"

GNUPGHOME="$(mktemp -d)"; export GNUPGHOME
cleanup() { gpgconf --homedir "$GNUPGHOME" --kill gpg-agent >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"; unset PASS PASS2; }
trap cleanup EXIT

ask_pass() {   # $1 = new: ask twice
  [ -t 0 ] || die "run this in a terminal: it asks for the passphrase"
  read -rsp "passphrase for the offline roots: " PASS; echo
  if [ "${1:-}" = new ]; then
    [ "${#PASS}" -ge 16 ] || die "use a passphrase of at least 16 characters"
    read -rsp "the same passphrase again: " PASS2; echo
    [ "$PASS" = "$PASS2" ] || die "the passphrases differ"
  fi
}

gpg_enc() {    # stdin -> $1
  gpg --batch --yes --quiet --no-symkey-cache --pinentry-mode loopback --passphrase-fd 3 \
    --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712 \
    --output "$1" 3< <(printf '%s' "$PASS")
}
gpg_dec() {    # $1 -> stdout
  gpg --batch --quiet --no-symkey-cache --pinentry-mode loopback --passphrase-fd 3 \
    --decrypt "$1" 3< <(printf '%s' "$PASS") || die "cannot decrypt $1 (wrong passphrase, or not this file)"
}

# Reads the bundle on stdin; prints each root's subject, expiry and SHA-256 fingerprint (public data), checks
# each key matches its certificate and, with "live", that the cluster's Secret is the same. Never prints a key.
inspect() {
  python3 -I - "$FORMAT" "$NS" "$1" "$KUBECTL" 3<&0 <<'PY'
import base64, json, os, subprocess, sys
fmt, ns, mode, kubectl = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].split()
try:
    bundle = json.load(os.fdopen(3))
except ValueError:
    sys.exit(1)   # gpg has said why
if bundle.get("format") != fmt:
    sys.exit("not an open-infra offline-roots file")
def run(args, data=b""):
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout
ok = True
for s in bundle["secrets"]:
    crt = base64.b64decode(s["data"]["tls.crt"]); key = base64.b64decode(s["data"]["tls.key"])
    pub_c = run(["openssl", "x509", "-noout", "-pubkey"], crt)
    pub_k = run(["openssl", "pkey", "-pubout"], key)
    info = run(["openssl", "x509", "-noout", "-subject", "-enddate", "-fingerprint", "-sha256"], crt).decode().split("\n")
    line = "  %s: %s" % (s["name"], "; ".join(x.strip() for x in info if x.strip()))
    if pub_c != pub_k:
        ok = False; line += "  KEY DOES NOT MATCH ITS CERTIFICATE"
    if mode == "live":
        r = subprocess.run(kubectl + ["-n", ns, "get", "secret", s["name"], "-o", "json"], capture_output=True)
        if r.returncode != 0:
            ok = False; line += "  NOT IN THE CLUSTER"
        elif json.loads(r.stdout).get("data") != s["data"]:
            ok = False; line += "  DIFFERS FROM THE CLUSTER'S"
        else:
            line += "  (same as the cluster's)"
    print(line)
sys.exit(0 if ok else 1)
PY
}

ready() { [ "$($KUBECTL get clusterissuer "$1" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ]; }

case "${1:-}" in
  export)
    FILE="${2:?usage: $0 export FILE}"
    [ ! -e "$FILE" ] || die "$FILE exists: choose a new file"
    for i in openinfra-ca openinfra-aws-endpoints; do
      [ -n "$($KUBECTL get clusterissuer "$i" -o jsonpath='{.spec.vault.path}')" ] \
        || die "ClusterIssuer $i does not sign through OpenBao yet: the roots are still in use"
      ready "$i" || die "ClusterIssuer $i is not Ready: fix it before the roots leave"
    done
    for s in $ROOTS; do $KUBECTL -n "$NS" get secret "$s" >/dev/null || die "no secret $NS/$s"; done
    ask_pass new
    umask 077
    # shellcheck disable=SC2086
    python3 -I - "$FORMAT" "$NS" "$KUBECTL" $ROOTS <<'PY' | gpg_enc "$FILE"
import datetime, json, subprocess, sys
fmt, ns, kubectl, names = sys.argv[1], sys.argv[2], sys.argv[3].split(), sys.argv[4:]
out = {"format": fmt, "created": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "secrets": []}
for n in names:
    s = json.loads(subprocess.run(kubectl + ["-n", ns, "get", "secret", n, "-o", "json"], capture_output=True, check=True).stdout)
    out["secrets"].append({"name": n, "type": s["type"], "labels": s["metadata"].get("labels", {}),
                           "annotations": s["metadata"].get("annotations", {}), "data": s["data"]})
json.dump(out, sys.stdout)
PY
    echo "wrote $FILE; checking it opens with your passphrase and matches the cluster:"
    gpg_dec "$FILE" | inspect live || die "the file does not check out: nothing was deleted"
    echo
    echo "The roots are in $FILE. Next, this deletes from the cluster: the two root keys ($ROOTS), the ACM-style"
    echo "CA's Secret and its Certificate (its key is in OpenBao, openinfra/pki-acm). Afterwards, signing a new"
    echo "intermediate needs this file and its passphrase (restore)."
    read -rp "type yes to delete them now: " yes
    [ "$yes" = yes ] || { echo "nothing deleted; run it again with a new FILE when ready"; exit 0; }
    $KUBECTL -n "$NS" delete certificate openinfra-acm-ca --ignore-not-found
    $KUBECTL -n "$NS" delete secret -l openinfra.dev/acm-ca=true --ignore-not-found
    # shellcheck disable=SC2086
    $KUBECTL -n "$NS" delete secret $ROOTS
    echo
    echo "Done: the root keys are off the cluster. Now:"
    echo "  1. copy $FILE to two places off the cluster (a USB drive you keep, and your PC), and keep the"
    echo "     passphrase in a password manager, not with the file;"
    echo "  2. delete this copy: shred -u $FILE"
    ;;
  check)
    FILE="${2:?usage: $0 check FILE}"
    ask_pass
    gpg_dec "$FILE" | inspect offline
    ;;
  restore)
    FILE="${2:?usage: $0 restore FILE}"
    ask_pass
    gpg_dec "$FILE" | python3 -I - "$FORMAT" "$NS" "$RESTORED_LABEL" "$KUBECTL" 3<&0 <<'PY'
import json, os, subprocess, sys
fmt, ns, label, kubectl = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].split()
try:
    b = json.load(os.fdopen(3))
except ValueError:
    sys.exit(1)   # gpg has said why
if b.get("format") != fmt:
    sys.exit("not an open-infra offline-roots file")
for s in b["secrets"]:
    labels = dict(s.get("labels") or {}); labels[label] = "true"
    obj = {"apiVersion": "v1", "kind": "Secret", "type": s["type"], "data": s["data"],
           "metadata": {"name": s["name"], "namespace": ns, "labels": labels}}
    r = subprocess.run(kubectl + ["create", "-f", "-"], input=json.dumps(obj).encode(), capture_output=True)
    if r.returncode != 0:
        sys.exit("could not restore secret %s/%s: %s" % (ns, s["name"], r.stderr.decode().strip()))
    print("restored secret %s/%s" % (ns, s["name"]))
PY
    echo "Rotate now (scripts/openbao-pki.sh prepare, then rotate platform openinfra-root-ca-2 or"
    echo "rotate aws-endpoints openinfra-aws-endpoints-ca-1), then: $0 unrestore"
    ;;
  unrestore)
    $KUBECTL -n "$NS" delete secret -l "$RESTORED_LABEL=true"
    ;;
  *) echo "usage: $0 export FILE | check FILE | restore FILE | unrestore" >&2; exit 2 ;;
esac
