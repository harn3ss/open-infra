#!/usr/bin/env bash
# A one-time OpenBao root token, for configuration that needs one (docs/openbao.md, "A root token, once").
#
#   scripts/openbao-root-access.sh mint     two recovery keys, typed at hidden prompts, make a root token that
#                                          goes straight into Secret openbao/openbao-bootstrap; it is never shown
#   scripts/openbao-root-access.sh revoke   revoke that token with itself, show a call made with it is refused,
#                                          and delete the Secret
#
# `mint` reaches the active member's loopback recovery listener (security/openbao.yaml), the only listener
# that takes recovery keys, through kubectl port-forward. `revoke` runs in a throwaway pod that reads the token from the Secret, so the
# token is never on this machine. Run `mint` in your own terminal.
set -euo pipefail
KUBECTL="${KUBECTL:-kubectl}"
NS=openbao
IMG="quay.io/openbao/openbao:2.7.2@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f"

active() { $KUBECTL -n "$NS" get pods -l openbao-active=true -o jsonpath='{.items[0].metadata.name}'; }

mint() {
  if $KUBECTL -n "$NS" get secret openbao-bootstrap >/dev/null 2>&1; then
    echo "secret $NS/openbao-bootstrap exists already: revoke that token first ($0 revoke)" >&2; exit 1
  fi
  addr="${MINT_ADDR:-}"   # MINT_ADDR: tests only (a local server's recovery listener)
  if [ -z "$addr" ]; then
    A="$(active)"; [ -n "$A" ] || { echo "no active OpenBao member" >&2; exit 1; }
    # port-forward enters the member's own network namespace, where the recovery listener is.
    $KUBECTL -n "$NS" port-forward "pod/$A" 18202:8202 >/dev/null 2>&1 & pf=$!
    trap 'kill $pf 2>/dev/null' EXIT
    sleep 3
    addr=http://127.0.0.1:18202
  fi
  KUBECTL="$KUBECTL" NS="$NS" python3 -I - "$addr" <<'PY_MINT'
import base64, getpass, json, os, subprocess, sys, urllib.error, urllib.request
addr = sys.argv[1]
def call(method, path, body=None):
    req = urllib.request.Request(addr + "/v1/" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}
keys_file = os.environ.get("BAO_KEYS_FILE")   # tests only
lines = open(keys_file).read().split("\n") if keys_file else None
call("DELETE", "sys/generate-root/attempt")
att = call("PUT", "sys/generate-root/attempt", {})
print("OpenBao needs %d of its recovery keys." % att["required"])
res, i = {}, 0
while not res.get("complete"):
    i += 1
    if lines is not None:
        if not lines:
            sys.exit("no more keys")
        k = lines.pop(0)
    else:
        k = getpass.getpass("recovery key %d (hidden): " % i)
    k = "".join(k.split())
    if not k:
        continue
    try:
        res = call("PUT", "sys/generate-root/update", {"key": k, "nonce": att["nonce"]})
    except urllib.error.HTTPError as e:
        print("  not accepted: %s" % "; ".join(json.loads(e.read() or b"{}").get("errors", [])) or e.code)
        continue
    finally:
        k = None
    if not res.get("complete"):
        print("  accepted (%d of %d)" % (res.get("progress", 0), att["required"]))
enc = res.get("encoded_token") or res.get("encoded_root_token")
enc += "=" * (-len(enc) % 4)
enc = base64.urlsafe_b64decode(enc) if ("-" in enc or "_" in enc) else base64.b64decode(enc)
token = bytes(a ^ b for a, b in zip(enc, att["otp"].encode()))
kubectl = os.environ["KUBECTL"].split()
subprocess.run(kubectl + ["-n", os.environ["NS"], "create", "secret", "generic", "openbao-bootstrap",
                          "--from-file=token=/dev/stdin"], input=token, check=True, capture_output=True)
token = None
print("a root token is in secret %s/openbao-bootstrap (not shown)." % os.environ["NS"])
PY_MINT
  echo "Revoke it once its work is done: $0 revoke"
}

revoke() {
  $KUBECTL -n "$NS" get secret openbao-bootstrap >/dev/null 2>&1 || { echo "no secret $NS/openbao-bootstrap: nothing to revoke"; exit 0; }
  ov="$(jq -cn --arg img "$IMG" '{spec:{restartPolicy:"Never",
    securityContext:{runAsNonRoot:true,runAsUser:100,runAsGroup:1000,seccompProfile:{type:"RuntimeDefault"}},
    volumes:[{name:"ca",configMap:{name:"openbao-ca"}}],
    containers:[{name:"revoke",image:$img,command:["sh","-c",
      "bao token revoke -self >/dev/null && if bao token lookup >/dev/null 2>&1; then echo FAIL: the token still answers; exit 1; else echo the root token is revoked: a call made with it is refused; fi"],
      env:[{name:"HOME",value:"/tmp"},{name:"BAO_ADDR",value:"https://openbao-active.openbao.svc:8200"},{name:"BAO_CACERT",value:"/ca/ca.crt"},
           {name:"BAO_TOKEN",valueFrom:{secretKeyRef:{name:"openbao-bootstrap",key:"token"}}}],
      volumeMounts:[{name:"ca",mountPath:"/ca"}],
      securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:["ALL"]}},
      resources:{requests:{cpu:"10m",memory:"32Mi"},limits:{cpu:"200m",memory:"128Mi"}}}]},
    metadata:{labels:{"openinfra.dev/openbao-client":"true"}}}')"
  $KUBECTL -n "$NS" run openbao-root-revoke --rm -i --restart=Never --image="$IMG" --overrides="$ov" 2>/dev/null | grep -E 'revoked|FAIL'
  $KUBECTL -n "$NS" delete secret openbao-bootstrap >/dev/null && echo "secret $NS/openbao-bootstrap deleted"
}

case "${1:-}" in
  mint) mint ;;
  revoke) revoke ;;
  *) echo "usage: $0 mint|revoke" >&2; exit 2 ;;
esac
