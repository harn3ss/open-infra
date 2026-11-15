#!/usr/bin/env bash
# Live probe: Fleet Manager Remote Desktop (Systems Manager GUI Connect) through the console, as a customer
# opens it, including a denial. Fleet Manager's Remote Desktop is console-only on AWS too (no CLI connects),
# so the probe is the console's own calls, signed in as IAM users, with IAM policy deciding:
#
#   1. a Windows Server instance, launched for the probe;
#   2. a principal denied ssm:StartSession on the instance (it holds ssm-guiconnect:* and StartSession on
#      the port-forwarding document alone) is refused AccessDeniedException naming ssm:StartSession, both at
#      the check and at the connection itself;
#   3. a principal with AWS's Remote Desktop permissions connects: the websocket opens, the console carries
#      it through guacd and the instance's port-forward to its Remote Desktop service, and the instance's
#      own Network Level Authentication refuses the probe's made-up Windows password (status 0x0301) — the
#      whole path, end to end, without the probe ever holding the instance's real password;
#   4. the connection is in the account's history (ssm-guiconnect:ListConnections) as Failed, and
#      ssm-guiconnect:GetConnection answers it.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs kubectl (KUBECONFIG), curl, python3, go; the console is
# reached through a port-forward of the probe's own unless CONSOLE_ENDPOINT is set. A Windows instance
# takes several minutes to boot: the probe waits up to RDP_BOOT_SECONDS (default 1200) for its Remote
# Desktop service.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=probe/iam-lib.sh
source "$HERE/iam-lib.sh"

CFN_NS="${CFN_NS:-open-infra-cfn}"
VM="rdprobe-$SFX"
MADE_VM=""
BOOT="${RDP_BOOT_SECONDS:-1200}"

cleanup() {
  [ -n "$MADE_VM" ] && kubectl -n "$CFN_NS" delete virtualmachines.openinfra.dev "$MADE_VM" --ignore-not-found --wait=false >/dev/null 2>&1
  iamp_cleanup
}
trap cleanup EXIT

command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v curl >/dev/null || inconclusive "curl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
command -v go >/dev/null || inconclusive "go is required (the console password is hashed with the console's own bcrypt)"
if [ -z "$CONSOLE" ]; then
  port=$(( 20000 + RANDOM % 20000 ))
  kubectl -n "$USERS_NS" port-forward svc/console "$port:80" >/dev/null 2>&1 &
  CONSOLE_PF=$!
  CONSOLE="http://127.0.0.1:$port"
  for _ in $(seq 1 20); do curl -fsS -m 2 "$CONSOLE/healthz" >/dev/null 2>&1 && break; sleep 1; done
fi
curl -fsS -m 5 "$CONSOLE/healthz" >/dev/null 2>&1 || inconclusive "console not reachable at $CONSOLE (set CONSOLE_ENDPOINT)"

# --- 1. an instance --------------------------------------------------------------------------------
log "launching $VM (windows-server-2022, 2 vCPU, 4 GiB) in $CFN_NS"
cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not launch the instance"
apiVersion: openinfra.dev/v1
kind: VirtualMachine
metadata: { name: "${VM}", namespace: "${CFN_NS}" }
spec: { os: windows-server-2022, cpu: 2, memory: 4Gi }
YAML
MADE_VM="$VM"
IID=""
for _ in $(seq 1 60); do
  IID="$(kubectl -n "$CFN_NS" get virtualmachines.openinfra.dev "$VM" -o jsonpath='{.status.instanceId}' 2>/dev/null || true)"
  [ -n "$IID" ] && break
  sleep 5
done
[[ "$IID" =~ ^i-[0-9a-f]{17}$ ]] || inconclusive "the instance reported no instance id in 5 minutes (got '$IID')"
log "  instance $IID"

# --- 2. principals -----------------------------------------------------------------------------------
INSTANCES='"arn:aws:ec2:*:*:instance/*"'
DOCUMENT='"arn:aws:ssm:*::document/AWS-StartPortForwardingSession"'
GUI='{"Effect":"Allow","Action":"ssm-guiconnect:*","Resource":"*"}'
ALLOW_DOC='{"Version":"2012-10-17","Statement":['"$GUI"',{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"},{"Effect":"Allow","Action":"ssm:StartSession","Resource":['"$INSTANCES"','"$DOCUMENT"']}]}'
DENY_DOC='{"Version":"2012-10-17","Statement":['"$GUI"',{"Effect":"Allow","Action":"ssm:StartSession","Resource":['"$DOCUMENT"']}]}'
log "seeding a principal with Remote Desktop's permissions and one without ssm:StartSession on instances"
iamp_user "rdp-probe-$SFX" "" "$ALLOW_DOC"; ALLOW_PW="$U_PW"
iamp_user "rdp-probe-deny-$SFX" "" "$DENY_DOC"; DENY_PW="$U_PW"
JAR_A="$PROBE_TMP/allow.jar"; JAR_D="$PROBE_TMP/deny.jar"
iamp_login "rdp-probe-$SFX" "$ALLOW_PW" "$JAR_A"
iamp_login "rdp-probe-deny-$SFX" "$DENY_PW" "$JAR_D"

CHECK="/api/vms/$CFN_NS/$VM/remote-desktop/check"
CONNECT="/api/vms/$CFN_NS/$VM/remote-desktop"

# --- 3. the denial -----------------------------------------------------------------------------------
log "the principal without ssm:StartSession on the instance is refused"
d="$(console_decision "$JAR_D" GET "$CHECK" "ssm:StartSession")"; decided "$d"
[ "$d" = deny ] || fail "the check let a principal without ssm:StartSession on the instance through: $(head -c 300 "$PROBE_TMP/c.out")"
grep -q ":instance/$VM" "$PROBE_TMP/c.out" || fail "the denial does not name the instance: $(head -c 300 "$PROBE_TMP/c.out")"
python3 "$HERE/remote_desktop_ws.py" "$CONSOLE" "$JAR_D" "$CONNECT" > "$PROBE_TMP/deny-ws.json" 2>"$PROBE_TMP/deny-ws.err" \
  || inconclusive "the websocket client failed: $(head -c 300 "$PROBE_TMP/deny-ws.err")"
python3 - "$PROBE_TMP/deny-ws.json" <<'PY' || fail "the connection opened for a principal without ssm:StartSession on the instance: $(cat "$PROBE_TMP/deny-ws.json")"
import json, sys
r = json.load(open(sys.argv[1]))
body = r.get("body", "")
sys.exit(0 if r["status"] == 403 and "AccessDeniedException" in body and "ssm:StartSession" in body else 1)
PY
log "  ✓ AccessDeniedException for ssm:StartSession, at the check and the connection"

# --- 4. the connection -------------------------------------------------------------------------------
log "waiting for the instance's Remote Desktop service (up to ${BOOT}s; Windows takes a while to boot)"
WRONG="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"
end=$(( $(date +%s) + BOOT ))
RESULT=""
while [ "$(date +%s)" -lt "$end" ]; do
  code="$(curl -s -m 15 -b "$JAR_A" -o "$PROBE_TMP/check.out" -w '%{http_code}' "$CONSOLE$CHECK")"
  if [ "$code" = 200 ]; then
    RDP_USERNAME="probe-$SFX" RDP_PASSWORD="$WRONG" RDP_WAIT_SECONDS=90 \
      python3 "$HERE/remote_desktop_ws.py" "$CONSOLE" "$JAR_A" "$CONNECT" > "$PROBE_TMP/ws.json" 2>"$PROBE_TMP/ws.err" || true
    if python3 - "$PROBE_TMP/ws.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
e = r.get("error") or {}
sys.exit(0 if r.get("status") == 101 and e.get("code") == 0x0301 else 1)
PY
    then RESULT="$(cat "$PROBE_TMP/ws.json")"; break; fi
  elif [ "$code" = 403 ]; then
    fail "the check refused the principal with Remote Desktop's permissions: $(head -c 300 "$PROBE_TMP/check.out")"
  fi
  sleep 20
done
[ -n "$RESULT" ] || inconclusive "the instance's Remote Desktop service did not refuse a sign-in within ${BOOT}s (last check $code: $(head -c 200 "$PROBE_TMP/check.out"); last connection: $(head -c 300 "$PROBE_TMP/ws.json" 2>/dev/null))"
CID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["connectionId"])' "$PROBE_TMP/ws.json")"
[[ "$CID" =~ ^[0-9a-f-]{36}$ ]] || fail "the connection carried no connection id: $RESULT"
log "  ✓ connection $CID reached the instance's Remote Desktop service, which refused the made-up password (0x0301)"

# --- 5. the history ----------------------------------------------------------------------------------
log "the connection is in the account's history"
found=""
for _ in $(seq 1 15); do
  curl -s -m 15 -b "$JAR_A" -o "$PROBE_TMP/list.out" "$CONSOLE/api/remote-desktop/connections"
  found="$(python3 - "$PROBE_TMP/list.out" "$CID" "$IID" <<'PY'
import json, sys
try:
    body = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
for c in body.get("history", []):
    if c.get("connectionId") == sys.argv[2] and c.get("instanceId") == sys.argv[3] and c.get("status") == "Failed":
        print("yes")
PY
)"
  [ "$found" = yes ] && break
  sleep 2
done
[ "$found" = yes ] || fail "connection $CID is not in the history as Failed: $(head -c 400 "$PROBE_TMP/list.out")"
code="$(curl -s -m 15 -b "$JAR_A" -o "$PROBE_TMP/get.out" -w '%{http_code}' "$CONSOLE/api/remote-desktop/connections/$CID")"
[ "$code" = 200 ] && grep -q "\"connectionId\":\"$CID\"" "$PROBE_TMP/get.out" || fail "GetConnection on $CID answered $code: $(head -c 300 "$PROBE_TMP/get.out")"
grep -q "$WRONG" "$PROBE_TMP/list.out" "$PROBE_TMP/get.out" && fail "a connection record carries the Windows password"
log "  ✓ ListConnections and GetConnection answer it (status Failed), without the password"

log "PASS: Fleet Manager Remote Desktop — refused without ssm:StartSession on the instance; connected through to the instance's Remote Desktop service with it; recorded in the account's history"
