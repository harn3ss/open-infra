#!/usr/bin/env bash
# Live probe: a Windows instance's metadata is served outside the instance, as on EC2, so the Windows Firewall
# rule AWS documents for keeping a local user from the metadata service works.
#
# As the management account's administrator, through the AWS CLI:
#   - a CloudFormation stack launches a Windows instance with an IAM role and its instance profile; the
#     instance's UserData, as LocalSystem, reads its instance id and the role's credentials over IMDSv2;
#   - a local user the UserData makes reaches the metadata service; after the outbound rule AWS documents
#     (New-NetFirewallRule -Direction Outbound -Action Block -Protocol TCP -RemoteAddress 169.254.169.254
#     -RemotePort 80 -LocalUser <the user's SDDL>) it is refused, while LocalSystem still gets credentials;
#   - the results are read through GetConsoleOutput: the launch agent reports the metadata service answering
#     from outside the instance, and the UserData's lines follow;
#   - a principal with no policy is refused GetConsoleOutput with EC2's access-denied error.
# Everything it makes is deleted: the stack (its instance, role and profile) and the probe's principals.
#
# Exit 0 pass, 1 fail, 42 inconclusive. Needs the aws CLI, kubectl (KUBECONFIG) and curl; reaches the shim at
# SHIM_ENDPOINT (e.g. a port-forward of svc/aws-shim 4566).
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
CONSOLE_WAIT="${CONSOLE_WAIT_SECONDS:-1200}" # a Windows instance's first boot, then its UserData
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for c in aws kubectl curl; do command -v "$c" >/dev/null || inconclusive "$c is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"

ADMIN="winmd-admin-$SFX"; NOPOL="winmd-nopol-$SFX"; STACK="winmd-probe-$SFX"
CREATED_KEYS=(); CREATED_USERS=(); MADE=""

as() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"; }
cleanup() {
  if [ -n "$MADE" ]; then
    as "$AAK" "$ASK" cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1
    as "$AAK" "$ASK" cloudformation wait stack-delete-complete --stack-name "$STACK" >/dev/null 2>&1
  fi
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# mint_key <owner> [group]: a kind: User (in group, or in none) and an access key the shim authenticates;
# sets MK_AK MK_SK.
mint_key() {
  local owner="$1" group="${2:-}" ak sk name groups="[]"
  [ -n "$group" ] && groups="[\"${group}\"]"
  ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create User $owner"
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ${groups}, source: local }
YAML
  CREATED_USERS+=("$owner")
  name="iam-ak-$(printf '%s' "$ak" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" \
    --from-literal=owner="$owner" >/dev/null || inconclusive "could not create the access key"
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"
}

# await_control_plane <user>: once IAM policy decides, the administrator acts on the cluster as its account
# identity, whose rights the IAM compiler compiles after the principal is made: wait until they arrive.
await_control_plane() {
  local acct ok
  acct="$(kubectl -n "$SHIM_NS" get configmap openinfra-aws-identity -o jsonpath='{.data.ACCOUNT_ID}' 2>/dev/null)"
  for _ in $(seq 1 60); do
    ok="$(kubectl create -o jsonpath='{.status.allowed}' -f - 2>/dev/null <<SAR
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: "openinfra:${acct:-000000000000}:$1"
  resourceAttributes: { verb: create, group: openinfra.dev, resource: virtualmachines, namespace: open-infra-cfn }
SAR
)"
    [ "$ok" = true ] && return 0
    sleep 5
  done
  inconclusive "the control plane never allowed ${1}"
}

log "seeding an administrator and a principal with no policy"
mint_key "$ADMIN" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
mint_key "$NOPOL"; NAK="$MK_AK"; NSK="$MK_SK"
await_control_plane "$ADMIN"

# The UserData, as LocalSystem: its instance id and the role's credentials; a local user before and after
# AWS's documented outbound rule; each result a "PROBE" line on the serial console.
cat > "$TMP/ud.txt" <<'PS'
<powershell>
function Con([string]$s) { try { $p = New-Object System.IO.Ports.SerialPort 'COM1',115200,'None',8,'One'; $p.Open(); $p.WriteLine('PROBE ' + $s); $p.Close() } catch { } }
function SystemCheck([string]$tag) {
  try {
    $t = Invoke-RestMethod -Method Put -Uri http://169.254.169.254/latest/api/token -Headers @{ 'X-aws-ec2-metadata-token-ttl-seconds' = '60' } -TimeoutSec 5
    $h = @{ 'X-aws-ec2-metadata-token' = $t }
    $iid = Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/instance-id -Headers $h -TimeoutSec 5
    $role = ([string](Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/iam/security-credentials/ -Headers $h -TimeoutSec 5)).Trim()
    $c = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role" -Headers $h -TimeoutSec 5
    Con ("$tag system: instance $iid key " + $c.AccessKeyId.Substring(0, 4))
  } catch { Con "$tag system: error $($_.Exception.Message)" }
}
SystemCheck 'before'
$u = 'imdsprobe'; $pw = 'Aa1!' + [guid]::NewGuid().ToString('N')
New-LocalUser $u -Password (ConvertTo-SecureString $pw -AsPlainText -Force) | Out-Null
Add-LocalGroupMember -Group Administrators -Member $u
$sid = (Get-LocalUser $u).SID.Value
New-Item -ItemType Directory -Force C:\imdsprobe | Out-Null
Set-Content C:\imdsprobe\probe.ps1 -Value @'
param([string]$Out)
try { Invoke-RestMethod -Method Put -Uri http://169.254.169.254/latest/api/token -Headers @{ 'X-aws-ec2-metadata-token-ttl-seconds' = '60' } -TimeoutSec 5 | Out-Null; Set-Content $Out 'reached' }
catch { Set-Content $Out 'refused' }
'@
function AsUser([string]$tag) {
  $out = "C:\imdsprobe\$tag.txt"
  $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\imdsprobe\probe.ps1 -Out $out"
  Register-ScheduledTask -TaskName "imdsprobe-$tag" -Action $a -User $u -Password $pw -RunLevel Limited -Force | Out-Null
  Start-ScheduledTask -TaskName "imdsprobe-$tag"
  for ($i = 0; $i -lt 60 -and -not (Test-Path $out); $i++) { Start-Sleep -Seconds 1 }
  Unregister-ScheduledTask -TaskName "imdsprobe-$tag" -Confirm:$false
  if (Test-Path $out) { Con ("$tag user: " + (Get-Content $out -Raw).Trim()) } else { Con "$tag user: no result" }
}
AsUser 'before-rule'
New-NetFirewallRule -DisplayName "Block metadata service for $u" -Action Block -Direction Outbound -Protocol TCP -RemoteAddress 169.254.169.254 -RemotePort 80 -LocalUser "D:(A;;CC;;;$sid)" | Out-Null
AsUser 'after-rule'
SystemCheck 'after-rule'
Con 'done'
</powershell>
PS
UD="$(base64 -w0 < "$TMP/ud.txt")"

WIN="$(as "$AAK" "$ASK" ec2 describe-images --owners amazon --filters Name=name,Values=windows-server-2022 --query 'Images[0].ImageId' 2>/dev/null)"
case "$WIN" in ami-*) ;; *) inconclusive "no windows-server-2022 catalog image (got ${WIN})" ;; esac
printf '{"Resources":{"Role":{"Type":"AWS::IAM::Role","Properties":{"AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}}},"Profile":{"Type":"AWS::IAM::InstanceProfile","Properties":{"Roles":[{"Ref":"Role"}]}},"Box":{"Type":"AWS::EC2::Instance","Properties":{"ImageId":"%s","InstanceType":"t3.medium","IamInstanceProfile":{"Ref":"Profile"},"UserData":"%s"}}},"Outputs":{"InstanceId":{"Value":{"Ref":"Box"}}}}' \
  "$WIN" "$UD" > "$TMP/stack.json"

# --- 1. a Windows instance with a role -----------------------------------------------------------------------
log "launching a Windows instance (${WIN}) with an instance profile"
as "$AAK" "$ASK" cloudformation create-stack --stack-name "$STACK" --template-body "file://$TMP/stack.json" --capabilities CAPABILITY_IAM \
  >/dev/null 2>"$TMP/cs" || fail "create-stack: $(head -c 300 "$TMP/cs")"
MADE=1
as "$AAK" "$ASK" cloudformation wait stack-create-complete --stack-name "$STACK" 2>/dev/null \
  || fail "the stack did not complete: $(as "$AAK" "$ASK" cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].[StackStatus,StackStatusReason]' 2>&1 | tr '\t\n' '  ')"
IID="$(as "$AAK" "$ASK" cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue | [0]")"
log "  ✓ ${IID} is running"

# --- 2. a principal with no policy may not read its console --------------------------------------------------
if as "$NAK" "$NSK" ec2 get-console-output --instance-id "$IID" >/dev/null 2>"$TMP/deny"; then
  fail "get-console-output was allowed for a principal with no policy"
fi
grep -qE 'UnauthorizedOperation|AccessDenied' "$TMP/deny" || fail "get-console-output failed without EC2's access-denied error: $(head -c 300 "$TMP/deny")"
log "  ✓ a principal with no policy is refused GetConsoleOutput (UnauthorizedOperation)"

# --- 3. the console: metadata from outside the instance, and the firewall rule working -----------------------
log "reading the instance's console until its UserData is done (up to ${CONSOLE_WAIT}s)"
deadline=$((SECONDS + CONSOLE_WAIT))
while :; do
  as "$AAK" "$ASK" ec2 get-console-output --instance-id "$IID" --latest --query Output > "$TMP/console" 2>/dev/null
  grep -q 'PROBE done' "$TMP/console" && break
  [ "$SECONDS" -lt "$deadline" ] || fail "the UserData did not finish within ${CONSOLE_WAIT}s; console tail: $(tail -5 "$TMP/console" | tr '\r\n' '  ')"
  sleep 15
done
want() { grep -q -- "$1" "$TMP/console" || fail "$2; console: $(grep -E 'PROBE|metadata' "$TMP/console" | tr '\r\n' '  ' | head -c 900)"; }
want 'Instance metadata is answering at http://169.254.169.254/ (served outside the instance)' "the launch agent did not report metadata served outside the instance"
want "PROBE before system: instance ${IID} key ASIA" "LocalSystem did not get its instance id and the role's credentials over IMDSv2"
want 'PROBE before-rule user: reached' "a local user did not reach the metadata service before the firewall rule"
want 'PROBE after-rule user: refused' "AWS's documented firewall rule did not keep the local user from the metadata service"
want "PROBE after-rule system: instance ${IID} key ASIA" "LocalSystem lost the metadata service under the rule for one local user"
log "  ✓ metadata is served outside the instance: LocalSystem gets the role's credentials over IMDSv2"
log "  ✓ a local user reaches it until the documented -LocalUser outbound rule, then is refused; LocalSystem still is not"

printf '✓ PASS — a Windows instance'"'"'s metadata is served outside it, so the Windows Firewall rule AWS documents for a local user applies, and a principal with no policy is refused its console.\n'
