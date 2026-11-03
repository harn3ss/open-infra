#!/usr/bin/env bash
# Compatibility probe for SSM Run Command on the aws-shim.
#
# Deploys a minimal stack through the CloudFormation front door — one instance whose role attaches
# AmazonSSMManagedInstanceCore — and drives it with the real aws CLI as a deploy script does, asserting:
#   - the instance's agent registers: describe-instance-information lists it Online, by the stack's
#     InstanceId output (the i- id its instance metadata reports)
#   - send-command (AWS-RunShellScript) + `aws ssm wait command-executed` succeed; get-command-invocation
#     returns the output (stdout and stderr apart), ResponseCode 0, and the command ran as root in its
#     workingDirectory; list-command-invocations --details and list-commands report it
#   - a command that exits 3 is Failed with ResponseCode 3 (the waiter fails); one past its executionTimeout
#     is TimedOut
# and the NEGATIVES:
#   - an instance id that is not a managed instance is InvalidInstanceId; another document is InvalidDocument
#   - a principal whose policy denies ssm:SendCommand on the document is refused (AccessDeniedException), and
#     nothing runs
#   - a principal whose policy denies ssm:GetCommandInvocation cannot read the output
#
# On-demand (needs a deployed shim with the CloudFormation front door, IMDS_ENABLED, the SSM Postgres, and
# the platform IAM; the instance boots, so allow ~10 minutes). Exit 0 = pass, 1 = a real failure,
# 42 = INCONCLUSIVE (a prerequisite was missing).
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-ssm-runcommand.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
STACK="ssm-rc-probe-$SFX"
TMP="$(mktemp -d)"
REGISTER_TIMEOUT="${REGISTER_TIMEOUT:-900}"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principals + keys"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=()
WAK=""; WSK=""
cleanup() {
  if [ -n "$WAK" ] && [ "${KEEP:-0}" != 1 ]; then
    as "$WAK" "$WSK" cloudformation delete-stack --stack-name "$STACK" >/dev/null 2>&1 || true
    as "$WAK" "$WSK" cloudformation wait stack-delete-complete --stack-name "$STACK" >/dev/null 2>&1 || true
  fi
  for k in "${CREATED_KEYS[@]:-}";     do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";    do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for pol in "${CREATED_POLICIES[@]:-}"; do [ -n "$pol" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$pol" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }

mint_key() { # <owner> <group>; returns MK_AK MK_SK (runs in THIS shell so CREATED_* reach cleanup)
  local owner="$1" group="$2"
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"
}

as() { # AK SK -- <aws args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text "$@"
}

deny_policy() { # <user> <action> <resource>
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "$1", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::$1"]
    statements:
      - { effect: Allow, actions: ["ssm:*"], resources: ["*"] }
      - { effect: Deny,  actions: ["$2"], resources: ["$3"] }
YAML
  CREATED_POLICIES+=("$1")
}

# --- 1. principals, and the instance ------------------------------------------------------------
log "seeding an admin deployer and two principals with one SSM action denied"
mint_key "ssm-rc-probe-$SFX" "admins"; WAK="$MK_AK"; WSK="$MK_SK"
mint_key "ssm-rc-nosend-$SFX" "admins"; NAK="$MK_AK"; NSK="$MK_SK"
mint_key "ssm-rc-noread-$SFX" "admins"; RAK="$MK_AK"; RSK="$MK_SK"
deny_policy "ssm-rc-nosend-$SFX" "ssm:SendCommand" "Document::AWS-RunShellScript"
deny_policy "ssm-rc-noread-$SFX" "ssm:GetCommandInvocation" "*"

cat > "$TMP/template.yaml" <<'YAML'
AWSTemplateFormatVersion: "2010-09-09"
Description: SSM Run Command probe - one managed instance.
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - { Effect: Allow, Principal: { Service: ec2.amazonaws.com }, Action: sts:AssumeRole }
      ManagedPolicyArns: [arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore]
  Profile:
    Type: AWS::IAM::InstanceProfile
    Properties: { Roles: [!Ref Role] }
  Group:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: no inbound }
  Box:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ubuntu-24.04
      InstanceType: t3.small
      IamInstanceProfile: !Ref Profile
      SecurityGroupIds: [!GetAtt Group.GroupId]
      Tags: [{ Key: Name, Value: ssm-rc-probe }]
Outputs:
  InstanceId: { Value: !Ref Box }
YAML
log "aws cloudformation deploy --stack-name $STACK (one instance; AmazonSSMManagedInstanceCore)"
sleep 35 # the data-plane policies above reach the loader meanwhile
as "$WAK" "$WSK" cloudformation deploy --template-file "$TMP/template.yaml" --stack-name "$STACK" --capabilities CAPABILITY_IAM \
  > "$TMP/deploy.txt" 2>&1 || inconclusive "the stack did not deploy (is the CloudFormation front door on?): $(tail -3 "$TMP/deploy.txt" | tr '\n' ' ')"
IID="$(as "$WAK" "$WSK" cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue")"
[[ "$IID" =~ ^i-[0-9a-f]{17}$ ]] || fail "the InstanceId output is '$IID', want an i- id"

# --- 2. the agent registers -------------------------------------------------------------------------
log "waiting for $IID's agent to register (up to ${REGISTER_TIMEOUT}s)"
deadline=$(( $(date +%s) + REGISTER_TIMEOUT )); PING=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  PING="$(as "$WAK" "$WSK" ssm describe-instance-information --filters "Key=InstanceIds,Values=$IID" --query 'InstanceInformationList[0].PingStatus' 2>/dev/null || true)"
  [ "$PING" = Online ] && break
  sleep 15
done
[ "$PING" = Online ] || inconclusive "the instance's agent did not register in ${REGISTER_TIMEOUT}s (PingStatus '$PING': is IMDS_ENABLED on the shim, and did the VM boot?)"
[ "$(as "$WAK" "$WSK" ssm describe-instance-information --filters "Key=tag:Name,Values=ssm-rc-probe" --query "InstanceInformationList[?InstanceId=='$IID'].PlatformType")" = Linux ] \
  || fail "describe-instance-information by tag does not find $IID"

# --- 3. a command, end to end -------------------------------------------------------------------------
cat > "$TMP/ok.json" <<'JSON'
{"commands": ["id -un", "pwd", "echo to-stderr >&2"], "workingDirectory": ["/tmp"]}
JSON
log "send-command AWS-RunShellScript → wait command-executed → get-command-invocation"
CMD="$(as "$WAK" "$WSK" ssm send-command --document-name AWS-RunShellScript --instance-ids "$IID" --comment "probe $SFX" \
  --parameters "file://$TMP/ok.json" --query Command.CommandId)" || fail "send-command failed"
as "$WAK" "$WSK" ssm wait command-executed --command-id "$CMD" --instance-id "$IID" || fail "wait command-executed did not see $CMD succeed"
OUT="$(as "$WAK" "$WSK" ssm get-command-invocation --command-id "$CMD" --instance-id "$IID" --query StandardOutputContent)"
ERR="$(as "$WAK" "$WSK" ssm get-command-invocation --command-id "$CMD" --instance-id "$IID" --query StandardErrorContent)"
CODE="$(as "$WAK" "$WSK" ssm get-command-invocation --command-id "$CMD" --instance-id "$IID" --query ResponseCode)"
[ "$(printf '%s\n' "$OUT" | sed -n 1p)" = root ] || fail "the command did not run as root: '$OUT'"
[ "$(printf '%s\n' "$OUT" | sed -n 2p)" = /tmp ] || fail "the command did not run in its workingDirectory: '$OUT'"
[ "$ERR" = to-stderr ] || fail "stderr is '$ERR', want to-stderr"
[ "$CODE" = 0 ] || fail "ResponseCode $CODE, want 0"
as "$WAK" "$WSK" ssm list-command-invocations --command-id "$CMD" --details --query 'CommandInvocations[0].CommandPlugins[0].Output' | grep -q root \
  || fail "list-command-invocations --details does not carry the output"
[ "$(as "$WAK" "$WSK" ssm list-commands --command-id "$CMD" --query 'Commands[0].Status')" = Success ] || fail "list-commands does not report Success"
log "  ✓ ran as root in /tmp; stdout and stderr apart; ResponseCode 0; listed"

log "a command that exits 3 is Failed; one past its executionTimeout is TimedOut"
echo '{"commands": ["echo before", "exit 3"]}' > "$TMP/fail.json"
CMDF="$(as "$WAK" "$WSK" ssm send-command --document-name AWS-RunShellScript --instance-ids "$IID" --parameters "file://$TMP/fail.json" --query Command.CommandId)"
if as "$WAK" "$WSK" ssm wait command-executed --command-id "$CMDF" --instance-id "$IID" 2>/dev/null; then fail "the waiter succeeded on a failing command"; fi
[ "$(as "$WAK" "$WSK" ssm get-command-invocation --command-id "$CMDF" --instance-id "$IID" --query '[Status,ResponseCode]' | tr '\t' ' ')" = "Failed 3" ] \
  || fail "a command that exits 3: $(as "$WAK" "$WSK" ssm get-command-invocation --command-id "$CMDF" --instance-id "$IID" --query '[Status,ResponseCode]')"
echo '{"commands": ["sleep 60"], "executionTimeout": ["2"]}' > "$TMP/slow.json"
CMDT="$(as "$WAK" "$WSK" ssm send-command --document-name AWS-RunShellScript --instance-ids "$IID" --parameters "file://$TMP/slow.json" --query Command.CommandId)"
if as "$WAK" "$WSK" ssm wait command-executed --command-id "$CMDT" --instance-id "$IID" 2>/dev/null; then fail "the waiter succeeded on a timed-out command"; fi
[ "$(as "$WAK" "$WSK" ssm get-command-invocation --command-id "$CMDT" --instance-id "$IID" --query Status)" = TimedOut ] || fail "a command past its executionTimeout is not TimedOut"

# --- 4. the refusals ------------------------------------------------------------------------------------
log "the refusals: an unmanaged instance, another document, a denied document, a denied read"
if as "$WAK" "$WSK" ssm send-command --document-name AWS-RunShellScript --instance-ids i-00000000000000000 --parameters "file://$TMP/ok.json" >/dev/null 2>"$TMP/e1"; then fail "send-command to an unmanaged instance succeeded"; fi
grep -q InvalidInstanceId "$TMP/e1" || fail "an unmanaged instance gave $(cat "$TMP/e1")"
if as "$WAK" "$WSK" ssm send-command --document-name AWS-ConfigureDocker --instance-ids "$IID" --parameters "file://$TMP/ok.json" >/dev/null 2>"$TMP/e2"; then fail "another document ran"; fi
grep -q InvalidDocument "$TMP/e2" || fail "another document gave $(cat "$TMP/e2")"
BEFORE="$(as "$WAK" "$WSK" ssm list-commands --instance-id "$IID" --query 'length(Commands)')"
if as "$NAK" "$NSK" ssm send-command --document-name AWS-RunShellScript --instance-ids "$IID" --parameters "file://$TMP/ok.json" >/dev/null 2>"$TMP/e3"; then fail "a principal denied the document sent a command"; fi
grep -q AccessDeniedException "$TMP/e3" || fail "a denied document gave $(cat "$TMP/e3")"
[ "$(as "$WAK" "$WSK" ssm list-commands --instance-id "$IID" --query 'length(Commands)')" = "$BEFORE" ] || fail "a refused send-command still recorded a command"
if as "$RAK" "$RSK" ssm get-command-invocation --command-id "$CMD" --instance-id "$IID" >/dev/null 2>"$TMP/e4"; then fail "a principal denied ssm:GetCommandInvocation read the output"; fi
grep -q AccessDeniedException "$TMP/e4" || fail "a denied read gave $(cat "$TMP/e4")"

log "PASS: SSM Run Command"
