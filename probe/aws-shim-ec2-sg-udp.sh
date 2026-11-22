#!/usr/bin/env bash
# Probe: a security group whose rule names the group itself lets its members reach each other over UDP, on
# the rule's port only, and nobody else, as on AWS.
#
# Through the real AWS CLI, in one CloudFormation stack in a throwaway member account:
#   - group Game, with a standalone AWS::EC2::SecurityGroupIngress that names Game as its own source
#     (SourceSecurityGroupId: !Ref Game), UDP 27015; group Other, with no inbound rules;
#   - Server (in Game) listens on UDP 27015 and 27016 and writes what it receives to its serial console;
#     Member (in Game) and Outsider (in Other) send it datagrams on both ports (their UserData, given the
#     server's address by Fn::GetAtt Server.PrivateIp);
#   1. DescribeSecurityGroups reports Game's rule as EC2 does: udp 27015-27015 from the group itself;
#   2. Server's console (GetConsoleOutput) shows Member's datagrams on 27015, and none on 27016 (no rule names
#      that port), and none from Outsider, whose console shows it sent them;
#   3. DENIAL: a user of the member account with no policy is refused GetConsoleOutput
#      (UnauthorizedOperation).
# Everything the probe made is removed on exit: the stack, the user, the member account and its home
# namespace (only when this run created it), and the administrator and its key.
#
# Needs: aws (v2), kubectl (a cluster operator), curl, python3; a deployed shim with the Organizations, STS,
# IAM, CloudFormation and EC2 front doors; room for three t3.micro instances. Exit 0 = pass, 1 = fail,
# 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-ec2-sg-udp.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NAME="sgudp-$SFX"
TMP="$(mktemp -d)"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
die()  { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl curl python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get crd accounts.organizations.openinfra.dev >/dev/null 2>&1 || inconclusive "the Account kind is not installed"

OWNER="sgudp-admin-$SFX"; AK=""; SK=""; KS=""; NEW_ACCOUNT=""; NEW_HOME=""
CLEAN=() # commands run on exit, in reverse
cleanup() {
  local i
  for ((i=${#CLEAN[@]}-1; i>=0; i--)); do eval "${CLEAN[$i]}" >/dev/null 2>&1 || true; done
  [ -n "$NEW_ACCOUNT" ] && kubectl delete accounts.organizations.openinfra.dev "$NEW_ACCOUNT" --ignore-not-found --wait=false >/dev/null 2>&1
  if [ -n "$NEW_HOME" ]; then
    created="$(kubectl get ns "$NEW_HOME" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)"
    if [ -n "$created" ] && [[ "$created" > "$START" || "$created" == "$START" ]]; then
      kubectl delete ns "$NEW_HOME" --ignore-not-found --wait=false >/dev/null 2>&1
    fi
  fi
  [ -n "$KS" ] && kubectl -n "$SHIM_NS" delete secret "$KS" --ignore-not-found >/dev/null 2>&1
  kubectl -n "$USERS_NS" delete users.iam.openinfra.dev "$OWNER" --ignore-not-found >/dev/null 2>&1
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

stack_settles() {
  local st=""
  for _ in $(seq 1 $(($2 / 10))); do
    st="$(B cloudformation describe-stacks --stack-name "$1" --query 'Stacks[0].StackStatus' --output text 2>/dev/null)"
    case "$st" in *_IN_PROGRESS|"") sleep 10 ;; *) break ;; esac
  done
  printf '%s' "$st"
}
output() { B cloudformation describe-stacks --stack-name "$NAME" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue | [0]" --output text; }
console() { B ec2 get-console-output --instance-id "$1" --latest --query Output --output text 2>/dev/null | tr -d '\r' | grep "UDP-PROBE" || true; }

# --- the management account's administrator and a member account ------------------------------------------
AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
KS="iam-ak-$(printf '%s' "$AK" | sha256sum | cut -c1-40)"
printf 'apiVersion: iam.openinfra.dev/v1\nkind: User\nmetadata: { name: "%s", namespace: "%s" }\nspec: { displayName: "%s", groups: ["admins"], source: local }\n' \
  "$OWNER" "$USERS_NS" "$OWNER" | kubectl apply -f - >/dev/null || inconclusive "could not create the administrator"
kubectl -n "$SHIM_NS" create secret generic "$KS" --from-literal=accessKeyId="$AK" --from-literal=secretKey="$SK" \
  --from-literal=owner="$OWNER" >/dev/null || inconclusive "could not create the administrator's key"
M() { AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
for _ in $(seq 1 20); do M sts get-caller-identity >/dev/null 2>&1 && break; sleep 3; done
sleep "$SETTLE"
M sts get-caller-identity >/dev/null 2>&1 || inconclusive "the administrator's key does not authenticate"

log "a throwaway member account"
car="$(M organizations create-account --email "$NAME@example.com" --account-name "$NAME" --query 'CreateAccountStatus.Id' --output text 2>"$TMP/err")" \
  || inconclusive "create-account: $(tr '\n' ' ' < "$TMP/err")"
for _ in $(seq 1 60); do
  read -r state acct < <(M organizations describe-create-account-status --create-account-request-id "$car" \
    --query 'CreateAccountStatus.[State,AccountId]' --output text 2>/dev/null)
  [ "$state" = SUCCEEDED ] && NEW_ACCOUNT="$acct" && break
  [ "$state" = FAILED ] && inconclusive "create-account FAILED"
  sleep 5
done
[ -n "$NEW_ACCOUNT" ] || inconclusive "the member account was not created"
NEW_HOME="$(kubectl get accounts.organizations.openinfra.dev "$NEW_ACCOUNT" -o jsonpath='{.spec.namespaces[0]}' 2>/dev/null)"
for _ in $(seq 1 60); do
  [ "$(kubectl -n "$NEW_HOME" get roles.iam.openinfra.dev organizationaccountaccessrole \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ] && break
  sleep 5
done
sleep "$SETTLE"
M sts assume-role --role-arn "arn:aws:iam::$NEW_ACCOUNT:role/OrganizationAccountAccessRole" \
  --role-session-name sgudp --output json > "$TMP/session.json" 2>"$TMP/err" \
  || die "assume-role into the member account: $(tr '\n' ' ' < "$TMP/err")"
read -r MAK MSK MST < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$TMP/session.json")
B() { AWS_ACCESS_KEY_ID="$MAK" AWS_SECRET_ACCESS_KEY="$MSK" AWS_SESSION_TOKEN="$MST" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
[ "$(B sts get-caller-identity --query Account --output text 2>/dev/null)" = "$NEW_ACCOUNT" ] || die "the assumed session is not the member account's"
AMI="$(B ec2 describe-images --owners amazon --filters Name=name,Values=ubuntu-24.04 --query 'Images[0].ImageId' --output text 2>/dev/null)"
case "$AMI" in ami-*) ;; *) inconclusive "no ubuntu-24.04 image is listed (got '$AMI')" ;; esac
ok "acting in member account $NEW_ACCOUNT, image $AMI"

# --- the stack: two groups, a listener, a member and an outsider ------------------------------------------
cat > "$TMP/stack.yaml" <<'EOF'
Resources:
  Game:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: "members reach each other on UDP 27015" }
  GameSelf:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: { GroupId: !Ref Game, SourceSecurityGroupId: !Ref Game, IpProtocol: udp, FromPort: 27015, ToPort: 27015 }
  Other:
    Type: AWS::EC2::SecurityGroup
    Properties: { GroupDescription: "not a member" }
  Server:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: __AMI__
      InstanceType: t3.micro
      SecurityGroupIds: [!Ref Game]
      UserData:
        Fn::Base64: |
          #!/bin/bash
          cat > /usr/local/bin/udp-listen.py <<'PY'
          import select, socket
          socks = []
          for port in (27015, 27016):
              s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
              s.bind(("0.0.0.0", port))
              socks.append(s)
          out = open("/dev/ttyS0", "w")
          out.write("UDP-PROBE listening on 27015 and 27016\n"); out.flush()
          while True:
              ready, _, _ = select.select(socks, [], [])
              for s in ready:
                  data, addr = s.recvfrom(512)
                  out.write("UDP-PROBE port %d got %s from %s\n" % (s.getsockname()[1], data.decode(errors="replace"), addr[0])); out.flush()
          PY
          setsid python3 /usr/local/bin/udp-listen.py >/dev/null 2>&1 < /dev/null &
  Member:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: __AMI__
      InstanceType: t3.micro
      SecurityGroupIds: [!Ref Game]
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          cat > /usr/local/bin/udp-send.py <<'PY'
          import socket, sys, time
          dst, tag = sys.argv[1], sys.argv[2]
          out = open("/dev/ttyS0", "w")
          s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          for i in range(240):
              for port in (27015, 27016):
                  s.sendto(("%s-%d" % (tag, port)).encode(), (dst, port))
              if i % 12 == 0:
                  out.write("UDP-PROBE sent %s round %d\n" % (tag, i)); out.flush()
              time.sleep(5)
          PY
          setsid python3 /usr/local/bin/udp-send.py ${Server.PrivateIp} member-__SFX__ >/dev/null 2>&1 < /dev/null &
  Outsider:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: __AMI__
      InstanceType: t3.micro
      SecurityGroupIds: [!Ref Other]
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          cat > /usr/local/bin/udp-send.py <<'PY'
          import socket, sys, time
          dst, tag = sys.argv[1], sys.argv[2]
          out = open("/dev/ttyS0", "w")
          s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          for i in range(240):
              for port in (27015, 27016):
                  s.sendto(("%s-%d" % (tag, port)).encode(), (dst, port))
              if i % 12 == 0:
                  out.write("UDP-PROBE sent %s round %d\n" % (tag, i)); out.flush()
              time.sleep(5)
          PY
          setsid python3 /usr/local/bin/udp-send.py ${Server.PrivateIp} outsider-__SFX__ >/dev/null 2>&1 < /dev/null &
Outputs:
  Game: { Value: !Ref Game }
  Server: { Value: !Ref Server }
  Member: { Value: !Ref Member }
  Outsider: { Value: !Ref Outsider }
  ServerIp: { Value: !GetAtt Server.PrivateIp }
EOF
sed -i "s/__AMI__/$AMI/g; s/__SFX__/$SFX/g" "$TMP/stack.yaml"

log "a stack: group Game (UDP 27015 from itself), group Other, and Server, Member and Outsider"
B cloudformation create-stack --stack-name "$NAME" --template-body "file://$TMP/stack.yaml" >/dev/null 2>"$TMP/err" \
  || die "create-stack: $(tr '\n' ' ' < "$TMP/err")"
CLEAN+=("B cloudformation delete-stack --stack-name $NAME")
st="$(stack_settles "$NAME" 1500)"
[ "$st" = CREATE_COMPLETE ] || die "the stack is $st: $(B cloudformation describe-stack-events --stack-name "$NAME" \
  --query "StackEvents[?ends_with(ResourceStatus, 'FAILED')].[LogicalResourceId,ResourceStatusReason] | [0]" --output text 2>&1 | head -c 400)"
GAME="$(output Game)"; SERVER="$(output Server)"; MEMBER="$(output Member)"; OUTSIDER="$(output Outsider)"; SIP="$(output ServerIp)"
ok "CREATE_COMPLETE: Server $SERVER ($SIP), Member $MEMBER, Outsider $OUTSIDER"

# --- 1. the group's rule, as EC2 reports it ----------------------------------------------------------------
log "1. DescribeSecurityGroups reports Game's rule: udp 27015 from Game itself"
B ec2 describe-security-groups --group-ids "$GAME" --output json > "$TMP/sg.json" 2>"$TMP/err" || die "describe-security-groups: $(cat "$TMP/err")"
python3 - "$TMP/sg.json" "$GAME" <<'PY' || die "Game's inbound rules are not udp 27015 from itself: $(head -c 600 "$TMP/sg.json")"
import json, sys
g = json.load(open(sys.argv[1]))["SecurityGroups"][0]
rules = [p for p in g["IpPermissions"] if p.get("IpProtocol") == "udp" and p.get("FromPort") == 27015 and p.get("ToPort") == 27015
         and any(pair.get("GroupId") == sys.argv[2] for pair in p.get("UserIdGroupPairs", []))]
assert rules and len(g["IpPermissions"]) == 1, g["IpPermissions"]
PY
ok "udp 27015-27015 from $GAME"

# --- 2. what the server received --------------------------------------------------------------------------
log "2. Server receives Member's datagrams on 27015 only, and none of Outsider's"
seen=""
for _ in $(seq 1 90); do
  console "$SERVER" > "$TMP/server"
  grep -q "got member-$SFX-27015 " "$TMP/server" && { seen=1; break; }
  sleep 10
done
[ -n "$seen" ] || die "Server never received Member's datagrams on 27015 (UDP between two members of a group whose rule names itself): $(tail -5 "$TMP/server" | tr '\n' ';')"
console "$OUTSIDER" > "$TMP/outsider"
for _ in $(seq 1 30); do grep -q "sent outsider-$SFX" "$TMP/outsider" && break; sleep 10; console "$OUTSIDER" > "$TMP/outsider"; done
grep -q "sent outsider-$SFX" "$TMP/outsider" || inconclusive "Outsider's console never shows it sending, so its silence at Server proves nothing"
sleep 30 # Outsider and Member keep sending on both ports: anything let through would have arrived by now
console "$SERVER" > "$TMP/server"
member="$(grep -c "got member-$SFX-27015 " "$TMP/server")"
if grep -q "got outsider-$SFX" "$TMP/server"; then die "Server received Outsider's datagrams: $(grep "outsider-$SFX" "$TMP/server" | head -2 | tr '\n' ';')"; fi
if grep -q "got member-$SFX-27016" "$TMP/server"; then die "Server received Member's datagrams on 27016, which no rule allows"; fi
ok "Server got $member datagram(s) from Member on 27015; none on 27016; none from Outsider, which sent $(grep -c "sent outsider-$SFX" "$TMP/outsider") round(s)"

# --- 3. DENIAL: a user with no policy may not read an instance's console ---------------------------------
log "3. a user of the member account with no policy is refused GetConsoleOutput"
B iam create-user --user-name "$NAME-nopol" >/dev/null 2>"$TMP/err" || die "create-user: $(cat "$TMP/err")"
CLEAN+=("B iam delete-user --user-name $NAME-nopol")
B iam create-access-key --user-name "$NAME-nopol" --output json >"$TMP/key.json" 2>"$TMP/err" || die "create-access-key: $(cat "$TMP/err")"
read -r NAK NSK < <(python3 -c 'import json,sys; k=json.load(open(sys.argv[1]))["AccessKey"]; print(k["AccessKeyId"], k["SecretAccessKey"])' "$TMP/key.json")
CLEAN+=("B iam delete-access-key --user-name $NAME-nopol --access-key-id $NAK")
sleep "$SETTLE"
if AWS_ACCESS_KEY_ID="$NAK" AWS_SECRET_ACCESS_KEY="$NSK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" \
  ec2 get-console-output --instance-id "$SERVER" >/dev/null 2>"$TMP/deny"; then
  die "a user with no policy read an instance's console"
fi
grep -q UnauthorizedOperation "$TMP/deny" || die "the refusal is not UnauthorizedOperation: $(tail -c 300 "$TMP/deny")"
ok "GetConsoleOutput by a user with no policy: UnauthorizedOperation"

B cloudformation delete-stack --stack-name "$NAME" >/dev/null 2>&1
for _ in $(seq 1 90); do B cloudformation describe-stacks --stack-name "$NAME" >/dev/null 2>&1 || break; sleep 5; done
printf '✓ PASS — two members of a security group whose rule names the group itself exchanged UDP on the rule'"'"'s port (27015), not on another (27016); an instance outside the group was not let through; EC2 reported the rule as udp 27015 from the group itself; a user with no policy was refused GetConsoleOutput.\n'
