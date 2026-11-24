#!/usr/bin/env bash
# Probe: a network load balancer brings LAN clients to an instance that has no route out, and only the clients
# its security group admits; the instance answers them and starts nothing itself.
#
# Through the real AWS CLI:
#   1. the management account's administrator creates a throwaway member account (Organizations
#      CreateAccount) and assumes its OrganizationAccountAccessRole; the operator gives the account a default
#      VPC without its internet gateway and a public subnet for load balancers (kind: Account
#      spec.defaultVpc);
#   2. EC2 lists an internet gateway attached to the VPC, the public subnet, its route table sending 0.0.0.0/0
#      to the gateway, and the default subnet's main route table with no such route;
#   3. a stack's instance in the default subnet runs a UDP service on 27015 and a TCP service on 27016, its
#      security group admitting client A alone on both; it keeps trying to start TCP connections to client A and to the internet, and to send
#      client A datagrams of its own, printing each outcome to its serial console (GetConsoleOutput);
#   4. an internet-facing load balancer in the default subnet (no route to the gateway) is refused
#      (InvalidSubnet); one in the public subnet with a UDP 27015 listener and a TCP 27016 listener (TCP and
#      UDP on one load balancer) forwards each to a target group of the instance, becomes active with an
#      address, and reports the targets healthy;
#   5. client A, a LAN host outside the cluster, gets each service's reply through the load balancer, over UDP
#      and over TCP, and the instance saw client A's own address on both; client B, which the group does not
#      admit, gets nothing on either;
#   6. the instance's own connections reach neither client A nor the internet (each times out), and none of
#      its own datagrams reaches client A;
#   7. DENIAL: a user of the member account with no policy is refused DescribeLoadBalancers (AccessDenied).
# Everything the probe made is removed on exit: the load balancer, its listeners and target groups, the stack,
# the user, the member account and its home namespace (only when this run created it), and the
# administrator and its key.
#
# The LAN clients: LAN_CLIENT_A and LAN_CLIENT_B are command prefixes that run a command on two LAN hosts
# outside the cluster, each with python3 (e.g. "sudo -n ip netns exec lanclient-a" for a client made with
# probe/lan-client-netns.sh, or "ssh user@host"). Their addresses are read from them.
#
# Needs: aws (v2), kubectl (a cluster operator), curl, python3; a deployed shim with the Organizations, STS,
# IAM, CloudFormation, EC2 and Elastic Load Balancing front doors. Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   LAN_CLIENT_A=... LAN_CLIENT_B=... SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-elbv2-nlb.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
PUBLIC_CIDR="${PUBLIC_SUBNET_CIDR:-172.31.240.0/24}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NAME="nlb-$SFX"
TMP="$(mktemp -d)"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
fail()  { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl curl python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
[ -n "${LAN_CLIENT_A:-}" ] && [ -n "${LAN_CLIENT_B:-}" ] || inconclusive "LAN_CLIENT_A and LAN_CLIENT_B (two LAN hosts outside the cluster) are required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get crd accounts.organizations.openinfra.dev >/dev/null 2>&1 || inconclusive "the Account kind is not installed"

# A and B run python on the two LAN clients.
A() { $LAN_CLIENT_A python3 -I -c "$@"; }
Bc() { $LAN_CLIENT_B python3 -I -c "$@"; }
ADDR_PY='import socket; s = socket.socket(2, 2); s.connect(("192.0.2.1", 9)); print(s.getsockname()[0])'
A_ADDR="$(A "$ADDR_PY" 2>/dev/null)"; B_ADDR="$(Bc "$ADDR_PY" 2>/dev/null)"
[[ "$A_ADDR" =~ ^[0-9.]+$ ]] && [[ "$B_ADDR" =~ ^[0-9.]+$ ]] || inconclusive "could not read the LAN clients' addresses (A '$A_ADDR', B '$B_ADDR')"
[ "$A_ADDR" != "$B_ADDR" ] || inconclusive "LAN_CLIENT_A and LAN_CLIENT_B have the same address ($A_ADDR)"

# ASK sends one datagram to host:port and prints the reply (or "timeout"), up to tries times.
ASK_PY='import socket, sys
host, port, msg, tries = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(), int(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
for _ in range(tries):
    s.sendto(msg, (host, port))
    try:
        print(s.recvfrom(2048)[0].decode(errors="replace")); sys.exit(0)
    except socket.timeout:
        pass
print("timeout")'
# TASK connects to host:port over TCP and prints the first line it is sent (or "timeout"/"refused"), up to
# tries times.
TASK_PY='import socket, sys
host, port, tries = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
for _ in range(tries):
    try:
        c = socket.create_connection((host, port), timeout=3); c.settimeout(3)
        print(c.makefile().readline().strip() or "empty"); sys.exit(0)
    except ConnectionRefusedError:
        print("refused"); sys.exit(0)
    except OSError:
        pass
print("timeout")'
# LISTEN prints every datagram (UDP port) and connection (TCP port) that arrives within seconds.
LISTEN_PY='import select, socket, sys, time
up, tp, secs = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", up))
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("0.0.0.0", tp)); t.listen(8)
end = time.time() + secs
while time.time() < end:
    r, _, _ = select.select([u, t], [], [], max(0.1, end - time.time()))
    for s in r:
        if s is u:
            d, a = u.recvfrom(2048); print("udp", a[0], d.decode(errors="replace"), flush=True)
        else:
            c, a = t.accept(); print("tcp", a[0], flush=True); c.close()'

OWNER="nlb-admin-$SFX"; AK=""; SK=""; KS=""; NEW_ACCOUNT=""; NEW_HOME=""
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
console() { B ec2 get-console-output --instance-id "$1" --latest --query Output --output text 2>/dev/null | tr -d '\r' | grep "ELB-PROBE" || true; }

# --- 1. the management account's administrator, a member account, its default VPC --------------------------
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

log "1. a member account whose default VPC has no internet gateway, and a public subnet ($PUBLIC_CIDR)"
log "   LAN clients: A $A_ADDR, B $B_ADDR"
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
kubectl patch accounts.organizations.openinfra.dev "$NEW_ACCOUNT" --type merge \
  -p "{\"spec\":{\"defaultVpc\":{\"internetGateway\":false,\"publicSubnet\":{\"subnetCidr\":\"$PUBLIC_CIDR\"}}}}" >/dev/null \
  || inconclusive "could not set the account's default VPC"
for _ in $(seq 1 60); do
  [ "$(kubectl get subnets.kubeovn.io "default-vpc-$NEW_ACCOUNT" -o jsonpath='{.spec.natOutgoing}' 2>/dev/null)" = false ] && break
  sleep 5
done
[ "$(kubectl get subnets.kubeovn.io "default-vpc-$NEW_ACCOUNT" -o jsonpath='{.spec.natOutgoing}' 2>/dev/null)" = false ] \
  || inconclusive "the account's default subnet still has its route out"
sleep "$SETTLE"
M sts assume-role --role-arn "arn:aws:iam::$NEW_ACCOUNT:role/OrganizationAccountAccessRole" \
  --role-session-name nlb --output json > "$TMP/session.json" 2>"$TMP/err" \
  || fail "assume-role into the member account: $(tr '\n' ' ' < "$TMP/err")"
read -r MAK MSK MST < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$TMP/session.json")
B() { AWS_ACCESS_KEY_ID="$MAK" AWS_SECRET_ACCESS_KEY="$MSK" AWS_SESSION_TOKEN="$MST" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
[ "$(B sts get-caller-identity --query Account --output text 2>/dev/null)" = "$NEW_ACCOUNT" ] || fail "the assumed session is not the member account's"
AMI="$(B ec2 describe-images --owners amazon --filters Name=name,Values=ubuntu-24.04 --query 'Images[0].ImageId' --output text 2>/dev/null)"
case "$AMI" in ami-*) ;; *) inconclusive "no ubuntu-24.04 image is listed (got '$AMI')" ;; esac
ok "acting in member account $NEW_ACCOUNT (home $NEW_HOME), image $AMI"

# --- 2. the VPC as EC2 shows it ---------------------------------------------------------------------------
log "2. EC2: the gateway, the public subnet and its route, the default subnet without one"
VPC="$(B ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text 2>/dev/null)"
[[ "$VPC" == vpc-* ]] || fail "no default VPC (got '$VPC')"
IGW="$(B ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values="$VPC" --query 'InternetGateways[0].InternetGatewayId' --output text 2>/dev/null)"
[[ "$IGW" == igw-* ]] || fail "no internet gateway is attached to the default VPC for its public subnet (got '$IGW')"
PUBLIC="$(B ec2 describe-subnets --filters Name=vpc-id,Values="$VPC" Name=cidr-block,Values="$PUBLIC_CIDR" --query 'Subnets[0].SubnetId' --output text 2>/dev/null)"
PRIVATE="$(B ec2 describe-subnets --filters Name=vpc-id,Values="$VPC" Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text 2>/dev/null)"
[[ "$PUBLIC" == subnet-* ]] && [[ "$PRIVATE" == subnet-* ]] && [ "$PUBLIC" != "$PRIVATE" ] || fail "the public ('$PUBLIC') and default ('$PRIVATE') subnets"
pub_route="$(B ec2 describe-route-tables --filters Name=association.subnet-id,Values="$PUBLIC" \
  --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0'].GatewayId | [0]" --output text 2>/dev/null)"
[ "$pub_route" = "$IGW" ] || fail "the public subnet's route table does not send 0.0.0.0/0 to $IGW (got '$pub_route')"
main_route="$(B ec2 describe-route-tables --filters Name=vpc-id,Values="$VPC" Name=association.main,Values=true \
  --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0'] | length(@)" --output text 2>/dev/null)"
[ "$main_route" = 0 ] || fail "the default subnet's main route table has a route to the internet ($main_route)"
ok "$IGW attached; public subnet $PUBLIC routes 0.0.0.0/0 to it; default subnet $PRIVATE has no such route"

# --- 3. the instance ----------------------------------------------------------------------------------------
log "3. an instance in the default subnet, its group admitting client A alone on UDP 27015 and TCP 27016"
cat > "$TMP/stack.yaml" <<'EOF'
Parameters:
  ClientA: { Type: String }
Resources:
  Game:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: "client A on UDP 27015 and TCP 27016"
      SecurityGroupIngress:
        - { IpProtocol: udp, FromPort: 27015, ToPort: 27015, CidrIp: !Sub "${ClientA}/32" }
        - { IpProtocol: tcp, FromPort: 27016, ToPort: 27016, CidrIp: !Sub "${ClientA}/32" }
  Server:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: __AMI__
      InstanceType: t3.micro
      SecurityGroupIds: [!Ref Game]
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          cat > /usr/local/bin/elb-probe.py <<'PY'
          import socket, sys, threading, time
          lan, tag = sys.argv[1], sys.argv[2]
          out = open("/dev/ttyS0", "w")
          def say(m):
              out.write("ELB-PROBE " + m + "\n"); out.flush()
          def serve():
              s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
              s.bind(("0.0.0.0", 27015))
              say("listening on 27015")
              while True:
                  d, a = s.recvfrom(512)
                  say("got %s from %s" % (d.decode(errors="replace"), a[0]))
                  s.sendto(("%s seen-from %s" % (tag, a[0])).encode(), a)
          def serve_tcp():
              t = socket.socket()
              t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              t.bind(("0.0.0.0", 27016)); t.listen(8)
              say("listening on tcp 27016")
              while True:
                  c, a = t.accept()
                  say("tcp from %s" % a[0])
                  c.sendall(("%s tcp-seen-from %s\n" % (tag, a[0])).encode()); c.close()
          def reach(host, port):
              try:
                  socket.create_connection((host, port), timeout=4).close()
                  return "open"
              except ConnectionRefusedError:
                  return "refused"
              except OSError:
                  return "timeout"
          threading.Thread(target=serve, daemon=True).start()
          threading.Thread(target=serve_tcp, daemon=True).start()
          for i in range(240):
              u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
              try:
                  u.sendto(("%s-own-%d" % (tag, i)).encode(), (lan, 28017))
              except OSError:
                  pass
              u.close()
              say("egress tcp-lan=%s tcp-internet=%s" % (reach(lan, 28016), reach("1.1.1.1", 443)))
              time.sleep(5)
          PY
          setsid python3 /usr/local/bin/elb-probe.py ${ClientA} __TAG__ >/dev/null 2>&1 < /dev/null &
Outputs:
  Server: { Value: !Ref Server }
EOF
sed -i "s/__AMI__/$AMI/g; s/__TAG__/$NAME/g" "$TMP/stack.yaml"
B cloudformation create-stack --stack-name "$NAME" --template-body "file://$TMP/stack.yaml" \
  --parameters ParameterKey=ClientA,ParameterValue="$A_ADDR" >/dev/null 2>"$TMP/err" || fail "create-stack: $(cat "$TMP/err")"
CLEAN+=("B cloudformation delete-stack --stack-name $NAME")
st="$(stack_settles "$NAME" 900)"
[ "$st" = CREATE_COMPLETE ] || fail "the stack is $st"
SERVER="$(B cloudformation describe-stacks --stack-name "$NAME" --query "Stacks[0].Outputs[?OutputKey=='Server'].OutputValue | [0]" --output text)"
[[ "$SERVER" == i-* ]] || fail "no instance id (got '$SERVER')"
ok "CREATE_COMPLETE: $SERVER"

# --- 4. the load balancer -----------------------------------------------------------------------------------
log "4. a network load balancer in the public subnet: UDP 27015 and TCP 27016 listeners to the instance's target groups"
if B elbv2 create-load-balancer --name "$NAME-private" --type network --scheme internet-facing --subnets "$PRIVATE" >/dev/null 2>"$TMP/err"; then
  B elbv2 delete-load-balancer --load-balancer-arn "$(B elbv2 describe-load-balancers --names "$NAME-private" --query 'LoadBalancers[0].LoadBalancerArn' --output text)" >/dev/null 2>&1
  fail "an internet-facing load balancer was placed in a subnet with no route to the internet gateway"
fi
grep -q InvalidSubnet "$TMP/err" || fail "the refusal is not InvalidSubnet: $(tail -c 300 "$TMP/err")"
ok "in the default subnet (no route to the gateway): InvalidSubnet"
TG="$(B elbv2 create-target-group --name "$NAME" --protocol UDP --port 27015 --vpc-id "$VPC" --target-type instance \
  --query 'TargetGroups[0].TargetGroupArn' --output text 2>"$TMP/err")" || fail "create-target-group: $(cat "$TMP/err")"
CLEAN+=("B elbv2 delete-target-group --target-group-arn $TG")
B elbv2 register-targets --target-group-arn "$TG" --targets Id="$SERVER" 2>"$TMP/err" || fail "register-targets: $(cat "$TMP/err")"
TG_TCP="$(B elbv2 create-target-group --name "$NAME-tcp" --protocol TCP --port 27016 --vpc-id "$VPC" --target-type instance \
  --query 'TargetGroups[0].TargetGroupArn' --output text 2>"$TMP/err")" || fail "create-target-group (TCP): $(cat "$TMP/err")"
CLEAN+=("B elbv2 delete-target-group --target-group-arn $TG_TCP")
B elbv2 register-targets --target-group-arn "$TG_TCP" --targets Id="$SERVER" 2>"$TMP/err" || fail "register-targets (TCP): $(cat "$TMP/err")"
LB="$(B elbv2 create-load-balancer --name "$NAME" --type network --scheme internet-facing --subnets "$PUBLIC" \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>"$TMP/err")" || fail "create-load-balancer: $(cat "$TMP/err")"
CLEAN+=("B elbv2 delete-load-balancer --load-balancer-arn $LB")
case "$LB" in "arn:aws:elasticloadbalancing:$REGION:$NEW_ACCOUNT:loadbalancer/net/$NAME/"*) ;; *) fail "a load balancer ARN not in AWS's form: $LB" ;; esac
LST="$(B elbv2 create-listener --load-balancer-arn "$LB" --protocol UDP --port 27015 \
  --default-actions Type=forward,TargetGroupArn="$TG" --query 'Listeners[0].ListenerArn' --output text 2>"$TMP/err")" \
  || fail "create-listener: $(cat "$TMP/err")"
CLEAN+=("B elbv2 delete-listener --listener-arn $LST")
LST_TCP="$(B elbv2 create-listener --load-balancer-arn "$LB" --protocol TCP --port 27016 \
  --default-actions Type=forward,TargetGroupArn="$TG_TCP" --query 'Listeners[0].ListenerArn' --output text 2>"$TMP/err")" \
  || fail "create-listener (TCP): $(cat "$TMP/err")"
CLEAN+=("B elbv2 delete-listener --listener-arn $LST_TCP")
B elbv2 wait load-balancer-available --load-balancer-arns "$LB" 2>"$TMP/err" || fail "the load balancer did not become active: $(cat "$TMP/err")"
VIP="$(B elbv2 describe-load-balancers --load-balancer-arns "$LB" \
  --query 'LoadBalancers[0].AvailabilityZones[0].LoadBalancerAddresses[0].IpAddress' --output text)"
[[ "$VIP" =~ ^[0-9.]+$ ]] || fail "the active load balancer has no address (got '$VIP')"
health=""
for _ in $(seq 1 60); do
  health="$(B elbv2 describe-target-health --target-group-arn "$TG" --query 'TargetHealthDescriptions[0].TargetHealth.State' --output text 2>/dev/null)"
  [ "$health" = healthy ] && break
  sleep 5
done
[ "$health" = healthy ] || fail "the target is $health"
health="$(B elbv2 describe-target-health --target-group-arn "$TG_TCP" --query 'TargetHealthDescriptions[0].TargetHealth.State' --output text 2>/dev/null)"
[ "$health" = healthy ] || fail "the TCP target is $health"
for _ in $(seq 1 60); do console "$SERVER" | grep -q "listening on tcp 27016" && break; sleep 5; done
console "$SERVER" | grep -q "listening on 27015" && console "$SERVER" | grep -q "listening on tcp 27016" \
  || fail "the instance's services did not start: $(console "$SERVER" | tail -3 | tr '\n' ';')"
ok "active at $VIP (UDP 27015, TCP 27016); target $SERVER healthy in both groups, its services listening"

# --- 5. the clients -----------------------------------------------------------------------------------------
log "5. client A gets the reply through the load balancer; client B, outside the group, gets nothing"
reply=""
for _ in $(seq 1 24); do
  reply="$(A "$ASK_PY" "$VIP" 27015 "hello-a-$SFX" 3 2>/dev/null)"
  [ "$reply" != timeout ] && [ -n "$reply" ] && break
  sleep 5
done
[ "$reply" = "$NAME seen-from $A_ADDR" ] || fail "client A's reply through the load balancer: '$reply' (want '$NAME seen-from $A_ADDR')"
ok "client A ($A_ADDR): '$reply' — the instance saw the client's own address"
treply="$(A "$TASK_PY" "$VIP" 27016 8 2>/dev/null)"
[ "$treply" = "$NAME tcp-seen-from $A_ADDR" ] || fail "client A's TCP reply through the load balancer: '$treply' (want '$NAME tcp-seen-from $A_ADDR')"
ok "client A over TCP: '$treply' — the instance saw the client's own address"
b_reply="$(Bc "$ASK_PY" "$VIP" 27015 "hello-b-$SFX" 5 2>/dev/null)"
[ "$b_reply" = timeout ] || fail "client B, which the security group does not admit, got '$b_reply'"
sleep 5
b_treply="$(Bc "$TASK_PY" "$VIP" 27016 2 2>/dev/null)"
[ "$b_treply" = timeout ] || fail "client B, which the security group does not admit, got '$b_treply' over TCP"
sleep 5
if console "$SERVER" | grep -q "from $B_ADDR"; then fail "client B's traffic reached the instance: $(console "$SERVER" | grep "from $B_ADDR" | head -2 | tr '\n' ';')"; fi
ok "client B ($B_ADDR): no reply over UDP or TCP, and nothing reached the instance"

# --- 6. the instance starts nothing ---------------------------------------------------------------------------
log "6. the instance's own connections and datagrams reach neither client A nor the internet"
heard="$(A "$LISTEN_PY" 28017 28016 40 2>&1)"
[ -z "$heard" ] || fail "client A heard from the instance it never asked: $(printf '%s' "$heard" | head -3 | tr '\n' ';')"
lines="$(console "$SERVER" | grep 'egress ')"
[ -n "$lines" ] || fail "the instance printed no egress attempts"
if printf '%s\n' "$lines" | grep -Eq 'tcp-lan=(open|refused)|tcp-internet=(open|refused)'; then
  fail "a connection the instance started got out: $(printf '%s\n' "$lines" | grep -E '=(open|refused)' | head -2 | tr '\n' ';')"
fi
ok "$(printf '%s\n' "$lines" | wc -l) attempts, each timed out ($(printf '%s\n' "$lines" | tail -1 | sed 's/.*ELB-PROBE //')); client A heard nothing in 40s"

# --- 7. DENIAL ----------------------------------------------------------------------------------------------
log "7. a user of the member account with no policy is refused DescribeLoadBalancers"
B iam create-user --user-name "$NAME-nopol" >/dev/null 2>"$TMP/err" || fail "create-user: $(cat "$TMP/err")"
CLEAN+=("B iam delete-user --user-name $NAME-nopol")
B iam create-access-key --user-name "$NAME-nopol" --output json >"$TMP/key.json" 2>"$TMP/err" || fail "create-access-key: $(cat "$TMP/err")"
read -r NAK NSK < <(python3 -c 'import json,sys; k=json.load(open(sys.argv[1]))["AccessKey"]; print(k["AccessKeyId"], k["SecretAccessKey"])' "$TMP/key.json")
CLEAN+=("B iam delete-access-key --user-name $NAME-nopol --access-key-id $NAK")
sleep "$SETTLE"
if AWS_ACCESS_KEY_ID="$NAK" AWS_SECRET_ACCESS_KEY="$NSK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" \
  elbv2 describe-load-balancers >/dev/null 2>"$TMP/deny"; then
  fail "a user with no policy described the load balancers"
fi
grep -q AccessDenied "$TMP/deny" || fail "the refusal is not AccessDenied: $(tail -c 300 "$TMP/deny")"
ok "DescribeLoadBalancers by a user with no policy: AccessDenied"

printf '✓ PASS — a network load balancer at %s brought client A to an instance with no route out over UDP and TCP (the instance saw the client'"'"'s own address and answered it on both); client B, outside its security group, got nothing on either; the instance'"'"'s own connections to the LAN and the internet all timed out and none of its datagrams arrived; a user with no policy was refused DescribeLoadBalancers.\n' "$VIP"
