#!/usr/bin/env bash
# Compatibility probe for the aws-shim EC2 front door.
#
# Fires REAL AWS SDK calls (the aws CLI) at a deployed shim and asserts what tooling and deploy scripts
# depend on, over real round-trips:
#   - DescribeRegions / DescribeAvailabilityZones answer the install's one region and zone
#   - DescribeImages lists the OS catalog, each by the ami- id a guest's instance metadata reports
#   - DescribeInstances / DescribeVolumes / DescribeSecurityGroups / DescribeVpcs / DescribeSubnets answer
#     in AWS's shape (the CLI parses them), and every instance id is AWS-shaped (i- and 17 hex digits)
#   - ImportKeyPair (an ed25519 key made here) reports AWS's SHA-256 fingerprint, DescribeKeyPairs finds it
#     by name, a second import is InvalidKeyPair.Duplicate, CreateKeyPair returns a private key once, and
#     DeleteKeyPair removes both (DescribeKeyPairs then InvalidKeyPair.NotFound)
# and the NEGATIVES:
#   - a valid key ID with a WRONG secret is rejected (AuthFailure)
#   - an instance id that does not exist is InvalidInstanceID.NotFound; a name is InvalidInstanceID.Malformed
#   - a principal whose data-plane policy denies ec2:DeleteKeyPair on the key is refused
#     (UnauthorizedOperation) and the key stays
#   - an operation the shim does not serve (RunInstances) and a service it does not front answer
#     NotImplemented in their own error shape — the CLI names the code, never "Unknown"
#
# On-demand (needs a deployed shim with the CloudFormation front door + the SSM Postgres + the platform
# IAM). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE (a prerequisite was missing).
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-ec2.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws        >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl    >/dev/null || inconclusive "kubectl is required to seed the principals + keys"
command -v ssh-keygen >/dev/null || inconclusive "ssh-keygen is required to make the key pair imported"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=(); CREATED_PAIRS=()
WAK=""; WSK=""
cleanup() {
  for p in "${CREATED_PAIRS[@]:-}";    do [ -n "$p" ] && AWS_ACCESS_KEY_ID="$WAK" AWS_SECRET_ACCESS_KEY="$WSK" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager ec2 delete-key-pair --key-name "$p" >/dev/null 2>&1 || true; done
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

# --- 1. principals ---------------------------------------------------------------------------
log "seeding an admin principal and a principal denied ec2:DeleteKeyPair on one key"
mint_key "ec2-probe-$SFX" "admins"; WAK="$MK_AK"; WSK="$MK_SK"
mint_key "ec2-probe-nodel-$SFX" "admins"; DAK="$MK_AK"; DSK="$MK_SK"
KEY="ec2-probe-$SFX"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "ec2-nodel-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::ec2-probe-nodel-$SFX"]
    statements:
      - { effect: Allow, actions: ["ec2:*"], resources: ["*"] }
      - { effect: Deny,  actions: ["ec2:DeleteKeyPair"], resources: ["KeyPair::${KEY}"] }
YAML
CREATED_POLICIES+=("ec2-nodel-$SFX")
log "  waiting ~35s for the data-plane policy loader to pick it up..."
sleep 35

# --- 2. a wrong secret ------------------------------------------------------------------------
log "a wrong secret is refused (AuthFailure)"
if as "$WAK" "wrong-secret" ec2 describe-regions >/dev/null 2>"$TMP/auth"; then fail "a wrong secret was accepted"; fi
grep -q "AuthFailure" "$TMP/auth" || fail "a wrong secret gave the wrong error: $(cat "$TMP/auth")"

# --- 3. region, zone, catalog -----------------------------------------------------------------
log "describe-regions / describe-availability-zones / describe-images"
[ "$(as "$WAK" "$WSK" ec2 describe-regions --query 'Regions[].RegionName')" = "$REGION" ] || fail "describe-regions is not the one region $REGION"
[ "$(as "$WAK" "$WSK" ec2 describe-availability-zones --query 'AvailabilityZones[].ZoneName')" = "${REGION}a" ] || fail "describe-availability-zones is not ${REGION}a"
IMG="$(as "$WAK" "$WSK" ec2 describe-images --filters Name=name,Values=ubuntu-24.04 --query 'Images[0].ImageId')" || fail "describe-images failed"
WANT_IMG="ami-$(printf '%s' "ubuntu-24.04-image" | sha256sum | cut -c1-17)"
[ "$IMG" = "$WANT_IMG" ] || fail "the catalog's ubuntu-24.04 is $IMG, want the guest's ami-id $WANT_IMG"

# --- 4. the account's resources, in AWS's shape -----------------------------------------------
log "describe-instances / volumes / security-groups / vpcs / subnets parse"
IDS="$(as "$WAK" "$WSK" ec2 describe-instances --query 'Reservations[].Instances[].InstanceId')" || fail "describe-instances failed"
for id in $IDS; do
  [[ "$id" =~ ^i-[0-9a-f]{17}$ ]] || fail "instance id $id is not AWS-shaped"
done
for op in describe-volumes describe-security-groups describe-vpcs describe-subnets describe-addresses; do
  as "$WAK" "$WSK" ec2 "$op" >/dev/null || fail "ec2 $op failed"
done
log "  ✓ $(printf '%s\n' $IDS | grep -c . || true) instance(s), all i- ids"
if as "$WAK" "$WSK" ec2 describe-instances --instance-ids i-00000000000000000 >/dev/null 2>"$TMP/nf"; then fail "an unknown instance id was found"; fi
grep -q "InvalidInstanceID.NotFound" "$TMP/nf" || fail "an unknown instance id gave the wrong error: $(cat "$TMP/nf")"
if as "$WAK" "$WSK" ec2 describe-instances --instance-ids not-an-instance >/dev/null 2>"$TMP/mf"; then fail "a name was taken as an instance id"; fi
grep -q "InvalidInstanceID.Malformed" "$TMP/mf" || fail "a malformed id gave the wrong error: $(cat "$TMP/mf")"
# The instance state operations are served (their state changes are unit-tested on a VM): an unknown id is
# InvalidInstanceID.NotFound for each, a malformed one Malformed, and nothing is changed.
for op in stop-instances start-instances reboot-instances terminate-instances; do
  if as "$WAK" "$WSK" ec2 "$op" --instance-ids i-00000000000000000 >/dev/null 2>"$TMP/st"; then fail "ec2 $op of an unknown instance succeeded"; fi
  grep -q "InvalidInstanceID.NotFound" "$TMP/st" || fail "ec2 $op of an unknown instance gave the wrong error: $(cat "$TMP/st")"
done
if as "$WAK" "$WSK" ec2 stop-instances --instance-ids not-an-instance >/dev/null 2>"$TMP/st"; then fail "stop-instances took a name"; fi
grep -q "InvalidInstanceID.Malformed" "$TMP/st" || fail "stop-instances of a malformed id gave the wrong error: $(cat "$TMP/st")"
log "  ✓ stop/start/reboot/terminate-instances are served: an unknown id is InvalidInstanceID.NotFound"

# --- 5. key pairs -----------------------------------------------------------------------------
log "import-key-pair (ed25519) reports AWS's fingerprint; duplicate refused; create-key-pair; delete"
ssh-keygen -q -t ed25519 -N '' -C "probe@example.test" -f "$TMP/id" >/dev/null
FP="$(as "$WAK" "$WSK" ec2 import-key-pair --key-name "$KEY" --public-key-material "fileb://$TMP/id.pub" --query KeyFingerprint)" \
  || inconclusive "import-key-pair failed — is SQS_PG_URI set on the shim?"
CREATED_PAIRS+=("$KEY")
WANT_FP="$(ssh-keygen -l -E sha256 -f "$TMP/id.pub" | awk '{print $2}' | sed 's/^SHA256://')"
[ "${FP%=}" = "$WANT_FP" ] || fail "fingerprint $FP, want the key's SHA-256 $WANT_FP"
[ "$(as "$WAK" "$WSK" ec2 describe-key-pairs --key-names "$KEY" --query 'KeyPairs[0].KeyType')" = "ed25519" ] || fail "describe-key-pairs did not find $KEY"
if as "$WAK" "$WSK" ec2 import-key-pair --key-name "$KEY" --public-key-material "fileb://$TMP/id.pub" >/dev/null 2>"$TMP/dup"; then fail "a duplicate import succeeded"; fi
grep -q "InvalidKeyPair.Duplicate" "$TMP/dup" || fail "a duplicate import gave the wrong error: $(cat "$TMP/dup")"
MADE="ec2-probe-made-$SFX"
as "$WAK" "$WSK" ec2 create-key-pair --key-name "$MADE" --query KeyMaterial > "$TMP/made.pem" || fail "create-key-pair failed"
CREATED_PAIRS+=("$MADE")
grep -q "BEGIN RSA PRIVATE KEY" "$TMP/made.pem" || fail "create-key-pair returned no private key"
chmod 600 "$TMP/made.pem"
ssh-keygen -y -f "$TMP/made.pem" >/dev/null || fail "the private key create-key-pair returned does not parse"

log "a principal denied ec2:DeleteKeyPair on $KEY is refused, and the key stays"
if as "$DAK" "$DSK" ec2 delete-key-pair --key-name "$KEY" >/dev/null 2>"$TMP/deny"; then fail "a denied DeleteKeyPair succeeded"; fi
grep -q "UnauthorizedOperation" "$TMP/deny" || fail "a denied DeleteKeyPair gave the wrong error: $(cat "$TMP/deny")"
as "$WAK" "$WSK" ec2 describe-key-pairs --key-names "$KEY" >/dev/null || fail "the key went despite the refusal"
as "$WAK" "$WSK" ec2 delete-key-pair --key-name "$KEY" >/dev/null || fail "delete-key-pair failed"
as "$WAK" "$WSK" ec2 delete-key-pair --key-name "$MADE" >/dev/null || fail "delete-key-pair failed"
if as "$WAK" "$WSK" ec2 describe-key-pairs --key-names "$KEY" >/dev/null 2>"$TMP/gone"; then fail "a deleted key pair is still described"; fi
grep -q "InvalidKeyPair.NotFound" "$TMP/gone" || fail "a deleted key pair gave the wrong error: $(cat "$TMP/gone")"

# --- 6. what is not served says so in its own shape ---------------------------------------------
log "run-instances and an unfronted service answer NotImplemented, named by the CLI"
if as "$WAK" "$WSK" ec2 run-instances --image-id "$IMG" --count 1 >/dev/null 2>"$TMP/ni"; then fail "run-instances succeeded"; fi
grep -q "(NotImplemented)" "$TMP/ni" || fail "run-instances gave $(cat "$TMP/ni")"
if as "$WAK" "$WSK" elasticache describe-cache-clusters >/dev/null 2>"$TMP/svc"; then fail "an unfronted service answered"; fi
grep -q "(NotImplemented)" "$TMP/svc" || fail "an unfronted service gave $(cat "$TMP/svc") (want NotImplemented, not Unknown)"

log "PASS: the EC2 front door"
