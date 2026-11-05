#!/usr/bin/env bash
# Compatibility probe for the aws-shim Service Quotas front door: an account's quotas, as AWS Service Quotas
# answers for them, through the real AWS CLI (aws service-quotas).
#   - ListServices lists the services whose quotas are reported (Lambda, EC2, S3, DynamoDB, CloudFormation);
#   - GetAWSDefaultServiceQuota answers AWS's default (Lambda's Concurrent executions, 1000) with an
#     account-less QuotaArn; GetServiceQuota answers the account's applied value — its kind: Account's
#     spec.serviceQuotas where an operator set one, else the platform's default — under the caller's account;
#   - ListServiceQuotas lists EC2's quotas under AWS's codes and names; an unknown service is
#     NoSuchResourceException;
#   - RequestServiceQuotaIncrease above the applied value is recorded PENDING, and
#     GetRequestedServiceQuotaChange and both change-history calls show it; a second request for the same
#     quota is ResourceAlreadyExistsException; a value not above the current one is IllegalArgumentException;
#     an unknown request id is NoSuchResourceException;
#   - a principal with no policy is denied ListServices.
# Approval (an operator raising spec.serviceQuotas until the request reads APPROVED) and the enforcement of
# Lambda's concurrency on a member account's namespaces are not driven here: the probe never changes an
# account's quotas. The request it records is removed on exit (only that entry, by its id).
#
# Not yet run live: the service is registered gated. Once this exits 0 against a deployed shim, rename it to
# probe/aws-shim-servicequotas.sh and promote Service Quotas to proven in probe/shim-services.yaml.
#
# On-demand (needs a deployed shim with the Service Quotas front door, an admin caller).
# Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/servicequotas.sh
set -uo pipefail

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

command -v aws >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
MGMT="$(kubectl -n "$SHIM_NS" get configmap openinfra-aws-identity -o jsonpath='{.data.ACCOUNT_ID}' 2>/dev/null)"
MGMT="${MGMT:-000000000000}"

CREATED_USERS=(); CREATED_KEYS=(); REQ_IDS=()
# drop_requests removes this run's request entries (by id) from the shim's record, leaving every other
# entry as it is; a concurrent write conflicts on the resourceVersion and is re-read.
drop_requests() {
  [ "${#REQ_IDS[@]}" -gt 0 ] || return 0
  for _ in 1 2 3 4 5; do
    kubectl -n "$SHIM_NS" get configmap servicequota-requests -o json > "$TMP/cm.json" 2>/dev/null || return 0
    python3 - "$TMP/cm.json" "${REQ_IDS[@]}" > "$TMP/cm-new.json" <<'PY' || return 0
import json, sys
cm, ids = json.load(open(sys.argv[1])), set(sys.argv[2:])
for k, v in list((cm.get("data") or {}).items()):
    cm["data"][k] = json.dumps([r for r in json.loads(v or "[]") if r.get("Id") not in ids], separators=(",", ":"))
for f in ("managedFields", "creationTimestamp", "uid"):
    cm["metadata"].pop(f, None)
print(json.dumps(cm))
PY
    kubectl replace -f "$TMP/cm-new.json" >/dev/null 2>&1 && return 0
    sleep 1
  done
}
cleanup() {
  drop_requests
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete users.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

# mint_key <owner> <groups-json> <policies-json>: sets MK_AK MK_SK (in this shell, so cleanup sees them).
mint_key() {
  local owner="$1" groups="$2" policies="$3"
  MK_AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  MK_SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create User $owner"
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "$owner", namespace: "$USERS_NS" }
spec: { displayName: "$owner", source: local, groups: $groups, policies: $policies }
YAML
  CREATED_USERS+=("$owner")
  local name; name="iam-ak-$(printf '%s' "$MK_AK" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$MK_AK" \
    --from-literal=secretKey="$MK_SK" --from-literal=owner="$owner" >/dev/null || inconclusive "could not create an access key"
  CREATED_KEYS+=("$name")
}
sq() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json service-quotas "$@"; }
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }
errline() { tr '\n' ' ' < "$TMP/err" | cut -c1-300; }

log "seeding an administrator (AdministratorAccess; in the admins group for the legacy check) + a principal with no policy"
mint_key "sq-probe-admin-$SFX" '["admins"]' '["aws-administratoraccess"]'; AAK="$MK_AK"; ASK="$MK_SK"
mint_key "sq-probe-nobody-$SFX" '[]' '[]'; NAK="$MK_AK"; NSK="$MK_SK"
sleep "${KEY_SETTLE_SECONDS:-12}"

log "list-services"
sq "$AAK" "$ASK" list-services > "$TMP/svcs.json" 2>"$TMP/err" || {
  grep -q "not implemented\|NotImplemented" "$TMP/err" && inconclusive "the Service Quotas front door is not on this shim"
  fail "list-services: $(errline)"; }
got="$(jq_ 'sorted(s["ServiceCode"] for s in d["Services"] if s.get("ServiceName"))' < "$TMP/svcs.json")"
[ "$got" = "['cloudformation', 'dynamodb', 'ec2', 'lambda', 's3']" ] || fail "list-services: want cloudformation, dynamodb, ec2, lambda and s3, each named; got $got"
log "  ✓ $got"

log "get-aws-default-service-quota lambda L-B99A9384"
sq "$AAK" "$ASK" get-aws-default-service-quota --service-code lambda --quota-code L-B99A9384 > "$TMP/def.json" 2>"$TMP/err" \
  || fail "get-aws-default-service-quota: $(errline)"
got="$(jq_ '"%s|%g|%s" % (d["Quota"]["QuotaName"], d["Quota"]["Value"], d["Quota"]["QuotaArn"])' < "$TMP/def.json")"
[ "$got" = "Concurrent executions|1000|arn:aws:servicequotas:${REGION}::lambda/L-B99A9384" ] \
  || fail "AWS's default for Lambda's concurrent executions: want Concurrent executions, 1000, an account-less ARN; got $got"
log "  ✓ AWS's default: Concurrent executions = 1000"

# The applied value: the management account's kind: Account where an operator set one, else the default.
want="$(kubectl get accounts.organizations.openinfra.dev "$MGMT" -o json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
v = [q["value"] for q in (d.get("spec") or {}).get("serviceQuotas") or [] if (q.get("serviceCode"), q.get("quotaCode")) == ("lambda", "L-B99A9384")]
print("%g" % (v[0] if v else 1000))')"
log "get-service-quota lambda L-B99A9384 (want $want)"
sq "$AAK" "$ASK" get-service-quota --service-code lambda --quota-code L-B99A9384 > "$TMP/applied.json" 2>"$TMP/err" \
  || fail "get-service-quota: $(errline)"
got="$(jq_ '"%g|%s" % (d["Quota"]["Value"], d["Quota"]["QuotaArn"])' < "$TMP/applied.json")"
[ "$got" = "$want|arn:aws:servicequotas:${REGION}:${MGMT}:lambda/L-B99A9384" ] \
  || fail "the account's applied Lambda concurrency: want $want under account $MGMT; got $got"
log "  ✓ the account's applied value is $want under account $MGMT"

log "list-service-quotas ec2"
sq "$AAK" "$ASK" list-service-quotas --service-code ec2 > "$TMP/ec2.json" 2>"$TMP/err" || fail "list-service-quotas: $(errline)"
got="$(jq_ 'sorted(q["QuotaCode"]+"="+q["QuotaName"] for q in d["Quotas"])' < "$TMP/ec2.json")"
[ "$got" = "['L-0263D0A3=EC2-VPC Elastic IPs', 'L-1216C47A=Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances']" ] \
  || fail "EC2's quotas: want AWS's codes and names; got $got"
log "  ✓ EC2's quotas carry AWS's codes and names"
if sq "$AAK" "$ASK" list-service-quotas --service-code no-such-service >/dev/null 2>"$TMP/err"; then
  fail "list-service-quotas of an unknown service answered"
fi
grep -q NoSuchResourceException "$TMP/err" || fail "an unknown service: want NoSuchResourceException, got $(errline)"
log "  ✓ an unknown service is NoSuchResourceException"

SVC=ec2; CODE=L-0263D0A3
sq "$AAK" "$ASK" list-requested-service-quota-change-history-by-quota --service-code "$SVC" --quota-code "$CODE" --status PENDING \
  > "$TMP/pending.json" 2>"$TMP/err" || fail "list-requested-service-quota-change-history-by-quota: $(errline)"
pending="$(jq_ '",".join(r["Id"] for r in d["RequestedQuotas"])' < "$TMP/pending.json")"
[ -z "$pending" ] || inconclusive "a request for $SVC $CODE is already pending ($pending), so a new one would be refused; this probe leaves it alone"

sq "$AAK" "$ASK" get-service-quota --service-code "$SVC" --quota-code "$CODE" > "$TMP/cur.json" 2>"$TMP/err" || fail "get-service-quota $SVC $CODE: $(errline)"
cur="$(jq_ '"%g" % d["Quota"]["Value"]' < "$TMP/cur.json")"
desired="$(python3 -c 'import sys; print("%g" % (float(sys.argv[1]) + 1))' "$cur")"
log "request-service-quota-increase $SVC $CODE $cur → $desired"
sq "$AAK" "$ASK" request-service-quota-increase --service-code "$SVC" --quota-code "$CODE" --desired-value "$desired" \
  > "$TMP/req.json" 2>"$TMP/err" || fail "request-service-quota-increase: $(errline)"
RID="$(jq_ 'd["RequestedQuota"]["Id"]' < "$TMP/req.json")"
[ -n "$RID" ] && REQ_IDS+=("$RID")
got="$(jq_ '"%s|%g" % (d["RequestedQuota"]["Status"], d["RequestedQuota"]["DesiredValue"])' < "$TMP/req.json")"
[ "$got" = "PENDING|$desired" ] || fail "the request: want PENDING for $desired; got $got"
log "  ✓ request $RID is PENDING"

sq "$AAK" "$ASK" get-requested-service-quota-change --request-id "$RID" > "$TMP/getreq.json" 2>"$TMP/err" \
  || fail "get-requested-service-quota-change: $(errline)"
got="$(jq_ '"%s|%s|%s" % (d["RequestedQuota"]["Status"], d["RequestedQuota"]["QuotaName"], d["RequestedQuota"]["QuotaArn"])' < "$TMP/getreq.json")"
[ "$got" = "PENDING|EC2-VPC Elastic IPs|arn:aws:servicequotas:${REGION}:${MGMT}:${SVC}/${CODE}" ] \
  || fail "get-requested-service-quota-change: got $got"
sq "$AAK" "$ASK" list-requested-service-quota-change-history > "$TMP/hist.json" 2>"$TMP/err" \
  || fail "list-requested-service-quota-change-history: $(errline)"
[ "$(jq_ 'len([r for r in d["RequestedQuotas"] if r["Id"]=="'"$RID"'"])' < "$TMP/hist.json")" = 1 ] \
  || fail "the change history does not list request $RID"
sq "$AAK" "$ASK" list-requested-service-quota-change-history-by-quota --service-code "$SVC" --quota-code "$CODE" \
  > "$TMP/histq.json" 2>"$TMP/err" || fail "list-requested-service-quota-change-history-by-quota: $(errline)"
[ "$(jq_ 'len([r for r in d["RequestedQuotas"] if r["Id"]=="'"$RID"'"])' < "$TMP/histq.json")" = 1 ] \
  || fail "the quota's change history does not list request $RID"
log "  ✓ the request reads back, and both change-history calls list it"

if sq "$AAK" "$ASK" request-service-quota-increase --service-code "$SVC" --quota-code "$CODE" --desired-value "$desired" \
  > "$TMP/dup.json" 2>"$TMP/err"; then
  d2="$(jq_ 'd["RequestedQuota"]["Id"]' < "$TMP/dup.json")"; [ -n "$d2" ] && REQ_IDS+=("$d2")
  fail "a second request for a quota with one pending was recorded"
fi
grep -q ResourceAlreadyExistsException "$TMP/err" || fail "a second pending request: want ResourceAlreadyExistsException, got $(errline)"
log "  ✓ a second request while one is pending is ResourceAlreadyExistsException"

if sq "$AAK" "$ASK" request-service-quota-increase --service-code "$SVC" --quota-code "$CODE" --desired-value "$cur" \
  > "$TMP/low.json" 2>"$TMP/err"; then
  d3="$(jq_ 'd["RequestedQuota"]["Id"]' < "$TMP/low.json")"; [ -n "$d3" ] && REQ_IDS+=("$d3")
  fail "a request for the current value was recorded"
fi
grep -q IllegalArgumentException "$TMP/err" || fail "a request not above the current value: want IllegalArgumentException, got $(errline)"
log "  ✓ a request not above the current value is IllegalArgumentException"

if sq "$AAK" "$ASK" get-requested-service-quota-change --request-id "nosuch$SFX" >/dev/null 2>"$TMP/err"; then
  fail "an unknown request id was found"
fi
grep -q NoSuchResourceException "$TMP/err" || fail "an unknown request id: want NoSuchResourceException, got $(errline)"
log "  ✓ an unknown request id is NoSuchResourceException"

if sq "$NAK" "$NSK" list-services >/dev/null 2>"$TMP/err"; then
  fail "a principal with no policy may list the services"
fi
grep -qE 'AccessDenied' "$TMP/err" || fail "a principal with no policy: want AccessDenied, got $(errline)"
log "  ✓ a principal with no policy is AccessDenied"

log "✓ PASS — the Service Quotas front door answers as AWS Service Quotas: services, AWS's defaults and the account's applied values, a request PENDING and in its history, the duplicate and too-low refusals, unknown ids, and access denied without a policy"
