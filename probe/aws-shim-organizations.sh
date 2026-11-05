#!/usr/bin/env bash
# Compatibility probe for the aws-shim Organizations front door: the install's accounts, as AWS
# Organizations answers for them, through the real AWS CLI.
#   - DescribeOrganization names the management account (the install's own account id);
#   - ListAccounts lists it, ACTIVE;
#   - CreateAccount of a throwaway account answers IN_PROGRESS, DescribeCreateAccountStatus reaches
#     SUCCEEDED with the new 12-digit AccountId, and ListAccounts / DescribeAccount then show it ACTIVE
#     with its email;
#   - a second CreateAccount with the same email FAILS with EMAIL_ALREADY_EXISTS, as on AWS;
#   - DescribeCreateAccountStatus of an id that was never issued is CreateAccountStatusNotFoundException;
#   - a principal with no policy is denied DescribeOrganization.
# The throwaway account (its kind: Account and the new namespace CreateAccount made for it) is removed
# on exit; the namespace only when this run created it.
#
# On-demand (needs a deployed shim with the Organizations front door, the Account kind, an admin caller).
# Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-organizations.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TMP="$(mktemp -d)"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws >/dev/null || inconclusive "the aws CLI is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v python3 >/dev/null || inconclusive "python3 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get crd accounts.organizations.openinfra.dev >/dev/null 2>&1 || inconclusive "the Account kind is not installed"
MGMT="$(kubectl -n "$SHIM_NS" get configmap openinfra-aws-identity -o jsonpath='{.data.ACCOUNT_ID}' 2>/dev/null)"
MGMT="${MGMT:-000000000000}"

CREATED_USERS=(); CREATED_KEYS=(); NEW_ACCOUNT=""; NEW_HOME=""
cleanup() {
  if [ -n "$NEW_ACCOUNT" ]; then
    kubectl delete accounts.organizations.openinfra.dev "$NEW_ACCOUNT" --ignore-not-found --wait=false >/dev/null 2>&1
  fi
  if [ -n "$NEW_HOME" ]; then
    # Only a namespace this run created: CreateAccount always makes a new one, and it must be younger
    # than the probe.
    created="$(kubectl get ns "$NEW_HOME" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)"
    if [ -n "$created" ] && [[ "$created" > "$START" || "$created" == "$START" ]]; then
      kubectl delete ns "$NEW_HOME" --ignore-not-found --wait=false >/dev/null 2>&1
    fi
  fi
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
org() { local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json organizations "$@"; }
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

log "seeding an administrator (AdministratorAccess; in the admins group for the legacy check) + a principal with no policy"
mint_key "org-probe-admin-$SFX" '["admins"]' '["aws-administratoraccess"]'; AAK="$MK_AK"; ASK="$MK_SK"
mint_key "org-probe-nobody-$SFX" '[]' '[]'; NAK="$MK_AK"; NSK="$MK_SK"
sleep "${KEY_SETTLE_SECONDS:-12}"

log "describe-organization"
org "$AAK" "$ASK" describe-organization > "$TMP/org.json" 2>"$TMP/err" || {
  grep -q "not implemented\|NotImplemented" "$TMP/err" && inconclusive "the Organizations front door is not on this shim"
  fail "describe-organization: $(tr '\n' ' ' < "$TMP/err")"; }
got="$(jq_ 'd["Organization"]["MasterAccountId"]' < "$TMP/org.json")"
[ "$got" = "$MGMT" ] || fail "the organization's management account is $got, want the install's account $MGMT"
log "  ✓ the organization's management account is $MGMT ($(jq_ 'd["Organization"]["Arn"]' < "$TMP/org.json"))"

log "list-accounts"
org "$AAK" "$ASK" list-accounts > "$TMP/list.json" 2>"$TMP/err" || fail "list-accounts: $(tr '\n' ' ' < "$TMP/err")"
st="$(jq_ '[a["Status"] for a in d["Accounts"] if a["Id"]=="'"$MGMT"'"]' < "$TMP/list.json")"
[ "$st" = "['ACTIVE']" ] || fail "list-accounts shows the management account as $st, want ACTIVE"
log "  ✓ the management account is listed ACTIVE ($(jq_ 'len(d["Accounts"])' < "$TMP/list.json") account(s))"

NAME="org-probe-$SFX"; EMAIL="org-probe-$SFX@example.com"
log "create-account $NAME"
org "$AAK" "$ASK" create-account --email "$EMAIL" --account-name "$NAME" > "$TMP/create.json" 2>"$TMP/err" \
  || fail "create-account: $(tr '\n' ' ' < "$TMP/err")"
CAR="$(jq_ 'd["CreateAccountStatus"]["Id"]' < "$TMP/create.json")"
state="$(jq_ 'd["CreateAccountStatus"]["State"]' < "$TMP/create.json")"
[ "$state" = IN_PROGRESS ] || [ "$state" = SUCCEEDED ] || fail "create-account answered $state, want IN_PROGRESS"
for _ in $(seq 1 60); do
  org "$AAK" "$ASK" describe-create-account-status --create-account-request-id "$CAR" > "$TMP/status.json" 2>"$TMP/err" \
    || fail "describe-create-account-status: $(tr '\n' ' ' < "$TMP/err")"
  state="$(jq_ 'd["CreateAccountStatus"]["State"]' < "$TMP/status.json")"
  NEW_ACCOUNT="$(jq_ 'd["CreateAccountStatus"].get("AccountId","")' < "$TMP/status.json")"
  if [ -n "$NEW_ACCOUNT" ] && [ -z "$NEW_HOME" ]; then
    NEW_HOME="$(kubectl get accounts.organizations.openinfra.dev "$NEW_ACCOUNT" -o jsonpath='{.spec.namespaces[0]}' 2>/dev/null)"
  fi
  [ "$state" = IN_PROGRESS ] || break
  sleep 3
done
[ "$state" = SUCCEEDED ] || fail "the account's creation ended $state: $(jq_ 'd["CreateAccountStatus"].get("FailureReason","")' < "$TMP/status.json")"
[[ "$NEW_ACCOUNT" =~ ^[0-9]{12}$ ]] || fail "SUCCEEDED with AccountId '$NEW_ACCOUNT', want 12 digits"
[ "$NEW_ACCOUNT" != "$MGMT" ] || fail "the new account was given the management account's id"
log "  ✓ $CAR SUCCEEDED: account $NEW_ACCOUNT (home namespace $NEW_HOME)"

org "$AAK" "$ASK" describe-account --account-id "$NEW_ACCOUNT" > "$TMP/acct.json" 2>"$TMP/err" || fail "describe-account: $(tr '\n' ' ' < "$TMP/err")"
[ "$(jq_ 'd["Account"]["Status"]' < "$TMP/acct.json")" = ACTIVE ] || fail "describe-account: not ACTIVE"
[ "$(jq_ 'd["Account"]["Email"]' < "$TMP/acct.json")" = "$EMAIL" ] || fail "describe-account: the email is not the one created"
org "$AAK" "$ASK" list-accounts > "$TMP/list.json" 2>/dev/null
[ "$(jq_ 'len([a for a in d["Accounts"] if a["Id"]=="'"$NEW_ACCOUNT"'"])' < "$TMP/list.json")" = 1 ] || fail "list-accounts does not list the new account"
log "  ✓ describe-account and list-accounts show it ACTIVE with its email"

org "$AAK" "$ASK" create-account --email "$EMAIL" --account-name "$NAME-again" > "$TMP/dup.json" 2>"$TMP/err" \
  || fail "a duplicate-email create-account must answer a FAILED status, not an error: $(tr '\n' ' ' < "$TMP/err")"
[ "$(jq_ 'd["CreateAccountStatus"]["State"]+"/"+d["CreateAccountStatus"].get("FailureReason","")' < "$TMP/dup.json")" = FAILED/EMAIL_ALREADY_EXISTS ] \
  || fail "a duplicate email: want FAILED/EMAIL_ALREADY_EXISTS, got $(cat "$TMP/dup.json")"
log "  ✓ a second account with the same email FAILS with EMAIL_ALREADY_EXISTS"

if org "$AAK" "$ASK" describe-create-account-status --create-account-request-id "car-${MGMT}zzzzzzzz" >/dev/null 2>"$TMP/err"; then
  fail "an unissued create request id was found"
fi
grep -q CreateAccountStatusNotFoundException "$TMP/err" || fail "an unissued request id: want CreateAccountStatusNotFoundException, got $(tr '\n' ' ' < "$TMP/err")"
log "  ✓ an unissued request id is CreateAccountStatusNotFoundException"

if org "$NAK" "$NSK" describe-organization >/dev/null 2>"$TMP/err"; then
  fail "a principal with no policy may describe the organization"
fi
grep -qE 'AccessDenied' "$TMP/err" || fail "a principal with no policy: want AccessDenied, got $(tr '\n' ' ' < "$TMP/err")"
log "  ✓ a principal with no policy is AccessDenied"

log "✓ PASS — the Organizations front door answers as AWS Organizations: the management account, CreateAccount to SUCCEEDED, duplicate-email FAILED, unknown request id, and access denied without a policy"
