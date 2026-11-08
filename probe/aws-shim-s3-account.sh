#!/usr/bin/env bash
# Probe: a member account's administrator makes, writes, reads and deletes buckets in its own account, and
# deploys a Lambda function from one of them (Code S3Bucket/S3Key), as on AWS (#414). A bucket is decided in
# the account that made it: another account's principals and a principal of the account whose policy does
# not allow S3 are refused.
#
# Through the real AWS CLI:
#   1. the management account's administrator creates a throwaway member account (Organizations
#      CreateAccount) and assumes its OrganizationAccountAccessRole (AdministratorAccess);
#   2. in the member account: CreateBucket, PutObject of a deployment package, HeadObject and GetObject of it
#      (byte for byte), ListBuckets lists the bucket;
#   3. CreateFunction with --code S3Bucket=<bucket>,S3Key=<key>, and an Invoke returns the handler's result;
#   4. DENIAL: the management account's administrator is refused GetObject on the member account's bucket
#      (AccessDenied: no bucket policy lets it in) and does not list the bucket; a user of the member account
#      whose only policy allows lambda:InvokeFunction is refused GetObject, PutObject and CreateBucket
#      (AccessDenied);
#   5. DeleteObject and DeleteBucket by the member account's administrator.
# Everything the probe made is removed on exit: the function, the user, the role, the bucket, the member
# account and its home namespace (only when this run created it), and the administrator's key.
#
# Needs: aws (v2), kubectl (a cluster operator), curl, python3; a deployed shim with the Organizations,
# STS, IAM, S3 and Lambda front doors. Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-s3-account.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NAME="s3acct-$SFX"
TMP="$(mktemp -d)"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log()  { printf '▸ %s\n' "$*"; }
ok()   { printf '▸   ✓ %s\n' "$*"; }
die()  { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

for t in aws kubectl curl python3; do command -v "$t" >/dev/null || inconclusive "$t is required"; done
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT}"
kubectl get crd accounts.organizations.openinfra.dev >/dev/null 2>&1 || inconclusive "the Account kind is not installed"

OWNER="s3acct-admin-$SFX"; AK=""; SK=""; KS=""; NEW_ACCOUNT=""; NEW_HOME=""
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

# --- 1. the management account's administrator, and a member account ---------------------------------
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

log "1. a member account, and its OrganizationAccountAccessRole"
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
  --role-session-name s3acct --output json > "$TMP/session.json" 2>"$TMP/err" \
  || die "assume-role into the member account: $(tr '\n' ' ' < "$TMP/err")"
read -r MAK MSK MST < <(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["Credentials"]; print(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])' "$TMP/session.json")
B() { AWS_ACCESS_KEY_ID="$MAK" AWS_SECRET_ACCESS_KEY="$MSK" AWS_SESSION_TOKEN="$MST" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
[ "$(B sts get-caller-identity --query Account --output text 2>/dev/null)" = "$NEW_ACCOUNT" ] || die "the assumed session is not the member account's"
ok "acting in member account $NEW_ACCOUNT (home $NEW_HOME)"

log "2. a bucket in the member account, written and read by its administrator"
BUCKET="$NAME-pkg"
cat >"$TMP/index.py" <<'PY'
import os
def handler(event, context):
    return {"function": os.environ.get("AWS_LAMBDA_FUNCTION_NAME"), "echo": event}
PY
(cd "$TMP" && python3 -c "import zipfile;z=zipfile.ZipFile('fn.zip','w');z.write('index.py');z.close()")
B s3api create-bucket --bucket "$BUCKET" >/dev/null 2>"$TMP/err" || die "the member account's administrator could not CreateBucket: $(tr '\n' ' ' < "$TMP/err")"
CLEAN+=("B s3api delete-object --bucket $BUCKET --key pkg/fn.zip; B s3api delete-bucket --bucket $BUCKET")
B s3api put-object --bucket "$BUCKET" --key pkg/fn.zip --body "$TMP/fn.zip" >/dev/null 2>"$TMP/err" || die "PutObject: $(tr '\n' ' ' < "$TMP/err")"
B s3api head-object --bucket "$BUCKET" --key pkg/fn.zip >/dev/null 2>"$TMP/err" || die "HeadObject: $(tr '\n' ' ' < "$TMP/err")"
B s3api get-object --bucket "$BUCKET" --key pkg/fn.zip "$TMP/back.zip" >/dev/null 2>"$TMP/err" || die "GetObject: $(tr '\n' ' ' < "$TMP/err")"
cmp -s "$TMP/fn.zip" "$TMP/back.zip" || die "GetObject did not return the object PutObject wrote"
B s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' | grep -qx "$BUCKET" || die "ListBuckets does not list $BUCKET"
ok "CreateBucket, PutObject, HeadObject, GetObject (byte for byte) and ListBuckets in member account $NEW_ACCOUNT"

log "3. a function deployed from the bucket"
B iam create-role --role-name "$NAME-exec" --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
  >/dev/null 2>"$TMP/err" || die "create-role: $(cat "$TMP/err")"
CLEAN+=("B iam delete-role --role-name $NAME-exec")
sleep 10
for i in $(seq 1 6); do
  B lambda create-function --function-name "$NAME-fn" --runtime python3.12 --handler index.handler \
    --role "arn:aws:iam::$NEW_ACCOUNT:role/$NAME-exec" --code "S3Bucket=$BUCKET,S3Key=pkg/fn.zip" --timeout 30 >/dev/null 2>"$TMP/err" && break
  grep -q 'denied by S3' "$TMP/err" && die "CreateFunction from the account's own bucket was refused by S3: $(tail -c 300 "$TMP/err")"
  [ "$i" = 6 ] && die "create-function from S3: $(cat "$TMP/err")"
  sleep 10
done
CLEAN+=("B lambda delete-function --function-name $NAME-fn")
for _ in $(seq 1 24); do
  B --cli-read-timeout 120 lambda invoke --function-name "$NAME-fn" --cli-binary-format raw-in-base64-out \
    --payload "{\"probe\":\"$SFX\"}" "$TMP/fn.out" >/dev/null 2>"$TMP/fn.err" && break
  sleep 10
done
python3 - "$TMP/fn.out" "$NAME-fn" "$SFX" <<'PY' || die "$NAME-fn did not return its handler's result: $(cat "$TMP/fn.out" 2>/dev/null) $(tail -c 300 "$TMP/fn.err")"
import json, sys
r = json.load(open(sys.argv[1]))
assert r == {"function": sys.argv[2], "echo": {"probe": sys.argv[3]}}, r
PY
ok "CreateFunction --code S3Bucket=$BUCKET,S3Key=pkg/fn.zip, and the function answers"

log "4. DENIAL"
M s3api get-object --bucket "$BUCKET" --key pkg/fn.zip "$TMP/m.zip" >/dev/null 2>"$TMP/m.err" \
  && die "the management account read the member account's bucket, which no bucket policy lets it into"
grep -q AccessDenied "$TMP/m.err" || die "the management account's refusal is not AccessDenied: $(tail -c 300 "$TMP/m.err")"
M s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' | grep -qx "$BUCKET" \
  && die "the management account lists the member account's bucket"
B iam create-user --user-name "$NAME-tester" >/dev/null 2>"$TMP/err" || die "create-user: $(cat "$TMP/err")"
CLEAN+=("B iam delete-user --user-name $NAME-tester")
B iam put-user-policy --user-name "$NAME-tester" --policy-name invoke-only --policy-document \
  "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:$REGION:$NEW_ACCOUNT:function:$NAME-fn\"}]}" \
  >/dev/null 2>"$TMP/err" || die "put-user-policy: $(cat "$TMP/err")"
CLEAN+=("B iam delete-user-policy --user-name $NAME-tester --policy-name invoke-only")
B iam create-access-key --user-name "$NAME-tester" --output json >"$TMP/key.json" 2>"$TMP/err" || die "create-access-key: $(cat "$TMP/err")"
read -r TAK TSK < <(python3 -c 'import json,sys; k=json.load(open(sys.argv[1]))["AccessKey"]; print(k["AccessKeyId"], k["SecretAccessKey"])' "$TMP/key.json")
CLEAN+=("B iam delete-access-key --user-name $NAME-tester --access-key-id $TAK")
T() { AWS_ACCESS_KEY_ID="$TAK" AWS_SECRET_ACCESS_KEY="$TSK" AWS_SESSION_TOKEN="" AWS_PAGER="" aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"; }
sleep "$SETTLE"
T s3api get-object --bucket "$BUCKET" --key pkg/fn.zip "$TMP/t.zip" >/dev/null 2>"$TMP/t1.err" && die "an invoke-only user read the bucket"
T s3api put-object --bucket "$BUCKET" --key pkg/other --body "$TMP/fn.zip" >/dev/null 2>"$TMP/t2.err" && die "an invoke-only user wrote the bucket"
T s3api create-bucket --bucket "$NAME-nope" >/dev/null 2>"$TMP/t3.err" && { CLEAN+=("B s3api delete-bucket --bucket $NAME-nope"); die "an invoke-only user made a bucket"; }
for e in t1 t2 t3; do grep -q AccessDenied "$TMP/$e.err" || die "an invoke-only user's refusal ($e) is not AccessDenied: $(tail -c 300 "$TMP/$e.err")"; done
ok "the management account: GetObject AccessDenied, bucket not listed; an invoke-only user: GetObject, PutObject, CreateBucket AccessDenied"

log "5. the member account's administrator deletes its bucket"
B s3api delete-object --bucket "$BUCKET" --key pkg/fn.zip >/dev/null 2>"$TMP/err" || die "DeleteObject: $(tr '\n' ' ' < "$TMP/err")"
B s3api delete-bucket --bucket "$BUCKET" >/dev/null 2>"$TMP/err" || die "DeleteBucket: $(tr '\n' ' ' < "$TMP/err")"
B s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1 && die "the bucket is still there after DeleteBucket"
ok "DeleteObject, DeleteBucket"

log "PASS — a member account's administrator owns its buckets: made, written, read, deployed from and deleted in its own account, and refused to everyone else"
