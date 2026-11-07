#!/usr/bin/env bash
# DynamoDB refuses what a principal's IAM policy does not allow, as AWS does.
#
# The principal is a throwaway User whose one inline policy allows reading ONE table (DescribeTable,
# GetItem, Query, Scan on its ARN). Through the real AWS CLI it is:
#   - allowed its own table's reads (a ResourceNotFoundException for the made-up table is an allow:
#     authorization passed);
#   - refused, with AccessDeniedException, writing that table (PutItem), deleting it, creating a table, and
#     reading a table its policy does not name.
# Decisions are read on made-up table names, so the probe creates no table.
#
# Needs IAM policy to decide for the principal (IAM_AUTHZ=enforce, or shadow with PRINCIPAL_MODE=canary).
# Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-dynamodb-deny.sh
set -uo pipefail
# shellcheck source=probe/iam-lib.sh
. "$(dirname "$0")/iam-lib.sh"
trap iamp_cleanup EXIT
iamp_require

TABLE="ddb-deny-$SFX"
OTHER="ddb-deny-other-$SFX"
ARN="arn:aws:dynamodb:$REGION:$ACCOUNT:table/$TABLE"
DOC="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:DescribeTable\",\"dynamodb:GetItem\",\"dynamodb:Query\",\"dynamodb:Scan\"],\"Resource\":\"$ARN\"}]}"
USER="ddb-deny-$SFX"
log "principal $USER: reads table $TABLE only${PRINCIPAL_MODE:+ (PRINCIPAL_MODE=$PRINCIPAL_MODE)}"
iamp_user "$USER" "" "$DOC"
iamp_settle

allowed() { # <what> <aws args…>
  local what="$1" d; shift
  d="$(shim_decision "$U_AK" "$U_SK" "$@")"; decided "$d"
  [ "$d" = allow ] || fail "$what: refused, want allowed ($(head -c 300 "$PROBE_TMP/s.err"))"
  log "  ✓ $what: allowed"
}
denied() { # <what> <aws args…>
  local what="$1" d; shift
  d="$(shim_decision "$U_AK" "$U_SK" "$@")"; decided "$d"
  [ "$d" = deny ] || fail "$what: allowed, want AccessDeniedException"
  grep -q AccessDeniedException "$PROBE_TMP/s.err" || fail "$what: refused, but not with AccessDeniedException: $(head -c 300 "$PROBE_TMP/s.err")"
  log "  ✓ $what: AccessDeniedException"
}

allowed "describe its own table" dynamodb describe-table --table-name "$TABLE"
allowed "get-item on its own table" dynamodb get-item --table-name "$TABLE" --key '{"k":{"S":"x"}}'
denied "put-item on its own table (read-only policy)" dynamodb put-item --table-name "$TABLE" --item '{"k":{"S":"x"}}'
denied "delete its own table" dynamodb delete-table --table-name "$TABLE"
denied "create a table" dynamodb create-table --table-name "$OTHER" --attribute-definitions AttributeName=k,AttributeType=S \
  --key-schema AttributeName=k,KeyType=HASH --billing-mode PAY_PER_REQUEST
denied "get-item on a table its policy does not name" dynamodb get-item --table-name "$OTHER" --key '{"k":{"S":"x"}}'
log "PASS: DynamoDB allows the principal its policy's reads and refuses everything else with AccessDeniedException"
