#!/usr/bin/env bash
# AppSync refuses what a principal's IAM policy does not allow, as AWS does.
#
# The principal is a throwaway User whose one inline policy allows only appsync:ListGraphqlApis and
# appsync:GetGraphqlApi. Through the real AWS CLI it is allowed to list and read APIs (a NotFoundException
# for a made-up API id is an allow: authorization passed), and refused with an access-denied error creating
# an API, deleting one, and changing one's schema. Decisions are read on made-up names, so nothing is made.
#
# Needs IAM policy to decide for the principal (IAM_AUTHZ=enforce, or shadow with PRINCIPAL_MODE=canary).
# Exit 0 = pass, 1 = fail, 42 = inconclusive.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-appsync-deny.sh
set -uo pipefail
# shellcheck source=probe/iam-lib.sh
. "$(dirname "$0")/iam-lib.sh"
trap iamp_cleanup EXIT
iamp_require

API="appsyncdeny$SFX"
DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["appsync:ListGraphqlApis","appsync:GetGraphqlApi"],"Resource":"*"}]}'
USER="appsync-deny-$SFX"
log "principal $USER: lists and reads GraphQL APIs only${PRINCIPAL_MODE:+ (PRINCIPAL_MODE=$PRINCIPAL_MODE)}"
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
  [ "$d" = deny ] || fail "$what: allowed, want an access-denied error"
  grep -qE 'AccessDenied|UnauthorizedException' "$PROBE_TMP/s.err" || fail "$what: refused, but not as access denied: $(head -c 300 "$PROBE_TMP/s.err")"
  log "  ✓ $what: access denied"
}

allowed "list GraphQL APIs" appsync list-graphql-apis
allowed "get a GraphQL API" appsync get-graphql-api --api-id "$API"
denied "create a GraphQL API" appsync create-graphql-api --name "$API" --authentication-type API_KEY
denied "delete a GraphQL API" appsync delete-graphql-api --api-id "$API"
denied "start a schema creation" appsync start-schema-creation --api-id "$API" --definition "dHlwZSBRdWVyeSB7IHg6IFN0cmluZyB9"
log "PASS: AppSync allows the principal its policy's reads and refuses its writes"
