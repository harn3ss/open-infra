#!/usr/bin/env bash
# AppSync refuses what a principal's IAM policy does not allow, as AWS does.
#
# The principal is a throwaway User whose one inline policy allows only appsync:ListGraphqlApis and
# appsync:GetGraphqlApi. Through the real AWS CLI it is allowed to list and read APIs (a NotFoundException
# for a made-up API id is an allow: authorization passed), and refused with an access-denied error on each
# change the AppSync front door serves: creating and deleting a data source, and creating, updating and
# deleting a resolver. (CreateGraphqlApi and the schema operations are not served by the front door: an API
# is a stack's or the console's kind: GraphQLApi, so they answer NotImplementedException and prove nothing
# here.) The front door decides IAM policy before it reads the API, so the decisions are read on made-up
# names and nothing is made.
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
denied "create a data source" appsync create-data-source --api-id "$API" --name probe --type NONE
denied "delete a data source" appsync delete-data-source --api-id "$API" --name probe
denied "create a resolver" appsync create-resolver --api-id "$API" --type-name Query --field-name probe --data-source-name probe
denied "update a resolver" appsync update-resolver --api-id "$API" --type-name Query --field-name probe --data-source-name probe
denied "delete a resolver" appsync delete-resolver --api-id "$API" --type-name Query --field-name probe
log "PASS: AppSync allows the principal its policy's reads and refuses its changes"
