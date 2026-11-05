# Shared helpers for the IAM probes (iam-parity.sh, iam-no-policy.sh, iam-managed-policies.sh): throwaway
# principals that sign in to the console AND hold an access key for the aws-shim, and one decision reader
# per door. Sourced, never run.
#
# A principal is a kind: User in the management account's IAM home with the policies a probe gives it, a
# console password (a bcrypt hash in a Secret the probe creates; nothing pre-existing is read) and an
# access key the shim authenticates. With PRINCIPAL_MODE=canary each User carries
# openinfra.dev/iam-authz: enforce, so IAM policy decides for it while the platform runs in shadow.
#
# Decisions are IAM decisions, read so a downstream refusal can't pass for one:
#   console: denied when the gate answers 403 naming the action it was asked (its AccessDenied body has
#            the action); anything else — 200, 404 for a probe's made-up resource, a 400 — is allowed.
#   shim:    denied when the call fails with AWS's denial codes; a success or a NotFound for a made-up
#            resource is allowed.
#
# Every helper runs in the probe's own shell (no command substitution around a mint), so the CREATED_*
# lists reach the EXIT trap and nothing a probe made outlives it.

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
CONSOLE="${CONSOLE_ENDPOINT:-}"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT="${ACCOUNT_ID:-000000000000}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PROBE_TMP="$(mktemp -d)"
HERE_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

CREATED_USERS=(); CREATED_SECRETS=(); CREATED_SHIM_SECRETS=(); CONSOLE_PF=""
iamp_cleanup() {
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl -n "$USERS_NS" delete users.iam.openinfra.dev "$u" --ignore-not-found --wait=false >/dev/null 2>&1; done
  for s in "${CREATED_SECRETS[@]:-}"; do [ -n "$s" ] && kubectl -n "$USERS_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1; done
  for s in "${CREATED_SHIM_SECRETS[@]:-}"; do [ -n "$s" ] && kubectl -n "$SHIM_NS" delete secret "$s" --ignore-not-found >/dev/null 2>&1; done
  [ -n "$CONSOLE_PF" ] && kill "$CONSOLE_PF" 2>/dev/null
  rm -rf "$PROBE_TMP"
  return 0
}

iamp_require() {
  command -v aws >/dev/null || inconclusive "the aws CLI is required"
  command -v kubectl >/dev/null || inconclusive "kubectl is required"
  command -v curl >/dev/null || inconclusive "curl is required"
  command -v python3 >/dev/null || inconclusive "python3 is required"
  command -v go >/dev/null || inconclusive "go is required (the console password is hashed with the console's own bcrypt)"
  curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"
  if [ -z "$CONSOLE" ]; then
    # No endpoint given: reach the console through a port-forward of our own, closed by the trap.
    local port=$(( 20000 + RANDOM % 20000 ))
    kubectl -n "$USERS_NS" port-forward svc/console "$port:80" >/dev/null 2>&1 &
    CONSOLE_PF=$!
    CONSOLE="http://127.0.0.1:$port"
    for _ in $(seq 1 20); do curl -fsS -m 2 "$CONSOLE/healthz" >/dev/null 2>&1 && break; sleep 1; done
  fi
  curl -fsS -m 5 "$CONSOLE/healthz" >/dev/null 2>&1 || inconclusive "console not reachable at $CONSOLE (set CONSOLE_ENDPOINT)"
}

# bcrypt with the console's own library (golang.org/x/crypto/bcrypt, from console-api's module), so the
# hash is exactly what the console verifies. Prints the hash.
iamp_bcrypt() {
  mkdir -p "$PROBE_TMP/bcrypt"
  cat > "$PROBE_TMP/bcrypt/main.go" <<'GO'
package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	h, err := bcrypt.GenerateFromPassword([]byte(os.Args[1]), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(string(h))
}
GO
  (cd "$HERE_REPO/console-api" && go run "$PROBE_TMP/bcrypt/main.go" "$1")
}

# iamp_user <name> <managed-policies-csv> <inline-document-json|"">: a principal; sets U_AK U_SK U_PW.
# The User is in no group (authority comes only from the policies named here).
iamp_user() {
  local name="$1" managed="$2" doc="$3"
  U_PW="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 22)"
  local hash; hash="$(iamp_bcrypt "$U_PW")" || inconclusive "could not hash the console password (go run in console-api)"
  [ -n "$hash" ] || inconclusive "empty password hash"
  local pwsec="iam-probe-pw-$name"
  kubectl -n "$USERS_NS" create secret generic "$pwsec" --from-literal=hash="$hash" >/dev/null || inconclusive "could not create the password Secret"
  CREATED_SECRETS+=("$pwsec")
  local labels="{}"
  [ "${PRINCIPAL_MODE:-}" = canary ] && labels='{"openinfra.dev/iam-authz":"enforce"}'
  python3 - "$name" "$managed" "$doc" "$pwsec" "$USERS_NS" "$labels" > "$PROBE_TMP/user-$name.json" <<'PY'
import json, sys
name, managed, doc, pwsec, ns, labels = sys.argv[1:7]
spec = {"displayName": name, "source": "local", "groups": [],
        "policies": [p for p in managed.split(",") if p],
        "passwordSecretRef": {"name": pwsec, "key": "hash"}}
if doc:
    spec["inlinePolicies"] = [{"name": "probe", "document": json.loads(doc)}]
print(json.dumps({"apiVersion": "iam.openinfra.dev/v1", "kind": "User",
                  "metadata": {"name": name, "namespace": ns, "labels": json.loads(labels)},
                  "spec": spec}))
PY
  kubectl apply -f "$PROBE_TMP/user-$name.json" >/dev/null || inconclusive "could not create User $name"
  CREATED_USERS+=("$name")
  U_AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  U_SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  local keysec; keysec="iam-ak-$(printf '%s' "$U_AK" | sha256sum | cut -c1-40)"
  kubectl -n "$SHIM_NS" create secret generic "$keysec" --from-literal=accessKeyId="$U_AK" \
    --from-literal=secretKey="$U_SK" --from-literal=owner="$name" >/dev/null || inconclusive "could not create the access key"
  CREATED_SHIM_SECRETS+=("$keysec")
}

# iamp_login <name> <password> <cookiejar>: a console session; also checks IAM policy decides for it.
iamp_login() {
  local name="$1" pw="$2" jar="$3" code mode
  for _ in $(seq 1 15); do
    code="$(curl -s -m 15 -c "$jar" -o "$PROBE_TMP/login.out" -w '%{http_code}' -H 'Content-Type: application/json' \
      -d "{\"Username\":\"$name\",\"Password\":\"$pw\"}" "$CONSOLE/api/auth/login")"
    [ "$code" = 200 ] && break
    sleep 2   # the console reads Users through an informer: a new one takes a moment
  done
  [ "$code" = 200 ] || inconclusive "console sign-in as $name answered $code: $(head -c 200 "$PROBE_TMP/login.out")"
  mode="$(curl -s -m 10 -b "$jar" "$CONSOLE/api/auth/me" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("iamAuthz",""))' 2>/dev/null)"
  if [ "$mode" != enforce ]; then
    inconclusive "IAM policy does not decide for $name yet (iamAuthz=${mode:-unknown}): run with the console and shim in IAM_AUTHZ=shadow and PRINCIPAL_MODE=canary, or after the cutover's enforce step"
  fi
}

# console_decision <cookiejar> <method> <path> <action>: prints allow or deny (the IAM gate's answer), or
# unknown with the reason in $PROBE_TMP/why (decided turns that into exit 42 in the probe's own shell).
console_decision() {
  local jar="$1" method="$2" path="$3" action="$4" code
  code="$(curl -s -m 30 -b "$jar" -X "$method" -o "$PROBE_TMP/c.out" -w '%{http_code}' \
    -H 'Content-Type: application/json' ${CONSOLE_BODY:+-d "$CONSOLE_BODY"} "$CONSOLE$path")"
  case "$code" in
    401) echo "the console session expired during the probe" > "$PROBE_TMP/why"; echo unknown; return ;;
    000) echo "the console did not answer $method $path" > "$PROBE_TMP/why"; echo unknown; return ;;
  esac
  if [ "$code" = 403 ] && python3 - "$PROBE_TMP/c.out" "$action" <<'PY'
import json, sys
try:
    body = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
want, got = sys.argv[2], body.get("action", "")
named = got.startswith(want[:-1]) if want.endswith("*") else got == want
sys.exit(0 if body.get("errorCode") == "AccessDeniedException" and named else 1)
PY
  then echo deny; else echo allow; fi
}

# iamp_console_routes <routes.go> <made-up-name>: "METHOD /api/path action" for every console route with a
# fixed IAM action (registered as h(method, "path", timeout, "action", …) in the console's route table),
# path parameters filled with a made-up name ({namespace} with default).
iamp_console_routes() {
  python3 - "$1" "$2" <<'PY'
import re, sys
src, nope = open(sys.argv[1]).read(), sys.argv[2]
methods = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "del": "DELETE"}
seen = set()
for m, path, action in re.findall(r'\bh\((get|post|put|patch|del), "([^"]+)", [^,]+, "([^"]+)"', src):
    p = re.sub(r"\{namespace\}", "default", "/api" + path)
    p = re.sub(r"\{[^}]+\}", nope, p)
    key = (methods[m], p)
    if key in seen:
        continue
    seen.add(key)
    print(f"{methods[m]} {p} {action}")
PY
}

# decided <answer>: an unknown answer ends the probe inconclusive, in the probe's own shell so the trap runs.
decided() { if [ "$1" = unknown ]; then inconclusive "$(cat "$PROBE_TMP/why" 2>/dev/null)"; fi; }

# shim_decision <ak> <sk> <aws args…>: prints allow or deny (the front door's answer), or unknown.
shim_decision() {
  local ak="$1" sk="$2"; shift 2
  if AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_SESSION_TOKEN="" AWS_REGION="$REGION" \
     AWS_RETRY_MODE=standard AWS_MAX_ATTEMPTS=2 \
     aws --endpoint-url "$ENDPOINT" --no-cli-pager --output json "$@" >/dev/null 2>"$PROBE_TMP/s.err"; then
    echo allow; return
  fi
  if grep -qE 'AccessDenied|AccessDeniedException|UnauthorizedOperation|AuthorizationError|AuthorizationErrorException|not authorized to perform' "$PROBE_TMP/s.err"; then
    echo deny
  elif grep -qE 'Could not connect|EndpointConnectionError|Connection was closed|Bad Gateway|ServiceUnavailable' "$PROBE_TMP/s.err"; then
    echo "the shim did not answer: aws $* — $(tr '\n' ' ' < "$PROBE_TMP/s.err" | cut -c1-200)" > "$PROBE_TMP/why"
    echo unknown
  else
    echo allow   # a NotFound / validation error for a probe's made-up resource: authorization passed
  fi
}
