#!/usr/bin/env bash
# The IAM cutover: from Kubernetes RBAC tiers to IAM policy as the only authority, one reversible step at
# a time (docs/iam.md, "Running the cutover").
#
#   hack/iam-cutover.sh <step> [--rollback] [--yes]
#
#   0  dark → shadow   the webhook's root floor; console and aws-shim evaluate IAM policy in shadow (log
#                      both decisions, act on the old one); the compiler reports
#   1  equivalents     hack/iam-migrate: the tiers' AWS managed policies attached to their groups,
#                      documents written next to the old forms (additive)
#   2  canary          the IAM probes as canary principals: parity, no policy, managed policies
#   3  enforce         IAM policy decides for every User and Role; the compiler applies generated RBAC
#                      and the IAM corpus; the RBAC corpus stops carrying user principals
#   4  no users group  check nothing still names the implicit openinfra:users group (the ceilings are
#                      GitOps-managed: a change there is a commit, which this step names)
#   5  accounts        the estate mirror's namespace becomes its own member account
#   6  delete legacy   after 24 h clean: hack/iam-migrate --drop-legacy, and the repo changes to make
#
# Every step first checks the break-glass root (SubjectAccessReviews for the root floor, then a console
# sign-in as root that writes IAM and creates a resource), prints what it will change, asks (unless
# --yes), applies, verifies and prints its rollback. Every step is idempotent. --rollback undoes a step
# (6 has none). State is kept in $IAM_CUTOVER_STATE (default ~/.local/state/openinfra-iam-cutover).
#
# Switches live in an out-of-git ConfigMap `openinfra-iam` in each component's namespace (IAM_AUTHZ for
# the console and the aws-shim, IAM_PROXY_IDENTITY for the console, IAM_COMPILER_MODE for the compiler):
# ArgoCD's self-heal would undo a live edit of a GitOps-managed Deployment, but never this.
#
# Needs: kubectl (cluster admin), go, python3, curl, the aws CLI (step 2), and ROOT_PASSWORD (the
# console root's password) for the root sign-in check. KUBECONFIG as usual.
set -uo pipefail

STEP="${1:-}"; shift || true
ROLLBACK=0; YES=0
for a in "$@"; do case "$a" in --rollback) ROLLBACK=1 ;; --yes) YES=1 ;; *) echo "unknown flag $a" >&2; exit 2 ;; esac; done
case "$STEP" in 0|1|2|3|4|5|6) ;; *) sed -n '2,24p' "$0"; exit 2 ;; esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
STATE="${IAM_CUTOVER_STATE:-$HOME/.local/state/openinfra-iam-cutover}"
mkdir -p "$STATE"
CONSOLE_NS=open-infra-console; SHIM_NS=open-infra-aws-shim; AUTHZ_NS=open-infra-authz
MGMT="$(kubectl -n "$SHIM_NS" get configmap openinfra-aws-identity -o jsonpath='{.data.ACCOUNT_ID}' 2>/dev/null)"
MGMT="${MGMT:-000000000000}"
TMP="$(mktemp -d)"; PF=""
trap '[ -n "$PF" ] && kill "$PF" 2>/dev/null; rm -rf "$TMP"' EXIT

say()  { printf '▸ %s\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }
die()  { printf '✗ %s\n' "$*" >&2; exit 1; }
confirm() {
  [ "$YES" = 1 ] && return 0
  read -r -p "  apply? [y/N] " ans; [ "$ans" = y ] || [ "$ans" = Y ] || die "stopped before applying"
}
done_mark() { date -u +%Y-%m-%dT%H:%M:%SZ > "$STATE/step-$1.done"; }

# --- switches: the openinfra-iam ConfigMaps -------------------------------------------------------------
cm_set() { # <namespace> KEY=VALUE…  (KEY= removes the key)
  local ns="$1"; shift
  kubectl -n "$ns" get configmap openinfra-iam -o json 2>/dev/null > "$TMP/cm.json" || echo '{}' > "$TMP/cm.json"
  python3 - "$TMP/cm.json" "$ns" "$@" > "$TMP/cm.new.json" <<'PY'
import json, sys
# The current ConfigMap is read from its file: the script itself arrives on stdin.
raw = open(sys.argv[1]).read().strip()
cur = (json.loads(raw).get("data") if raw else None) or {}
sys.argv = [sys.argv[0]] + sys.argv[2:]
for kv in sys.argv[2:]:
    k, v = kv.split("=", 1)
    if v:
        cur[k] = v
    else:
        cur.pop(k, None)
print(json.dumps({"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": "openinfra-iam", "namespace": sys.argv[1],
                               "labels": {"app.kubernetes.io/managed-by": "iam-cutover"}},
                  "data": cur}))
PY
  kubectl apply -f "$TMP/cm.new.json" >/dev/null || die "could not write $ns/openinfra-iam"
}
cm_get() { kubectl -n "$1" get configmap openinfra-iam -o jsonpath="{.data.$2}" 2>/dev/null; }
restart() { # <namespace> <deployment>
  kubectl -n "$1" rollout restart "deploy/$2" >/dev/null || die "could not restart $1/$2"
  kubectl -n "$1" rollout status "deploy/$2" --timeout=300s >/dev/null || die "$1/$2 did not roll out"
  ok "$1/$2 restarted"
}

# --- the console, through a port-forward of our own -----------------------------------------------------
console_up() {
  [ -n "$PF" ] && return 0
  local port=$(( 20000 + RANDOM % 20000 ))
  kubectl -n "$CONSOLE_NS" port-forward svc/console "$port:80" >/dev/null 2>&1 & PF=$!
  CONSOLE="http://127.0.0.1:$port"
  for _ in $(seq 1 20); do curl -fsS -m 2 "$CONSOLE/healthz" >/dev/null 2>&1 && return 0; sleep 1; done
  die "the console did not answer through a port-forward"
}

# --- the break-glass root: checked before (and after) every step ----------------------------------------
can() { kubectl auth can-i "$@" 2>/dev/null | head -1 | awk '{print $1}'; }   # "no - <reason>" → no
verify_root() {
  say "break-glass root"
  [ "$(can create clusterrolebindings --as=openinfra:"$MGMT":root)" = yes ] \
    || die "the account root openinfra:$MGMT:root cannot create ClusterRoleBindings — the webhook's root floor is missing (step 0 applies it)"
  [ "$(can delete secrets -n kube-system --as=openinfra:root --as-group=openinfra:admins)" = yes ] \
    || die "the console root (openinfra:root with openinfra:admins) is not all-powerful"
  [ "$(can delete secrets -n kube-system --as=openinfra:root --as-group=openinfra:readers)" = no ] \
    || die "openinfra:root without the admins group must not be root (the floor is name AND group)"
  [ "$(can impersonate users/openinfra:"$MGMT":root --as=system:serviceaccount:"$SHIM_NS":aws-shim)" = no ] \
    || die "the aws-shim may impersonate the account root — its ceiling must deny it (regen the corpus)"
  ok "SubjectAccessReviews: the root floor holds, and no front door may impersonate root"
  if [ -z "${ROOT_PASSWORD:-}" ]; then
    [ "${ALLOW_NO_ROOT_SIGNIN:-}" = 1 ] && { echo "  ⚠ ROOT_PASSWORD unset: the console sign-in as root was NOT checked"; return 0; }
    die "set ROOT_PASSWORD (the console root's password) so the sign-in as root can be checked (or ALLOW_NO_ROOT_SIGNIN=1 to skip it, knowingly)"
  fi
  console_up
  local jar="$TMP/root.jar" code
  code="$(curl -s -m 15 -c "$jar" -o "$TMP/login" -w '%{http_code}' -H 'Content-Type: application/json' \
    -d "$(python3 -c 'import json,os; print(json.dumps({"Username":"root","Password":os.environ["ROOT_PASSWORD"]}))')" "$CONSOLE/api/auth/login")"
  [ "$code" = 200 ] || die "the console refused root's sign-in ($code)"
  python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("principalType")=="Root" else 1)' \
    < <(curl -s -m 10 -b "$jar" "$CONSOLE/api/auth/me") || die "the console does not treat the root sign-in as the account root"
  local g="cutover-root-check-$(date +%s)"
  code="$(curl -s -m 15 -b "$jar" -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
    -d "{\"name\":\"$g\",\"description\":\"iam-cutover root check\"}" "$CONSOLE/api/iam/groups")"
  case "$code" in 2*) ;; *) die "root could not create an IAM group through the console ($code)" ;; esac
  code="$(curl -s -m 15 -b "$jar" -X DELETE -o /dev/null -w '%{http_code}' "$CONSOLE/api/iam/groups/$g")"
  case "$code" in 2*) ;; *) die "root could not delete the IAM group it created ($code) — remove $g by hand" ;; esac
  code="$(curl -s -m 15 -b "$jar" -o "$TMP/dry" -w '%{http_code}' -H 'Content-Type: application/json' \
    -d "{\"apiVersion\":\"openinfra.dev/v1\",\"kind\":\"Parameter\",\"metadata\":{\"name\":\"cutover-root-check\",\"namespace\":\"default\"},\"spec\":{\"value\":\"x\"}}" \
    "$CONSOLE/api/k8s/apis/openinfra.dev/v1/namespaces/default/parameters?dryRun=All")"
  case "$code" in 2*|400|422) ;; *) die "root could not create a resource through the console ($code: $(head -c 200 "$TMP/dry"))" ;; esac
  ok "console: root signs in as the account root, writes IAM (create + delete a group) and creates a resource (dry run)"
}

# --- the control-plane corpus ---------------------------------------------------------------------------
corpus_regen() { # [extra rbac-to-cedar flags]
  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  kubectl -n "$AUTHZ_NS" get configmap control-plane-corpus -o yaml > "$STATE/corpus-before-$ts.yaml" || die "could not save the live corpus"
  (cd "$REPO/console-api" && go run ./cmd/rbac-to-cedar -configmap "$@") > "$TMP/corpus.yaml" 2> "$TMP/corpus.err" \
    || die "rbac-to-cedar failed: $(tail -3 "$TMP/corpus.err")"
  python3 - "$STATE/corpus-before-$ts.yaml" "$TMP/corpus.yaml" "$*" <<'PY' || exit 1
import sys, yaml
def load(p):
    d = yaml.safe_load(open(p)); c = yaml.safe_load(d["data"]["corpus.yaml"]); out = {}
    for e in c:
        for a in e.get("appliesTo", []):
            out.setdefault(a, []).append(yaml.safe_dump(e.get("statements"), sort_keys=True))
    return out
old, new = load(sys.argv[1]), load(sys.argv[2])
print("    added:  ", sorted(set(new) - set(old)))
print("    removed:", sorted(set(old) - set(new)))
print("    changed:", sorted(p for p in set(old) & set(new) if sorted(old[p]) != sorted(new[p])))
if "-skip-iam-principals" not in sys.argv[3] and "Group::openinfra:admins" not in new:
    sys.exit("    the new corpus has no Group::openinfra:admins: refusing (that would lock admins out)")
PY
  confirm
  kubectl replace -f "$TMP/corpus.yaml" >/dev/null || die "could not replace the corpus"
  ok "corpus replaced (the previous one is $STATE/corpus-before-$ts.yaml)"
  sleep 20
}

# --- step 0 ---------------------------------------------------------------------------------------------
step0() {
  if [ "$ROLLBACK" = 1 ]; then
    say "rollback 0: console and aws-shim back to the legacy decision"
    cm_set "$CONSOLE_NS" IAM_AUTHZ= IAM_PROXY_IDENTITY=; cm_set "$SHIM_NS" IAM_AUTHZ=
    restart "$CONSOLE_NS" console; restart "$SHIM_NS" aws-shim
    return
  fi
  say "step 0: the root floor in the webhook, then shadow"
  kubectl diff -f "$REPO/platform/security/manifests/authz-webhook-shadow.yaml" > "$TMP/wh.diff" 2>&1
  if [ -s "$TMP/wh.diff" ]; then
    grep -E '^[-+] ' "$TMP/wh.diff" | grep -vE 'generation|resourceVersion|last-applied' | head -20
    confirm
    kubectl apply -f "$REPO/platform/security/manifests/authz-webhook-shadow.yaml" >/dev/null || die "could not apply the webhook"
    restart "$AUTHZ_NS" authz-webhook
  else ok "the webhook already carries the root floor"; fi
  say "the corpus (new platform principals: the compiler; the shim's ceiling denying root)"
  corpus_regen
  verify_root
  say "prerequisites"
  kubectl get accounts.organizations.openinfra.dev "$MGMT" >/dev/null 2>&1 || die "no management Account $MGMT: run install.sh (step 4b2) first"
  local n; n="$(kubectl -n "$CONSOLE_NS" get policies.iam.openinfra.dev -l openinfra.dev/aws-managed-policy=true --no-headers 2>/dev/null | wc -l)"
  [ "$n" -ge 3 ] || die "the AWS managed policies are not installed ($n found)"
  kubectl -n "$AUTHZ_NS" get deploy iam-compiler >/dev/null 2>&1 || die "the iam-compiler is not deployed (platform/security/iam-compiler.yaml)"
  [ "$(cm_get "$AUTHZ_NS" IAM_COMPILER_MODE)" != apply ] || die "the compiler is already in apply mode: this is past step 3"
  ok "management account $MGMT, $n managed policies, the compiler in report mode"
  say "shadow: the console and the aws-shim log the IAM decision next to the one they act on"
  echo "    $CONSOLE_NS/openinfra-iam IAM_AUTHZ=shadow IAM_PROXY_IDENTITY=legacy; $SHIM_NS/openinfra-iam IAM_AUTHZ=shadow"
  confirm
  cm_set "$CONSOLE_NS" IAM_AUTHZ=shadow IAM_PROXY_IDENTITY=legacy
  cm_set "$SHIM_NS" IAM_AUTHZ=shadow
  restart "$CONSOLE_NS" console; restart "$SHIM_NS" aws-shim
  sleep 30
  local s; s="$(kubectl -n "$SHIM_NS" logs deploy/aws-shim --since=2m 2>/dev/null | grep -c 'iam-shadow')"
  ok "the aws-shim logged $s iam-shadow line(s) in the last 2 minutes (any differences are what step 1 and 2 settle)"
  verify_root
  done_mark 0
  echo "  rollback: hack/iam-cutover.sh 0 --rollback"
}

# --- step 1 ---------------------------------------------------------------------------------------------
migrate() { (cd "$REPO/hack/iam-migrate" && go run . "$@"); }
resource_of() { case "$1" in Policy) echo policies.iam.openinfra.dev ;; Group) echo groups.iam.openinfra.dev ;;
  User) echo users.iam.openinfra.dev ;; Role) echo roles.iam.openinfra.dev ;; *) echo "" ;; esac; }
step1() {
  if [ "$ROLLBACK" = 1 ]; then
    [ -f "$STATE/step1-plan.json" ] || die "no recorded step-1 plan to roll back"
    say "rollback 1: restore every object the migration changed, delete the ones it created"
    python3 - "$STATE/step1-plan.json" "$STATE/step1-before" <<'PY' > "$TMP/undo.sh"
import json, os, shlex, sys
res = {"Policy": "policies.iam.openinfra.dev", "Group": "groups.iam.openinfra.dev",
       "User": "users.iam.openinfra.dev", "Role": "roles.iam.openinfra.dev"}
plan = json.load(open(sys.argv[1]))
for c in plan.get("changes", []):
    r = res.get(c["kind"]); ns, name = c["namespace"], c["name"]
    if not r:
        continue
    if c.get("create"):
        print(f"kubectl -n {shlex.quote(ns)} delete {r} {shlex.quote(name)} --ignore-not-found")
        continue
    snap = os.path.join(sys.argv[2], f"{c['kind']}-{ns}-{name}.json")
    before = (json.load(open(snap)).get("spec") or {}) if os.path.exists(snap) else {}
    patch = {"spec": {k: before.get(k) for k in (c.get("patch") or {})}}
    print(f"kubectl -n {shlex.quote(ns)} patch {r} {shlex.quote(name)} --type merge -p {shlex.quote(json.dumps(patch))}")
PY
    cat "$TMP/undo.sh"; confirm
    bash "$TMP/undo.sh" || die "the rollback did not complete"
    ok "step 1 rolled back"; rm -f "$STATE/step-1.done"; return
  fi
  verify_root
  say "step 1: the AWS policy model next to the old forms (hack/iam-migrate, additive)"
  migrate --json > "$TMP/plan.json" || die "hack/iam-migrate could not plan"
  migrate | tail -40
  local n; n="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("changes",[])))' "$TMP/plan.json")"
  if [ "$n" = 0 ]; then ok "nothing left to migrate"; done_mark 1; return; fi
  confirm
  cp "$TMP/plan.json" "$STATE/step1-plan.json"
  mkdir -p "$STATE/step1-before"
  python3 -c '
import json,sys
for c in json.load(open(sys.argv[1]))["changes"]:
    if not c.get("create"): print(c["kind"], c["namespace"], c["name"])' "$TMP/plan.json" |
  while read -r kind ns name; do
    kubectl -n "$ns" get "$(resource_of "$kind")" "$name" -o json > "$STATE/step1-before/$kind-$ns-$name.json" 2>/dev/null
  done
  migrate --apply || die "hack/iam-migrate --apply failed (roll back with: hack/iam-cutover.sh 1 --rollback)"
  migrate --json > "$TMP/plan2.json"
  n="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("changes",[])))' "$TMP/plan2.json")"
  [ "$n" = 0 ] || die "$n change(s) still planned after --apply"
  ok "migrated: a re-plan finds nothing left"
  verify_root
  done_mark 1
  echo "  rollback: hack/iam-cutover.sh 1 --rollback"
}

# --- step 2 ---------------------------------------------------------------------------------------------
step2() {
  if [ "$ROLLBACK" = 1 ]; then
    say "rollback 2: the canary principals remove themselves; unlabel a real canary user if one was set"
    if [ -n "${CANARY_USER:-}" ]; then kubectl -n "$CONSOLE_NS" label users.iam.openinfra.dev "$CANARY_USER" openinfra.dev/iam-authz-; fi
    rm -f "$STATE/step-2.done"; return
  fi
  verify_root
  [ "$(cm_get "$SHIM_NS" IAM_AUTHZ)" = shadow ] || die "run step 0 first (the shim is not in shadow)"
  say "step 2: the IAM probes as canary principals (IAM policy decides for them alone)"
  local pf_shim port=$(( 40000 + RANDOM % 20000 ))
  kubectl -n "$SHIM_NS" port-forward svc/aws-shim "$port:4566" >/dev/null 2>&1 & pf_shim=$!
  sleep 3
  local rc=0
  for p in iam-parity iam-no-policy iam-managed-policies; do
    SHIM_ENDPOINT="http://127.0.0.1:$port" PRINCIPAL_MODE=canary bash "$REPO/probe/$p.sh"; r=$?
    case "$r" in 0) ok "$p passed" ;; 42) echo "  ⚠ $p inconclusive"; rc=42 ;; *) echo "  ✗ $p failed"; rc=1 ;; esac
  done
  kill "$pf_shim" 2>/dev/null
  if [ -n "${CANARY_USER:-}" ]; then
    kubectl -n "$CONSOLE_NS" label users.iam.openinfra.dev "$CANARY_USER" openinfra.dev/iam-authz=enforce --overwrite >/dev/null
    ok "real canary user $CANARY_USER: IAM policy now decides for it (rollback unlabels it)"
  fi
  [ "$rc" = 0 ] || die "the canary did not pass (exit $rc): fix before step 3"
  verify_root
  done_mark 2
  echo "  rollback: hack/iam-cutover.sh 2 --rollback"
}

# --- step 3 ---------------------------------------------------------------------------------------------
step3() {
  if [ "$ROLLBACK" = 1 ]; then
    say "rollback 3: legacy decisions, the compiler back to report, generated RBAC removed, the RBAC corpus with users"
    cm_set "$CONSOLE_NS" IAM_AUTHZ=shadow IAM_PROXY_IDENTITY=legacy; cm_set "$SHIM_NS" IAM_AUTHZ=shadow
    cm_set "$AUTHZ_NS" IAM_COMPILER_MODE=report
    restart "$CONSOLE_NS" console; restart "$SHIM_NS" aws-shim; restart "$AUTHZ_NS" iam-compiler
    kubectl delete clusterrole,clusterrolebinding,rolebinding -A -l openinfra.dev/generated-by=iam-compiler --ignore-not-found >/dev/null
    corpus_regen
    verify_root
    rm -f "$STATE/step-3.done"; return
  fi
  [ -f "$STATE/step-2.done" ] || die "step 2 (the canary) has not passed"
  verify_root
  say "step 3: the compiler applies (generated RBAC + the IAM corpus)"
  kubectl apply -f "$REPO/platform/security/manifests/iam-compiler-apply.yaml" >/dev/null || die "could not grant the compiler its apply rights"
  cm_set "$AUTHZ_NS" IAM_COMPILER_MODE=apply
  restart "$AUTHZ_NS" iam-compiler
  local n
  for _ in $(seq 1 30); do
    n="$(kubectl get clusterrole -l openinfra.dev/generated-by=iam-compiler --no-headers 2>/dev/null | wc -l)"
    kubectl -n "$AUTHZ_NS" get configmap iam-corpus >/dev/null 2>&1 && [ "$n" -gt 0 ] && break
    sleep 10
  done
  kubectl -n "$AUTHZ_NS" get configmap iam-corpus >/dev/null 2>&1 || die "the compiler wrote no iam-corpus (roll back: hack/iam-cutover.sh 3 --rollback)"
  ok "iam-corpus written; $n generated ClusterRole(s)"
  say "the RBAC corpus without user principals (they are the IAM corpus's now)"
  corpus_regen -skip-iam-principals
  say "enforce: IAM policy decides for every principal at the console and the aws-shim"
  echo "    $CONSOLE_NS/openinfra-iam IAM_AUTHZ=enforce (proxy identity: the account identity); $SHIM_NS/openinfra-iam IAM_AUTHZ=enforce"
  confirm
  cm_set "$CONSOLE_NS" IAM_AUTHZ=enforce IAM_PROXY_IDENTITY=
  cm_set "$SHIM_NS" IAM_AUTHZ=enforce
  restart "$CONSOLE_NS" console; restart "$SHIM_NS" aws-shim
  verify_root
  say "the IAM probes, now for every principal (no canary label)"
  local port=$(( 40000 + RANDOM % 20000 )) pf_shim rc=0
  kubectl -n "$SHIM_NS" port-forward svc/aws-shim "$port:4566" >/dev/null 2>&1 & pf_shim=$!
  sleep 3
  for p in iam-parity iam-no-policy iam-managed-policies; do
    SHIM_ENDPOINT="http://127.0.0.1:$port" bash "$REPO/probe/$p.sh"; r=$?
    case "$r" in 0) ok "$p passed" ;; *) echo "  ✗ $p exit $r"; rc=1 ;; esac
  done
  kill "$pf_shim" 2>/dev/null
  [ "$rc" = 0 ] || die "a probe failed under enforce — roll back: hack/iam-cutover.sh 3 --rollback"
  done_mark 3
  echo "  rollback: hack/iam-cutover.sh 3 --rollback"
}

# --- step 4 ---------------------------------------------------------------------------------------------
step4() {
  if [ "$ROLLBACK" = 1 ]; then
    echo "rollback 4: revert the commit that removed openinfra:users from the impersonation ceilings; nothing live to undo"
    rm -f "$STATE/step-4.done"; return
  fi
  verify_root
  say "step 4: nothing names the implicit openinfra:users group"
  local bound; bound="$(kubectl get clusterrolebinding,rolebinding -A -o json | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(sum(1 for b in d["items"] for s in (b.get("subjects") or []) if s.get("kind")=="Group" and s.get("name")=="openinfra:users"))')"
  [ "$bound" = 0 ] || die "$bound binding(s) grant openinfra:users: remove them (in git) first"
  ok "no binding grants openinfra:users"
  local ceil; ceil="$(kubectl get clusterrole -o json | python3 -c '
import json,sys
d=json.load(sys.stdin)
print(" ".join(r["metadata"]["name"] for r in d["items"] if r["metadata"]["name"].endswith("-impersonator")
      and any("openinfra:users" in (x.get("resourceNames") or []) for x in r.get("rules") or [])))')"
  if [ -n "$ceil" ]; then
    echo "  ⚠ the impersonation ceilings still name openinfra:users: $ceil"
    echo "    they are GitOps-managed: remove openinfra:users from their resourceNames in"
    echo "    platform/console/manifests/rbac-roles.yaml and platform/aws-shim/aws-shim.yaml, commit, let ArgoCD sync,"
    echo "    regen the corpus (this script's step 0 does it), then re-run step 4"
    exit 3
  fi
  ok "no impersonation ceiling names openinfra:users"
  verify_root
  done_mark 4
  echo "  rollback: revert that ceiling commit"
}

# --- step 5 ---------------------------------------------------------------------------------------------
mirror_namespace() { # the namespace holding the most estate-mirror (observed-aws-*) claims
  kubectl get functions.openinfra.dev,roles.iam.openinfra.dev,policies.iam.openinfra.dev -A --no-headers 2>/dev/null \
    | awk '{name=$2; sub(/.*\//, "", name)} name ~ /^observed-aws/ {n[$1]++} END {for (k in n) print n[k], k}' \
    | sort -rn | head -1 | awk '{print $2}'
}
ready_counts() { # <namespace>: Ready claims per kind
  for k in functions.openinfra.dev roles.iam.openinfra.dev tables.openinfra.dev queues.openinfra.dev; do
    printf '%s=%s ' "${k%%.*}" "$(kubectl -n "$1" get "$k" -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null | grep -c True)"
  done
}
step5() {
  local ns; ns="${MIRROR_NAMESPACE:-$(mirror_namespace)}"
  [ -n "$ns" ] || die "no namespace holds estate-mirror claims (set MIRROR_NAMESPACE)"
  local id; id="${MIRROR_ACCOUNT_ID:-$(python3 - "$ns" <<'PY'
import hashlib, sys
s = hashlib.sha256(sys.argv[1].encode()).digest()
print("9%011d" % (int.from_bytes(s[:8], "big") % 100_000_000_000))
PY
)}"
  if [ "$ROLLBACK" = 1 ]; then
    say "rollback 5: $ns back into the management account"
    kubectl delete accounts.organizations.openinfra.dev "$id" --ignore-not-found >/dev/null
    kubectl label ns "$ns" openinfra.dev/account-id- openinfra.dev/account-home- openinfra.dev/account-status- >/dev/null 2>&1
    ok "account $id removed; $ns resolves to the management account again"
    rm -f "$STATE/step-5.done"; return
  fi
  [ -f "$STATE/step-3.done" ] || die "step 3 (enforce) has not run"
  verify_root
  say "step 5: the estate mirror ($ns) becomes member account $id"
  local before; before="$(ready_counts "$ns")"; echo "    Ready before: $before"
  local cur; cur="$(kubectl get ns "$ns" -o jsonpath='{.metadata.labels.openinfra\.dev/account-id}')"
  if [ "$cur" = "$id" ]; then ok "$ns is already account $id"
  else
    [ -z "$cur" ] || [ "$cur" = "$MGMT" ] || die "$ns already belongs to account $cur"
    cat > "$TMP/acct.yaml" <<YAML
apiVersion: organizations.openinfra.dev/v1
kind: Account
metadata: { name: "$id" }
spec:
  accountId: "$id"
  alias: estate-mirror
  isolation: none
  namespaces: ["$ns"]
YAML
    cat "$TMP/acct.yaml"; confirm
    kubectl apply -f "$TMP/acct.yaml" >/dev/null || die "could not create the account"
  fi
  for _ in $(seq 1 30); do
    [ "$(kubectl get accounts.organizations.openinfra.dev "$id" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = True ] && break
    sleep 5
  done
  [ "$(kubectl get ns "$ns" -o jsonpath='{.metadata.labels.openinfra\.dev/account-id}')" = "$id" ] || die "$ns was not labelled into account $id"
  ok "account $id is Ready; $ns carries its label"
  sleep 60
  local after; after="$(ready_counts "$ns")"; echo "    Ready after:  $after"
  [ "$before" = "$after" ] || die "Ready claims changed in $ns ($before → $after): roll back with hack/iam-cutover.sh 5 --rollback"
  ok "the mirror's claims are as Ready as before"
  verify_root
  done_mark 5
  echo "  the engagement users that hold this mirror's shim keys still live in the management account: move them"
  echo "  (a User in the member account's home, keys re-owned) only when their callers can take the new ARNs"
  echo "  rollback: hack/iam-cutover.sh 5 --rollback"
}

# --- step 6 ---------------------------------------------------------------------------------------------
step6() {
  [ "$ROLLBACK" = 1 ] && die "step 6 removes the old forms for good: there is no rollback (roll back step 3 instead, before this)"
  [ -f "$STATE/step-3.done" ] || die "step 3 (enforce) has not run"
  local since; since="$(( $(date +%s) - $(date -d "$(cat "$STATE/step-3.done")" +%s) ))"
  [ "$since" -ge 86400 ] || [ "${FORCE_NOW:-}" = 1 ] || die "enforce has run $((since / 3600)) h: wait 24 h clean (or FORCE_NOW=1)"
  verify_root
  say "step 6: drop the forms the migration replaced"
  migrate --drop-legacy | tail -30
  confirm
  migrate --apply --drop-legacy || die "hack/iam-migrate --drop-legacy failed"
  ok "legacy forms dropped"
  cat <<'TXT'
  Then, in git (GitOps-managed, so a commit, not a live edit):
    - delete the bindings labelled openinfra.dev/legacy (platform/console/manifests/rbac-roles.yaml,
      platform/security/pass-role.yaml, platform/aws-shim/ecr-pusher.yaml, ecr-node-pull.yaml);
    - delete the 25 kebab-case alias policies (platform/security/managed-policies.yaml);
    - make test/render/rbac_user_authority_test.go blocking with no legacy allowance.
TXT
  verify_root
  done_mark 6
}

"step$STEP"
