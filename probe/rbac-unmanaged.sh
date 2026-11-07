#!/usr/bin/env bash
# Read-only probe: Kubernetes RBAC that NOTHING manages.
#
# Lists the ClusterRoles and ClusterRoleBindings — and the Roles and RoleBindings in the platform's
# own namespaces — that exist on the cluster but are owned by no GitOps Application, controller,
# chart, or Kubernetes/k3s default. Such an object is invisible to review: it is not in git, nothing
# re-applies or prunes it, and a security-relevant behavior can quietly come to depend on it (a
# binding applied by hand once, then relied on). Each finding is printed with its subjects or rules,
# who wrote it (field managers) and, when run from a checkout, whether its name appears in the repo
# (named in the repo but untracked = applied out of band).
#
# MAKES NO CHANGES: every cluster call is a `kubectl get` (plus API discovery).
#
# An object counts as MANAGED when the first of these signals that holds says so:
#   owner       metadata.ownerReferences is set (Crossplane's RBAC manager, CDI, other operators).
#   argocd      ArgoCD tracks it — annotation argocd.argoproj.io/tracking-id (annotation tracking)
#               or label app.kubernetes.io/instance (label tracking), whichever this ArgoCD uses
#               (ARGOCD_TRACKING; auto-detected). A tracking-id is checked, not trusted: it must name
#               this object, its Application must exist, and the Application must not mark the
#               object requiresPruning (removed from git, still live). Any of those failing is a
#               FINDING.
#   helm        label app.kubernetes.io/managed-by=Helm, or annotation meta.helm.sh/release-name.
#   crossplane  a provider-kubernetes Object that manages it (managementPolicies not Observe-only)
#               declares it in spec.forProvider.manifest.
#   managed-by  any other app.kubernetes.io/managed-by label (an operator or reconciler naming
#               itself), except the build tools in RBAC_WEAK_MANAGED_BY.
#   system      the API server's bootstrap policy (label kubernetes.io/bootstrapping=rbac-defaults),
#               or a system:-prefixed name that no hand tool wrote. A hand-applied system:* object
#               is NOT exempt: the prefix is reserved, not proof of origin.
#   k3s         the k3s/RKE2 deploy controller (objectset.rio.cattle.io label/annotation) or the
#               addon manager (addonmanager.kubernetes.io/mode).
#   controller  every field manager in metadata.managedFields is a program and none is a hand tool
#               (RBAC_HAND_MANAGERS) — e.g. an operator applying its own manifests.
#   allow       an object that would otherwise be a finding matches the allow-list.
#   acknowledged  an object that nothing manages, deliberately, carries the annotation
#               openinfra.dev/rbac-unmanaged-reason with the reason (for example a per-site grant that
#               belongs to one engagement, not to the platform). It is not a finding, but it is always
#               printed, with its reason and rules or subjects, so it stays in view. Only the "nothing
#               manages it" case can be acknowledged: an ArgoCD tracking-id that is copied, orphaned or
#               marked requiresPruning stays a finding whatever the annotation says.
#
# ALLOW-LIST — RBAC_ALLOW_DEFAULT plus RBAC_ALLOW: whitespace- or comma-separated extended regexes,
# each matched ANCHORED against the object id: `Kind/name` (cluster-scoped) or `Kind/namespace/name`.
# RBAC_ALLOW_DEFAULT names the RBAC that install.sh applies from upstream release manifests, which
# carries no management signal: kube-ovn, MetalLB, Multus, the KubeVirt and CDI operators, and Argo CD
# itself. Set RBAC_ALLOW_DEFAULT='' to audit those too. Add site-specific exceptions with RBAC_ALLOW:
#   RBAC_ALLOW='ClusterRole/my-operator-.* RoleBinding/team-a/legacy-.*'
#
# Env:
#   RBAC_NAMESPACES     regex of the namespaces whose Roles/RoleBindings are audited (default: the
#                       platform's own — open-infra-*, openinfra-*, crossplane-system; '' = only
#                       cluster-scoped RBAC; '.*' = every namespace).
#   ARGOCD_NS           ArgoCD's namespace (default argocd).
#   ARGOCD_TRACKING     auto | annotation | label | annotation+label (default auto: argocd-cm's
#                       application.resourceTrackingMethod, else the server version's default).
#   RBAC_HAND_MANAGERS  regex of field managers that mean a person or ad-hoc script wrote the object
#                       (default: kubectl*, k9s, curl, generic HTTP/SDK user agents).
#   RBAC_WEAK_MANAGED_BY  managed-by values that name a tool, not an owner (default: kustomize kubectl).
#   RBAC_REPO_DIR       a checkout of this repo, searched for each finding's name (default: the repo
#                       this script is in; '' = skip).
#   RBAC_VERBOSE=1      also print the tally of managed objects per signal.
#
# Exit 0 = no unmanaged RBAC. 1 = findings. 42 = INCONCLUSIVE (no kubectl/jq, the cluster is
# unreachable, or RBAC cannot be listed), mirroring the other probes.
#
#   ./probe/rbac-unmanaged.sh
#   RBAC_NAMESPACES='.*' RBAC_ALLOW='ClusterRoleBinding/my-.*' ./probe/rbac-unmanaged.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
ARGOCD_NS="${ARGOCD_NS:-argocd}"
RBAC_NAMESPACES="${RBAC_NAMESPACES-^(open-infra(-.*)?|openinfra-.*|crossplane-system)$}"
ARGOCD_TRACKING="${ARGOCD_TRACKING:-auto}"
RBAC_HAND_MANAGERS="${RBAC_HAND_MANAGERS:-^(kubectl(-.*)?|k9s|curl.*|OpenAPI-Generator.*|python-requests.*|Go-http-client.*|Mozilla.*)$}"
RBAC_WEAK_MANAGED_BY="${RBAC_WEAK_MANAGED_BY-kustomize kubectl}"
RBAC_ALLOW_DEFAULT="${RBAC_ALLOW_DEFAULT-
  ClusterRole/system:(ovn|ovn-ovs|kube-ovn-cni|kube-ovn-app)
  ClusterRoleBinding/(ovn|ovn-ovs|kube-ovn-cni|kube-ovn-app)
  (ClusterRole|ClusterRoleBinding)/metallb-system:(controller|speaker)
  (ClusterRole|ClusterRoleBinding)/multus
  (ClusterRole|ClusterRoleBinding)/kubevirt-operator
  ClusterRole/kubevirt\.io:operator
  ClusterRole/cdi-operator-cluster
  ClusterRoleBinding/cdi-operator
  (ClusterRole|ClusterRoleBinding)/argocd-(application-controller|applicationset-controller|server)
  RoleBinding/kube-system/(ovn|ovn-ovs|kube-ovn-cni|kube-ovn-app)
  (Role|RoleBinding)/metallb-system/(controller|pod-lister)
  Role/kubevirt/kubevirt-operator
  RoleBinding/kubevirt/kubevirt-operator-rolebinding
  (Role|RoleBinding)/argocd/argocd-(application-controller|applicationset-controller|dex-server|notifications-controller|redis|server)
}"
RBAC_ALLOW="${RBAC_ALLOW:-}"
SCRIPT_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || true)"
RBAC_REPO_DIR="${RBAC_REPO_DIR-$SCRIPT_REPO}"
RBAC_VERBOSE="${RBAC_VERBOSE:-0}"

log()          { printf '▸ %s\n' "$*"; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

# --- 0. Preflight -----------------------------------------------------------------------------------
command -v kubectl >/dev/null || inconclusive "kubectl is required"
command -v jq      >/dev/null || inconclusive "jq is required"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
kubectl version --request-timeout=15s >/dev/null 2>"$WORK/err" \
  || inconclusive "cluster unreachable: $(head -c300 "$WORK/err")"

# --- 1. The RBAC under audit ------------------------------------------------------------------------
kubectl get clusterroles,clusterrolebindings -o json --show-managed-fields >"$WORK/cluster.json" 2>"$WORK/err" \
  || inconclusive "cannot list ClusterRoles/ClusterRoleBindings: $(head -c300 "$WORK/err")"
if [ -n "$RBAC_NAMESPACES" ]; then
  kubectl get roles,rolebindings -A -o json --show-managed-fields >"$WORK/ns-all.json" 2>"$WORK/err" \
    || inconclusive "cannot list Roles/RoleBindings: $(head -c300 "$WORK/err")"
  jq --arg re "$RBAC_NAMESPACES" '{items: [.items[] | select(.metadata.namespace | test($re))]}' \
    "$WORK/ns-all.json" >"$WORK/ns.json"
else
  echo '{"items":[]}' >"$WORK/ns.json"
fi
jq -s '{items: (.[0].items + .[1].items)}' "$WORK/cluster.json" "$WORK/ns.json" >"$WORK/rbac.json"
# Every role that exists, to flag a binding whose roleRef is missing (namespaced Roles are known only
# when Roles are listed).
role_src=("$WORK/cluster.json")
if [ -n "$RBAC_NAMESPACES" ]; then role_src+=("$WORK/ns-all.json"); fi
jq -r '.items[] | select(.kind == "ClusterRole" or .kind == "Role")
  | .kind + "/" + (if (.metadata.namespace // "") != "" then .metadata.namespace + "/" else "" end) + .metadata.name' \
  "${role_src[@]}" >"$WORK/roles.txt"

# --- 2. Crossplane: RBAC that provider-kubernetes Objects manage ------------------------------------
# Only identities leave jq — Objects can embed Secret manifests, which are never written to disk.
: >"$WORK/xp.txt"
xp_kinds="$(kubectl api-resources --api-group=kubernetes.crossplane.io -o name 2>/dev/null || true)"
if grep -qx 'objects.kubernetes.crossplane.io' <<<"$xp_kinds"; then
  if ! kubectl get objects.kubernetes.crossplane.io -o json 2>/dev/null \
      | jq -r '.items[]
          | select((.spec.managementPolicies // ["*"]) | any(. == "*" or . == "Create" or . == "Update"))
          | .spec.forProvider.manifest // empty
          | select(.kind == "ClusterRole" or .kind == "ClusterRoleBinding" or .kind == "Role" or .kind == "RoleBinding")
          | .kind + "/" + (if (.metadata.namespace // "") != "" then .metadata.namespace + "/" else "" end) + (.metadata.name // "")' \
      >"$WORK/xp.txt"; then
    log "note: cannot list Crossplane Objects — RBAC they manage may be reported as unmanaged"
    : >"$WORK/xp.txt"
  fi
fi

# --- 3. ArgoCD: tracking method + Applications (to check tracking-ids, not trust them) --------------
tracking="$ARGOCD_TRACKING"
if [ "$tracking" = auto ]; then
  tracking="$(kubectl -n "$ARGOCD_NS" get configmap argocd-cm -o jsonpath='{.data.application\.resourceTrackingMethod}' 2>/dev/null || true)"
  if [ -z "$tracking" ]; then
    img="$(kubectl -n "$ARGOCD_NS" get deployment argocd-server -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)"
    case "$img" in
      *:v[3-9].*|*:v[1-9][0-9].*) tracking=annotation ;; # Argo CD 3.x+ default
      *:v[12].*)                  tracking=label ;;      # Argo CD 1.x/2.x default
      *)                          tracking=annotation+label ;;
    esac
  fi
fi
apps_ok=true
if ! kubectl get applications.argoproj.io -A -o json 2>/dev/null \
    | jq -r '.items[] | (.metadata.namespace + "/" + .metadata.name) as $app
        | ("app\t" + $app),
          (.status.resources[]? | select(.requiresPruning == true)
            | "prune\t" + .kind + "/" + (if (.namespace // "") != "" then .namespace + "/" else "" end) + .name)' \
    >"$WORK/argo.tsv"; then
  apps_ok=false
  : >"$WORK/argo.tsv"
  log "note: cannot list ArgoCD Applications — tracking-ids are trusted, not checked"
fi

# --- 4. Classify ------------------------------------------------------------------------------------
words() { printf '%s\n' "$*" | tr -s ', \t' '\n\n\n' | jq -Rn '[inputs | select(length > 0)]'; }
allow="$(words "$RBAC_ALLOW_DEFAULT" "$RBAC_ALLOW")"
weak="$(words "$RBAC_WEAK_MANAGED_BY")"
case "$tracking" in *annotation*) ann=true ;; *) ann=false ;; esac
case "$tracking" in *label*) lbl=true ;; *) lbl=false ;; esac

jq --rawfile xp "$WORK/xp.txt" --rawfile argo "$WORK/argo.tsv" --rawfile roles "$WORK/roles.txt" \
   --argjson allow "$allow" --argjson weak "$weak" --argjson nsroles "$([ -n "$RBAC_NAMESPACES" ] && echo true || echo false)" \
   --arg hand "$RBAC_HAND_MANAGERS" --arg argons "$ARGOCD_NS" --argjson ann "$ann" --argjson lbl "$lbl" \
   --argjson appsok "$apps_ok" '
  def toset: reduce (split("\n")[] | select(length > 0)) as $x ({}; .[$x] = true);
  ($xp | toset) as $xpset
  | ($roles | toset) as $roleset
  | ($argo | split("\n") | map(select(startswith("app\t")) | ltrimstr("app\t")) | join("\n") | toset) as $apps
  | ($argo | split("\n") | map(select(startswith("prune\t")) | ltrimstr("prune\t")) | join("\n") | toset) as $prune
  | [ .items[]
      | .kind as $k | (.metadata.namespace // "") as $ns | .metadata.name as $n
      | ($k + "/" + (if $ns == "" then "" else $ns + "/" end) + $n) as $id
      | (.metadata.labels // {}) as $l | (.metadata.annotations // {}) as $a
      | ([(.metadata.managedFields // [])[] | .manager // empty] | unique) as $mgrs
      | (($mgrs | length) > 0 and ($mgrs | all(test($hand) | not))) as $programOnly
      | ($a["argocd.argoproj.io/tracking-id"] // "") as $tid
      | (if $tid == "" then null
         else ($tid | capture("^(?<app>[^:]+):(?<group>[^/]*)/(?<kind>[^:]+):(?<ns>[^/]*)/(?<name>.+)$")? // {bad: true}) end) as $t
      | ($l["app.kubernetes.io/managed-by"] // "") as $mb
      | ( if ((.metadata.ownerReferences // []) | length) > 0 then {managed: "owner"}
          elif $ann and $t != null then
            ( if $t.bad then {finding: "its ArgoCD tracking-id is malformed (\($tid))"}
              elif $t.kind != $k or $t.name != $n or ($ns != "" and $t.ns != $ns) then
                {finding: "its ArgoCD tracking-id names a different object (\($tid)) — copied, not tracked"}
              elif $appsok and ($apps[(if ($t.app | contains("_")) then ($t.app | sub("_"; "/")) else $argons + "/" + $t.app end)] | not) then
                {finding: "its ArgoCD tracking-id names Application \"\($t.app)\", which no longer exists"}
              elif $prune[$id] then {finding: "its ArgoCD Application marks it requiresPruning — removed from git, still live"}
              else {managed: "argocd"} end )
          elif $lbl and (($l["app.kubernetes.io/instance"] // "") != "") then {managed: "argocd"}
          elif $mb == "Helm" or (($a["meta.helm.sh/release-name"] // "") != "") then {managed: "helm"}
          elif $xpset[$id] then {managed: "crossplane"}
          elif $mb != "" and ($weak | any(. == $mb) | not) then {managed: "managed-by"}
          elif ($l["kubernetes.io/bootstrapping"] // "") == "rbac-defaults" then {managed: "system"}
          elif ($n | startswith("system:")) and $programOnly then {managed: "system"}
          elif (($l["objectset.rio.cattle.io/hash"] // "") != "") or (($a["objectset.rio.cattle.io/id"] // "") != "")
               or (($l["addonmanager.kubernetes.io/mode"] // "") != "") then {managed: "k3s"}
          elif $programOnly then {managed: "controller"}
          else {finding: "no owner, GitOps tracking, chart, controller or default manages it", unowned: true} end ) as $c
      | (if $c.finding and ($allow | any(. as $re | $id | test("^(" + $re + ")$"))) then {managed: "allow"} else $c end) as $c
      | (($a["openinfra.dev/rbac-unmanaged-reason"] // "") | gsub("^\\s+|\\s+$"; "")) as $why
      | (if $c.unowned and $why != "" then {managed: "acknowledged", reason: $why} else $c end) as $c
      | { id: $id, kind: $k, ns: $ns, name: $n, created: .metadata.creationTimestamp, managers: $mgrs,
          roleRef: .roleRef, subjects: (.subjects // []), rules: (.rules // []),
          aggregated: (.aggregationRule != null),
          dangling: (if .roleRef == null then false
                     elif .roleRef.kind == "ClusterRole" then ($roleset["ClusterRole/" + .roleRef.name] | not)
                     elif $nsroles then ($roleset["Role/" + $ns + "/" + .roleRef.name] | not)
                     else false end) } + $c ]
' "$WORK/rbac.json" >"$WORK/classified.json"

total="$(jq 'length' "$WORK/classified.json")"
nfind="$(jq '[.[] | select(.finding)] | length' "$WORK/classified.json")"
log "audited ${total} RBAC objects: $(jq -r 'group_by(.kind) | map("\(length) \(.[0].kind)") | join(", ")' "$WORK/classified.json") (Role/RoleBinding namespaces: ${RBAC_NAMESPACES:-none}; ArgoCD tracking: ${tracking})"
if [ "$RBAC_VERBOSE" = 1 ]; then
  log "managed, by signal: $(jq -r '[.[] | select(.managed)] | group_by(.managed) | map("\(.[0].managed)=\(length)") | join(" ")' "$WORK/classified.json")"
fi

# --- 5. Report --------------------------------------------------------------------------------------
in_repo() { # in_repo <name>: the repo files that declare `name: <name>`, if any
  [ -n "$RBAC_REPO_DIR" ] && [ -d "$RBAC_REPO_DIR" ] || return 0
  local re
  re="name:[[:space:]]*[\"']?$(printf '%s' "$1" | sed 's/[][\.*^$+?(){}|/]/\\&/g')[\"']?([[:space:]]*[,}#]|[[:space:]]*\$)"
  if git -C "$RBAC_REPO_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$RBAC_REPO_DIR" grep -lE "$re" -- '*.yaml' '*.yml' '*.sh' 2>/dev/null | head -3 | paste -sd' ' - || true
  else
    grep -rlE "$re" --include='*.yaml' --include='*.yml' --include='*.sh' --exclude-dir=.git \
      --exclude-dir=node_modules --exclude-dir=.claude "$RBAC_REPO_DIR" 2>/dev/null | head -3 | paste -sd' ' - || true
  fi
}

# describe <id> <name> <mark>: one object's header, writers, and its subjects or rules.
describe() {
  jq -r --arg id "$1" --arg mark "$3" '
    def rule: (if .nonResourceURLs then "nonResource " + (.nonResourceURLs | join(","))
               else ((.apiGroups // [""]) | map(if . == "" then "core" else . end) | join(",")) + "/"
                    + ((.resources // []) | join(",")) end)
              + (if (.resourceNames // []) | length > 0 then "[" + (.resourceNames | join(",")) + "]" else "" end)
              + ": " + ((.verbs // []) | join(","));
    def flags: [ (if any(.[]; any((.verbs // [])[]; . == "*") or any((.resources // [])[]; . == "*")) then "wildcard" else empty end),
                 (if any(.[]; any((.resources // [])[]; . == "secrets")) then "secrets" else empty end),
                 (if any(.[]; any((.verbs // [])[]; . == "escalate" or . == "bind" or . == "impersonate")) then "escalate/bind/impersonate" else empty end) ];
    .[] | select(.id == $id) |
    (if .finding then "\($mark) \(.id) — \(.finding)" else "\($mark) \(.id) — acknowledged: \(.reason)" end),
    "    written by: \(if (.managers | length) > 0 then (.managers | join(", ")) else "(no managedFields)" end) · created \(.created)",
    ( if .roleRef then
        "    roleRef: \(.roleRef.kind)/\(.roleRef.name)" + (if .roleRef.name == "cluster-admin" then "   ⚠ cluster-admin" else "" end)
          + (if .dangling then "   ⚠ does not exist — dangling: creating that role would activate this binding" else "" end),
        "    subjects: " + (if (.subjects | length) == 0 then "(none)"
                           else (.subjects | map(.kind + " " + (if (.namespace // "") != "" then .namespace + "/" else "" end) + .name) | join("; ")) end)
      else
        "    rules (\(.rules | length))\(if .aggregated then ", aggregated" else "" end): "
          + ((.rules[:6] | map(rule) | join(" · ")) + (if (.rules | length) > 6 then " · (+\((.rules | length) - 6) more)" else "" end))
          + ((.rules | flags) as $f | if ($f | length) > 0 then "   ⚠ " + ($f | join(", ")) else "" end)
      end )
  ' "$WORK/classified.json"
  if [ -n "$RBAC_REPO_DIR" ] && [ -d "$RBAC_REPO_DIR" ]; then
    where="$(in_repo "$2")"
    if [ -n "$where" ]; then
      echo "    repo: named in ${where} — in the repo but not tracked (applied out of band)"
    else
      echo "    repo: not found — live-only"
    fi
  fi
}

# --- 6. User authority outside the generated set ----------------------------------------------------
# IAM policy is the only place a console or shim principal's authority is written: the iam-compiler
# generates the RBAC that still enforces (label openinfra.dev/generated-by: iam-compiler). Any other
# binding — in ANY namespace — whose subject is an openinfra:* User or Group is user authority granted by
# hand, and a finding, except: the break-glass binding (openinfra-root-break-glass, exactly the management
# account's root) and an object acknowledged with openinfra.dev/rbac-unmanaged-reason. The legacy tiers
# were deleted at the IAM cutover's last step. No composition renders a user
# binding (a Group is a container of policies, a Grant attaches policies), so a binding named like one is a
# finding too. The repo-side twin is test/render/rbac_user_authority_test.go.
if [ -f "$WORK/ns-all.json" ]; then
  cp "$WORK/ns-all.json" "$WORK/rb-all.json"   # every namespace's Roles and RoleBindings, listed above
else
  kubectl get rolebindings -A -o json >"$WORK/rb-all.json" 2>"$WORK/err" \
    || inconclusive "cannot list RoleBindings: $(head -c300 "$WORK/err")"
fi
jq -s '[ (.[0].items[] | select(.kind == "ClusterRoleBinding")), .[1].items[] ]
  | map(select(any(.subjects[]?; (.kind == "User" or .kind == "Group") and (.name | startswith("openinfra:")))))
  | map(select(
      ((.metadata.labels // {})["openinfra.dev/generated-by"] != "iam-compiler")
      and (((.metadata.annotations // {})["openinfra.dev/rbac-unmanaged-reason"] // "") == "")
      and ((.metadata.name == "openinfra-root-break-glass" and .kind == "ClusterRoleBinding"
            and (.subjects | length) == 1 and .subjects[0].kind == "User"
            and .subjects[0].name == "openinfra:000000000000:root") | not)))
  | map({id: (.kind + "/" + (if (.metadata.namespace // "") != "" then .metadata.namespace + "/" else "" end) + .metadata.name),
         roleRef: (.roleRef.kind + "/" + .roleRef.name),
         subjects: ([.subjects[] | select((.kind == "User" or .kind == "Group") and (.name | startswith("openinfra:"))) | .kind + " " + .name] | join("; "))})' \
  "$WORK/cluster.json" "$WORK/rb-all.json" >"$WORK/user-authority.json"
nuser="$(jq 'length' "$WORK/user-authority.json")"
if [ "$nuser" -gt 0 ]; then
  echo
  echo "✗ ${nuser} binding(s) grant a console or shim principal authority outside the generated set (IAM policy is the source; the iam-compiler generates the RBAC):"
  jq -r '.[] | "✗ \(.id) — roleRef \(.roleRef) — subjects \(.subjects)"' "$WORK/user-authority.json" | sort
fi

# Acknowledged objects are printed on every run, pass or fail: an annotation ends the finding, not
# the review.
nack="$(jq '[.[] | select(.managed == "acknowledged")] | length' "$WORK/classified.json")"
if [ "$nack" -gt 0 ]; then
  echo
  echo "ℹ ${nack} unmanaged RBAC object(s) acknowledged (annotation openinfra.dev/rbac-unmanaged-reason):"
  jq -r '.[] | select(.managed == "acknowledged") | [.id, .name] | @tsv' "$WORK/classified.json" | sort \
    | while IFS=$'\t' read -r id name; do describe "$id" "$name" "ℹ"; done
fi

if [ "$nfind" -eq 0 ]; then
  echo
  if [ "$nuser" -gt 0 ]; then
    printf '✗ every audited RBAC object is managed, but %s binding(s) grant user authority outside the generated set (above).\n' "$nuser"
    exit 1
  fi
  ack_note=""; [ "$nack" -gt 0 ] && ack_note=" or acknowledged"
  echo "✓ PASS — every audited ClusterRole/ClusterRoleBinding/Role/RoleBinding is managed${ack_note}."
  echo "✓ no binding grants a console or shim principal authority outside the generated set."
  exit 0
fi

echo
jq -r '.[] | select(.finding) | [.id, .name] | @tsv' "$WORK/classified.json" | sort \
  | while IFS=$'\t' read -r id name; do describe "$id" "$name" "✗"; done

echo
printf '✗ %s unmanaged RBAC object(s) of %s audited — bring each under GitOps (or its operator), delete it, allow-list it (RBAC_ALLOW), or acknowledge it with the annotation openinfra.dev/rbac-unmanaged-reason.\n' "$nfind" "$total"
exit 1
