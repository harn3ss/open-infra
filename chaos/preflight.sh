#!/usr/bin/env bash
# Pre-flight guard for the Nightly Chaos Suite (design §3, layer 5: the dead-man's
# switch). Given a kind: FaultInjection manifest, it resolves the effective target and
# REFUSES to proceed unless the fault can only touch the chaos-sandbox namespace.
#
# This is the typo-catcher: a fault that names another namespace, or a label selector
# that also matches a pod outside the sandbox, aborts here — before anything is applied.
#
#   usage: chaos/preflight.sh <faultinjection.yaml>
#   exit 0 = safe to apply;  exit >0 = ABORT (never apply the fault).
set -euo pipefail

SANDBOX="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
FILE="${1:?usage: preflight.sh <faultinjection.yaml>}"

# Parse the manifest (namespace + target) without assuming yq is installed. Pipe-
# delimited (a non-whitespace IFS) so an empty target.namespace field is preserved —
# whitespace delimiters collapse consecutive separators and would drop it.
IFS='|' read -r FI_NS TGT_NS SEL < <(python3 - "$FILE" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
meta = d.get("metadata", {}) or {}
spec = d.get("spec", {}) or {}
tgt = spec.get("target", {}) or {}
labels = tgt.get("labelSelector", {}) or {}
sel = ",".join(f"{k}={v}" for k, v in labels.items())
print("|".join([meta.get("namespace", ""), tgt.get("namespace", ""), sel or "<none>"]))
PY
)

EFFECTIVE_NS="${TGT_NS:-$FI_NS}"

echo "preflight: fault ns=${FI_NS:-<none>} target.namespace=${TGT_NS:-<none>} → effective=${EFFECTIVE_NS:-<none>} selector=${SEL}"

abort() { echo "PREFLIGHT ABORT: $*" >&2; exit 3; }

[ -n "$EFFECTIVE_NS" ] || abort "could not determine the fault's namespace"
[ "$EFFECTIVE_NS" = "$SANDBOX" ] || \
  abort "fault targets namespace '$EFFECTIVE_NS', not '$SANDBOX' — refusing to touch anything outside the sandbox"
[ "$SEL" != "<none>" ] || abort "fault has no target.labelSelector — refusing an unscoped fault"

# Resolve the selector cluster-wide (read-only) and confirm every matched pod is in the
# sandbox. A selector that also matches a kube-system / app / node-adjacent pod aborts.
OUTSIDE="$(kubectl get pods -A -l "$SEL" \
  -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}' 2>/dev/null \
  | grep -v "^${SANDBOX}/" || true)"

if [ -n "$OUTSIDE" ]; then
  echo "$OUTSIDE" | sed 's/^/  offending: /' >&2
  abort "selector '$SEL' matches pod(s) OUTSIDE '$SANDBOX' (above) — this fault could hit real workloads"
fi

INSANDBOX="$(kubectl get pods -n "$SANDBOX" -l "$SEL" -o name 2>/dev/null | wc -l | tr -d ' ')"
if [ "$INSANDBOX" = "0" ]; then
  echo "preflight: WARNING — selector matches 0 pods in $SANDBOX (fault will be a no-op; possible typo)" >&2
fi

echo "preflight OK: fault is contained to $SANDBOX ($INSANDBOX matching pod(s))."
