#!/usr/bin/env bash
# Proof-of-fire probe — oracle pillar 1 for the network-partition scenario. See
# docs/chaos-oracle.md. Do NOT trust the injector's own status (that's the 2026-07-23
# failure: the fault silently didn't fire and the night went green on a lie). Instead
# witness the CUT directly, from the same path the mesh uses.
#
# The mesh reaches site B via the a→b sink pod, and the partition drops exactly the
# sink↔B link. So we attach an ephemeral busybox to the sink pod (sharing its netns and
# its pod IP — the IP B's drop rules target) and try to reach pg-b:5432, a guaranteed
# listener. During the fault this MUST fail; before/after it must succeed.
#
#   probe-partition.sh up     -> exit 0 if the link is OPEN,  1 if cut
#   probe-partition.sh down   -> exit 0 if the link is CUT,   1 if open
#   (exit 2 = infrastructure error — treat as INCONCLUSIVE, never as green)
set -uo pipefail

NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
EXPECT="${1:?usage: probe-partition.sh up|down}"
SINK_LABEL="${SINK_LABEL:-app=chaos-mesh-pg-repl-a-b-sink}"
TARGET="${PROBE_TARGET:-pg-b}"
PORT="${PROBE_PORT:-5432}"
IMG="${PROBE_IMAGE:-busybox:1.36}"

sink="$(kubectl -n "$NS" get pod -l "$SINK_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
[ -n "$sink" ] || { echo "probe: no sink pod ($SINK_LABEL) — cannot witness the cut"; exit 2; }
cname="$(kubectl -n "$NS" get pod "$sink" -o jsonpath='{.spec.containers[0].name}' 2>/dev/null)"

# Ephemeral busybox in the sink's netns; emit a marker we parse (kubectl debug's own exit
# code isn't a reliable proxy for the probed command).
out="$(kubectl -n "$NS" debug "$sink" --image="$IMG" --target="$cname" -q --attach -- \
        sh -c "nc -z -w3 $TARGET $PORT && echo OI_OPEN || echo OI_CUT" 2>/dev/null)"
case "$out" in
  *OI_OPEN*) state=up ;;
  *OI_CUT*)  state=down ;;
  *) echo "probe: could not determine link state (output: '${out:-<empty>}')"; exit 2 ;;
esac

echo "probe: a→b link to $TARGET:$PORT is $state (expected: $EXPECT)"
[ "$state" = "$EXPECT" ]
