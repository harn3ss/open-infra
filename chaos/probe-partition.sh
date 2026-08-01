#!/usr/bin/env bash
# Proof-of-fire probe — oracle pillar 1 for the network fault scenarios. See
# docs/chaos-oracle.md. Do NOT trust the injector's own status (that's the 2026-07-23
# failure: the fault silently didn't fire and the night went green on a lie). Instead
# witness the fault directly, from the same path the mesh uses.
#
# The mesh reaches site B via the a→b sink pod, and the fault targets exactly the
# sink↔B link. So we attach an ephemeral busybox to the sink pod (sharing its netns and
# its pod IP — the IP B's rules target) and TIME a TCP handshake to pg-b:5432, a
# guaranteed listener. We measure the handshake wall-time with busybox `time` (0.01s
# resolution — busybox `date` has no %N, so `time` is the only sub-second clock we get):
#
#   fast connect (< FAST_MAX, default 0.30s)   → up    (healthy)
#   connects, but slow (>= FAST_MAX)           → slow  (latency degrade — link intact but delayed)
#   connect fails within CONNECT_TIMEOUT       → down  (cut)
#
#   probe-partition.sh up     -> exit 0 if the link is OPEN & fast
#   probe-partition.sh slow   -> exit 0 if the link is UP but DELAYED
#   probe-partition.sh down   -> exit 0 if the link is CUT
#   (exit 2 = infrastructure error — treat as INCONCLUSIVE, never as green)
set -uo pipefail

NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
EXPECT="${1:?usage: probe-partition.sh up|slow|down}"
SINK_LABEL="${SINK_LABEL:-app=chaos-mesh-pg-repl-a-b-sink}"
TARGET="${PROBE_TARGET:-pg-b}"
PORT="${PROBE_PORT:-5432}"
IMG="${PROBE_IMAGE:-busybox:1.36}"
FAST_MAX="${PROBE_FAST_MAX:-0.30}"       # seconds: at/above this a live link counts as `slow`
CONNECT_TIMEOUT="${PROBE_CONNECT_TIMEOUT:-6}"  # nc -w: fail => `down`. Must exceed 2× injected latency.

sink="$(kubectl -n "$NS" get pod -l "$SINK_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
[ -n "$sink" ] || { echo "probe: no sink pod ($SINK_LABEL) — cannot witness the fault"; exit 2; }
cname="$(kubectl -n "$NS" get pod "$sink" -o jsonpath='{.spec.containers[0].name}' 2>/dev/null)"

# Ephemeral busybox in the sink's netns. busybox ash's `time` keyword prints its report
# ("real\t0m 1.50s") to STDERR — but any redirection on the timed pipeline (e.g.
# `time nc ... >/dev/null 2>&1`) swallows THAT report too, so we must NOT redirect nc.
# `nc -z` is silent without -v, so nothing but the timing lands on stderr. kubectl attach
# streams the container's stderr to OUR stderr, so we merge it with `2>&1` on the host side.
# OI_RC carries nc's real exit so we classify from data, not kubectl debug's exit code.
out="$(kubectl -n "$NS" debug "$sink" --image="$IMG" --target="$cname" -q --attach -- \
        sh -c "time nc -z -w${CONNECT_TIMEOUT} $TARGET $PORT; echo OI_RC=\$?" 2>&1)"

rc="$(printf '%s\n' "$out" | sed -n 's/.*OI_RC=\([0-9]*\).*/\1/p' | head -1)"
# Parse the "real 0m 1.50s" line into total seconds (min*60 + sec).
realsec="$(printf '%s\n' "$out" | awk '/real/{m=0;s=0; for(i=1;i<=NF;i++){ if($i ~ /m$/) m=$i+0; else if($i ~ /s$/) s=$i+0 }; print m*60+s; exit}')"

[ -n "$rc" ] || { echo "probe: could not read handshake result (output: '${out:-<empty>}')"; exit 2; }
if [ "$rc" != "0" ]; then
  state=down
elif [ -z "$realsec" ]; then
  echo "probe: connected but could not time the handshake (output: '${out:-<empty>}')"; exit 2
else
  # awk does the float compare (POSIX sh has no float arithmetic).
  if awk -v r="$realsec" -v f="$FAST_MAX" 'BEGIN{exit !(r < f)}'; then state=up; else state=slow; fi
fi

echo "probe: a→b link to $TARGET:$PORT is $state (handshake=${realsec:-n/a}s rc=$rc, expected: $EXPECT)"
[ "$state" = "$EXPECT" ]
