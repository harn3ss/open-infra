#!/usr/bin/env bash
# Statistical proof-of-fire for the network-LOSS degrade (oracle pillar 1; see
# docs/chaos-oracle.md). A SINGLE handshake can't witness probabilistic loss — it either
# happens to hit a dropped packet or doesn't. So sample N handshakes from the sink netns
# (the same path the mesh applies through) and assert the *impaired fraction* is non-trivial
# but not total: 0 means loss isn't biting (INCONCLUSIVE, not green); 100% means it's a cut,
# not loss.
#
# Each sample is a TCP connect with a 1s deadline. With no loss the same-netns handshake
# completes in <1ms → success. When a SYN or SYN-ACK is dropped there's no response and the
# kernel's first retransmit lands at ~1s (initial RTO) — at/after the deadline — so a
# loss-hit handshake fails within the window. The fraction that fail is therefore a direct,
# if coarse, estimate of the loss biting the link.
#
#   probe-loss.sh lossy  -> exit 0 if a non-trivial FRACTION of samples are impaired
#   probe-loss.sh clean  -> exit 0 if (near) ALL samples succeed (no loss biting)
#   (exit 2 = infrastructure error — treat as INCONCLUSIVE, never as green)
set -uo pipefail

NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
EXPECT="${1:?usage: probe-loss.sh lossy|clean}"
SINK_LABEL="${SINK_LABEL:-app=chaos-mesh-pg-repl-a-b-sink}"
TARGET="${PROBE_TARGET:-pg-b}"
PORT="${PROBE_PORT:-5432}"
IMG="${PROBE_IMAGE:-busybox:1.36}"
SAMPLES="${LOSS_SAMPLES:-20}"               # enough samples to keep binomial variance low
PERCONN_TIMEOUT="${LOSS_CONN_TIMEOUT:-1}"   # -w per handshake; a loss-hit connect fails within this
# Floor set BELOW the empirical 15%-loss signal (~0.17–0.28 impaired), well ABOVE clean (0.00),
# so a moderate loss reliably reads `lossy` without a variance dip tripping a false INCONCLUSIVE.
LOSSY_MIN="${LOSS_MIN_FRAC:-0.10}"          # impaired fraction must be >= this (loss is biting)
LOSSY_MAX="${LOSS_MAX_FRAC:-0.98}"          # ...and < this (else it's a cut, not a degrade)
CLEAN_MAX="${CLEAN_MAX_FRAC:-0.05}"         # `clean` = at most this fraction impaired

sink="$(kubectl -n "$NS" get pod -l "$SINK_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)"
[ -n "$sink" ] || { echo "probe-loss: no sink pod ($SINK_LABEL) — cannot witness loss"; exit 2; }
cname="$(kubectl -n "$NS" get pod "$sink" -o jsonpath='{.spec.containers[0].name}' 2>/dev/null)"

# Run ALL samples inside ONE ephemeral container — kubectl debug's per-call overhead is
# seconds, so N separate probes would be far too slow.
out="$(kubectl -n "$NS" debug "$sink" --image="$IMG" --target="$cname" -q --attach -- \
  sh -c "ok=0; i=0; while [ \$i -lt $SAMPLES ]; do nc -z -w$PERCONN_TIMEOUT $TARGET $PORT >/dev/null 2>&1 && ok=\$((ok+1)); i=\$((i+1)); done; echo OI_OK=\$ok OI_N=$SAMPLES" 2>&1)"

ok="$(printf '%s\n' "$out" | sed -n 's/.*OI_OK=\([0-9]*\).*/\1/p' | head -1)"
n="$(printf '%s\n' "$out" | sed -n 's/.*OI_N=\([0-9]*\).*/\1/p' | head -1)"
{ [ -n "$ok" ] && [ -n "$n" ] && [ "$n" -gt 0 ]; } || { echo "probe-loss: could not sample (output: '${out:-<empty>}')"; exit 2; }

impaired=$(( n - ok ))
frac="$(awk -v a="$impaired" -v b="$n" 'BEGIN{printf "%.2f", a/b}')"
echo "probe-loss: $impaired/$n handshakes impaired (frac=$frac, expected: $EXPECT)"
case "$EXPECT" in
  lossy) awk -v f="$frac" -v lo="$LOSSY_MIN" -v hi="$LOSSY_MAX" 'BEGIN{exit !(f>=lo && f<hi)}' ;;
  clean) awk -v f="$frac" -v hi="$CLEAN_MAX" 'BEGIN{exit !(f<=hi)}' ;;
  *) echo "probe-loss: unknown expectation '$EXPECT' (use lossy|clean)"; exit 2 ;;
esac
