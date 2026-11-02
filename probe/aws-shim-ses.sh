#!/usr/bin/env bash
# Compatibility probe for the aws-shim SES surface (SES v1: SendEmail / SendRawEmail over the platform
# SMTP relay, the mail component).
#
# Fires REAL AWS SDK calls (the aws CLI) at a deployed shim and asserts what an app that mails through SES
# depends on — that a send which reports a MessageId was really handed to the relay, as the identity it
# names — not merely HTTP 200:
#   - SendEmail returns a MessageId; SendRawEmail (a MIME message whose sender is only its From header)
#     returns one too; GetSendQuota answers
#   - identity verification is refused honestly (the shim will not claim a verified identity no DNS backs)
# and the NEGATIVES:
#   - a principal whose policy grants ses:SendEmail on ONE identity sends as it, and is DENIED as another
#     (SendEmail and SendRawEmail alike: a raw message is authorized as its From header)
#   - a read-only principal is DENIED
# With the relay in capture mode (mail.capture: a test cluster's sink, platform/mail/relay-capture.yaml),
# every message that was accepted is found in the sink, and none that was denied is.
#
# On-demand (needs a deployed shim, the platform IAM and the mail component). Exit 0 = pass, 1 = a real
# failure, 42 = INCONCLUSIVE (a prerequisite was missing — e.g. the mail component is off, so SES is not
# fronted). By policy, a probe failure is presumed a shim defect, and 42 is not a pass.
#
#   SHIM_ENDPOINT=http://localhost:4566 ./probe/aws-shim-ses.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
REGION="${AWS_REGION:-us-east-1}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SENDER="ses-probe-${SFX}@example.test"
OTHER="someone-else-${SFX}@example.test"
RCPT="ses-probe-rcpt-${SFX}@example.test"
TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v aws     >/dev/null || inconclusive "the aws CLI (a real AWS SDK) is required"
command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principals + keys"
command -v python3 >/dev/null || inconclusive "python3 is required"
curl -fsS -m 5 "${ENDPOINT}/healthz" >/dev/null 2>&1 || inconclusive "shim not reachable at ${ENDPOINT} (set SHIM_ENDPOINT / port-forward)"

CREATED_KEYS=(); CREATED_USERS=(); CREATED_POLICIES=()
cleanup() {
  for k in "${CREATED_KEYS[@]:-}";       do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1 || true; done
  for u in "${CREATED_USERS[@]:-}";      do [ -n "$u" ] && kubectl -n "$USERS_NS" delete user.iam.openinfra.dev "$u" --ignore-not-found >/dev/null 2>&1 || true; done
  for p in "${CREATED_POLICIES[@]:-}";   do [ -n "$p" ] && kubectl -n "$USERS_NS" delete policy.iam.openinfra.dev "$p" --ignore-not-found >/dev/null 2>&1 || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }

mint_key() { # <owner> <group>; the key comes back in MK_AK/MK_SK (run in THIS shell, so cleanup sees it)
  local owner="$1" group="$2"
  local ak="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  local sk; sk="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "${owner}", namespace: "${USERS_NS}" }
spec: { displayName: "${owner}", groups: ["${group}"], source: local }
YAML
  CREATED_USERS+=("$owner")
  local name; name="$(secret_name "$ak")"
  kubectl -n "$SHIM_NS" create secret generic "$name" \
    --from-literal=accessKeyId="$ak" --from-literal=secretKey="$sk" --from-literal=owner="$owner" >/dev/null
  CREATED_KEYS+=("$name")
  MK_AK="$ak"; MK_SK="$sk"
}

ses() { # AK SK -- <ses args...>
  local ak="$1" sk="$2"; shift 2
  AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_REGION="$REGION" \
    aws --endpoint-url "$ENDPOINT" --no-cli-pager --output text ses "$@"
}
send() { # AK SK FROM SUBJECT
  ses "$1" "$2" send-email --from "$3" --destination "ToAddresses=$RCPT" --query MessageId \
    --message "Subject={Data=$4},Body={Text={Data=sent by the ses probe}}"
}
send_raw() { # AK SK FROM SUBJECT — the sender is only the message's From header
  printf 'From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\nraw, sent by the ses probe\r\n' "$3" "$RCPT" "$4" > "$TMP/raw.eml"
  python3 -c 'import json,sys; json.dump({"Data": open(sys.argv[1], newline="").read()}, open(sys.argv[2], "w"))' "$TMP/raw.eml" "$TMP/raw.json"
  ses "$1" "$2" send-raw-email --cli-binary-format raw-in-base64-out --raw-message "file://$TMP/raw.json" --query MessageId
}

# --- 1. principals ------------------------------------------------------------------------------------
log "seeding a sender (openinfra:admins), a sender scoped to one identity, and a reader"
mint_key "ses-probe-$SFX" "admins"; AAK="$MK_AK"; ASK="$MK_SK"
mint_key "ses-probe-scoped-$SFX" "admins"; SAK="$MK_AK"; SSK="$MK_SK"
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: iam.openinfra.dev/v1
kind: Policy
metadata: { name: "ses-probe-scoped-$SFX", namespace: "${USERS_NS}" }
spec:
  dataPlane:
    appliesTo: ["User::ses-probe-scoped-$SFX"]
    statements:
      - { effect: Allow, actions: ["ses:SendEmail", "ses:SendRawEmail"], resources: ["Identity::$SENDER"] }
YAML
CREATED_POLICIES+=("ses-probe-scoped-$SFX")
mint_key "ses-probe-reader-$SFX" "readers"; RAK="$MK_AK"; RSK="$MK_SK"
sleep 3

# --- 2. SES is fronted (the mail component is on) -----------------------------------------------------
Q="$(ses "$AAK" "$ASK" get-send-quota --query Max24HourSend 2>"$TMP/q.err" || true)"
if grep -q NotImplemented "$TMP/q.err"; then
  inconclusive "SES is not fronted: the mail component (the platform SMTP relay) is off — $(tr '\n' ' ' < "$TMP/q.err")"
fi
[ -n "$Q" ] || fail "GetSendQuota failed: $(tr '\n' ' ' < "$TMP/q.err")"
log "  ✓ GetSendQuota answers (Max24HourSend=$Q)"

# --- 3. SendEmail + SendRawEmail ----------------------------------------------------------------------
log "send-email and send-raw-email as $SENDER"
ID1="$(send "$AAK" "$ASK" "$SENDER" "ses-probe $SFX send-email" 2>"$TMP/e1")" || fail "send-email failed: $(tr '\n' ' ' < "$TMP/e1")"
[ -n "$ID1" ] && [ "$ID1" != None ] || fail "send-email returned no MessageId"
ID2="$(send_raw "$AAK" "$ASK" "$SENDER" "ses-probe $SFX send-raw-email" 2>"$TMP/e2")" || fail "send-raw-email failed: $(tr '\n' ' ' < "$TMP/e2")"
[ -n "$ID2" ] && [ "$ID2" != None ] || fail "send-raw-email returned no MessageId"
log "  ✓ MessageIds $ID1, $ID2"

# --- 4. identity verification is refused honestly ----------------------------------------------------
ERR="$(ses "$AAK" "$ASK" verify-email-identity --email-address "$SENDER" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q InvalidParameterValue || fail "VerifyEmailIdentity should be refused (InvalidParameterValue): $ERR"
log "  ✓ VerifyEmailIdentity refused (no identity the DNS does not back)"

# --- 5. the identity a policy names, and only it ------------------------------------------------------
log "a principal granted ses:Send* on Identity::$SENDER only"
send "$SAK" "$SSK" "$SENDER" "ses-probe $SFX scoped-allowed" >/dev/null 2>"$TMP/e3" || fail "the scoped principal could not send as its identity: $(tr '\n' ' ' < "$TMP/e3")"
ERR="$(send "$SAK" "$SSK" "$OTHER" "ses-probe $SFX scoped-denied" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "sending as another identity should be AccessDenied: $ERR"
ERR="$(send_raw "$SAK" "$SSK" "$OTHER" "ses-probe $SFX scoped-raw-denied" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a raw message From another identity should be AccessDenied: $ERR"
log "  ✓ sends as its identity; DENIED as another (SendEmail and SendRawEmail)"
ERR="$(send "$RAK" "$RSK" "$SENDER" "ses-probe $SFX reader-denied" 2>&1 >/dev/null || true)"
printf '%s' "$ERR" | grep -q AccessDenied || fail "a reader's send-email should be AccessDenied: $ERR"
log "  ✓ a reader is DENIED"

# --- 6. what was accepted reached the relay (capture mode) -------------------------------------------
if [ "$(kubectl -n mail get deploy smtp-relay -o jsonpath='{.metadata.labels.openinfra\.dev/mail-capture}' 2>/dev/null)" = true ]; then
  SUBJECTS="$(kubectl -n mail exec deploy/smtp-relay -- wget -qO- 'http://127.0.0.1:8025/api/v1/messages?limit=500' 2>/dev/null \
    | python3 -c 'import json,sys; print("\n".join(m.get("Subject","") for m in json.load(sys.stdin).get("messages",[])))' || true)"
  for s in send-email send-raw-email scoped-allowed; do
    printf '%s\n' "$SUBJECTS" | grep -qx "ses-probe $SFX $s" || fail "the capturing relay has no message 'ses-probe $SFX $s'"
  done
  for s in scoped-denied scoped-raw-denied reader-denied; do
    printf '%s\n' "$SUBJECTS" | grep -qx "ses-probe $SFX $s" && fail "a DENIED send reached the relay: 'ses-probe $SFX $s'"
  done
  log "  ✓ the capturing relay holds the 3 accepted messages and none of the 3 denied"
else
  log "  (the relay delivers — not in capture mode — so the sink check is skipped)"
fi

log "✓ PASS — the aws-shim SES front door hands each accepted message to the platform relay, as the identity the caller's policy grants, and refuses the rest"
