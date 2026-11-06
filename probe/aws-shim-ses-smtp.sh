#!/usr/bin/env bash
# Compatibility probe for the aws-shim SES SMTP interface (Amazon SES's email-smtp endpoint): SMTP submission
# with SES SMTP credentials — an IAM user's access key id, and the SMTP password derived from its secret with
# AWS's algorithm — where every message is SendRawEmail as that user.
#
# Drives the interface with Python's smtplib (STARTTLS, AUTH LOGIN), as an app's SMTP library would, and
# asserts what an app that mails through it depends on:
#   - a user whose policy allows ses:SendRawEmail as one address (the policy kind: EmailSender gives its SMTP
#     user) signs in and sends as it: 250 Ok <MessageId>
# and the NEGATIVES:
#   - AUTH before STARTTLS is 530 Must issue a STARTTLS command first (no credential crosses in clear)
#   - a wrong password is 535 Authentication Credentials Invalid
#   - a message whose From header is another address, and a user with no ses:SendRawEmail, are 554 Access denied
#   - in a member account (a throwaway one this run creates), a From address the account has not verified is
#     554 Message rejected: Email address is not verified; once its kind: Account verifies the domain (and
#     grants production access), the same send is delivered
# With the relay in capture mode (mail.capture: platform/mail/relay-capture.yaml), every accepted message is in
# the sink and no refused one is.
#
# On-demand (needs a deployed shim with its SMTP interface, the platform IAM, the Account kind and the mail
# component; kubectl as a cluster administrator). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE (a
# prerequisite was missing). A probe failure is presumed a shim defect, and 42 is not a pass.
#
#   ./probe/aws-shim-ses-smtp.sh                                     # in-cluster: the shim's Service, port 587
#   kubectl -n open-infra-aws-shim port-forward svc/aws-shim 10587:587 &
#   SES_SMTP_HOST=127.0.0.1 SES_SMTP_PORT=10587 ./probe/aws-shim-ses-smtp.sh
set -uo pipefail

EXIT_INCONCLUSIVE=42
SHIM_NS="${SHIM_NS:-open-infra-aws-shim}"
USERS_NS="${USERS_NS:-open-infra-console}"
ENDPOINT="${SHIM_ENDPOINT:-http://aws-shim.${SHIM_NS}.svc.cluster.local:4566}"
SMTP_HOST="${SES_SMTP_HOST:-aws-shim.${SHIM_NS}.svc.cluster.local}"
SMTP_PORT="${SES_SMTP_PORT:-587}"
SETTLE="${IAM_SETTLE_SECONDS:-35}"
SFX="$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SENDER="smtp-probe-${SFX}@example.test"
OTHER="someone-else-${SFX}@example.test"
RCPT="smtp-probe-rcpt-${SFX}@example.test"
MDOMAIN="smtp-probe-${SFX}.example.test"   # the member account's domain, verified mid-run
TMP="$(mktemp -d)"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v kubectl >/dev/null || inconclusive "kubectl is required to seed the principals, keys and account"
command -v python3 >/dev/null || inconclusive "python3 is required (smtplib)"
kubectl get crd accounts.organizations.openinfra.dev >/dev/null 2>&1 || inconclusive "the Account kind is not installed"
kubectl -n mail get svc smtp-relay >/dev/null 2>&1 || inconclusive "the mail component (the platform SMTP relay) is off, so SES is not served"
kubectl -n "$SHIM_NS" get secret aws-shim-internal-tls >/dev/null 2>&1 \
  || inconclusive "the shim's in-cluster certificate (aws-shim-internal-tls) is not issued yet, so STARTTLS cannot complete"
REGION="$(kubectl -n "$SHIM_NS" get configmap openinfra-aws-identity -o jsonpath='{.data.AWS_REGION}' 2>/dev/null)"
REGION="${REGION:-us-east-1}"

CREATED_USERS=(); CREATED_KEYS=(); MEMBER_ACCOUNT=""; MEMBER_HOME=""
cleanup() {
  for u in "${CREATED_USERS[@]:-}"; do [ -n "$u" ] && kubectl delete users.iam.openinfra.dev -n "${u%%/*}" "${u#*/}" --ignore-not-found >/dev/null 2>&1; done
  for k in "${CREATED_KEYS[@]:-}"; do [ -n "$k" ] && kubectl -n "$SHIM_NS" delete secret "$k" --ignore-not-found >/dev/null 2>&1; done
  if [ -n "$MEMBER_ACCOUNT" ]; then
    kubectl delete accounts.organizations.openinfra.dev "$MEMBER_ACCOUNT" --ignore-not-found --wait=false >/dev/null 2>&1
  fi
  if [ -n "$MEMBER_HOME" ]; then
    # Only the namespace this run's account created (younger than the probe).
    created="$(kubectl get ns "$MEMBER_HOME" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null)"
    if [ -n "$created" ] && [[ "$created" > "$START" || "$created" == "$START" ]]; then
      kubectl delete ns "$MEMBER_HOME" --ignore-not-found --wait=false >/dev/null 2>&1
    fi
  fi
  rm -rf "$TMP"
  return 0
}
trap cleanup EXIT

# The SMTP client. Credentials and addresses arrive in the environment (never on a command line); it prints
# one line, "<code> <reply text>", for the step that answered last.
cat > "$TMP/smtp.py" <<'PY'
import base64, hashlib, hmac, os, smtplib, ssl, sys

e = os.environ

def smtp_password(secret, region):
    # AWS's SES SMTP password, version 4 ("Obtaining Amazon SES SMTP credentials").
    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    sig = sign(("AWS4" + secret).encode("utf-8"), "11111111")
    for part in (region, "ses", "aws4_request", "SendRawEmail"):
        sig = sign(sig, part)
    return base64.b64encode(bytes([0x04]) + sig).decode()

def reply(code, text):
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    print("%d %s" % (code, " ".join(str(text).split())))

def tls_context():
    ctx = ssl.create_default_context()
    ca = e.get("SMTP_CA_FILE", "")
    if ca and e.get("SMTP_VERIFY_HOST") == "1":
        ctx.load_verify_locations(cafile=ca)
    else:
        # A port-forward (127.0.0.1) does not carry the shim's name: encrypt without verifying it.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

mode = sys.argv[1]
if mode == "password":
    print(smtp_password(e["SMTP_SECRET"], e["SMTP_REGION"]))
    sys.exit(0)

try:
    s = smtplib.SMTP(e["SMTP_HOST"], int(e["SMTP_PORT"]), timeout=60)
except OSError as err:
    reply(0, "cannot connect: %s" % err)  # unreachable: inconclusive, not a shim answer
    sys.exit(0)
try:
    s.ehlo("smtp-probe.example.test")
    if mode == "auth-in-clear":
        code, text = s.docmd("AUTH", "PLAIN " + base64.b64encode(("\0%s\0%s" % (e["SMTP_USER"], e["SMTP_PASS"])).encode()).decode())
        reply(code, text)
        sys.exit(0)
    s.starttls(context=tls_context())
    s.ehlo("smtp-probe.example.test")
    try:
        if mode == "login":
            # AUTH LOGIN, the other mechanism SES speaks (login() below picks PLAIN).
            s.user, s.password = e["SMTP_USER"], e["SMTP_PASS"]
            code, text = s.auth("LOGIN", s.auth_login)
            reply(code, text)
            sys.exit(0)
        s.login(e["SMTP_USER"], e["SMTP_PASS"])
    except smtplib.SMTPAuthenticationError as err:
        reply(err.smtp_code, err.smtp_error)
        sys.exit(0)
    msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\nsent by the ses smtp probe\r\n"
           % (e["HEADER_FROM"], e["RCPT"], e["SUBJECT"])).encode()
    code, text = s.mail(e["MAIL_FROM"])
    if code != 250:
        reply(code, text); sys.exit(0)
    code, text = s.rcpt(e["RCPT"])
    if code not in (250, 251):
        reply(code, text); sys.exit(0)
    code, text = s.data(msg)
    reply(code, text)
finally:
    try:
        s.quit()
    except Exception:
        pass
PY

# The platform root CA, to verify the shim's certificate when the probe reaches it by its Service name.
VERIFY=0
if curl -fsS -m 5 "${ENDPOINT}/v1/ca-bundle" -o "$TMP/ca.pem" 2>/dev/null && [ -s "$TMP/ca.pem" ]; then
  case "$SMTP_HOST" in *.svc|*.svc.cluster.local) VERIFY=1 ;; esac
fi

smtp() { # <mode> <user> <password> [MAIL_FROM HEADER_FROM SUBJECT]
  SMTP_HOST="$SMTP_HOST" SMTP_PORT="$SMTP_PORT" SMTP_USER="$2" SMTP_PASS="$3" MAIL_FROM="${4:-}" HEADER_FROM="${5:-}" \
    SUBJECT="${6:-}" RCPT="$RCPT" SMTP_CA_FILE="$TMP/ca.pem" SMTP_VERIFY_HOST="$VERIFY" \
    python3 -I "$TMP/smtp.py" "$1" 2>"$TMP/smtp.err" || echo "999 $(tail -n 3 "$TMP/smtp.err" | tr '\n' ' ' | cut -c1-300)"
}
password() { SMTP_SECRET="$1" SMTP_REGION="$REGION" python3 -I "$TMP/smtp.py" password; }

secret_name() { printf 'iam-ak-%s' "$(printf '%s' "$1" | sha256sum | cut -c1-40)"; }

# user_with_key <namespace> <name> <inline-policy-json|""> [account]: a policy-only IAM user (the canary label:
# IAM policy alone decides it, as an EmailSender's SMTP user) and an access key. MK_AK / MK_SK / MK_PW come
# back in THIS shell, so cleanup sees what was made.
user_with_key() {
  local ns="$1" owner="$2" doc="$3" acct="${4:-}"
  local inline="[]"
  [ -n "$doc" ] && inline="[{\"name\": \"AmazonSesSendingAccess\", \"document\": $doc}]"
  cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create User $ns/$owner"
apiVersion: iam.openinfra.dev/v1
kind: User
metadata: { name: "$owner", namespace: "$ns", labels: { "openinfra.dev/iam-authz": "enforce" } }
spec: { displayName: "$owner", groups: [], source: local, inlinePolicies: $inline }
YAML
  CREATED_USERS+=("$ns/$owner")
  MK_AK="OIAK$(head -c 10 /dev/urandom | base32 | tr -d '=' | head -c 16 | tr 'a-z' 'A-Z')"
  MK_SK="$(head -c 30 /dev/urandom | base64 | tr -d '\n')"
  local name; name="$(secret_name "$MK_AK")"
  local extra=()
  [ -n "$acct" ] && extra=(--from-literal=account="$acct")
  kubectl -n "$SHIM_NS" create secret generic "$name" --from-literal=accessKeyId="$MK_AK" \
    --from-literal=secretKey="$MK_SK" --from-literal=owner="$owner" "${extra[@]}" >/dev/null \
    || inconclusive "could not create an access key for $owner"
  kubectl -n "$SHIM_NS" label secret "$name" app.kubernetes.io/managed-by=open-infra-console "openinfra.dev/iam-user=$owner" >/dev/null 2>&1 || true
  CREATED_KEYS+=("$name")
  MK_PW="$(password "$MK_SK")"
  [ -n "$MK_PW" ] || inconclusive "could not derive an SMTP password"
}

expect() { # <got> <code> <text-prefix> <what>
  case "$1" in
    "$2 $3"*) log "  ✓ $4: $1" ;;
    "0 "*) inconclusive "$4: the SMTP interface could not be reached at $SMTP_HOST:$SMTP_PORT — ${1#0 }" ;;
    *) fail "$4: got '$1', want '$2 $3…'" ;;
  esac
}

# --- 1. principals in the management account ---------------------------------------------------------
log "seeding an SMTP user allowed ses:SendRawEmail as $SENDER only (kind: EmailSender's policy), and a user with none"
user_with_key "$USERS_NS" "smtp-probe-$SFX" \
  '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ses:SendRawEmail", "Resource": "arn:aws:ses:*:*:identity/'"$SENDER"'"}]}'
SAK="$MK_AK"; SPW="$MK_PW"
user_with_key "$USERS_NS" "smtp-probe-none-$SFX" ""
NAK="$MK_AK"; NPW="$MK_PW"

# --- 2. a throwaway member account, and a user in it allowed ses:SendRawEmail as anything ------------------
MEMBER_ACCOUNT="9$(head -c 16 /dev/urandom | od -An -tu1 | tr -cd '0-9' | head -c 11)"
MEMBER_HOME="smtp-probe-$SFX"
log "creating member account $MEMBER_ACCOUNT (home namespace $MEMBER_HOME), which has verified no identity"
cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not create the member account"
apiVersion: organizations.openinfra.dev/v1
kind: Account
metadata: { name: "$MEMBER_ACCOUNT" }
spec: { accountId: "$MEMBER_ACCOUNT", namespaces: ["$MEMBER_HOME"] }
YAML
for _ in $(seq 1 60); do
  [ "$(kubectl get ns "$MEMBER_HOME" -o jsonpath='{.metadata.labels.openinfra\.dev/account-home}' 2>/dev/null)" = true ] && break
  sleep 2
done
[ "$(kubectl get ns "$MEMBER_HOME" -o jsonpath='{.metadata.labels.openinfra\.dev/account-id}' 2>/dev/null)" = "$MEMBER_ACCOUNT" ] \
  || inconclusive "the member account's home namespace was not labeled into it within 120 s"
user_with_key "$MEMBER_HOME" "smtp-probe-member-$SFX" \
  '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ses:SendRawEmail", "Resource": "*"}]}' "$MEMBER_ACCOUNT"
MAK="$MK_AK"; MPW="$MK_PW"

# The shim reloads IAM policy and the account directory on a short cache (~30 s): wait it out, so every
# check below meets the principals just made (as an AWS client retries while a new principal propagates).
sleep "$SETTLE"

# --- 3. encryption before credentials ------------------------------------------------------------------
log "AUTH before STARTTLS"
expect "$(smtp auth-in-clear "$SAK" "$SPW")" 530 "Must issue a STARTTLS command first" "AUTH on a clear connection is refused"

# --- 4. credentials ---------------------------------------------------------------------------------------
log "sign in with a wrong password, then with the derived one"
expect "$(smtp login "$SAK" "$(password "not-the-secret")")" 535 "Authentication Credentials Invalid" "a wrong password"
expect "$(smtp login "$SAK" "$SPW")" 235 "" "the derived SMTP password signs in"

# --- 5. sending, and what the user may not send as ----------------------------------------------------------
log "send as $SENDER, the identity the user's policy grants"
expect "$(smtp send "$SAK" "$SPW" "$SENDER" "Probe <$SENDER>" "ses-smtp-probe $SFX granted")" 250 "Ok " "a granted send is delivered"
log "a From header outside the grant, and a user with no ses:SendRawEmail"
expect "$(smtp send "$SAK" "$SPW" "$SENDER" "$OTHER" "ses-smtp-probe $SFX header-denied")" 554 "Access denied:" "a From header naming another address"
expect "$(smtp send "$NAK" "$NPW" "$SENDER" "$SENDER" "ses-smtp-probe $SFX nopolicy-denied")" 554 "Access denied:" "a user without ses:SendRawEmail"

# --- 6. a member account's verified identities -------------------------------------------------------------
log "the member account sends as app@$MDOMAIN, which it has not verified"
expect "$(smtp send "$MAK" "$MPW" "app@$MDOMAIN" "app@$MDOMAIN" "ses-smtp-probe $SFX unverified")" 554 \
  "Message rejected: Email address is not verified." "an unverified identity"
log "the operator verifies $MDOMAIN for the member account (and grants production access)"
kubectl patch accounts.organizations.openinfra.dev "$MEMBER_ACCOUNT" --type merge \
  -p "{\"spec\":{\"ses\":{\"verifiedIdentities\":[\"$MDOMAIN\"],\"productionAccessEnabled\":true}}}" >/dev/null \
  || fail "could not set the member account's verified identities"
[ "$(kubectl get accounts.organizations.openinfra.dev "$MEMBER_ACCOUNT" -o jsonpath='{.spec.ses.verifiedIdentities[0]}' 2>/dev/null)" = "$MDOMAIN" ] \
  || inconclusive "the deployed Account kind has no spec.ses (this release's XRD is not synced)"
sleep "$SETTLE"
expect "$(smtp send "$MAK" "$MPW" "app@$MDOMAIN" "app@$MDOMAIN" "ses-smtp-probe $SFX verified")" 250 "Ok " "a send as a now-verified identity"

# --- 7. what was accepted reached the relay (capture mode) ---------------------------------------------------
if [ "$(kubectl -n mail get deploy smtp-relay -o jsonpath='{.metadata.labels.openinfra\.dev/mail-capture}' 2>/dev/null)" = true ]; then
  SUBJECTS="$(kubectl -n mail exec deploy/smtp-relay -- wget -qO- 'http://127.0.0.1:8025/api/v1/messages?limit=500' 2>/dev/null \
    | python3 -c 'import json,sys; print("\n".join(m.get("Subject","") for m in json.load(sys.stdin).get("messages",[])))' || true)"
  for s in granted verified; do
    printf '%s\n' "$SUBJECTS" | grep -qx "ses-smtp-probe $SFX $s" || fail "the capturing relay has no message 'ses-smtp-probe $SFX $s'"
  done
  for s in header-denied nopolicy-denied unverified; do
    printf '%s\n' "$SUBJECTS" | grep -qx "ses-smtp-probe $SFX $s" && fail "a REFUSED send reached the relay: 'ses-smtp-probe $SFX $s'"
  done
  log "  ✓ the capturing relay holds the 2 accepted messages and none of the 3 refused"
else
  log "  (the relay delivers — not in capture mode — so the sink check is skipped)"
fi

log "✓ PASS — the SES SMTP interface signs in SES SMTP credentials over TLS only, sends each message as SendRawEmail as the signed-in user's policy and account allow, and refuses the rest with SES's replies"
