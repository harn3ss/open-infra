#!/usr/bin/env bash
# Live probe for kind: StaticSite — the S3-static-website + CDN-origin primitive (and the target of the
# cfn engine's CloudFront subset).
#
# It creates a throwaway StaticSite on two hostnames with SPA fallback and response headers, uploads a
# tiny site to its bucket with the site's OWN scoped credentials, and asserts the real served effect:
#   1. the site serves the uploaded index.html at / (bucket → sync → nginx works);
#   2. a deep client-side route (/deep/client/route) falls back to index.html with 200 (SPA fallback);
#   3. a real asset (/assets/app.js) is served as itself, not as the fallback;
#   4. the configured response headers (a marker X-Probe-Header + a CSP) are on every response,
#      including the fallback;
#   5. through Traefik over HTTPS (cert-manager TLS), BOTH hostnames serve the site and the deep route,
#      and the Certificate covers both names;
#   6. NEGATIVE: an unrelated hostname through the same Traefik does NOT reach the site (the Ingress is
#      host-scoped, not a catch-all).
#
# Everything it creates is removed on exit (EXIT trap): the StaticSite, its namespace (secrets, client
# pods), the minio-namespace setup Job, and — through a short-lived pod in the minio namespace that uses
# the platform's MinIO root secret — the site's bucket and the scoped MinIO user/policy its setup minted.
#
# On-demand (needs a deployed platform: Crossplane + the StaticSite composition, MinIO, cert-manager with
# the openinfra-issuer ClusterIssuer, k3s Traefik). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE
# (a prerequisite was missing or did not converge, so nothing was proven).
#
#   KUBECONFIG=/etc/rancher/k3s/k3s.yaml ./probe/staticsite.sh
#   TRAEFIK_NS=kube-system TRAEFIK_SVC=traefik ./probe/staticsite.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
MINIO_NS="${MINIO_NS:-minio}"
TRAEFIK_NS="${TRAEFIK_NS:-kube-system}"
TRAEFIK_SVC="${TRAEFIK_SVC:-traefik}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.10.1}"
AWSCLI_IMAGE="${AWSCLI_IMAGE:-alpine/k8s:1.30.0}"
# The same pinned mc image the StaticSite/Bucket compositions use.
MC_IMAGE="${MC_IMAGE:-ghcr.io/harn3ss/open-infra-mc@sha256:a689825d5299d02e6f35973e726a6e49a77469cde644dd52d60586b07bd85744}"

SFX="$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NS="staticsite-probe-$SFX"
SITE="ssp-$SFX"
BUCKET="$SITE-site"          # the StaticSite default bucket (<name>-site)
HOST1="$SITE.probe.invalid"  # .invalid: reserved, never a real site name
HOST2="www-$SITE.probe.invalid"
OTHER="other-$SITE.probe.invalid"
MARKER="SS_PROBE_OK_$SFX"
CLIENT="client-$SFX"

TMP="$(mktemp -d)"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }
snip() { printf '%s' "$1" | head -c 600 | tr '\n' ' '; }   # a response, on one line, for a message

# wait_pod <ns> <pod> <seconds>: 0 when the pod Succeeded, 1 when it Failed or timed out.
wait_pod() {
  local i=0 phase=""
  while [ "$i" -lt "$3" ]; do
    phase="$(kubectl -n "$1" get pod "$2" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "$phase" in Succeeded) return 0;; Failed) return 1;; esac
    sleep 3; i=$((i+3))
  done
  return 1
}

command -v kubectl >/dev/null || inconclusive "kubectl is required"
kubectl get crd staticsites.openinfra.dev >/dev/null 2>&1 || inconclusive "the StaticSite CRD is not installed"
kubectl -n "$MINIO_NS" get secret minio >/dev/null 2>&1 || inconclusive "secret/minio in ns $MINIO_NS not readable (needed to clean up the probe's bucket + MinIO user)"

# minio_cleanup removes the bucket and the scoped MinIO users/policies a StaticSite/Bucket setup mints, via a
# one-shot pod in the minio namespace (root creds come from secret/minio and never leave that namespace).
# The MinIO user a bucket-owning claim gets (bucket-composition / staticsite-composition $appUser).
app_user() { # <Kind> <namespace> <name>
  local base; base="$(printf '%s-%s' "$2" "$3" | tr . - | cut -c1-40)"; base="${base%-}"
  printf 'app-%s-%s' "$base" "$(printf '%s/%s/%s' "$1" "$2" "$3" | sha256sum | cut -c1-10)"
}
minio_cleanup() { # <bucket> <minio-user>...
  local bucket="$1"; shift
  local pod="ssprobe-clean-$SFX"
  cat <<YAML | kubectl apply -f - >/dev/null 2>&1 || { printf '  (cleanup) could not start the MinIO cleanup pod\n' >&2; return 0; }
apiVersion: v1
kind: Pod
metadata: { name: "$pod", namespace: "$MINIO_NS", labels: { app.kubernetes.io/managed-by: staticsite-probe } }
spec:
  restartPolicy: Never
  enableServiceLinks: false
  containers:
    - name: mc
      image: "$MC_IMAGE"
      env:
        - { name: RU, valueFrom: { secretKeyRef: { name: minio, key: rootUser } } }
        - { name: RP, valueFrom: { secretKeyRef: { name: minio, key: rootPassword } } }
      command: [sh, -c]
      args:
        - |
          export MC_CONFIG_DIR=/tmp/.mc   # the image runs as non-root with no writable HOME
          mc alias set m http://minio.$MINIO_NS.svc.cluster.local:9000 "\$RU" "\$RP" >/dev/null || exit 1
          mc rb --force "m/$bucket" >/dev/null 2>&1 && echo "removed bucket $bucket" || echo "bucket $bucket already gone"
          for u in $*; do
            mc admin user rm m "\$u" >/dev/null 2>&1 && echo "removed MinIO user \$u" || echo "MinIO user \$u already gone"
            mc admin policy rm m "\$u" >/dev/null 2>&1 || true
          done
YAML
  wait_pod "$MINIO_NS" "$pod" 120 || printf '  (cleanup) the MinIO cleanup pod did not succeed — remove bucket %s / users %s by hand\n' "$bucket" "$*" >&2
  kubectl -n "$MINIO_NS" logs "$pod" 2>/dev/null | sed 's/^/  (cleanup) /' || true
  kubectl -n "$MINIO_NS" delete pod "$pod" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

CREDS_NS="${CREDS_NS:-openinfra-bucket-creds}"
cleanup() {
  set +e
  local user; user="$(app_user StaticSite "$NS" "$SITE")"
  log "cleanup: StaticSite $SITE, namespace $NS, setup Job, MinIO bucket $BUCKET + user $user"
  kubectl -n "$NS" delete staticsite "$SITE" --ignore-not-found --wait=true --timeout=120s >/dev/null 2>&1
  kubectl -n "$MINIO_NS" delete job "$SITE-site-setup" --ignore-not-found >/dev/null 2>&1
  minio_cleanup "$BUCKET" "app-$SITE" "$user"
  # Owner records and the platform-side scoped-credential Secret now live in the creds namespace.
  kubectl -n "$CREDS_NS" delete secret "bucket-owner-$BUCKET" "$user" --ignore-not-found >/dev/null 2>&1
  kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1
  # Assert nothing was left behind in the creds namespace for this site.
  local left
  left="$(kubectl -n "$CREDS_NS" get secret "bucket-owner-$BUCKET" "$user" -o name 2>/dev/null; true)"  # an absent Secret is the expected answer, not a set -e exit
  [ -z "$left" ] || printf '  (cleanup) WARNING: leftover creds-namespace Secrets remain: %s\n' "$left" >&2
  rm -rf "$TMP"
}
trap cleanup EXIT

# --- 1. create the site ---------------------------------------------------------------------------
log "creating ns $NS + StaticSite $SITE on $HOST1 + $HOST2 (spa, responseHeaders, tls)"
kubectl create ns "$NS" >/dev/null 2>&1 || inconclusive "could not create ns $NS"
cat <<YAML | kubectl apply -f - >/dev/null 2>"$TMP/apply.err" || inconclusive "StaticSite apply failed: $(cat "$TMP/apply.err")"
apiVersion: openinfra.dev/v1
kind: StaticSite
metadata: { name: "$SITE", namespace: "$NS" }
spec:
  domain: "$HOST1"
  domains: ["$HOST2"]
  spa: true
  tls: true
  syncIntervalSeconds: 10
  responseHeaders:
    - { name: X-Probe-Header, value: "$MARKER" }
    - { name: Content-Security-Policy, value: "default-src 'self'" }
YAML

log "waiting for the bucket setup (secret $SITE-minio) and the server Deployment"
for i in $(seq 1 36); do
  kubectl -n "$NS" get secret "$SITE-minio" >/dev/null 2>&1 && break
  sleep 5
done
kubectl -n "$NS" get secret "$SITE-minio" >/dev/null 2>&1 || inconclusive "the bucket setup never wrote secret $SITE-minio (MinIO / the setup Job in ns $MINIO_NS)"
kubectl -n "$NS" rollout status "deploy/$SITE-site" --timeout=180s >/dev/null 2>&1 || inconclusive "deploy/$SITE-site did not become available"
log "  ✓ bucket $BUCKET set up, server available"

# --- 2. upload a tiny site with the site's OWN scoped credentials ---------------------------------
log "uploading index.html + assets/app.js to s3://$BUCKET with the $SITE-minio credentials"
cat <<YAML | kubectl apply -f - >/dev/null || inconclusive "could not start the upload pod"
apiVersion: v1
kind: Pod
metadata: { name: "upload-$SFX", namespace: "$NS" }
spec:
  restartPolicy: Never
  enableServiceLinks: false
  containers:
    - name: upload
      image: "$AWSCLI_IMAGE"
      env:
        - { name: MINIO_ENDPOINT, valueFrom: { secretKeyRef: { name: "$SITE-minio", key: MINIO_ENDPOINT } } }
        - { name: AWS_ACCESS_KEY_ID, valueFrom: { secretKeyRef: { name: "$SITE-minio", key: MINIO_ACCESS_KEY } } }
        - { name: AWS_SECRET_ACCESS_KEY, valueFrom: { secretKeyRef: { name: "$SITE-minio", key: MINIO_SECRET_KEY } } }
        - { name: AWS_DEFAULT_REGION, value: us-east-1 }
      command: [sh, -c]
      args:
        - |
          set -e
          mkdir -p /tmp/site/assets
          printf '<!doctype html><title>probe</title><div id="app">%s</div>\n' "$MARKER" > /tmp/site/index.html
          printf 'console.log("asset-%s");\n' "$SFX" > /tmp/site/assets/app.js
          aws --endpoint-url "\$MINIO_ENDPOINT" s3 cp /tmp/site/ "s3://$BUCKET/" --recursive
YAML
wait_pod "$NS" "upload-$SFX" 180 \
  || fail "upload with the site's own credentials failed: $(kubectl -n "$NS" logs "upload-$SFX" 2>&1 | tail -5 | tr '\n' ' ')"
log "  ✓ uploaded (the site's scoped MinIO user can write its bucket)"

# --- 3. an in-namespace client to fetch from ------------------------------------------------------
kubectl -n "$NS" run "$CLIENT" --restart=Never --image="$CURL_IMAGE" --command -- sleep 900 >/dev/null 2>&1 \
  || inconclusive "could not start the curl client pod"
kubectl -n "$NS" wait --for=condition=Ready "pod/$CLIENT" --timeout=120s >/dev/null 2>&1 || inconclusive "curl client pod not Ready"
# fetch prints the response headers, a blank line, then the body (curl -D -).
fetch() { kubectl -n "$NS" exec "$CLIENT" -- curl -sS -m 10 -D - "$@" 2>/dev/null | tr -d '\r' || true; }
status_of() { printf '%s' "$1" | awk 'NR==1{print $2}'; }
# The X-Probe-Header carries $MARKER too: the body (after the headers) is what shows the upload is served.
body_of() { printf '%s' "$1" | awk 'f; /^$/ {f=1}'; }
# header_of <response> <name>: the header's value (case-insensitive name, header block only).
header_of() {
  printf '%s' "$1" | awk -v h="$(printf '%s' "$2" | tr 'A-Z' 'a-z')" \
    'NR>1 && /^$/ {exit} { i = index($0, ": "); if (i > 0 && tolower(substr($0, 1, i-1)) == h) { print substr($0, i+2); exit } }'
}

log "waiting for the server to sync the upload (every 10s)"
OUT=""
for i in $(seq 1 18); do
  OUT="$(fetch "http://$SITE-site/")"
  [ "$(status_of "$OUT")" = 200 ] && body_of "$OUT" | grep -q "$MARKER" && break
  sleep 5
done
body_of "$OUT" | grep -q "$MARKER" || fail "GET / never served the uploaded index.html (bucket→sync→nginx broken); last response: $(snip "$OUT")"
[ "$(status_of "$OUT")" = "200" ] || fail "GET / returned $(status_of "$OUT"), want 200"
log "  ✓ GET / → 200, serves the uploaded index.html"

# --- 4. SPA fallback, real asset, headers ---------------------------------------------------------
DEEP="$(fetch "http://$SITE-site/deep/client/route")"
[ "$(status_of "$DEEP")" = "200" ] || fail "deep route returned $(status_of "$DEEP"), want 200 (SPA fallback)"
body_of "$DEEP" | grep -q "$MARKER" || fail "deep route did not fall back to index.html; got: $(snip "$DEEP")"
log "  ✓ GET /deep/client/route → 200 index.html (SPA fallback)"

ASSET="$(fetch "http://$SITE-site/assets/app.js")"
printf '%s' "$ASSET" | grep -q "asset-$SFX" || fail "a real asset was not served as itself (got the fallback?): $(snip "$ASSET")"
# The marker is also the X-Probe-Header value, so look for index.html's marker in the BODY only.
printf '%s' "$ASSET" | sed '1,/^$/d' | grep -q "$MARKER" && fail "/assets/app.js served index.html instead of the asset"
log "  ✓ GET /assets/app.js → the asset itself"

for r in "$OUT" "$DEEP" "$ASSET"; do
  [ "$(header_of "$r" X-Probe-Header)" = "$MARKER" ] || fail "response missing X-Probe-Header: $MARKER; headers: $(snip "$(printf '%s' "$r" | sed '/^$/q')")"
  [ "$(header_of "$r" Content-Security-Policy)" = "default-src 'self'" ] || fail "response missing the configured Content-Security-Policy; headers: $(snip "$(printf '%s' "$r" | sed '/^$/q')")"
done
log "  ✓ X-Probe-Header + Content-Security-Policy on /, the fallback, and the asset"

# --- 5. through Traefik over HTTPS, both hostnames --------------------------------------------------
TRAEFIK_IP="$(kubectl -n "$TRAEFIK_NS" get svc "$TRAEFIK_SVC" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
[ -n "$TRAEFIK_IP" ] || inconclusive "svc/$TRAEFIK_SVC in ns $TRAEFIK_NS not found (set TRAEFIK_NS/TRAEFIK_SVC) — the in-cluster serving above passed; the Ingress/TLS path is unproven"

log "waiting for cert-manager to issue staticsite-$SITE-tls (openinfra-issuer) for both hostnames"
CERT_READY=""
for i in $(seq 1 24); do
  CERT_READY="$(kubectl -n "$NS" get certificate "staticsite-$SITE-tls" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)"
  [ "$CERT_READY" = "True" ] && break
  sleep 5
done
[ "$CERT_READY" = "True" ] || inconclusive "Certificate staticsite-$SITE-tls not Ready (an ACME openinfra-issuer can't issue for .invalid names) — the in-cluster serving above passed; TLS is unproven"
DNS_NAMES="$(kubectl -n "$NS" get certificate "staticsite-$SITE-tls" -o jsonpath='{.spec.dnsNames}' 2>/dev/null || true)"
printf '%s' "$DNS_NAMES" | grep -q "$HOST1" && printf '%s' "$DNS_NAMES" | grep -q "$HOST2" \
  || fail "the certificate does not cover both hostnames (dnsNames=$DNS_NAMES)"
log "  ✓ certificate issued for $HOST1 + $HOST2"

for h in "$HOST1" "$HOST2"; do
  T=""
  for i in $(seq 1 12); do
    T="$(fetch -k --resolve "$h:443:$TRAEFIK_IP" "https://$h/deep/client/route")"
    [ "$(status_of "$T")" = "200" ] && break
    sleep 5
  done
  [ "$(status_of "$T")" = "200" ] || fail "https://$h/deep/client/route via Traefik returned $(status_of "$T"), want 200; got: $(snip "$T")"
  printf '%s' "$T" | grep -q "$MARKER" || fail "https://$h/deep/client/route via Traefik did not serve the SPA fallback"
  [ "$(header_of "$T" X-Probe-Header)" = "$MARKER" ] || fail "https://$h via Traefik is missing X-Probe-Header"
  log "  ✓ https://$h/deep/client/route via Traefik → 200 index.html + headers"
done

# --- 6. NEGATIVE: an unrelated hostname must not reach the site ------------------------------------
N="$(fetch -k --resolve "$OTHER:443:$TRAEFIK_IP" "https://$OTHER/")"
printf '%s' "$N" | grep -q "$MARKER" && fail "an unrelated hostname ($OTHER) reached the site — the Ingress is not host-scoped"
log "  ✓ an unrelated hostname does not reach the site (status $(status_of "$N"))"

# Informational: the site answers HTTPS only (no plain-HTTP router on a TLS site).
H="$(fetch --resolve "$HOST1:80:$TRAEFIK_IP" "http://$HOST1/")"
log "  (info) plain http://$HOST1/ via Traefik → $(status_of "$H") (a TLS site has no plain-HTTP route)"

# --- 7. deleting the site leaves nothing behind ---------------------------------------------------
# Empty the bucket first, with the site's own credentials (a bucket that still holds data is never deleted
# by the platform; it is kept for its owner). Then delete the claim and check — sweeping nothing first —
# that its Secrets go with it and the bucket reaper removes the bucket, the scoped user's credentials and
# the owner record (the record is removed only once the bucket is gone).
log "emptying $BUCKET, deleting StaticSite $SITE: nothing of it may remain"
kubectl -n "$NS" delete pod "$CLIENT" --ignore-not-found --wait=false >/dev/null 2>&1
cat <<YAML | kubectl apply -f - >/dev/null || fail "could not start the emptying pod"
apiVersion: v1
kind: Pod
metadata: { name: "empty-$SFX", namespace: "$NS" }
spec:
  restartPolicy: Never
  enableServiceLinks: false
  containers:
    - name: empty
      image: "$AWSCLI_IMAGE"
      env:
        - { name: MINIO_ENDPOINT, valueFrom: { secretKeyRef: { name: "$SITE-minio", key: MINIO_ENDPOINT } } }
        - { name: AWS_ACCESS_KEY_ID, valueFrom: { secretKeyRef: { name: "$SITE-minio", key: MINIO_ACCESS_KEY } } }
        - { name: AWS_SECRET_ACCESS_KEY, valueFrom: { secretKeyRef: { name: "$SITE-minio", key: MINIO_SECRET_KEY } } }
        - { name: AWS_DEFAULT_REGION, value: us-east-1 }
      command: [sh, -c, 'aws --endpoint-url "\$MINIO_ENDPOINT" s3 rm "s3://$BUCKET" --recursive']
YAML
wait_pod "$NS" "empty-$SFX" 180 || fail "emptying $BUCKET failed: $(kubectl -n "$NS" logs "empty-$SFX" 2>&1 | tail -3 | tr '\n' ' ')"
kubectl -n "$NS" delete staticsite "$SITE" --wait=true --timeout=180s >/dev/null 2>&1 || fail "deleting StaticSite $SITE failed"
USER_="$(app_user StaticSite "$NS" "$SITE")"
left=""
for i in $(seq 1 30); do
  left="$(kubectl -n "$NS" get secret "$SITE-minio" "staticsite-$SITE-tls" -o name 2>/dev/null; kubectl -n "$CREDS_NS" get secret "bucket-owner-$BUCKET" "$USER_" -o name 2>/dev/null; true)"  # an absent Secret is the expected answer, not a set -e exit
  [ -z "$left" ] && break
  sleep 5
done
[ -z "$left" ] || fail "deleting the site left behind: $(echo $left)"
log "  ✓ deleted: its credentials, TLS Secret, scoped user, owner record and (empty) bucket are gone"

printf '\n✓ PASS — kind: StaticSite serves its bucket faithfully: uploads with its own scoped credentials go live,\n'
printf '  a deep client route falls back to index.html (200) while real assets are served as themselves, the\n'
printf '  configured response headers ride every response, and both hostnames serve over cert-manager TLS through\n'
printf '  Traefik — while an unrelated hostname does not reach the site.\n'
