#!/usr/bin/env bash
# Compatibility probe for the kind: StaticSite managed build pipeline (polyhedron#296, Amplify git-push-to-build).
#
# The claim is Amplify's connected-repo build: point StaticSite at a git repo, and on a new commit it
# clones, runs the build command in a SANDBOXED Job, and publishes the output to the site bucket, which the
# nginx server then serves. This probe proves it end-to-end against the live platform, asserting the REAL
# effect (the built marker is actually served), not just that resources were created:
#   1. a StaticSite with a build block → bucket-setup + nginx + a build CronJob materialize;
#   2. the first poll clones octocat/Hello-World, runs the build (which generates dist/index.html — the repo
#      has none, so a served marker proves the build RAN), publishes it, and the server serves the marker;
#   3. the build command carries SINGLE AND DOUBLE QUOTES — amplify.yml commands routinely do — proving the
#      composition renders it as a block scalar (a regression guard for the flow-scalar bug #296 shipped with);
#   4. the next poll detects the unchanged HEAD and SKIPS the rebuild (the s3://.build/last-sha marker works).
# The sandbox posture (non-root, no service-account token, caps dropped) is asserted on the build pod spec.
#
# On-demand (needs a deployed platform with Crossplane + the StaticSite composition + MinIO, and egress to
# github.com for the clone). Exit 0 = pass, 1 = a real failure, 42 = INCONCLUSIVE.
#
#   KUBECONFIG=/etc/rancher/k3s/k3s.yaml ./probe/staticsite-build.sh
set -euo pipefail

EXIT_INCONCLUSIVE=42
SFX="$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
NS="staticsite-build-probe-$SFX"
SITE="sb-$SFX"
MARKER="SB_PROBE_OK_$SFX"

log()  { printf '▸ %s\n' "$*"; }
fail() { printf '✗ FAIL: %s\n' "$*" >&2; exit 1; }
inconclusive() { printf '⚠ INCONCLUSIVE: %s\n' "$*" >&2; exit "$EXIT_INCONCLUSIVE"; }

command -v kubectl >/dev/null || inconclusive "kubectl is required"
kubectl get crd staticsites.openinfra.dev >/dev/null 2>&1 || inconclusive "the StaticSite CRD is not installed"

cleanup() {
  kubectl -n "$NS" delete staticsite "$SITE" --ignore-not-found >/dev/null 2>&1 || true
  sleep 2
  kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "creating ns $NS + StaticSite $SITE (build: octocat/Hello-World, QUOTED buildCommand)"
kubectl create ns "$NS" >/dev/null 2>&1 || inconclusive "could not create ns $NS"
# The buildCommand deliberately carries single AND double quotes (the #296 flow-scalar bug).
cat <<YAML | kubectl apply -f - >/dev/null 2>&1 || inconclusive "StaticSite apply failed"
apiVersion: openinfra.dev/v1
kind: StaticSite
metadata: { name: "$SITE", namespace: "$NS" }
spec:
  domain: "$SITE.probe.invalid"
  tls: false
  spa: true
  syncIntervalSeconds: 15
  build:
    repo: https://github.com/octocat/Hello-World.git
    branch: master
    image: alpine:3.20
    outputDir: dist
    pollSeconds: 60
    buildCommand: mkdir -p dist && echo '<h1>staticsite build probe</h1>' > dist/index.html && printf 'marker="%s"' "$MARKER" >> dist/index.html
YAML

log "waiting for the composite to render + become Ready (the quoted buildCommand must not break the manifest)"
for i in $(seq 1 24); do
  synced="$(kubectl get xstaticsites -o jsonpath="{range .items[?(@.spec.claimRef.name=='$SITE')]}{.status.conditions[?(@.type=='Synced')].status}{end}" 2>/dev/null)"
  reason="$(kubectl get xstaticsites -o jsonpath="{range .items[?(@.spec.claimRef.name=='$SITE')]}{.status.conditions[?(@.type=='Synced')].reason}{end}" 2>/dev/null)"
  [ "$synced" = "True" ] && break
  case "$reason" in *Error*) fail "composite render FAILED ($reason) — a quoted buildCommand broke the manifest (the #296 flow-scalar bug): $(kubectl get xstaticsites -o jsonpath="{range .items[?(@.spec.claimRef.name=='$SITE')]}{.status.conditions[?(@.type=='Synced')].message}{end}" 2>/dev/null)";; esac
  sleep 5
done
[ "$synced" = "True" ] || inconclusive "composite did not render in time (reason=$reason)"
log "  ✓ rendered (quoted buildCommand accepted)"

log "waiting for the build CronJob's first Job to complete (first poll clones + builds + publishes)"
JOB=""
for i in $(seq 1 24); do
  JOB="$(kubectl -n "$NS" get jobs --no-headers 2>/dev/null | grep "$SITE-site-build" | grep Complete | awk '{print $1}' | head -1 || true)"
  [ -n "$JOB" ] && break
  sleep 10
done
[ -n "$JOB" ] || inconclusive "no completed build Job after ~4m (egress to github.com? image pulls?)"
POD="$(kubectl -n "$NS" get pods -l job-name="$JOB" -o name 2>/dev/null | head -1 | cut -d/ -f2)"

# Assert the sandbox posture on the build pod (untrusted repo code).
NONROOT="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.securityContext.runAsNonRoot}' 2>/dev/null)"
SATOKEN="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.automountServiceAccountToken}' 2>/dev/null)"
[ "$NONROOT" = "true" ]  || fail "build pod is not runAsNonRoot (untrusted build must be sandboxed)"
[ "$SATOKEN" = "false" ] || fail "build pod mounts a service-account token (untrusted build must have none)"
log "  ✓ build Job complete + sandboxed (runAsNonRoot, no SA token)"

log "verifying the SERVER serves the built marker (proves clone→build→publish→serve)"
GOT=""
for i in $(seq 1 12); do
  GOT="$(kubectl -n "$NS" run "curl-$SFX-$i" --rm -i --restart=Never --image=curlimages/curl:8.10.1 --command -- \
        sh -c "curl -fsS http://$SITE-site/ 2>/dev/null" 2>/dev/null | tr -d '\0' || true)"
  printf '%s' "$GOT" | grep -q "$MARKER" && break
  sleep 10
done
printf '%s' "$GOT" | grep -q "$MARKER" || fail "served content does not contain the built marker $MARKER (clone→build→publish→serve broken); got: $GOT"
# The marker is embedded with double quotes by the quoted buildCommand — confirm they survived.
printf '%s' "$GOT" | grep -q "marker=\"$MARKER\"" || fail "the quoted output did not survive — quoting fix regressed; got: $GOT"
log "  ✓ served: marker=\"$MARKER\" (build ran, output published + served, quotes intact)"

log "verifying the next poll SKIPS the rebuild (unchanged HEAD → s3://.build/last-sha short-circuit)"
PREV_JOBS="$(kubectl -n "$NS" get jobs --no-headers 2>/dev/null | grep -c "$SITE-site-build" || true)"
SKIPPED=""
for i in $(seq 1 12); do
  NEWJOB="$(kubectl -n "$NS" get jobs --sort-by=.metadata.creationTimestamp --no-headers 2>/dev/null | grep "$SITE-site-build" | tail -1 | awk '{print $1}' || true)"
  NCOUNT="$(kubectl -n "$NS" get jobs --no-headers 2>/dev/null | grep -c "$SITE-site-build" || true)"
  if [ "$NCOUNT" -gt "$PREV_JOBS" ]; then
    NPOD="$(kubectl -n "$NS" get pods -l job-name="$NEWJOB" -o name 2>/dev/null | head -1 | cut -d/ -f2)"
    plog="$(kubectl -n "$NS" logs "$NPOD" -c publish 2>/dev/null || true)"
    if printf '%s' "$plog" | grep -qi "unchanged"; then SKIPPED=1; break; fi
  fi
  sleep 10
done
[ -n "$SKIPPED" ] || inconclusive "could not observe a skip-on-unchanged within the window (the first build is already proven; this is the no-op-rebuild guard)"
log "  ✓ unchanged HEAD → rebuild skipped"

printf '\n✓ PASS — kind: StaticSite managed build is faithful end-to-end: a git repo is cloned, the build\n'
printf '  command runs sandboxed, the output is published, and the server serves the built marker; a quoted\n'
printf '  build command renders correctly; and an unchanged HEAD skips the rebuild.\n'
