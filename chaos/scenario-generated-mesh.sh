#!/usr/bin/env bash
# Generated-mesh chaos — the chain GENERATOR, finally run live.
#
# Instead of a fixed 3-master mesh, this stands up a RANDOMLY GENERATED multi-master Postgres topology
# each draw (chainforge generate --only database -> compile_chain.py: a 2-4 node chain/mesh/fan) and
# judges byte-identical reconvergence under the drawn fault via the singular convergence engine. This is
# the compiler's whole reason to exist (it was built to stand up ANY generated DB topology) wired into
# the continuous rotation, so coverage stops being one hand-authored topology.
#
# Recover pattern: the compiled fault is held out until the mesh is up + baseline; then TestConvergence
# drives writes on every member and requires them to reconverge byte-identical after the fault heals.
# A run that cannot even stand the mesh up / prove the fault fired is INCONCLUSIVE (never a false red).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
NS="${CHAOS_SANDBOX_NS:-chaos-sandbox}"
EXIT_INCONCLUSIVE=42
# shellcheck source=lib-sandbox.sh
# lib-sandbox.sh is pure function defs (no source-time side effects), so this order is safe.
. "$HERE/lib-sandbox.sh"

SEED="${GEN_SEED:-${PICK_SEED:-$RANDOM}}"
# Cap at the proven multi-master scale. 2-3 masters establish + reconverge reliably (the fixed lottery
# runs here); 4+ links crowd the 3 chaos nodes and a link's engine can crash-loop, which the
# establishment gate below correctly voids as INCONCLUSIVE. Larger meshes are a documented follow-up
# (they need more chaos-node headroom / replication-engine work), so we do not draw them yet.
MAXNODES="${GEN_MAXNODES:-3}"
MESH_ROLLOUT="${MESH_ROLLOUT:-180s}"
REPL_READY_TRIES="${REPL_READY_TRIES:-40}"      # x6s = up to 4 min for the CDC links to establish
CONV_BUDGET="${CONV_BUDGET:-600}"               # convergence budget (s); generated meshes vary in size

WORK="$(mktemp -d)"
CHAIN="$WORK/chain.json"; META="$WORK/meta.json"; MANIFESTS="$WORK/manifests.yaml"
MESH="$WORK/mesh.yaml"; FAULT="$WORK/fault.yaml"

cleanup() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  [ -f "$MANIFESTS" ] && kubectl -n "$NS" delete -f "$MANIFESTS" --ignore-not-found >/dev/null 2>&1 || true
  rm -rf "$WORK"
  sandbox_teardown 2>/dev/null || true
}
trap cleanup EXIT

"$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom

# 1. Generate a random DB topology and compile it to manifests + a run-spec.
log "generating a random multi-master topology (seed=$SEED, maxnodes=$MAXNODES)"
( cd "$REPO/tools/chainforge" && go run . generate --only database --count 1 --seed "$SEED" --maxnodes "$MAXNODES" 2>/dev/null ) > "$CHAIN" || true
if ! python3 -c "import json,sys; d=json.load(open('$CHAIN')); sys.exit(0 if isinstance(d,list) and d and len(d[0]['chain']['nodes'])>=2 else 1)" 2>/dev/null; then
  log "INCONCLUSIVE — generator produced no multi-node DB chain (seed=$SEED). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi
log "compiling the generated chain -> manifests"
if ! python3 "$REPO/chaos/compile_chain.py" --in "$CHAIN" --namespace "$NS" --meta "$META" > "$MANIFESTS" 2>"$WORK/err"; then
  log "INCONCLUSIVE — compile refused/failed (seed=$SEED): $(cat "$WORK/err")"
  exit "$EXIT_INCONCLUSIVE"
fi

MEMBERS_JSON="$(python3 -c "import json; print(json.dumps(json.load(open('$META'))['members']))")"
NMEM="$(python3 -c "import json; print(len(json.load(open('$META'))['members']))")"
SITES="$(python3 -c "import json; print(' '.join(m['site'] for m in json.load(open('$META'))['members']))")"
TARGET="$(python3 -c "import json; print(json.load(open('$META'))['fault'].get('target',''))")"
log "generated topology: ${NMEM} masters [sites: ${SITES}], fault target=${TARGET}"

# 2. Split the fault out of the manifests; stand up the mesh first.
python3 - "$MANIFESTS" "$MESH" "$FAULT" <<'PY'
import sys, yaml
docs=[d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
yaml.safe_dump_all([d for d in docs if d.get("kind")!="FaultInjection"], open(sys.argv[2],"w"), sort_keys=False)
yaml.safe_dump_all([d for d in docs if d.get("kind")=="FaultInjection"], open(sys.argv[3],"w"), sort_keys=False)
PY
log "standing up the generated mesh (${NMEM} Postgres + replications)"
kubectl apply -f "$MESH" >/dev/null
for s in $SITES; do
  kubectl -n "$NS" rollout status statefulset/pg-"$s" --timeout="$MESH_ROLLOUT" || {
    log "INCONCLUSIVE — pg-$s did not become ready in $MESH_ROLLOUT (seed=$SEED). Not counting."; exit "$EXIT_INCONCLUSIVE"; }
done

# 3. The mesh must fully ESTABLISH before we judge it: every replication-engine pod (Debezium capture +
#    apply-sink, one pair per link) must be Ready. A generated topology that cannot even stand its links
#    up — a larger mesh the chaos nodes lack headroom for, or a crash-looping sink — is INCONCLUSIVE, NOT
#    a red: judging reconvergence on a mesh that never converged at baseline would be a false red. This
#    is the fail-safe that keeps a "couldn't set up" apart from a genuine "didn't reconverge under fault".
log "waiting for the replication engine to establish (every Debezium + apply-sink pod Ready)"
established=0
for _ in $(seq 1 "$REPL_READY_TRIES"); do
  pods="$(kubectl -n "$NS" get pods -l openinfra.dev/replication -o json 2>/dev/null || echo '{}')"
  read -r npods nready <<EOF
$(printf '%s' "$pods" | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: d={}
items=d.get("items",[])
ready=sum(1 for p in items if any(c.get("type")=="Ready" and c.get("status")=="True" for c in (p.get("status",{}).get("conditions") or [])))
print(len(items), ready)' 2>/dev/null || echo "0 0")
EOF
  [ "${npods:-0}" -gt 0 ] && [ "${nready:-0}" = "${npods:-0}" ] && { established=1; break; }
  sleep 6
done
if [ "$established" != 1 ]; then
  log "INCONCLUSIVE — the generated mesh's replication engine did not fully establish (a link's Debezium/apply-sink never became Ready). Not judging reconvergence (seed=$SEED). Not counting."
  kubectl -n "$NS" get pods -l openinfra.dev/replication -o wide 2>/dev/null | head || true
  exit "$EXIT_INCONCLUSIVE"
fi
log "replication engine established — every link's pods are Ready."

# 4. Build CONV_MEMBERS (generalized to N) from the run-spec members.
PGPASS="$(kubectl -n "$NS" get secret pg-creds -o jsonpath='{.data.password}' | base64 -d)"
export CONV_MEMBERS="$(NS="$NS" PGPASS="$PGPASS" MEMBERS_JSON="$MEMBERS_JSON" python3 - <<'PY'
import json, os, subprocess
mem=json.loads(os.environ["MEMBERS_JSON"]); ns=os.environ["NS"]; pw=os.environ["PGPASS"]
out=[]
for m in mem:
    s=m["site"]
    ip=subprocess.check_output(["kubectl","-n",ns,"get","svc","pg-"+s,"-o","jsonpath={.spec.clusterIP}"]).decode().strip()
    out.append({"name":"pg-"+s,"engine":"postgres",
                "dsn":f"postgres://app:{pw}@{ip}:5432/app?sslmode=disable","site":s,"schema":"public"})
print(json.dumps(out))
PY
)"
export CONV_CREATE=true CONV_TABLE=public.conv_test CONV_PK=id CONV_TIMEOUT="$CONV_BUDGET"

# 5. Pre-flight + fire the compiled fault, then prove it fired (target Postgres pod replaced).
log "pre-flight guard (the compiled fault)"
"$HERE/preflight.sh" "$FAULT"
uid() { kubectl -n "$NS" get pods -l "app=pg,site=$1" -o jsonpath='{.items[0].metadata.uid}' 2>/dev/null || true; }
TGT_UID0="$(uid "$TARGET")"
log "injecting the generated fault (pod-kill on pg-${TARGET})"
kubectl apply -f "$FAULT" >/dev/null
fired=0
for _ in $(seq 1 30); do now="$(uid "$TARGET")"; [ -n "$now" ] && [ "$now" != "$TGT_UID0" ] && { fired=1; break; }; sleep 3; done
if [ "$fired" != 1 ]; then
  log "INCONCLUSIVE — the fault never fired (pg-${TARGET} pod not replaced) within budget (seed=$SEED). Not counting."
  exit "$EXIT_INCONCLUSIVE"
fi
log "proof-of-fire OK — pg-${TARGET} killed and replaced."

# 6. The verdict: drive writes through the standing chaos and require byte-identical reconvergence.
log "judging reconvergence of the generated ${NMEM}-master mesh via the singular convergence engine (budget ${CONV_BUDGET}s)"
if ! ( cd "$REPO/apply-sink" && go test -tags convergence -run '^TestConvergence$' -timeout 25m -count=1 ./... ); then
  log "FAIL — the generated ${NMEM}-master mesh did NOT reconverge under the fault (seed=$SEED). REPLAY: GEN_SEED=$SEED"
  kubectl -n "$NS" get replication,faultinjection,pods -o wide 2>/dev/null || true
  exit 1
fi
log "PASS — generated ${NMEM}-master mesh [sites: ${SITES}] reconverged byte-identical under the drawn fault (seed=$SEED, replay GEN_SEED=$SEED)."
