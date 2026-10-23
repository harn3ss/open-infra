#!/usr/bin/env bash
# polyhedron#313 — control-plane capacity measurement harness.
#
# Captures the evidence-bar metrics the in-cluster #314 reporter CANNOT (they need node/host access,
# apiserver metrics, or pod exec), and appends ONE timestamped TSV row so a stepped load test has a
# committable time series. Run it on the k3s server node (needs sudo for the datastore file + kubectl).
# READ-ONLY: it measures, it changes nothing. Run at each load-test step and across the soak.
#
#   sudo KUBECONFIG=/etc/rancher/k3s/k3s.yaml tools/capacity/capacity-probe.sh [OUT.tsv]
#
# Default OUT = /mnt/nas/open-infra/estate-capacity-313-measurements.tsv (private NAS — numbers are
# cluster-specific; the SCRIPT is committed, the OUTPUT is not).
set -u
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
OUT="${1:-/mnt/nas/open-infra/estate-capacity-313-measurements.tsv}"
DB_DIR=/var/lib/rancher/k3s/server/db
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

n() { kubectl get "$1" -A --no-headers 2>/dev/null | wc -l | tr -d ' '; }
bytes_mb() { awk "BEGIN{printf \"%.1f\", ${1:-0}/1048576}"; }

# --- object counts (the load drivers) ---
SVC_ALL=$(n svc); SVC_MD=$(kubectl -n main-dev get svc --no-headers 2>/dev/null | wc -l | tr -d ' ')
KPA=$(n kpa); FUNC=$(kubectl get functions.openinfra.dev -A --no-headers 2>/dev/null | wc -l | tr -d ' ')
FUNC_READY=$(kubectl get functions.openinfra.dev -A -o json 2>/dev/null | python3 -c "import json,sys;print(sum(1 for f in json.load(sys.stdin).get('items',[]) if any(c.get('type')=='Ready' and c.get('status')=='True' for c in (f.get('status',{}).get('conditions') or []))))" 2>/dev/null || echo "?")
EP=$(n endpoints); EPS=$(n endpointslices)

# --- datastore (kine/SQLite today; etcd fields show '-' until migrated) ---
STATE_MB=$(bytes_mb "$(stat -c %s "$DB_DIR/state.db" 2>/dev/null || echo 0)")
WAL_MB=$(bytes_mb "$(stat -c %s "$DB_DIR/state.db-wal" 2>/dev/null || echo 0)")

# --- OVN NB/SB db (kube-ovn central) ---
OVNPOD=$(kubectl -n kube-system get pods -l app=ovn-central -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
OVN_NB="-"; OVN_SB="-"
if [ -n "$OVNPOD" ]; then
  OVN_NB=$(bytes_mb "$(kubectl -n kube-system exec "$OVNPOD" -- stat -c %s /etc/ovn/ovnnb_db.db 2>/dev/null || echo 0)")
  OVN_SB=$(bytes_mb "$(kubectl -n kube-system exec "$OVNPOD" -- stat -c %s /etc/ovn/ovnsb_db.db 2>/dev/null || echo 0)")
fi

# --- API latency proxy: 5 timed list calls, avg ms ---
API_MS=$(python3 - <<'PY' 2>/dev/null || echo "?"
import subprocess,time
ts=[]
for _ in range(5):
    t=time.time(); subprocess.run(["kubectl","get","pods","-A","--no-headers"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); ts.append((time.time()-t)*1000)
print("%d"%(sum(ts)/len(ts)))
PY
)

# --- Knative control-plane usage (sum per component across replicas) ---
read -r AS_CPU AS_MEM ACT_MEM CTL_MEM <<<"$(kubectl -n knative-serving top pods --no-headers 2>/dev/null | python3 -c "
import sys,re
agg={}
for ln in sys.stdin:
    p=ln.split()
    if len(p)<3: continue
    name=p[0]; cpu=int(re.sub(r'[^0-9]','',p[1]) or 0); mem=int(re.sub(r'[^0-9]','',p[2]) or 0)
    for k in ('autoscaler','activator','controller'):
        if name.startswith(k): agg.setdefault(k,[0,0]); agg[k][0]+=cpu; agg[k][1]+=mem
a=agg.get('autoscaler',[0,0]);ac=agg.get('activator',[0,0]);c=agg.get('controller',[0,0])
print(a[0],a[1],ac[1],c[1])
" 2>/dev/null || echo '? ? ? ?')"

# --- nodes NotReady + max pods-per-node density ---
NODES_NR=$(kubectl get nodes -o json 2>/dev/null | python3 -c "import json,sys;print(sum(1 for n in json.load(sys.stdin)['items'] if not any(c.get('type')=='Ready' and c.get('status')=='True' for c in (n.get('status',{}).get('conditions') or []))))" 2>/dev/null || echo "?")
MAX_DENS=$(kubectl get pods -A -o json 2>/dev/null | python3 -c "import json,sys;from collections import Counter;c=Counter(p['spec'].get('nodeName') for p in json.load(sys.stdin)['items'] if p['spec'].get('nodeName') and p['status'].get('phase') not in ('Succeeded','Failed'));print(max(c.values()) if c else 0)" 2>/dev/null || echo "?")

HDR="ts\tsvc_all\tsvc_maindev\tkpa\tfunc\tfunc_ready\tendpoints\tepslices\tstatedb_mb\twal_mb\tovn_nb_mb\tovn_sb_mb\tapi_list_ms\tas_cpu_m\tas_mem_mi\tact_mem_mi\tctl_mem_mi\tnodes_notready\tmax_pod_density"
ROW="$TS\t$SVC_ALL\t$SVC_MD\t$KPA\t$FUNC\t$FUNC_READY\t$EP\t$EPS\t$STATE_MB\t$WAL_MB\t$OVN_NB\t$OVN_SB\t$API_MS\t$AS_CPU\t$AS_MEM\t$ACT_MEM\t$CTL_MEM\t$NODES_NR\t$MAX_DENS"
[ -f "$OUT" ] || printf "%b\n" "$HDR" > "$OUT"
printf "%b\n" "$ROW" >> "$OUT"
echo "appended to $OUT:"
printf "%b\n%b\n" "$HDR" "$ROW" | column -t -s $'\t'
