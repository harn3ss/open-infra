#!/usr/bin/env bash
# Shared helpers for the Nightly Chaos Suite scenarios: provision / describe / tear down
# the disposable two-site multi-master sandbox. Sourced by chaos/scenario-*.sh.
#
# Contract: the caller sets HERE (the chaos/ dir) and NS (the sandbox namespace).

log() { echo "▸ $*"; }

# Provision the disposable members + the multi-master mesh, seeded and empty.
# The table must exist BEFORE the mesh: the engine's mm-prep installs the version/origin
# columns + triggers onto it and CrashLoops if it's missing.
sandbox_provision() {
  # Abort INCONCLUSIVE (not red) if the cluster lacks headroom to run the sandbox.
  "$HERE/preflight-capacity.sh"
  log "provisioning sandbox members (${MEMBERS_MANIFEST:-members.yaml})"
  # Scenarios override MEMBERS_MANIFEST to swap the storage backing (e.g. members-longhorn.yaml
  # puts the DBs on the longhorn-chaos StorageClass for the storage replica-loss scenario).
  kubectl apply -f "$HERE/sandbox/${MEMBERS_MANIFEST:-members.yaml}"
  kubectl -n "$NS" rollout status statefulset/pg-a --timeout="${MEMBERS_ROLLOUT_TIMEOUT:-120s}"
  kubectl -n "$NS" rollout status statefulset/pg-b --timeout="${MEMBERS_ROLLOUT_TIMEOUT:-120s}"

  log "seeding conv_test on both members"
  for m in pg-a pg-b; do
    kubectl -n "$NS" exec "${m}-0" -- psql -U app -d app \
      -c "CREATE TABLE IF NOT EXISTS public.conv_test (id text PRIMARY KEY, val text);"
  done

  log "starting the multi-master mesh (Replication engine)"
  kubectl apply -f "$HERE/sandbox/mesh.yaml"
  sleep "${MESH_WARMUP:-45}"   # let mm-prep install triggers + connectors settle

  # start from a clean table (the harness inserts fresh keys; leftovers would collide)
  for m in pg-a pg-b; do
    kubectl -n "$NS" exec "${m}-0" -- psql -U app -d app -c "TRUNCATE conv_test;" >/dev/null 2>&1 || true
  done
  sleep 5
}

# Export CONV_MEMBERS/PGPASS pointing at the members' ClusterIPs (reachable from the runner).
sandbox_conv_members() {
  local ip_a ip_b
  ip_a="$(kubectl -n "$NS" get svc pg-a -o jsonpath='{.spec.clusterIP}')"
  ip_b="$(kubectl -n "$NS" get svc pg-b -o jsonpath='{.spec.clusterIP}')"
  PGPASS="$(kubectl -n "$NS" get secret pg-creds -o jsonpath='{.data.password}' | base64 -d)"
  export PGPASS
  export CONV_MEMBERS="[
    {\"name\":\"pg-a\",\"engine\":\"postgres\",\"dsn\":\"postgres://app:\${PGPASS}@${ip_a}:5432/app?sslmode=disable\",\"site\":\"a\",\"schema\":\"public\"},
    {\"name\":\"pg-b\",\"engine\":\"postgres\",\"dsn\":\"postgres://app:\${PGPASS}@${ip_b}:5432/app?sslmode=disable\",\"site\":\"b\",\"schema\":\"public\"}
  ]"
}

# ---- CNPG variant (Scenario 4): two REAL HA managed-Postgres clusters -------------

# Provision two HA CNPG clusters + the mesh over their -rw services, seeded and empty.
sandbox_provision_cnpg() {
  # Abort INCONCLUSIVE (not red) if the cluster lacks headroom to run the sandbox.
  "$HERE/preflight-capacity.sh"
  log "provisioning CNPG members (2 HA clusters)"
  kubectl apply -f "$HERE/sandbox/members-cnpg.yaml"
  for i in $(seq 1 40); do
    a="$(kubectl -n "$NS" get cluster cnpg-a -o jsonpath='{.status.readyInstances}' 2>/dev/null || true)"
    b="$(kubectl -n "$NS" get cluster cnpg-b -o jsonpath='{.status.readyInstances}' 2>/dev/null || true)"
    [ "$a" = "2" ] && [ "$b" = "2" ] && break
    sleep 10
  done
  [ "$a" = "2" ] && [ "$b" = "2" ] || { log "CNPG clusters never reached 2/2 (a=$a b=$b)"; return 1; }
  log "both CNPG clusters HA-ready (2/2)"

  # psql over the unix socket would use PEER auth (the container's OS user is postgres,
  # not app), so go over TCP with the password.
  local pw
  pw="$(kubectl -n "$NS" get secret cnpg-app-creds -o jsonpath='{.data.password}' | base64 -d)"
  cnpg_sql() { # $1=cluster $2=sql
    kubectl -n "$NS" exec "${1}-1" -c postgres -- env PGPASSWORD="$pw" \
      psql -h 127.0.0.1 -U app -d app -c "$2"
  }

  log "seeding conv_test on both members"
  for c in cnpg-a cnpg-b; do
    cnpg_sql "$c" "CREATE TABLE IF NOT EXISTS public.conv_test (id text PRIMARY KEY, val text);"
  done

  log "starting the multi-master mesh (Replication engine)"
  kubectl apply -f "$HERE/sandbox/mesh-cnpg.yaml"
  sleep "${MESH_WARMUP:-45}"
  for c in cnpg-a cnpg-b; do
    cnpg_sql "$c" "TRUNCATE conv_test;" >/dev/null 2>&1 || true
  done
  sleep 5
}

# CONV_MEMBERS over the -rw services (they follow the primary across a failover).
sandbox_conv_members_cnpg() {
  local ip_a ip_b
  ip_a="$(kubectl -n "$NS" get svc cnpg-a-rw -o jsonpath='{.spec.clusterIP}')"
  ip_b="$(kubectl -n "$NS" get svc cnpg-b-rw -o jsonpath='{.spec.clusterIP}')"
  PGPASS="$(kubectl -n "$NS" get secret cnpg-app-creds -o jsonpath='{.data.password}' | base64 -d)"
  export PGPASS
  export CONV_MEMBERS="[
    {\"name\":\"cnpg-a\",\"engine\":\"postgres\",\"dsn\":\"postgres://app:\${PGPASS}@${ip_a}:5432/app?sslmode=disable\",\"site\":\"a\",\"schema\":\"public\"},
    {\"name\":\"cnpg-b\",\"engine\":\"postgres\",\"dsn\":\"postgres://app:\${PGPASS}@${ip_b}:5432/app?sslmode=disable\",\"site\":\"b\",\"schema\":\"public\"}
  ]"
}

sandbox_teardown_cnpg() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down CNPG members + mesh"
    kubectl -n "$NS" delete -f "$HERE/sandbox/mesh-cnpg.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/members-cnpg.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete jobs --all --ignore-not-found >/dev/null 2>&1 || true
    # CNPG PVCs are not GC'd with the Cluster
    kubectl -n "$NS" delete pvc -l cnpg.io/cluster --ignore-not-found >/dev/null 2>&1 || true
  fi
}

# ---- Migration variant (#4 zero-downtime migration): one-way source -> target ------

# Provision the disposable source + target DBs, pre-create the probe table on the SOURCE, then
# start the kind: Migration (full-load + CDC). The table must exist before the Migration so the
# Debezium snapshot/publication includes it. Blocks until the migration's apply-sink is Ready.
sandbox_provision_migration() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning migration source + target DBs"
  kubectl apply -f "$HERE/sandbox/migration-members.yaml"
  kubectl -n "$NS" rollout status statefulset/mig-src --timeout="${MEMBERS_ROLLOUT_TIMEOUT:-120s}"
  kubectl -n "$NS" rollout status statefulset/mig-tgt --timeout="${MEMBERS_ROLLOUT_TIMEOUT:-120s}"

  log "pre-creating mig_test on the source (empty; the pipeline replicates schema + rows)"
  kubectl -n "$NS" exec mig-src-0 -- psql -U app -d app \
    -c "CREATE TABLE IF NOT EXISTS public.mig_test (id text PRIMARY KEY, val text);"

  log "starting the kind: Migration (full-load + CDC, src -> tgt)"
  kubectl apply -f "$HERE/sandbox/migration.yaml"
  # Wait for the apply-sink Deployment the composition renders to become available — that is the
  # engine the fault targets, and it must be live before the pipeline can carry anything.
  log "waiting for the migration apply-sink to become available (warmup)"
  for _ in $(seq 1 "${MIG_WARMUP_TRIES:-40}"); do
    if kubectl -n "$NS" get deploy mig-migration-applysink >/dev/null 2>&1; then
      kubectl -n "$NS" rollout status deploy/mig-migration-applysink --timeout="${MIG_ROLLOUT_TIMEOUT:-90s}" && break
    fi
    sleep "${MIG_WARMUP_SLEEP:-6}"
  done
}

# Export MIG_SOURCE / MIG_TARGET (single reconcileMember JSON each) pointing at the DBs' ClusterIPs
# — reachable from the runner. Password expanded from ${PGPASS} like the convergence helper.
sandbox_migration_endpoints() {
  local ip_src ip_tgt
  ip_src="$(kubectl -n "$NS" get svc mig-src -o jsonpath='{.spec.clusterIP}')"
  ip_tgt="$(kubectl -n "$NS" get svc mig-tgt -o jsonpath='{.spec.clusterIP}')"
  PGPASS="$(kubectl -n "$NS" get secret mig-creds -o jsonpath='{.data.password}' | base64 -d)"
  export PGPASS
  export MIG_SOURCE="{\"name\":\"mig-src\",\"engine\":\"postgres\",\"dsn\":\"postgres://app:\${PGPASS}@${ip_src}:5432/app?sslmode=disable\",\"schema\":\"public\"}"
  export MIG_TARGET="{\"name\":\"mig-tgt\",\"engine\":\"postgres\",\"dsn\":\"postgres://app:\${PGPASS}@${ip_tgt}:5432/app?sslmode=disable\",\"schema\":\"public\"}"
}

sandbox_teardown_migration() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down migration CR + endpoints"
    kubectl -n "$NS" delete -f "$HERE/sandbox/migration.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/migration-members.yaml" --ignore-not-found >/dev/null 2>&1 || true
    # sweep the composition's Jobs (schema-sync) + any leaked PVCs (offsets) not GC'd with the CR
    kubectl -n "$NS" delete jobs --all --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pvc -l app=mig --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pvc mig-migration-offsets --ignore-not-found >/dev/null 2>&1 || true
    # Remove the migration's JetStream stream so its reservation is returned to the shared store
    # (the composition's ensure-stream recreates it, right-sized, next provision).
    kubectl -n nats run nats-mig-rm-$$ --rm -i --restart=Never --image=natsio/nats-box:latest -- \
      nats --server=nats://nats.nats.svc:4222 stream rm mig-mig -f >/dev/null 2>&1 || true
  fi
}

# ---- Availability variant (app-availability): HA app + DB + SG, tolerate-mode oracle ------

# Provision the HA Application + its Database + the SecurityGroup, wait for ≥2 app replicas Ready,
# and deploy an in-sandbox prober pod (the app's NetworkPolicy denies off-cluster ingress by
# design, so the prober must live in-namespace). Blocks until the app rollout is complete.
sandbox_provision_appavail() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning availability chain (Application web + Database + SecurityGroup web-tier)"
  kubectl apply -f "$HERE/sandbox/app-availability.yaml"
  # The app pod mounts the CNPG app secret, so its rollout implicitly waits for the DB tier too.
  log "waiting for the app to reach its HA replica count (rollout)"
  for _ in $(seq 1 "${APPAVAIL_WARMUP_TRIES:-40}"); do
    if kubectl -n "$NS" get deploy web >/dev/null 2>&1; then
      kubectl -n "$NS" rollout status deploy/web --timeout="${APPAVAIL_ROLLOUT_TIMEOUT:-90s}" && break
    fi
    sleep "${APPAVAIL_WARMUP_SLEEP:-6}"
  done
  # Guarantee the HA precondition: the fault is only meaningful with ≥2 replicas to survive it.
  local ready
  ready="$(kubectl -n "$NS" get deploy web -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo 0)"
  log "app ready replicas: ${ready:-0}"

  log "deploying the in-sandbox availability prober"
  kubectl -n "$NS" run avail-prober --image=curlimages/curl:latest --restart=Never \
    --labels=app=avail-prober --command -- sleep 100000 >/dev/null 2>&1 || true
  kubectl -n "$NS" wait --for=condition=Ready pod/avail-prober --timeout=60s >/dev/null 2>&1 || true
}

sandbox_teardown_appavail() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down availability chain"
    kubectl -n "$NS" delete pod avail-prober --ignore-not-found --grace-period=0 --force >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/app-availability.yaml" --ignore-not-found >/dev/null 2>&1 || true
    # CNPG PVCs are not GC'd with the Cluster
    kubectl -n "$NS" delete pvc -l cnpg.io/cluster --ignore-not-found >/dev/null 2>&1 || true
  fi
}

# ---- Deny variant (security-deny): egress fence + negative-invariant oracle ------

# Provision svc-allowed + svc-forbidden + the two SecurityGroups, wait both apps Ready, and deploy
# the egress-locked prober (a member of client-egress, so its egress is fenced to svc-tier only).
sandbox_provision_deny() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning deny chain (svc-allowed + svc-forbidden + SecurityGroups svc-tier/client-egress)"
  kubectl apply -f "$HERE/sandbox/deny-chain.yaml"
  for a in svc-allowed svc-forbidden; do
    for _ in $(seq 1 "${DENY_WARMUP_TRIES:-30}"); do
      kubectl -n "$NS" get deploy "$a" >/dev/null 2>&1 && break
      sleep "${DENY_WARMUP_SLEEP:-4}"
    done
    kubectl -n "$NS" rollout status deploy/"$a" --timeout="${DENY_ROLLOUT_TIMEOUT:-90s}" || true
  done

  log "deploying the egress-locked prober (member of client-egress SG)"
  kubectl -n "$NS" run deny-prober --image=curlimages/curl:latest --restart=Never \
    --command -- sleep 100000 >/dev/null 2>&1 || true
  # Membership label: the client-egress netpol selects openinfra.dev/sg-client-egress (value "").
  kubectl -n "$NS" label pod deny-prober openinfra.dev/sg-client-egress= --overwrite >/dev/null 2>&1 || true
  kubectl -n "$NS" wait --for=condition=Ready pod/deny-prober --timeout=60s >/dev/null 2>&1 || true
  sleep 8   # let Cilium apply the egress policy after the label change
}

sandbox_teardown_deny() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down deny chain"
    kubectl -n "$NS" delete pod deny-prober --ignore-not-found --grace-period=0 --force >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/deny-chain.yaml" --ignore-not-found >/dev/null 2>&1 || true
  fi
}

# ---- shared ------------------------------------------------------------------------

# Remove any fault, then (unless CHAOS_KEEP=1) the mesh + members + composed mm-prep Jobs.
sandbox_teardown() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down sandbox members + mesh"
    kubectl -n "$NS" delete -f "$HERE/sandbox/mesh.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/${MEMBERS_MANIFEST:-members.yaml}" --ignore-not-found >/dev/null 2>&1 || true
    # sweep the engine's composed mm-prep Jobs (not GC'd with the Replication claim)
    kubectl -n "$NS" delete jobs --all --ignore-not-found >/dev/null 2>&1 || true
    # StatefulSet volumeClaimTemplate PVCs are NOT deleted with the StatefulSet — sweep them so
    # the Longhorn-backed variant doesn't leak volumes on the chaos nodes across runs.
    kubectl -n "$NS" delete pvc -l app=pg --ignore-not-found >/dev/null 2>&1 || true
  fi
}
