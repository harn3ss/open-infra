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
  log "provisioning sandbox members"
  kubectl apply -f "$HERE/sandbox/members.yaml"
  kubectl -n "$NS" rollout status statefulset/pg-a --timeout=120s
  kubectl -n "$NS" rollout status statefulset/pg-b --timeout=120s

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

# Remove any fault, then (unless CHAOS_KEEP=1) the mesh + members + composed mm-prep Jobs.
sandbox_teardown() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down sandbox members + mesh"
    kubectl -n "$NS" delete -f "$HERE/sandbox/mesh.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/members.yaml" --ignore-not-found >/dev/null 2>&1 || true
    # sweep the engine's composed mm-prep Jobs (not GC'd with the Replication claim)
    kubectl -n "$NS" delete jobs --all --ignore-not-found >/dev/null 2>&1 || true
  fi
}
