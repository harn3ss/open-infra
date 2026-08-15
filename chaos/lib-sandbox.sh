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
    # `pg_isready` (the readiness probe) flaps TRUE during the postgres image's init/temp-server
    # phase, so `rollout status` can report ready while the entrypoint is still tearing that temp
    # server down to start the real one. Seeding in that window fails with "the database system is
    # shutting down". Retry until the REAL server accepts a write. (Surfaced on a slower-disk
    # substrate; the CREATE is idempotent so retrying is safe everywhere.)
    seeded=0
    for _ in $(seq 1 40); do
      if kubectl -n "$NS" exec "${m}-0" -- psql -U app -d app \
           -c "CREATE TABLE IF NOT EXISTS public.conv_test (id text PRIMARY KEY, val text);" >/dev/null 2>&1; then
        seeded=1; break
      fi
      sleep 3
    done
    [ "$seeded" = 1 ] || { log "FATAL: ${m} never accepted the seed write after retries"; return 1; }
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

# ---- Stream variant (stream-noloss): CDC → JetStream, no-loss oracle -----------------

# Provision the disposable source DB, pre-create the capture table, then start the kind: Stream.
# Blocks until the capture (Debezium) Deployment is available.
sandbox_provision_stream() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning stream source DB"
  kubectl apply -f "$HERE/sandbox/stream-source.yaml"
  kubectl -n "$NS" rollout status statefulset/evt-src --timeout="${MEMBERS_ROLLOUT_TIMEOUT:-120s}"

  log "pre-creating public.events on the source (the Stream captures it)"
  kubectl -n "$NS" exec evt-src-0 -- psql -U app -d app \
    -c "CREATE TABLE IF NOT EXISTS public.events (id text PRIMARY KEY, val text);"

  log "starting the kind: Stream (CDC → JetStream cdc-evt)"
  kubectl apply -f "$HERE/sandbox/stream.yaml"
  log "waiting for the capture engine to become available (warmup)"
  for _ in $(seq 1 "${STREAM_WARMUP_TRIES:-40}"); do
    if kubectl -n "$NS" get deploy evt-stream-dbz >/dev/null 2>&1; then
      kubectl -n "$NS" rollout status deploy/evt-stream-dbz --timeout="${STREAM_ROLLOUT_TIMEOUT:-90s}" && break
    fi
    sleep "${STREAM_WARMUP_SLEEP:-6}"
  done
}

# The number of messages currently on the cdc-evt JetStream stream (one nats call, exact). This is
# the authoritative no-loss signal for the stream scenario: reading each message BODY back via the
# nats CLI (`stream get`) is unreliable past a few dozen (fresh connection per get → throttling),
# but the stream's message COUNT is O(1) metadata and always accurate.
sandbox_stream_msg_count() {
  kubectl -n nats run nats-stream-cnt-$$ --rm -i --restart=Never --image=natsio/nats-box:latest -- \
    sh -c "nats --server=nats://nats.nats.svc:4222 stream info cdc-evt --json 2>/dev/null | tr ',' '\n' | grep -oE '\"messages\": *[0-9]+' | grep -oE '[0-9]+' | head -1" 2>/dev/null \
    | grep -oE '[0-9]+' | head -1
}

sandbox_teardown_stream() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down stream CR + source"
    kubectl -n "$NS" delete -f "$HERE/sandbox/stream.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/stream-source.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pvc -l app=evt-db --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pvc evt-stream-offsets --ignore-not-found >/dev/null 2>&1 || true
    # Return the JetStream stream so it doesn't linger between runs (recreated by ensure-stream).
    kubectl -n nats run nats-stream-rm-$$ --rm -i --restart=Never --image=natsio/nats-box:latest -- \
      nats --server=nats://nats.nats.svc:4222 stream rm cdc-evt -f >/dev/null 2>&1 || true
  fi
}

# ---- Subscription variant (subscription-reconnect): open-appsync → JetStream, no-loss oracle ----

# Provision a 2-replica open-appsync engine wired to the platform NATS JetStream, serving a
# createTodo mutation that triggers an onCreateTodo subscription. Blocks until it is Available.
sandbox_provision_appsync() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning open-appsync engine (2 replicas → platform NATS JetStream)"
  kubectl apply -f "$HERE/sandbox/appsync-engine.yaml"
  kubectl -n "$NS" rollout status deploy/open-appsync-chaos --timeout="${APPSYNC_ROLLOUT_TIMEOUT:-120s}"
}

# Messages currently on the subscription subject's JetStream stream (authoritative, O(1) — the same
# nats-box pattern as sandbox_stream_msg_count).
sandbox_appsync_msg_count() {
  kubectl -n nats run nats-appsync-cnt-$$ --rm -i --restart=Never --image=natsio/nats-box:latest -- \
    sh -c "nats --server=nats://nats.nats.svc:4222 stream info ${SUB_STREAM:-open_appsync_subscriptions} --json 2>/dev/null | tr ',' '\n' | grep -oE '\"messages\": *[0-9]+' | grep -oE '[0-9]+' | head -1" 2>/dev/null \
    | grep -oE '[0-9]+' | head -1
}

sandbox_teardown_appsync() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down open-appsync engine"
    kubectl -n "$NS" delete -f "$HERE/sandbox/appsync-engine.yaml" --ignore-not-found >/dev/null 2>&1 || true
    # Return the JetStream stream so it doesn't linger between runs (the engine recreates it on boot).
    kubectl -n nats run nats-appsync-rm-$$ --rm -i --restart=Never --image=natsio/nats-box:latest -- \
      nats --server=nats://nats.nats.svc:4222 stream rm "${SUB_STREAM:-open_appsync_subscriptions}" -f >/dev/null 2>&1 || true
  fi
}

# ---- Async-invoke variant (async-invoke-noloss): aws-shim durable async worker → JetStream, no-loss ----

# Provision a 2-replica aws-shim wired to the platform NATS JetStream — its durable async (Event)
# delivery worker is what's under test. Blocks until Available. The work + DLQ streams (LAMBDA_ASYNC,
# LAMBDA_ASYNC_DLQ) are created by the shim on boot; teardown returns them so each run starts fresh.
sandbox_provision_shim_async() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning aws-shim (2 replicas → platform NATS JetStream async worker)"
  kubectl apply -f "$HERE/sandbox/shim-async.yaml"
  kubectl -n "$NS" rollout status deploy/aws-shim-chaos --timeout="${SHIM_ROLLOUT_TIMEOUT:-120s}"
}

# Total invocations ACCEPTED onto the work stream. last_seq is monotonic — the authoritative count of
# what was durably enqueued, unaffected by WorkQueue removal-on-ack (so it stays correct as the worker
# drains). This is the denominator of the no-loss oracle.
sandbox_async_accepted() {
  kubectl -n nats run nats-async-seq-$$ --rm -i --restart=Never --image=natsio/nats-box:latest -- \
    sh -c "nats --server=nats://nats.nats.svc:4222 stream info LAMBDA_ASYNC --json 2>/dev/null | tr ',' '\n' | grep -oE '\"last_seq\": *[0-9]+' | grep -oE '[0-9]+' | head -1" 2>/dev/null \
    | grep -oE '[0-9]+' | head -1
}

# Messages currently PENDING on the work stream (WorkQueue removes each on ack/term). Drains to 0 once
# every accepted invocation has been delivered-and-acked or dead-lettered — the delivered-path oracle.
sandbox_async_work_count() {
  kubectl -n nats run nats-async-wc-$$ --rm -i --restart=Never --image=natsio/nats-box:latest -- \
    sh -c "nats --server=nats://nats.nats.svc:4222 stream info LAMBDA_ASYNC --json 2>/dev/null | tr ',' '\n' | grep -oE '\"messages\": *[0-9]+' | grep -oE '[0-9]+' | head -1" 2>/dev/null \
    | grep -oE '[0-9]+' | head -1
}

# Messages currently in the dead-letter stream. With a non-existent target function every accepted
# invocation must fail delivery and land here — so DLQ >= accepted is the no-loss invariant.
sandbox_async_dlq_count() {
  kubectl -n nats run nats-async-dlq-$$ --rm -i --restart=Never --image=natsio/nats-box:latest -- \
    sh -c "nats --server=nats://nats.nats.svc:4222 stream info LAMBDA_ASYNC_DLQ --json 2>/dev/null | tr ',' '\n' | grep -oE '\"messages\": *[0-9]+' | grep -oE '[0-9]+' | head -1" 2>/dev/null \
    | grep -oE '[0-9]+' | head -1
}

# Publish COUNT async invocations for function NAME straight onto the work stream (lambda.async.<name>),
# each carrying the X-Fn-Name header the worker reads — byte-identical to what the shim's Event path
# enqueues, so this drives the worker without needing the SigV4 HTTP front door.
sandbox_publish_async() {
  local name="$1" count="$2"
  kubectl -n nats run "nats-async-pub-$$-$RANDOM" --rm -i --restart=Never --image=natsio/nats-box:latest -- \
    sh -c "for i in \$(seq 1 $count); do nats --server=nats://nats.nats.svc:4222 pub 'lambda.async.$name' 'invoke' -H 'X-Fn-Name:$name' >/dev/null 2>&1; done" >/dev/null 2>&1 || true
}

sandbox_teardown_shim_async() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down aws-shim (async)"
    kubectl -n "$NS" delete -f "$HERE/sandbox/shim-async.yaml" --ignore-not-found >/dev/null 2>&1 || true
    # Return both streams so the next run starts clean (the shim recreates them on boot).
    kubectl -n nats run nats-async-rm-$$ --rm -i --restart=Never --image=natsio/nats-box:latest -- \
      sh -c "nats --server=nats://nats.nats.svc:4222 stream rm LAMBDA_ASYNC -f; nats --server=nats://nats.nats.svc:4222 stream rm LAMBDA_ASYNC_DLQ -f" >/dev/null 2>&1 || true
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

# ---- VirtualMachine variant (vm-resilience): the VM comes back from a virt-launcher kill --------

# Provision the kind: VirtualMachine and wait until the VMI reaches Running (CDI import + boot is
# slow — a few minutes for the first boot).
sandbox_provision_vm() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning kind: VirtualMachine (ubuntu, CDI import + boot — slow)"
  kubectl apply -f "$HERE/sandbox/vm.yaml"
}

# Current VMI phase (Running/Scheduling/…), empty if the VMI doesn't exist yet.
sandbox_vmi_phase() { kubectl -n "$NS" get vmi vm -o jsonpath='{.status.phase}' 2>/dev/null || true; }

# Block until the VMI reports Running (or give up). $1 = tries (x6s).
sandbox_vm_wait_running() {
  local tries="${1:-70}"
  for _ in $(seq 1 "$tries"); do
    [ "$(sandbox_vmi_phase)" = "Running" ] && return 0
    sleep 6
  done
  return 1
}

sandbox_teardown_vm() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down kind: VirtualMachine"
    kubectl -n "$NS" delete -f "$HERE/sandbox/vm.yaml" --ignore-not-found >/dev/null 2>&1 || true
    # the CDI-provisioned root disk PVC is not GC'd with the VM
    kubectl -n "$NS" delete pvc vm-root --ignore-not-found >/dev/null 2>&1 || true
  fi
}

# ---- DataFlow variant (dataflow-converge): the DataFlow kind reconverges under a capture kill ----

# Provision the disposable members + pre-seed conv_test, then start the kind: DataFlow (one
# replication edge over pg-a<->pg-b). Reuses members.yaml; blocks until both nodes' capture is up.
sandbox_provision_dataflow() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning sandbox members (for the DataFlow nodes)"
  kubectl apply -f "$HERE/sandbox/members.yaml"
  kubectl -n "$NS" rollout status statefulset/pg-a --timeout="${MEMBERS_ROLLOUT_TIMEOUT:-120s}"
  kubectl -n "$NS" rollout status statefulset/pg-b --timeout="${MEMBERS_ROLLOUT_TIMEOUT:-120s}"
  log "seeding conv_test on both members"
  for m in pg-a pg-b; do
    # `pg_isready` (the readiness probe) flaps TRUE during the postgres image's init/temp-server
    # phase, so `rollout status` can report ready while the entrypoint is still tearing that temp
    # server down to start the real one. Seeding in that window fails with "the database system is
    # shutting down". Retry until the REAL server accepts a write. (Surfaced on a slower-disk
    # substrate; the CREATE is idempotent so retrying is safe everywhere.)
    seeded=0
    for _ in $(seq 1 40); do
      if kubectl -n "$NS" exec "${m}-0" -- psql -U app -d app \
           -c "CREATE TABLE IF NOT EXISTS public.conv_test (id text PRIMARY KEY, val text);" >/dev/null 2>&1; then
        seeded=1; break
      fi
      sleep 3
    done
    [ "$seeded" = 1 ] || { log "FATAL: ${m} never accepted the seed write after retries"; return 1; }
  done

  log "starting the kind: DataFlow (replication edge pg-a <-> pg-b)"
  kubectl apply -f "$HERE/sandbox/dataflow.yaml"
  sleep "${MESH_WARMUP:-45}"   # let mm-prep + per-node capture + per-edge sinks settle
  for m in pg-a pg-b; do
    kubectl -n "$NS" exec "${m}-0" -- psql -U app -d app -c "TRUNCATE conv_test;" >/dev/null 2>&1 || true
  done
  sleep 5
}

sandbox_teardown_dataflow() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down DataFlow + members"
    kubectl -n "$NS" delete -f "$HERE/sandbox/dataflow.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/members.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete jobs --all --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pvc -l app=pg --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pvc -l openinfra.dev/dataflow=df --ignore-not-found >/dev/null 2>&1 || true
    # return the per-node flow streams
    for node in pg-a pg-b; do
      kubectl -n nats run nats-df-rm-$$-$node --rm -i --restart=Never --image=natsio/nats-box:latest -- \
        sh -c "nats --server=nats://nats.nats.svc:4222 stream ls -n 2>/dev/null | grep '^flow-' | xargs -r -n1 nats --server=nats://nats.nats.svc:4222 stream rm -f" >/dev/null 2>&1 || true
      break
    done
  fi
}

# ---- Volume variant (volume-durable): block data survives a pod reschedule ----------

# Provision the kind: Volume + a writer Deployment that attaches its block device, and wait for the
# writer to be Running with the device present.
sandbox_provision_volume() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning kind: Volume (Longhorn block) + writer"
  kubectl apply -f "$HERE/sandbox/volume.yaml"
  for _ in $(seq 1 "${VOL_WARMUP_TRIES:-30}"); do
    kubectl -n "$NS" get pvc vol >/dev/null 2>&1 && break
    sleep "${VOL_WARMUP_SLEEP:-4}"
  done
  kubectl apply -f "$HERE/sandbox/volume-writer.yaml"
  kubectl -n "$NS" rollout status deploy/vol-writer --timeout="${VOL_ROLLOUT_TIMEOUT:-180s}" || true
}

# Run a shell command in the current vol-writer pod.
sandbox_vol_exec() { kubectl -n "$NS" exec deploy/vol-writer -- sh -c "$*"; }

sandbox_teardown_volume() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down kind: Volume + writer"
    kubectl -n "$NS" delete -f "$HERE/sandbox/volume-writer.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/volume.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pvc vol --ignore-not-found >/dev/null 2>&1 || true
  fi
}

# ---- FileShare variant (fileshare-durable): SMB share data survives a server kill ----

# Provision the kind: FileShare, wait for the Samba Deployment, and deploy an smbclient client pod
# (userspace SMB — no cifs kernel mount needed, so it tests the real share over the Service).
sandbox_provision_fileshare() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning kind: FileShare (Samba SMB share on Longhorn)"
  kubectl apply -f "$HERE/sandbox/fileshare.yaml"
  for _ in $(seq 1 "${FS_WARMUP_TRIES:-40}"); do
    kubectl -n "$NS" get deploy fs-smb >/dev/null 2>&1 && break
    sleep "${FS_WARMUP_SLEEP:-6}"
  done
  kubectl -n "$NS" rollout status deploy/fs-smb --timeout="${FS_ROLLOUT_TIMEOUT:-180s}" || true

  log "deploying the smbclient probe pod"
  # Force-recreate: a `kubectl run` silently no-ops if a prior fs-client is still Terminating,
  # leaving no ready client and every SMB probe failing. Delete + wait-gone, then create fresh.
  kubectl -n "$NS" delete pod fs-client --ignore-not-found --grace-period=0 --force >/dev/null 2>&1 || true
  kubectl -n "$NS" wait --for=delete pod/fs-client --timeout=30s >/dev/null 2>&1 || true
  kubectl -n "$NS" run fs-client --image=dperson/samba --restart=Never --command -- sleep 100000 >/dev/null 2>&1 || true
  kubectl -n "$NS" wait --for=condition=Ready pod/fs-client --timeout=90s >/dev/null 2>&1 || true
}

# smbclient against the share over the Service. $1 = the -c command string. Prints smbclient output.
# Trailing `|| true`: smbclient often exits non-zero even on a successful listing (dperson/samba
# emits messaging-context warnings), which under the callers' `set -o pipefail` would poison
# `sandbox_smb ... | grep` and make the check false even when grep matched. Force exit 0 so only the
# OUTPUT matters — a real failure just yields empty output (no grep match), which the callers handle.
sandbox_smb() {
  local pass="$1"; shift
  kubectl -n "$NS" exec fs-client -- smbclient "//fs.$NS.svc.cluster.local/fs" -U "openinfra%${pass}" -c "$*" 2>/dev/null || true
}

sandbox_teardown_fileshare() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down kind: FileShare"
    kubectl -n "$NS" delete pod fs-client --ignore-not-found --grace-period=0 --force >/dev/null 2>&1 || true
    kubectl -n "$NS" delete -f "$HERE/sandbox/fileshare.yaml" --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pvc -l openinfra.dev/fileshare=true --ignore-not-found >/dev/null 2>&1 || true
  fi
}

# ---- Directory variant (directory-recover): AD DC survives a kill with data intact ----

# Provision the kind: Directory and wait until the AD domain is actually provisioned and serving
# (samba-tool answers), not merely until the pod is Running — first-boot domain provisioning is slow.
sandbox_provision_directory() {
  "$HERE/preflight-capacity.sh"   # abort INCONCLUSIVE (not red) if the cluster lacks headroom
  log "provisioning kind: Directory (Samba AD DC)"
  kubectl apply -f "$HERE/sandbox/directory.yaml"
  log "waiting for the DC pod to appear + become Running"
  for _ in $(seq 1 "${DIR_WARMUP_TRIES:-50}"); do
    kubectl -n "$NS" get statefulset dir-dc >/dev/null 2>&1 && break
    sleep "${DIR_WARMUP_SLEEP:-6}"
  done
  kubectl -n "$NS" rollout status statefulset/dir-dc --timeout="${DIR_ROLLOUT_TIMEOUT:-300s}" || true
}

# Run samba-tool inside the current DC pod (dir-dc-0). Returns its exit status; used both to wait for
# the domain to be provisioned and to create/verify the probe account.
sandbox_dc_exec() { kubectl -n "$NS" exec dir-dc-0 -- "$@"; }

# Block until the AD domain answers `samba-tool user list` (domain provisioned + serving).
sandbox_dc_wait_ready() {
  local tries="${1:-40}"
  for _ in $(seq 1 "$tries"); do
    if sandbox_dc_exec samba-tool user list >/dev/null 2>&1; then return 0; fi
    sleep 6
  done
  return 1
}

sandbox_teardown_directory() {
  kubectl -n "$NS" delete faultinjection --all --ignore-not-found >/dev/null 2>&1 || true
  if [ "${CHAOS_KEEP:-0}" != "1" ]; then
    log "tearing down kind: Directory"
    kubectl -n "$NS" delete -f "$HERE/sandbox/directory.yaml" --ignore-not-found >/dev/null 2>&1 || true
    # StatefulSet volumeClaimTemplate PVC is not GC'd with the StatefulSet.
    kubectl -n "$NS" delete pvc -l openinfra.dev/directory=true --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pvc -l app=dir-dc --ignore-not-found >/dev/null 2>&1 || true
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
    # …and their orphaned Completed/Failed pods, which survive the Job deletion and otherwise
    # accumulate toward the namespace pod quota (fatal once continuous runs fire every ~30 min).
    kubectl -n "$NS" delete pod --field-selector status.phase=Succeeded --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n "$NS" delete pod --field-selector status.phase=Failed --ignore-not-found >/dev/null 2>&1 || true
    # StatefulSet volumeClaimTemplate PVCs are NOT deleted with the StatefulSet — sweep them so
    # the Longhorn-backed variant doesn't leak volumes on the chaos nodes across runs.
    kubectl -n "$NS" delete pvc -l app=pg --ignore-not-found >/dev/null 2>&1 || true
    # General orphan-PVC reclaim: any PVC no LIVE pod mounts is a leftover from an interrupted run
    # (the sandbox holds only ephemeral scenario PVCs — real data never lives here). Catches what the
    # app=pg selector misses (evt-stream-offsets, Longhorn volumes, cancelled-run debris) so they don't
    # accumulate and slowly fill the chaos-node disk.
    local _inuse _pvc
    _inuse="$(kubectl -n "$NS" get pods -o jsonpath='{range .items[*]}{range .spec.volumes[*]}{.persistentVolumeClaim.claimName}{"\n"}{end}{end}' 2>/dev/null | sort -u)"
    for _pvc in $(kubectl -n "$NS" get pvc -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null); do
      printf '%s\n' "$_inuse" | grep -qxF "$_pvc" || kubectl -n "$NS" delete pvc "$_pvc" --ignore-not-found >/dev/null 2>&1 || true
    done
  fi
}
