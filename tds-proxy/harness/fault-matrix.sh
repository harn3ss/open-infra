#!/usr/bin/env bash
# #40 fault-matrix orchestrator. Drives a driver client (harness/<driver>/Fault.*) through one fault
# scenario against the THROWAWAY backend behind the TLS-terminating proxy, injects the backend fault at
# a fixed offset after launch, and prints a normalized CELL line (client RESULT + proxy /status deltas).
# Never point at a real DB — the throwaway-and-delete rule. One cell per call:
#   ./fault-matrix.sh cell   <driver> <scenario> [restart|none]
#   ./fault-matrix.sh stampede <driver> <N>
# Drivers: jdbc tedious pyodbc dotnet sqlalchemy. Scenarios: failover-idle failover-during-txn
# midresult-drop pinned-discard.
set -uo pipefail
STATUS=${STATUS:-http://127.0.0.1:29114/status}
CONTAINER=${CONTAINER:-tdsgrid-mssql}
SA_PW=${SA_PW:-'Grid#Test2026!'}
HOST=${HOST:-127.0.0.1}; PORT=${PORT:-23433}
FAULT_AT=${FAULT_AT:-9}        # seconds after client launch to kill+restart the backend
FAULT_SLEEP=${FAULT_SLEEP:-34} # how long the client waits in its fault window (must outlast backend restart)
POOLMAX=${POOLMAX:-4}
ROOT=/home/cake/open-infra/tds-proxy/harness
JDBC=$ROOT/jdbc

sval(){ curl -s "$STATUS" 2>/dev/null | awk -v k="$1" '$1==k{print $2}'; }
wait_backend(){ for i in $(seq 1 40); do docker exec "$CONTAINER" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PW" -C -Q "SELECT 1" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

# Emit the shell command that runs a driver client for (scenario, sentinel). ENCRYPT=true — the proxy
# terminates TLS (modern drivers default encrypt=true); trustServerCertificate handled per client.
client_cmd(){
  local d=$1 sc=$2 sent=$3
  case "$d" in
    jdbc)    echo "env HOST=$HOST PORT=$PORT USER=sa PW=$SA_PW ENCRYPT=true SCENARIO=$sc SENTINEL=$sent FAULT_SLEEP=$FAULT_SLEEP java -cp $JDBC:$JDBC/mssql-jdbc.jar Fault" ;;
    tedious) echo "env HOST=$HOST PORT=$PORT USER=sa PW=$SA_PW SCENARIO=$sc SENTINEL=$sent FAULT_SLEEP=$FAULT_SLEEP node $ROOT/tedious/fault.js" ;;
    pyodbc)     echo "docker run --rm --network host -e HOST=$HOST -e PORT=$PORT -e USER=sa -e PW=$SA_PW -e SCENARIO=$sc -e SENTINEL=$sent -e FAULT_SLEEP=$FAULT_SLEEP -e MODE=pyodbc     -v $ROOT/pyodbc:/h tdsgrid-pyodbc python /h/fault.py" ;;
    sqlalchemy) echo "docker run --rm --network host -e HOST=$HOST -e PORT=$PORT -e USER=sa -e PW=$SA_PW -e SCENARIO=$sc -e SENTINEL=$sent -e FAULT_SLEEP=$FAULT_SLEEP -e MODE=sqlalchemy -e PRE_PING=${PRE_PING:-0} -v $ROOT/pyodbc:/h tdsgrid-pyodbc python /h/fault.py" ;;
    dotnet)  echo "docker run --rm --network host -e HOST=$HOST -e PORT=$PORT -e USER=sa -e PW=$SA_PW -e SCENARIO=$sc -e SENTINEL=$sent -e FAULT_SLEEP=$FAULT_SLEEP tdsgrid-dotnet-fault" ;;
  esac
}

run_cell(){
  local d=$1 sc=$2 fault=${3:-restart}
  local sent="${d}$(date +%s)"
  wait_backend || { echo "CELL driver=$d scenario=$sc ERROR=backend-down"; return 1; }
  local disc0=$(sval pool_discards) cold0=$(sval pool_cold_opens) warm0=$(sval pool_warm_reuses) evict0=$(sval pool_dead_evicted)
  local log; log=$(mktemp)
  eval "$(client_cmd "$d" "$sc" "$sent")" >"$log" 2>&1 &
  local cpid=$!
  if [ "$fault" = "restart" ]; then
    # docker kill = immediate SIGKILL (docker restart does a graceful 10s stop, which lets a WAITFOR
    # window outlast the "fault"). Kill hard so the backend dies exactly at FAULT_AT, then bring it back.
    sleep "$FAULT_AT"; docker kill "$CONTAINER" >/dev/null 2>&1; docker start "$CONTAINER" >/dev/null 2>&1; wait_backend
  fi
  wait "$cpid" 2>/dev/null
  local disc1=$(sval pool_discards) cold1=$(sval pool_cold_opens) warm1=$(sval pool_warm_reuses) evict1=$(sval pool_dead_evicted)
  local res; res=$(grep '^RESULT' "$log" | head -1 | sed 's/^RESULT //')
  [ -z "$res" ] && res="(no RESULT) $(tail -2 "$log" | tr '\n' ' ')"
  echo "CELL driver=$d scenario=$sc | $res | discards+$((disc1-disc0)) coldopens+$((cold1-cold0)) warmreuse+$((warm1-warm0)) deadevict+$((evict1-evict0))"
  rm -f "$log"
}

run_stampede(){
  local d=$1 n=${2:-6}
  wait_backend || { echo "STAMPEDE driver=$d ERROR=backend-down"; return 1; }
  local to0=$(sval pool_acquire_timeouts) cold0=$(sval pool_cold_opens)
  local dir; dir=$(mktemp -d); local i
  for i in $(seq 1 "$n"); do
    FAULT_SLEEP=8 eval "$(client_cmd "$d" pin-hold stamp$i)" >"$dir/$i.log" 2>&1 &
  done
  wait
  local to1=$(sval pool_acquire_timeouts) cold1=$(sval pool_cold_opens)
  local acq; acq=$(grep -l 'acquired=true' "$dir"/*.log 2>/dev/null | wc -l)
  local fail; fail=$(grep -l 'acquired=false' "$dir"/*.log 2>/dev/null | wc -l)
  echo "STAMPEDE driver=$d n=$n pool-max=$POOLMAX | acquired=$acq failed=$fail | acquire_timeouts+$((to1-to0)) coldopens+$((cold1-cold0))"
  rm -rf "$dir"
}

case "${1:-}" in
  cell) shift; run_cell "$@" ;;
  stampede) shift; run_stampede "$@" ;;
  *) echo "usage: $0 cell <driver> <scenario> [restart|none] | stampede <driver> <N>"; exit 2 ;;
esac
