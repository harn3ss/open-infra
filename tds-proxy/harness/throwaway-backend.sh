#!/usr/bin/env bash
# Stand up a THROWAWAY backend for the driver grid and print its host:port. Deleted with `--down`.
# Never point the harness at a real/user database — always this throwaway (throwaway-and-delete rule).
set -euo pipefail
NAME=tdsgrid-mssql
if [ "${1:-}" = "--down" ]; then docker rm -f "$NAME" >/dev/null 2>&1 || true; echo "removed $NAME"; exit 0; fi
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -e ACCEPT_EULA=Y -e "MSSQL_SA_PASSWORD=${SA_PASSWORD:-Grid#Test2026!}" \
  -e MSSQL_PID=Developer -p "${PORT:-21433}:1433" mcr.microsoft.com/mssql/server:2022-latest >/dev/null
for i in $(seq 1 24); do
  if docker exec "$NAME" /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "${SA_PASSWORD:-Grid#Test2026!}" -C -Q "SELECT 1" >/dev/null 2>&1; then
    echo "127.0.0.1:${PORT:-21433}"; exit 0
  fi; sleep 5
done
echo "backend did not come up" >&2; exit 1
