# tds-proxy — a TDS-aware connection multiplexer (RDS-Proxy-equivalent)

The open-infra analog of AWS RDS Proxy for the managed SQL-Server / Babelfish engine (TDS on 1433).
It relays each client session to a backend **faithfully** (raw packets, byte-for-byte) while parsing
the client→backend stream to classify every message **multiplexable-vs-pin** — the decision RDS Proxy
makes to know when a pooled backend can be shared vs must be dedicated. Design:
[`docs/design/rds-proxy-tds-multiplexing.md`](../docs/design/rds-proxy-tds-multiplexing.md).

## Status — v1

**Built and live-verified** against real SQL Server 2022:

- **TDS framing + message reassembly** (`tds/`) — packet header, EOM reassembly, SQLBatch text
  (UCS-2), RPC ProcID/name. Stdlib only.
- **The pin classifier** (`classify/`) — the v1 pin-trigger list: SET options, `SET TRANSACTION
  ISOLATION LEVEL`, temp tables, cursors, `USE`, `CONTEXT_INFO`, explicit transactions, applocks,
  `>16 KB` statements, `sp_prepare`/`sp_prepexec`/`sp_cursor*` (RPC), bulk load, and a **fail-safe pin
  on anything unrecognized**. Handles the driver **login-prelude** exception (a SET-only opening batch
  is re-applied on fresh backends, not pinned). Exhaustively unit-tested; verified live (a `SELECT`
  multiplexes, `SET`/temp/txn pin with the right reason).
- **The proxy** (`main.go`) — relays TDS client↔backend, classifies live, reports a per-session verdict
  and a `/status` **multiplex-opportunity** metric (fraction of sessions that never pinned → could
  share a pooled backend), with a per-reason pin breakdown.

**Not yet built (next increment):** the pooling that *acts* on the verdict — synthesizing the login
handshake so a clean backend can be handed to the next client, and transaction-boundary return. The
hard part is login termination; v1 deliberately relays login rather than terminating it. Also open:
**encrypted sessions** — with `Encrypt=mandatory` the SQLBatch is inside TLS and unreadable, so those
sessions must pin unless the proxy terminates TLS (see the design doc's TLS question). Babelfish's
`TDS-no-TLS` default is the classifiable path.

## Run

```bash
go build -o tds-proxy .
./tds-proxy -listen :1433 -backend <babelfish-host>:1433 -metrics :9114
curl localhost:9114/status
```

Test through it with any TDS client using an unencrypted (or login-only) session so the classifier can
read the batches (`encrypt=disable`); an encrypted session relays fine but classifies as pinned.
