import type { DbStats } from "@/lib/api";
import { formatBytes } from "@/lib/format";

/**
 * Live database-engine internals ("Peek"): connections, replication-slot/CDC lag, and
 * top queries. Shared by the DataFlow canvas (per-node Peek) and the managed /databases
 * detail pages. Pure presentation — the caller supplies the already-fetched stats.
 */
export function DbStatsPanel({
  stats,
  loading,
  error,
}: {
  stats: DbStats | undefined;
  loading?: boolean;
  error?: boolean;
}) {
  if (!stats) {
    return (
      <p className="text-xs text-muted-foreground">
        {error ? "Couldn't reach the database." : loading ? "Loading engine stats…" : "No stats yet."}
      </p>
    );
  }
  const c = stats.connections;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-4 gap-2">
        <Metric label="Connections" value={`${c.total}${c.max ? `/${c.max}` : ""}`} />
        <Metric label="Active" value={String(c.active)} />
        <Metric label="Idle" value={String(c.idle)} />
        <Metric label="Idle in txn" value={String(c.idleInTx)} />
      </div>

      {stats.replication && stats.replication.length ? (
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">Replication slots (CDC lag)</div>
          <div className="space-y-0.5">
            {stats.replication.map((s) => (
              <div key={s.slot} className="flex items-center justify-between rounded bg-muted/40 px-2 py-0.5 text-xs">
                <code>{s.slot}</code>
                <span className="flex gap-2">
                  <span className={s.active ? "text-emerald-600" : "text-muted-foreground"}>{s.active ? "● active" : "○ inactive"}</span>
                  <span className={s.lagBytes > 50_000_000 ? "text-amber-600" : "text-muted-foreground"}>{formatBytes(s.lagBytes)} behind</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {stats.topQueries && stats.topQueries.length ? (
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">Top queries</div>
          <div className="max-h-40 space-y-1 overflow-y-auto">
            {stats.topQueries.map((q, i) => (
              <div key={i} className="rounded border px-2 py-1 text-[11px]">
                <div className="flex justify-between text-muted-foreground">
                  <span>{q.calls ? `${q.calls.toLocaleString()} calls` : "active"}</span>
                  <span>
                    {q.meanMs ? `${q.meanMs.toFixed(1)} ms avg` : ""}
                    {q.totalMs ? ` · ${(q.totalMs / 1000).toFixed(1)}s total` : ""}
                  </span>
                </div>
                <code className="mt-0.5 block truncate font-mono" title={q.query}>{q.query}</code>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {stats.note ? <p className="text-[11px] italic text-muted-foreground">{stats.note}</p> : null}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border bg-card px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="text-sm font-semibold tabular-nums">{value}</div>
    </div>
  );
}
