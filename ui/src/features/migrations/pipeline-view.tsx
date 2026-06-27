import { ArrowRight, AlertTriangle, Database } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatBytes } from "@/lib/format";
import type { PipelineStatus } from "@/lib/api";

function Stage({ title, value, sub }: { title: string; value: string; sub?: string }) {
  return (
    <Card className="flex-1">
      <CardContent className="p-4">
        <div className="text-xs uppercase tracking-wide text-muted-foreground">{title}</div>
        <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
        {sub ? <div className="mt-0.5 text-xs text-muted-foreground">{sub}</div> : null}
      </CardContent>
    </Card>
  );
}

/**
 * The live apply-pipeline view: a headline replication-lag indicator, a
 * Capture → Buffer → Apply strip, a dead-letter panel, and per-table event
 * counts — driven by a single PipelineStatus (one direction). Shared by the
 * Migration detail page and each direction of the Replication detail page.
 */
export function PipelineView({
  ps,
  sourceEngine,
  targetEngine,
}: {
  ps?: PipelineStatus;
  sourceEngine?: string;
  targetEngine?: string;
}) {
  const lag = ps?.lag ?? 0;
  const inSync = !!ps?.found && lag === 0 && (ps?.ackPending ?? 0) === 0;

  return (
    <div className="space-y-4">
      {/* headline: freshness / lag */}
      <Card>
        <CardContent className="flex items-center justify-between p-5">
          <div>
            <div className="text-sm text-muted-foreground">Replication lag</div>
            <div className="mt-1 text-3xl font-semibold tabular-nums">
              {!ps?.found ? "Provisioning…" : inSync ? "In sync" : `${lag.toLocaleString()} behind`}
            </div>
          </div>
          <Badge variant={inSync ? "secondary" : "default"}>
            {!ps?.found ? "starting" : inSync ? "caught up" : "applying"}
          </Badge>
        </CardContent>
      </Card>

      {/* pipeline strip: Capture -> Buffer -> Apply */}
      <div className="flex items-stretch gap-2">
        <Stage title="Capture" value={sourceEngine ?? "—"} sub="Debezium CDC" />
        <div className="flex items-center text-muted-foreground"><ArrowRight className="size-4" /></div>
        <Stage
          title="Buffer"
          value={(ps?.captured ?? 0).toLocaleString()}
          sub={`${formatBytes(ps?.bytes ?? 0)} in stream`}
        />
        <div className="flex items-center text-muted-foreground"><ArrowRight className="size-4" /></div>
        <Stage
          title="Apply"
          value={lag === 0 ? "0 pending" : `${lag.toLocaleString()} pending`}
          sub={`${ps?.ackPending ?? 0} in flight · ${ps?.redelivered ?? 0} retries → ${targetEngine ?? "?"}`}
        />
      </div>

      {/* dead-letter */}
      {(ps?.deadLetter ?? 0) > 0 ? (
        <Card className="border-destructive/40">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="size-4" />
              <span className="font-medium">{ps?.deadLetter?.toLocaleString()} rows dead-lettered</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              {(ps?.dlqSubjects ?? []).map((d) => (
                <Badge key={d.subject} variant="destructive">
                  {d.table}: {d.count}
                </Badge>
              ))}
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Rows that failed to apply after retries (e.g. type/constraint errors). Kept in the
              dead-letter stream for inspection — they don't block other rows.
            </p>
          </CardContent>
        </Card>
      ) : null}

      {/* per-table */}
      <Card>
        <CardContent className="p-0">
          <div className="border-b px-4 py-2 text-xs uppercase tracking-wide text-muted-foreground">
            Tables
          </div>
          {(ps?.tables ?? []).length === 0 ? (
            <div className="px-4 py-3 text-sm text-muted-foreground">
              No change events captured yet.
            </div>
          ) : (
            <div className="divide-y divide-border">
              {(ps?.tables ?? []).map((t) => (
                <div key={t.subject} className="flex items-center justify-between px-4 py-2 text-sm">
                  <span className="flex items-center gap-2">
                    <Database className="size-3.5 text-muted-foreground" />
                    <code>{t.table}</code>
                  </span>
                  <span className="tabular-nums text-muted-foreground">
                    {t.count.toLocaleString()} events
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
